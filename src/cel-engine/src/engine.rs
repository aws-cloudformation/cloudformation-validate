use log::info;
use std::collections::HashMap;
use std::sync::Arc;

use diagnostics::{Diagnostic, Entity, PhaseMetric, phase_metric};
use guard_translator::{ensure_translatable, pack_name_from_path, parse_guard};
use rules::{RuleInfo, RuleMetadataEntry, RuleOrigin, Severity, build_rule_metadata_map, is_valid_custom_rule_id};
use template_model::{SemanticModel, UNKNOWN_SPAN};
use validation_engine::{
    EngineConfig, OverlayCatalog, SchemaValidator, ValidateConfig, ValidationEngine, ValidationError, build_rule_list,
    semantic_model_to_input_json,
};

use crate::rule_evaluator::GeneratedRuleRegistry;
use crate::rules::{CachedData, EvalContext, NativeRuleRegistry};

use serde::Deserialize;

use cel_interpreter::{Context, Program, Value as CelValue};

#[derive(Deserialize)]
struct CustomRuleFile {
    rules: Vec<CustomRuleDef>,
}

#[derive(Deserialize)]
struct CustomRuleDef {
    rule_id: String,
    severity: Severity,
    #[serde(default)]
    category: Option<String>,
    resource_type: Option<String>,
    expression: String,
    message: String,
    #[serde(default)]
    prop_path: Option<String>,
    #[serde(default)]
    suggested_fix: Option<String>,
}

pub struct CelEngine {
    native_rules: NativeRuleRegistry,
    generated_rules: GeneratedRuleRegistry,
    custom_rules: Vec<CustomRule>,
    /// Built-in rule metadata from the rules registry only.
    registry_metadata: HashMap<String, RuleMetadataEntry>,
    /// Metadata for custom user rules and translated guard rules.
    external_rule_metadata: HashMap<String, RuleMetadataEntry>,
    cached_data: CachedData,
    init_metric: PhaseMetric,
}

#[derive(Debug)]
struct CustomRule {
    rule_id: String,
    severity: Severity,
    category: Option<String>,
    resource_type: Option<String>,
    program: Program,
    message: String,
    prop_path: Option<String>,
    suggested_fix: Option<String>,
    source: RuleOrigin,
}

impl CelEngine {
    pub fn new(config: EngineConfig) -> anyhow::Result<Self> {
        let catalog =
            config.build_overlay_catalog().map_err(|e| anyhow::anyhow!("Failed to build overlay catalog: {e}"))?;
        Self::new_from_catalog(config, &catalog)
    }

    /// Constructs the engine reusing metadata from an already-built
    /// [`SchemaValidator`]. The validator's overlay catalog is treated as
    /// authoritative — the engine does not re-resolve overlay schemas.
    ///
    /// This entry point is intended for language bindings and the CLI, which
    /// construct a `SchemaValidator` once and share it with the engine.
    #[doc(hidden)]
    pub fn new_with_schema_validator(config: EngineConfig, validator: &SchemaValidator) -> anyhow::Result<Self> {
        Self::new_from_catalog(config, validator.overlay_catalog())
    }

    /// Internal constructor that accepts a pre-built overlay catalog.
    fn new_from_catalog(config: EngineConfig, overlay_catalog: &OverlayCatalog) -> anyhow::Result<Self> {
        let start = web_time::Instant::now();

        let native_rules = NativeRuleRegistry::new();
        let generated_rules = GeneratedRuleRegistry::new()?;

        let registry_metadata = build_rule_metadata_map();
        let mut external_rule_metadata: HashMap<String, RuleMetadataEntry> = HashMap::new();

        let mut translated_guard_sources = Vec::new();
        for entry in &config.guard_rules {
            let guard_file = parse_guard(&entry.content, &entry.name)
                .map_err(|e| anyhow::anyhow!("Failed to parse guard file '{}': {}", entry.name, e))?;
            ensure_translatable(&guard_file)
                .map_err(|e| anyhow::anyhow!("Unsupported guard rule in '{}': {}", entry.name, e))?;
            let pack = pack_name_from_path(&entry.name);
            let translated = crate::guard_to_cel::translate_to_cel(&guard_file, &pack, &[]);
            let json = crate::guard_to_cel::to_custom_rule_json(&translated)
                .map_err(|e| anyhow::anyhow!("Failed to translate guard file '{}' to CEL: {}", entry.name, e))?;
            translated_guard_sources.push((entry.name.clone(), json));
        }

        let mut custom_rules = Vec::new();
        for entry in &config.custom_rules {
            match load_custom_rules(&entry.content, RuleOrigin::Custom) {
                Ok(rules) => {
                    info!("Loaded {} custom rules from {}", rules.len(), entry.name);
                    for r in &rules {
                        external_rule_metadata.entry(r.rule_id.clone()).or_insert_with(|| RuleMetadataEntry {
                            category: r.category.clone(),
                            description: r.message.clone(),
                            severity: r.severity,
                            origin: RuleOrigin::Custom,
                        });
                    }
                    custom_rules.extend(rules);
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to load rules from {}: {}", entry.name, e));
                }
            }
        }
        for (path, source) in &translated_guard_sources {
            match load_custom_rules(source, RuleOrigin::Guard) {
                Ok(rules) => {
                    info!("Loaded {} guard rules from {}", rules.len(), path);
                    for r in &rules {
                        external_rule_metadata.entry(r.rule_id.clone()).or_insert_with(|| RuleMetadataEntry {
                            category: r.category.clone(),
                            description: r.message.clone(),
                            severity: r.severity,
                            origin: RuleOrigin::Guard,
                        });
                    }
                    custom_rules.extend(rules);
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to load guard rules from {}: {}", path, e));
                }
            }
        }

        info!(
            "CelEngine initialized: {} native rule fns, {} custom rules, {} registry + {} external metadata entries",
            native_rules.rules.len(),
            custom_rules.len(),
            registry_metadata.len(),
            external_rule_metadata.len()
        );
        let mut cached_data = CachedData::load()?;
        // Resource types introduced by an overlay schema are legitimate targets,
        // so rules working from the build-time type catalog must treat them as
        // known rather than reporting them as nonexistent.
        if !overlay_catalog.is_empty() {
            cached_data.merge_overlay_catalog(overlay_catalog)?;
        }
        let init_metric = phase_metric(start);
        Ok(CelEngine {
            native_rules,
            generated_rules,
            custom_rules,
            registry_metadata,
            external_rule_metadata,
            cached_data,
            init_metric,
        })
    }
}

impl ValidationEngine for CelEngine {
    fn engine_name(&self) -> &str {
        "cel"
    }

    fn evaluate_rules(
        &self,
        model: &Arc<SemanticModel>,
        config: &ValidateConfig,
    ) -> Result<Vec<Diagnostic>, ValidationError> {
        let input_json = semantic_model_to_input_json(model)?;
        let excluded_cats = config.filters.excluded_categories();
        let region = config.pseudo_parameter_overrides.region.clone();

        let mut diagnostics = if config.disable_builtin_rules {
            Vec::new()
        } else {
            let ctx = EvalContext { model, input: &input_json, region: &region, cached_data: &self.cached_data };
            let mut diags = self.native_rules.evaluate(&ctx, &excluded_cats);
            let gen_diags = self.generated_rules.evaluate(model, &input_json, &excluded_cats);
            diags.extend(gen_diags);
            diags
        };

        for rule in &self.custom_rules {
            if rule.category.as_deref().is_some_and(|c| excluded_cats.contains(c)) {
                continue;
            }
            if let Some(ref rtype) = rule.resource_type {
                for rid in model.resources_of_type(rtype) {
                    let cel_ctx = crate::functions::build_custom_context(&input_json, Some(rid), Some(model));
                    if execute_custom_rule(rule, &cel_ctx)? {
                        let msg = rule.message.replace("{name}", rid);
                        emit_custom_diagnostic(&mut diagnostics, rule, model, rid, &msg);
                    }
                }
            } else {
                let cel_ctx = crate::functions::build_custom_context(&input_json, None, Some(model));
                if execute_custom_rule(rule, &cel_ctx)? {
                    emit_custom_diagnostic(&mut diagnostics, rule, model, "", &rule.message);
                }
            }
        }

        Ok(diagnostics)
    }

    fn list_rules(&self) -> Vec<RuleInfo> {
        build_rule_list(&self.registry_metadata, &self.external_rule_metadata)
    }

    fn rule_metadata(&self) -> &HashMap<String, RuleMetadataEntry> {
        &self.registry_metadata
    }

    fn external_rule_metadata(&self) -> HashMap<String, RuleMetadataEntry> {
        self.external_rule_metadata.clone()
    }

    fn init_metric(&self) -> &PhaseMetric {
        &self.init_metric
    }
}

fn execute_custom_rule(rule: &CustomRule, cel_ctx: &Context<'static>) -> Result<bool, ValidationError> {
    match rule.program.execute(cel_ctx) {
        Ok(CelValue::Bool(fired)) => Ok(fired),
        // A rule expression must decide whether the rule fires, so it must produce a
        // boolean. A non-boolean result means the expression is malformed (e.g. it
        // names a property instead of testing one); treating it as "did not fire"
        // would let the mistake pass silently, so surface it as an error.
        Ok(_) => Err(ValidationError::Engine(format!(
            "Custom rule '{}' expression must evaluate to a boolean, but produced a non-boolean value",
            rule.rule_id
        ))),
        // A translated Guard clause reads properties that may be absent, so evaluation
        // errors on the missing key. Guard's semantics treat an absent property as a
        // check that simply does not pass, so tolerate the error as "did not fire"
        // rather than surfacing it.
        Err(error) if matches!(rule.source, RuleOrigin::Guard) => {
            log::error!("Guard rule '{}' failed to evaluate (tolerated): {error}", rule.rule_id);
            Ok(false)
        }
        Err(error) => {
            Err(ValidationError::Engine(format!("Custom rule '{}' failed to evaluate: {error}", rule.rule_id)))
        }
    }
}

// Custom and Guard rules are not in the rule registry, so their severity,
// category, and origin come from the parsed rule rather than the registry-driven
// `RegisteredDiagnostic` builder used for built-in rules.
fn emit_custom_diagnostic(
    out: &mut Vec<Diagnostic>,
    rule: &CustomRule,
    model: &Arc<SemanticModel>,
    rid: &str,
    msg: &str,
) {
    let span =
        if rid.is_empty() { UNKNOWN_SPAN } else { model.resource_span(rid, rule.prop_path.as_deref().unwrap_or("")) };
    out.push(Diagnostic {
        rule_id: rule.rule_id.clone(),
        severity: rule.severity,
        message: msg.to_string(),
        entity: Entity::resource(rid, model.resources.get(rid).map(|r| r.resource_type.clone())),
        property_path: rule.prop_path.clone(),
        suggested_fix: rule.suggested_fix.clone(),
        documentation_url: None,
        category: rule.category.clone(),
        location: if span == UNKNOWN_SPAN { None } else { Some(span) },
        related_resources: None,
        condition_scenario: None,
        rule_description: None,
        phase: None,
        context: None,
        source: rule.source,
    });
}

fn load_custom_rules(source: &str, origin: RuleOrigin) -> anyhow::Result<Vec<CustomRule>> {
    let file: CustomRuleFile = serde_json::from_str(source)?;
    let mut rules = Vec::new();
    for def in file.rules {
        // Required text fields must be present and non-blank. `serde` guarantees the
        // keys exist; these checks reject empty values that would otherwise yield a
        // diagnostic with no rule ID or no message.
        if def.rule_id.trim().is_empty() {
            return Err(anyhow::anyhow!("Custom rule has an empty 'rule_id'"));
        }
        // A custom rule ID may be any run of letters, digits, and the separators
        // `_`, `.`, `-` — it need not follow the built-in ID convention — but must
        // exclude whitespace and other punctuation that would corrupt formatting,
        // filtering, and de-duplication of diagnostics.
        if !is_valid_custom_rule_id(&def.rule_id) {
            return Err(anyhow::anyhow!(
                "Custom rule '{}' has an invalid 'rule_id': only letters, digits, and the separators '_', '.', '-' \
                 are allowed",
                def.rule_id
            ));
        }
        if def.message.trim().is_empty() {
            return Err(anyhow::anyhow!("Custom rule '{}' has an empty 'message'", def.rule_id));
        }
        if def.expression.trim().is_empty() {
            return Err(anyhow::anyhow!("Custom rule '{}' has an empty 'expression'", def.rule_id));
        }
        let program = Program::compile(&def.expression)
            .map_err(|e| anyhow::anyhow!("Failed to compile CEL expression for rule '{}': {}", def.rule_id, e))?;
        // A call to a function the interpreter cannot resolve errors only when the
        // expression is actually evaluated, so a rule scoped to an absent resource
        // type would load clean and silently never run. Reject it at load time
        // instead, when the failure is certain regardless of the template.
        for function in program.references().functions() {
            if !crate::functions::is_supported_function(function) {
                return Err(anyhow::anyhow!(
                    "Custom rule '{}' references unknown function '{}'",
                    def.rule_id,
                    function
                ));
            }
        }
        rules.push(CustomRule {
            rule_id: def.rule_id,
            severity: def.severity,
            category: def.category,
            resource_type: def.resource_type,
            program,
            message: def.message,
            prop_path: def.prop_path,
            suggested_fix: def.suggested_fix,
            source: origin,
        });
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_custom_rules_valid_json() {
        let json = r#"{"rules": [
            {
                "rule_id": "CUSTOM001",
                "severity": "ERROR",
                "resource_type": "AWS::S3::Bucket",
                "expression": "has(properties.BucketEncryption)",
                "message": "Encryption required"
            }
        ]}"#;
        let rules = load_custom_rules(json, RuleOrigin::Custom).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_id, "CUSTOM001");
        assert!(matches!(rules[0].severity, Severity::Error));
        assert_eq!(rules[0].resource_type, Some("AWS::S3::Bucket".into()));
        assert_eq!(rules[0].category, None);
    }

    #[test]
    fn load_custom_rules_severity_mapping() {
        let make = |sev: &str| -> String {
            format!(
                r#"{{"rules": [{{"rule_id": "R1", "severity": "{}", "expression": "true", "message": "m"}}]}}"#,
                sev
            )
        };

        let error_rules = load_custom_rules(&make(Severity::Error.as_str()), RuleOrigin::Custom).unwrap();
        assert_eq!(error_rules[0].severity, Severity::Error);

        let warn_rules = load_custom_rules(&make(Severity::Warn.as_str()), RuleOrigin::Custom).unwrap();
        assert_eq!(warn_rules[0].severity, Severity::Warn);

        let info_rules = load_custom_rules(&make(Severity::Info.as_str()), RuleOrigin::Custom).unwrap();
        assert_eq!(info_rules[0].severity, Severity::Info);
    }

    #[test]
    fn load_custom_rules_custom_category() {
        let json = r#"{"rules": [{
            "rule_id": "R1",
            "severity": "ERROR",
            "category": "security",
            "expression": "true",
            "message": "m"
        }]}"#;
        let rules = load_custom_rules(json, RuleOrigin::Custom).unwrap();
        assert_eq!(rules[0].category, Some("security".into()));
    }

    #[test]
    fn load_custom_rules_optional_fields() {
        let json = r#"{"rules": [{
            "rule_id": "R1",
            "severity": "ERROR",
            "expression": "true",
            "message": "m",
            "prop_path": "Properties.X",
            "suggested_fix": "Add X"
        }]}"#;
        let rules = load_custom_rules(json, RuleOrigin::Custom).unwrap();
        assert_eq!(rules[0].prop_path, Some("Properties.X".into()));
        assert_eq!(rules[0].suggested_fix, Some("Add X".into()));
    }

    #[test]
    fn load_custom_rules_global_rule_no_resource_type() {
        let json = r#"{"rules": [{
            "rule_id": "R1",
            "severity": "ERROR",
            "expression": "true",
            "message": "m"
        }]}"#;
        let rules = load_custom_rules(json, RuleOrigin::Custom).unwrap();
        assert_eq!(rules[0].resource_type, None);
    }

    #[test]
    fn load_custom_rules_invalid_json() {
        let result = load_custom_rules("not json", RuleOrigin::Custom);
        result.unwrap_err();
    }

    #[test]
    fn load_custom_rules_bad_cel_expression() {
        let json = r#"{"rules": [{
            "rule_id": "R1",
            "severity": "ERROR",
            "expression": "((( invalid cel",
            "message": "m"
        }]}"#;
        let result = load_custom_rules(json, RuleOrigin::Custom);
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("R1"), "Error should mention rule_id, got: {}", err_msg);
    }

    #[test]
    fn load_custom_rules_empty_rules_array() {
        let json = r#"{"rules": []}"#;
        let rules = load_custom_rules(json, RuleOrigin::Custom).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn load_custom_rules_empty_rule_id_is_rejected() {
        let json = r#"{"rules": [{"rule_id": "", "severity": "ERROR", "expression": "true", "message": "m"}]}"#;
        let err = format!("{}", load_custom_rules(json, RuleOrigin::Custom).unwrap_err());
        assert!(err.contains("empty 'rule_id'"), "an empty rule_id must be rejected, got: {err}");
    }

    #[test]
    fn load_custom_rules_blank_rule_id_is_rejected() {
        let json = r#"{"rules": [{"rule_id": "   ", "severity": "ERROR", "expression": "true", "message": "m"}]}"#;
        let err = format!("{}", load_custom_rules(json, RuleOrigin::Custom).unwrap_err());
        assert!(err.contains("empty 'rule_id'"), "a whitespace-only rule_id must be rejected, got: {err}");
    }

    #[test]
    fn load_custom_rules_arbitrary_alphanumeric_id_with_separators_is_accepted() {
        // A custom rule ID need not follow the built-in convention: letters, digits,
        // and the separators `_`, `.`, `-` are all permitted.
        let json = r#"{"rules": [{"rule_id": "s3.encryption-required_1", "severity": "ERROR", "expression": "true", "message": "m"}]}"#;
        let rules = load_custom_rules(json, RuleOrigin::Custom).expect("an alphanumeric+separator id must load");
        assert_eq!(rules[0].rule_id, "s3.encryption-required_1");
    }

    #[test]
    fn load_custom_rules_rule_id_with_space_or_punctuation_is_rejected() {
        let json = r#"{"rules": [{"rule_id": "bad id", "severity": "ERROR", "expression": "true", "message": "m"}]}"#;
        let err = format!("{}", load_custom_rules(json, RuleOrigin::Custom).unwrap_err());
        assert!(err.contains("invalid 'rule_id'"), "a rule_id with a space must be rejected, got: {err}");

        let json = r#"{"rules": [{"rule_id": "bad/id", "severity": "ERROR", "expression": "true", "message": "m"}]}"#;
        let err = format!("{}", load_custom_rules(json, RuleOrigin::Custom).unwrap_err());
        assert!(err.contains("invalid 'rule_id'"), "a rule_id with punctuation must be rejected, got: {err}");
    }

    #[test]
    fn load_custom_rules_empty_message_is_rejected() {
        let json = r#"{"rules": [{"rule_id": "R1", "severity": "ERROR", "expression": "true", "message": ""}]}"#;
        let err = format!("{}", load_custom_rules(json, RuleOrigin::Custom).unwrap_err());
        assert!(err.contains("R1") && err.contains("empty 'message'"), "an empty message must be rejected, got: {err}");
    }

    #[test]
    fn load_custom_rules_empty_expression_is_rejected() {
        let json = r#"{"rules": [{"rule_id": "R1", "severity": "ERROR", "expression": "  ", "message": "m"}]}"#;
        let err = format!("{}", load_custom_rules(json, RuleOrigin::Custom).unwrap_err());
        assert!(
            err.contains("R1") && err.contains("empty 'expression'"),
            "a blank expression must be rejected, got: {err}"
        );
    }

    #[test]
    fn load_custom_rules_unknown_function_is_rejected_at_load() {
        // The failure must surface at load time, not only when a matching resource
        // happens to exist during evaluation.
        let json = r#"{"rules": [{
            "rule_id": "R1",
            "severity": "ERROR",
            "resource_type": "AWS::S3::Bucket",
            "expression": "totally_unknown_fn(properties.BucketName)",
            "message": "m"
        }]}"#;
        let err = format!("{}", load_custom_rules(json, RuleOrigin::Custom).unwrap_err());
        assert!(
            err.contains("R1") && err.contains("unknown function") && err.contains("totally_unknown_fn"),
            "an unknown function reference must be rejected at load, got: {err}"
        );
    }

    #[test]
    fn load_custom_rules_standard_functions_and_macros_are_accepted() {
        // has()/size()/matches() and comprehension macros must not be mistaken for
        // unknown functions.
        let json = r#"{"rules": [{
            "rule_id": "R1",
            "severity": "ERROR",
            "expression": "has(resource.Properties) && size(resources) > 0 && [1, 2].all(x, x > 0)",
            "message": "m"
        }]}"#;
        let rules = load_custom_rules(json, RuleOrigin::Custom).expect("standard functions and macros must load");
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn load_custom_rules_type_function_is_accepted() {
        // `type` is registered by build_custom_context so Guard type-check operators
        // translate to a runnable expression; it must pass the load-time check.
        let json = r#"{"rules": [{
            "rule_id": "R1",
            "severity": "ERROR",
            "resource_type": "AWS::S3::Bucket",
            "expression": "type(resource) == \"map\"",
            "message": "m"
        }]}"#;
        let rules = load_custom_rules(json, RuleOrigin::Custom).expect("type() must be an accepted function");
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn load_custom_rules_multiple_rules() {
        let json = r#"{"rules": [
            {"rule_id": "R1", "severity": "ERROR", "expression": "true", "message": "m1"},
            {"rule_id": "R2", "severity": "WARN", "expression": "false", "message": "m2"}
        ]}"#;
        let rules = load_custom_rules(json, RuleOrigin::Custom).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].rule_id, "R1");
        assert_eq!(rules[1].rule_id, "R2");
    }

    fn single_rule(source: &str, origin: RuleOrigin) -> CustomRule {
        load_custom_rules(source, origin).expect("rule should load").pop().expect("one rule")
    }

    #[test]
    fn execute_custom_rule_boolean_true_fires() {
        let rule = single_rule(
            r#"{"rules": [{"rule_id": "R1", "severity": "ERROR", "expression": "true", "message": "m"}]}"#,
            RuleOrigin::Custom,
        );
        let ctx = crate::functions::build_custom_context(&serde_json::json!({}), None, None);
        assert!(execute_custom_rule(&rule, &ctx).expect("boolean expression evaluates"));
    }

    #[test]
    fn execute_custom_rule_boolean_false_does_not_fire() {
        let rule = single_rule(
            r#"{"rules": [{"rule_id": "R1", "severity": "ERROR", "expression": "false", "message": "m"}]}"#,
            RuleOrigin::Custom,
        );
        let ctx = crate::functions::build_custom_context(&serde_json::json!({}), None, None);
        assert!(!execute_custom_rule(&rule, &ctx).expect("boolean expression evaluates"));
    }

    #[test]
    fn execute_custom_rule_non_boolean_result_is_error() {
        // A rule whose expression yields a string (not a predicate) is malformed and
        // must error rather than silently be treated as "did not fire".
        let rule = single_rule(
            r#"{"rules": [{"rule_id": "R1", "severity": "ERROR", "expression": "\"a string\"", "message": "m"}]}"#,
            RuleOrigin::Custom,
        );
        let ctx = crate::functions::build_custom_context(&serde_json::json!({}), None, None);
        let err = execute_custom_rule(&rule, &ctx).expect_err("a non-boolean result must error");
        match err {
            ValidationError::Engine(message) => {
                assert!(message.contains("R1") && message.contains("boolean"), "got: {message}");
            }
            other => panic!("expected Engine error, got {other:?}"),
        }
    }

    #[test]
    fn execute_custom_rule_evaluation_error_is_fatal_for_custom_origin() {
        // A custom rule that errors at evaluation (e.g. reads a missing key) must
        // surface the error, not swallow it.
        let rule = single_rule(
            r#"{"rules": [{"rule_id": "R1", "severity": "ERROR", "expression": "resource.Missing.Deep == \"x\"", "message": "m"}]}"#,
            RuleOrigin::Custom,
        );
        let ctx = crate::functions::build_custom_context(&serde_json::json!({"resources": {}}), Some("Bucket"), None);
        execute_custom_rule(&rule, &ctx).expect_err("a custom-rule evaluation error must be fatal");
    }

    #[test]
    fn execute_custom_rule_evaluation_error_is_tolerated_for_guard_origin() {
        // The same missing-key error is tolerated for Guard-origin rules: Guard treats an
        // absent property as a check that does not pass, so the rule simply does not fire.
        let rule = single_rule(
            r#"{"rules": [{"rule_id": "G1", "severity": "ERROR", "expression": "resource.Missing.Deep == \"x\"", "message": "m"}]}"#,
            RuleOrigin::Guard,
        );
        let ctx = crate::functions::build_custom_context(&serde_json::json!({"resources": {}}), Some("Bucket"), None);
        assert!(!execute_custom_rule(&rule, &ctx).expect("guard evaluation error is tolerated as non-firing"));
    }
}
