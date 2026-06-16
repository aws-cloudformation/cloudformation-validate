use log::info;
use std::collections::HashMap;
use std::sync::Arc;

use diagnostics::{Diagnostic, PhaseMetric, phase_metric};
use rules::{RuleInfo, RuleMetadataEntry, RuleOrigin, Severity};
use template_model::SemanticModel;
use validation_engine::{
    EngineConfig, ValidateConfig, ValidationEngine, ValidationError, build_rule_list, semantic_model_to_input_json,
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
        let start = web_time::Instant::now();

        let native_rules = NativeRuleRegistry::new();
        let generated_rules = GeneratedRuleRegistry::new()?;

        let registry_metadata = rules::build_rule_metadata_map();
        let mut external_rule_metadata: HashMap<String, RuleMetadataEntry> = HashMap::new();

        let mut translated_guard_sources = Vec::new();
        for entry in &config.guard_rules {
            let guard_file = guard_translator::parse_guard(&entry.content, &entry.name)
                .map_err(|e| anyhow::anyhow!("Failed to parse guard file '{}': {}", entry.name, e))?;
            let pack = guard_translator::pack_name_from_path(&entry.name);
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
        let cached_data = CachedData::load()?;
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

        let ctx = EvalContext { model, input: &input_json, region: &region, cached_data: &self.cached_data };

        let mut diagnostics = self.native_rules.evaluate(&ctx, &excluded_cats);

        {
            let gen_diags = self.generated_rules.evaluate(model, &input_json, &excluded_cats);
            diagnostics.extend(gen_diags);
        }

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
        Ok(_) => Ok(false),
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
    let span = if rid.is_empty() {
        diagnostics::UNKNOWN_SPAN
    } else {
        model.resource_span(rid, rule.prop_path.as_deref().unwrap_or(""))
    };
    out.push(Diagnostic {
        rule_id: rule.rule_id.clone(),
        severity: rule.severity,
        message: msg.to_string(),
        resource: if rid.is_empty() {
            None
        } else {
            Some(diagnostics::ResourceRef {
                id: Some(rid.to_string()),
                resource_type: model.resources.get(rid).map(|r| r.resource_type.clone()),
            })
        },
        property_path: rule.prop_path.clone(),
        suggested_fix: rule.suggested_fix.clone(),
        documentation_url: None,
        category: rule.category.clone(),
        location: if span == diagnostics::UNKNOWN_SPAN { None } else { Some(span) },
        related_resources: None,
        condition_scenario: None,
        rule_description: None,
        phase: None,
        section: None,
        context: None,
        source: rule.source,
    });
}

fn load_custom_rules(source: &str, origin: RuleOrigin) -> anyhow::Result<Vec<CustomRule>> {
    let file: CustomRuleFile = serde_json::from_str(source)?;
    let mut rules = Vec::new();
    for def in file.rules {
        match Program::compile(&def.expression) {
            Ok(program) => rules.push(CustomRule {
                rule_id: def.rule_id,
                severity: def.severity,
                category: def.category,
                resource_type: def.resource_type,
                program,
                message: def.message,
                prop_path: def.prop_path,
                suggested_fix: def.suggested_fix,
                source: origin,
            }),
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to compile CEL expression for rule '{}': {}", def.rule_id, e));
            }
        }
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
}
