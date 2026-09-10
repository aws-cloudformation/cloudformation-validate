use cel_engine::CelEngine;
use diagnostics::{Diagnostic, PhaseMetric, phase_metric};
use rego_engine::RegoEngine;
use rules::{RuleInfo, RuleMetadataEntry};
use schema_validator::SchemaValidator;
use std::collections::HashMap;
use std::sync::Arc;
use template_model::SemanticModel;
use validation_engine::{
    CompositeEngineConfig, EngineConfig, ValidateConfig, ValidationEngine, ValidationError, build_rule_list,
};
use web_time::Instant;

/// A validation engine that composes two engines: one owns the built-in rules,
/// the other evaluates the caller-supplied external rules.
///
/// The built-in rules are always evaluated by the CEL engine, which also
/// evaluates any custom CEL rules since those are a CEL-engine feature. Custom
/// Rego rules and translated Guard rules are evaluated by a Rego engine built in
/// external-only mode, so it contributes no built-in findings of its own. That
/// external engine is constructed only when the configuration supplies custom
/// Rego or Guard rules. Findings from both are concatenated; the surrounding
/// validation pipeline performs the single finalize pass (dedup, sort, filter,
/// enrich).
pub struct CompositeEngine {
    builtin_engine: CelEngine,
    external_engine: Option<RegoEngine>,
    init_metric: PhaseMetric,
}

impl CompositeEngine {
    /// Builds the composite engine from a [`CompositeEngineConfig`]. The built-in
    /// engine is always constructed; the external engine is constructed only when
    /// the configuration supplies custom Rego or Guard rules.
    pub fn new(config: CompositeEngineConfig) -> anyhow::Result<Self> {
        let start = Instant::now();
        let (builtin_config, external_config) = split_configs(config);
        let builtin_engine = CelEngine::new(builtin_config)?;
        let external_engine = external_config.map(RegoEngine::new_external_only).transpose()?;
        Ok(Self { builtin_engine, external_engine, init_metric: phase_metric(start) })
    }

    /// Constructs the composite engine reusing an already-built
    /// [`SchemaValidator`], so both inner engines share its overlay catalog and
    /// schema-metadata catalog rather than re-resolving the overlay schemas.
    ///
    /// This entry point is intended for language bindings and the CLI, which
    /// construct a `SchemaValidator` once and share it with the engine.
    #[doc(hidden)]
    pub fn new_with_schema_validator(
        config: CompositeEngineConfig,
        validator: &SchemaValidator,
    ) -> anyhow::Result<Self> {
        let start = Instant::now();
        let config = CompositeEngineConfig { schema_validator_config: None, ..config };
        let (builtin_config, external_config) = split_configs(config);
        let builtin_engine = CelEngine::new_with_schema_validator(builtin_config, validator)?;
        let external_engine = external_config
            .map(|config| RegoEngine::new_external_only_with_schema_validator(config, validator))
            .transpose()?;
        Ok(Self { builtin_engine, external_engine, init_metric: phase_metric(start) })
    }
}

/// Splits a composite configuration into the built-in engine's config and an
/// optional external-engine config. Rule sources are moved rather than cloned;
/// the schema config is cloned only when both engines need it. Custom CEL rules
/// go to the built-in CEL engine, since CEL custom rules are a CEL-engine
/// feature; custom Rego and translated Guard rules go to the external engine.
fn split_configs(config: CompositeEngineConfig) -> (EngineConfig, Option<EngineConfig>) {
    let CompositeEngineConfig { rego_rules, cel_rules, guard_rules, schema_validator_config } = config;
    let has_external_rules = !rego_rules.is_empty() || !guard_rules.is_empty();
    let external_config = has_external_rules.then(|| EngineConfig {
        custom_rules: rego_rules,
        guard_rules,
        schema_validator_config: schema_validator_config.clone(),
    });
    let builtin_config = EngineConfig { custom_rules: cel_rules, guard_rules: Vec::new(), schema_validator_config };
    (builtin_config, external_config)
}

impl ValidationEngine for CompositeEngine {
    fn engine_name(&self) -> &str {
        "composite"
    }

    fn evaluate_rules(
        &self,
        model: &Arc<SemanticModel>,
        config: &ValidateConfig,
    ) -> Result<Vec<Diagnostic>, ValidationError> {
        // The built-in engine runs first and owns every built-in rule. The
        // external engine runs second and contributes only custom and Guard
        // findings, so it is evaluated even when built-ins are disabled. Findings
        // are concatenated only; the surrounding pipeline finalizes them once.
        let mut diagnostics = self.builtin_engine.evaluate_rules(model, config)?;
        if let Some(external_engine) = &self.external_engine {
            diagnostics.extend(external_engine.evaluate_rules(model, config)?);
        }
        Ok(diagnostics)
    }

    fn list_rules(&self) -> Vec<RuleInfo> {
        build_rule_list(self.builtin_engine.rule_metadata(), &self.external_rule_metadata())
    }

    fn rule_metadata(&self) -> &HashMap<String, RuleMetadataEntry> {
        self.builtin_engine.rule_metadata()
    }

    /// The external rule metadata is the union of both engines' external rules:
    /// custom CEL rules from the built-in engine and custom Rego plus translated
    /// Guard rules from the external engine. The two sets have disjoint rule IDs,
    /// so a plain merge cannot drop or overwrite a rule.
    fn external_rule_metadata(&self) -> HashMap<String, RuleMetadataEntry> {
        let mut merged = self.builtin_engine.external_rule_metadata();
        if let Some(external_engine) = &self.external_engine {
            merged.extend(external_engine.external_rule_metadata());
        }
        merged
    }

    fn init_metric(&self) -> &PhaseMetric {
        &self.init_metric
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules::{RuleOrigin, Severity};
    use std::collections::HashSet;
    use validation_engine::ExternalRuleSource;

    const BUCKET_TEMPLATE: &str = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
"#;

    const BUCKET_WITHOUT_NAME_TEMPLATE: &str = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"#;

    fn model(yaml: &str) -> Arc<SemanticModel> {
        Arc::new(SemanticModel::from_bytes(yaml.as_bytes()).expect("template must parse"))
    }

    /// A comparable projection of the fields that define a diagnostic's identity:
    /// rule ID, severity, source location, property path, and message. `Diagnostic`
    /// does not implement `PartialEq`, and these are its observable outcome.
    type Fingerprint = (String, Severity, Option<(u32, u32, u32, u32)>, Option<String>, String);

    fn fingerprints(diagnostics: &[Diagnostic]) -> Vec<Fingerprint> {
        let mut projected: Vec<Fingerprint> = diagnostics
            .iter()
            .map(|d| {
                let location = d.location.as_ref().map(|s| (s.start_line, s.start_column, s.end_line, s.end_column));
                (d.rule_id.clone(), d.severity, location, d.property_path.clone(), d.message.clone())
            })
            .collect();
        projected.sort();
        projected
    }

    fn custom_rego_rule() -> ExternalRuleSource {
        ExternalRuleSource {
            name: "composite_custom.rego".into(),
            content: r#"
package composite_custom
import rego.v1

violation contains v if {
    some name, res in input.resources
    res.resourceType == "AWS::S3::Bucket"
    v := {"rule_id": "COMPOSITE_CUSTOM", "severity": "error", "message": "custom rego fired", "resource_id": name}
}
"#
            .into(),
        }
    }

    fn bucket_name_exists_guard() -> ExternalRuleSource {
        ExternalRuleSource {
            name: "bucket_name.guard".into(),
            content: r#"
rule check_bucket_name {
    AWS::S3::Bucket {
        Properties.BucketName EXISTS
        <<BucketName must be specified>>
    }
}
"#
            .into(),
        }
    }

    /// A custom CEL rule that fires on every S3 bucket, exercising the
    /// composite's CEL-custom-rule path (evaluated by the built-in engine).
    fn custom_cel_rule() -> ExternalRuleSource {
        ExternalRuleSource {
            name: "composite_custom.json".into(),
            content: r#"{"rules": [{
                "rule_id": "COMPOSITE_CEL",
                "severity": "ERROR",
                "resource_type": "AWS::S3::Bucket",
                "expression": "true",
                "message": "custom cel fired"
            }]}"#
                .into(),
        }
    }

    fn builtin_only_diagnostics(model: &Arc<SemanticModel>, config: &ValidateConfig) -> Vec<Diagnostic> {
        CelEngine::new(EngineConfig::default())
            .expect("built-in engine builds")
            .evaluate_rules(model, config)
            .expect("built-in engine evaluates")
    }

    #[test]
    fn without_external_rules_no_external_engine_and_builtins_match_cel() {
        let composite = CompositeEngine::new(CompositeEngineConfig::default()).expect("composite builds");
        assert!(composite.external_engine.is_none(), "with no external rules there must be no external engine");

        let model = model(BUCKET_TEMPLATE);
        let config = ValidateConfig::default();
        let composite_diags = composite.evaluate_rules(&model, &config).expect("composite evaluates");

        assert_eq!(
            fingerprints(&composite_diags),
            fingerprints(&builtin_only_diagnostics(&model, &config)),
            "with no external rules the composite must produce exactly the built-in diagnostics"
        );
    }

    #[test]
    fn custom_rego_adds_one_finding_and_builtins_appear_exactly_once() {
        let composite = CompositeEngine::new(CompositeEngineConfig::new().with_rego_rules([custom_rego_rule()]))
            .expect("composite builds");
        assert!(composite.external_engine.is_some(), "custom rego rules must construct the external engine");

        let model = model(BUCKET_TEMPLATE);
        let config = ValidateConfig::default();
        let composite_diags = composite.evaluate_rules(&model, &config).expect("composite evaluates");

        let custom: Vec<&Diagnostic> = composite_diags.iter().filter(|d| d.rule_id == "COMPOSITE_CUSTOM").collect();
        assert_eq!(custom.len(), 1, "the custom rego rule must contribute exactly one finding");
        assert_eq!(custom[0].severity, Severity::Error);
        assert_eq!(custom[0].source, RuleOrigin::Custom);
        assert_eq!(custom[0].message, "custom rego fired");

        // The built-in portion must equal a standalone built-in run exactly - each
        // built-in appears once, with no duplication introduced by the composite.
        let builtins: Vec<Diagnostic> =
            composite_diags.iter().filter(|d| d.rule_id != "COMPOSITE_CUSTOM").cloned().collect();
        assert_eq!(
            fingerprints(&builtins),
            fingerprints(&builtin_only_diagnostics(&model, &config)),
            "built-in diagnostics must appear exactly once, matching a standalone built-in run"
        );
    }

    #[test]
    fn disabling_builtins_returns_only_external_findings() {
        let composite = CompositeEngine::new(CompositeEngineConfig::new().with_rego_rules([custom_rego_rule()]))
            .expect("composite builds");
        let model = model(BUCKET_TEMPLATE);
        let config = ValidateConfig { disable_builtin_rules: true, ..ValidateConfig::default() };

        let diags = composite.evaluate_rules(&model, &config).expect("composite evaluates");
        assert_eq!(diags.len(), 1, "only the external finding must remain when built-ins are disabled");
        assert_eq!(diags[0].rule_id, "COMPOSITE_CUSTOM");
        assert_eq!(diags[0].source, RuleOrigin::Custom);
    }

    #[test]
    fn custom_cel_adds_one_finding_and_builtins_appear_exactly_once() {
        let composite = CompositeEngine::new(CompositeEngineConfig::new().with_cel_rules([custom_cel_rule()]))
            .expect("composite builds");
        // A CEL custom rule is owned by the built-in engine, so it needs no
        // external engine.
        assert!(composite.external_engine.is_none(), "a CEL-only custom rule must not construct the external engine");

        let model = model(BUCKET_TEMPLATE);
        let config = ValidateConfig::default();
        let composite_diags = composite.evaluate_rules(&model, &config).expect("composite evaluates");

        let custom: Vec<&Diagnostic> = composite_diags.iter().filter(|d| d.rule_id == "COMPOSITE_CEL").collect();
        assert_eq!(custom.len(), 1, "the custom cel rule must contribute exactly one finding");
        assert_eq!(custom[0].severity, Severity::Error);
        assert_eq!(custom[0].source, RuleOrigin::Custom);
        assert_eq!(custom[0].message, "custom cel fired");

        let builtins: Vec<Diagnostic> =
            composite_diags.iter().filter(|d| d.rule_id != "COMPOSITE_CEL").cloned().collect();
        assert_eq!(
            fingerprints(&builtins),
            fingerprints(&builtin_only_diagnostics(&model, &config)),
            "built-in diagnostics must appear exactly once alongside the custom CEL finding"
        );
    }

    #[test]
    fn cel_rego_and_guard_custom_rules_all_fire_together() {
        let composite = CompositeEngine::new(
            CompositeEngineConfig::new()
                .with_cel_rules([custom_cel_rule()])
                .with_rego_rules([custom_rego_rule()])
                .with_guard_rules([bucket_name_exists_guard()]),
        )
        .expect("composite builds");
        assert!(composite.external_engine.is_some(), "Rego and Guard rules must construct the external engine");

        // BUCKET_WITHOUT_NAME_TEMPLATE has no BucketName, so the guard EXISTS
        // check fires while the CEL and Rego rules match any S3 bucket.
        let model = model(BUCKET_WITHOUT_NAME_TEMPLATE);
        let diags = composite.evaluate_rules(&model, &ValidateConfig::default()).expect("composite evaluates");

        assert_eq!(
            diags.iter().filter(|d| d.rule_id == "COMPOSITE_CEL").count(),
            1,
            "the custom CEL rule must fire once"
        );
        assert_eq!(
            diags.iter().filter(|d| d.rule_id == "COMPOSITE_CUSTOM").count(),
            1,
            "the custom Rego rule must fire once"
        );
        assert_eq!(
            diags.iter().filter(|d| d.rule_id == "check_bucket_name").count(),
            1,
            "the translated Guard rule must fire once"
        );
    }

    #[test]
    fn list_rules_includes_cel_custom_rules() {
        let composite = CompositeEngine::new(CompositeEngineConfig::new().with_cel_rules([custom_cel_rule()]))
            .expect("composite builds");
        let ids: HashSet<String> = composite.list_rules().into_iter().map(|r| r.id).collect();
        assert!(ids.contains("COMPOSITE_CEL"), "composite listRules must include the custom CEL rule");
    }

    #[test]
    fn guard_exists_does_not_fire_when_property_present() {
        let composite =
            CompositeEngine::new(CompositeEngineConfig::new().with_guard_rules([bucket_name_exists_guard()]))
                .expect("composite builds");
        let diags = composite.evaluate_rules(&model(BUCKET_TEMPLATE), &ValidateConfig::default()).expect("evaluates");
        assert!(
            !diags.iter().any(|d| d.rule_id == "check_bucket_name"),
            "the guard EXISTS check must be satisfied when BucketName is present; got: {:?}",
            diags.iter().map(|d| &d.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn guard_exists_fires_once_when_property_absent() {
        let composite =
            CompositeEngine::new(CompositeEngineConfig::new().with_guard_rules([bucket_name_exists_guard()]))
                .expect("composite builds");
        let diags = composite
            .evaluate_rules(&model(BUCKET_WITHOUT_NAME_TEMPLATE), &ValidateConfig::default())
            .expect("evaluates");

        let guard: Vec<&Diagnostic> = diags.iter().filter(|d| d.rule_id == "check_bucket_name").collect();
        assert_eq!(guard.len(), 1, "the guard rule must fire once when BucketName is absent");
        assert_eq!(guard[0].source, RuleOrigin::Guard);
    }

    #[test]
    fn guard_nested_exists_matches_nested_property_presence() {
        let guard_rule = ExternalRuleSource {
            name: "nested_exists.guard".into(),
            content: r#"
rule check_versioning_status {
    AWS::S3::Bucket {
        Properties.VersioningConfiguration.Status EXISTS
        <<Versioning status must be specified>>
    }
}
"#
            .into(),
        };
        let composite = CompositeEngine::new(CompositeEngineConfig::new().with_guard_rules([guard_rule]))
            .expect("composite builds");
        let present = model(
            r#"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: Enabled
"#,
        );

        let present_diagnostics = composite.evaluate_rules(&present, &ValidateConfig::default()).expect("evaluates");
        assert!(
            !present_diagnostics.iter().any(|diagnostic| diagnostic.rule_id == "check_versioning_status"),
            "nested EXISTS must pass when the nested property is present"
        );

        let absent_diagnostics = composite
            .evaluate_rules(&model(BUCKET_WITHOUT_NAME_TEMPLATE), &ValidateConfig::default())
            .expect("evaluates");
        assert_eq!(
            absent_diagnostics.iter().filter(|diagnostic| diagnostic.rule_id == "check_versioning_status").count(),
            1,
            "nested EXISTS must fire once when the nested property is absent"
        );
    }

    #[test]
    fn list_rules_includes_builtins_and_external_rules() {
        let composite =
            CompositeEngine::new(CompositeEngineConfig::new().with_guard_rules([bucket_name_exists_guard()]))
                .expect("composite builds");

        let composite_ids: HashSet<String> = composite.list_rules().into_iter().map(|r| r.id).collect();
        let builtin_ids: HashSet<String> = CelEngine::new(EngineConfig::default())
            .expect("built-in engine builds")
            .list_rules()
            .into_iter()
            .map(|r| r.id)
            .collect();

        assert!(!builtin_ids.is_empty(), "sanity: the built-in engine advertises rules");
        assert!(builtin_ids.is_subset(&composite_ids), "composite listRules must include every built-in rule");
        assert!(
            composite_ids.contains("check_bucket_name"),
            "composite listRules must include the external guard rule"
        );
    }

    #[test]
    fn init_metric_spans_both_engine_constructions() {
        let composite = CompositeEngine::new(CompositeEngineConfig::new().with_rego_rules([custom_rego_rule()]))
            .expect("composite builds");
        let external = composite.external_engine.as_ref().expect("external engine constructed");

        assert!(composite.init_metric().duration_ms > 0.0, "the init metric must be recorded");
        assert!(
            composite.init_metric().duration_ms >= external.init_metric().duration_ms,
            "the composite init metric must span the external engine's construction, not replace it"
        );
    }
}
