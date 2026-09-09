use crate::detail_level::DetailLevel;
use crate::filter::Filterable;
use crate::metrics::PhaseMetric;
use crate::output;
use crate::phase::Phase;
use rules::{RuleOrigin, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use template_model::{EntityType, JsonValue, SourceSpan};

pub(crate) fn serialize_sorted_optional_map<S, V>(
    map: &Option<HashMap<String, V>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    V: Serialize,
{
    match map {
        Some(m) => {
            let sorted: BTreeMap<&String, &V> = m.iter().collect();
            sorted.serialize(serializer)
        }
        None => serializer.serialize_none(),
    }
}

/// The template resource a diagnostic is attributed to, when it targets one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ResourceRef {
    /// Logical ID of the resource as declared in the template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub resource_type: Option<String>,
}

/// The named template entity a diagnostic is attributed to, when it targets
/// one. The entity type is the singular form of the top-level template
/// section the entity is declared in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct Entity {
    /// Logical ID of the entity as declared in the template.
    pub logical_id: String,
    pub entity_type: EntityType,
    /// CloudFormation resource type, when the entity is a resource whose type
    /// is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub resource_type: Option<String>,
}

impl Entity {
    /// An entity for a template resource. An empty logical ID yields `None` so
    /// callers can pass through an ID that may be blank.
    pub fn resource(logical_id: impl Into<String>, resource_type: Option<String>) -> Option<Entity> {
        let logical_id = logical_id.into();
        if logical_id.is_empty() {
            return None;
        }
        Some(Entity { logical_id, entity_type: EntityType::Resource, resource_type })
    }
}

/// Extra detail about a specific violation, present only at the `DETAILED` detail level.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ViolationContext {
    /// The resolved property value that triggered the violation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "JsonValue"))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub actual_value: Option<JsonValue>,
    /// The constraint the value was expected to satisfy (such as the required type or allowed pattern).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub expected_constraint: Option<String>,
    /// Name of the offending property.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub property: Option<String>,
    /// Lifecycle marker for the flagged resource type or property, such as 'deprecated', 'create-only', or 'write-only'.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub lifecycle: Option<String>,
    /// How the offending value was derived, such as a Ref, Fn::GetAtt, Fn::If, or parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub resolution_source: Option<String>,
    /// Additional finding-specific values keyed by name.
    #[serde(default, skip_serializing_if = "Option::is_none", serialize_with = "serialize_sorted_optional_map")]
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "Record<string, JsonValue>"))]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub extra: Option<HashMap<String, JsonValue>>,
}

/// Another resource involved in the diagnostic, such as the target of a reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct RelatedResource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub resource: Option<ResourceRef>,
    /// Source location of the related resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub location: Option<SourceSpan>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub source: RuleOrigin,
    /// The named template entity this finding targets, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity: Option<Entity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_fix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_resources: Option<Vec<RelatedResource>>,
    #[serde(default, skip_serializing_if = "Option::is_none", serialize_with = "serialize_sorted_optional_map")]
    pub condition_scenario: Option<HashMap<String, bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<Phase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ViolationContext>,
}

impl Diagnostic {
    /// Logical ID of the targeted entity when it is a resource, `None` otherwise.
    pub fn resource_logical_id(&self) -> Option<&str> {
        self.entity.as_ref().filter(|e| e.entity_type == EntityType::Resource).map(|e| e.logical_id.as_str())
    }
}

impl Filterable for Diagnostic {
    fn rule_id(&self) -> &str {
        &self.rule_id
    }
    fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }
    fn resource_id(&self) -> Option<&str> {
        self.resource_logical_id()
    }
    fn resource_type(&self) -> Option<&str> {
        self.entity.as_ref().and_then(|e| e.resource_type.as_deref())
    }
    fn logical_id(&self) -> Option<&str> {
        self.entity.as_ref().map(|e| e.logical_id.as_str())
    }
    fn entity_type(&self) -> Option<EntityType> {
        self.entity.as_ref().map(|e| e.entity_type)
    }
}

impl Diagnostic {
    /// Projects this diagnostic into the public flattened shape. The enrichment
    /// fields (`documentation_url`, `rule_description`, `phase`, `context`) are
    /// carried through only at the `DETAILED` detail level; the `STANDARD` detail
    /// level leaves them `None` so serialization omits them.
    pub fn to_report(&self, detail_level: DetailLevel) -> output::Diagnostic {
        let (start_line, start_column, end_line, end_column) = self
            .location
            .map(|span| (Some(span.start_line), Some(span.start_column), Some(span.end_line), Some(span.end_column)))
            .unwrap_or((None, None, None, None));
        let (documentation_url, rule_description, phase, context) = match detail_level {
            DetailLevel::Detailed => {
                (self.documentation_url.clone(), self.rule_description.clone(), self.phase, self.context.clone())
            }
            DetailLevel::Standard => (None, None, None, None),
        };
        output::Diagnostic {
            rule_id: self.rule_id.clone(),
            severity: self.severity,
            message: self.message.clone(),
            source: self.source,
            entity: self.entity.clone(),
            property_path: self.property_path.clone(),
            suggested_fix: self.suggested_fix.clone(),
            category: self.category.clone(),
            start_line,
            start_column,
            end_line,
            end_column,
            related_resources: self.related_resources.clone(),
            condition_scenario: self.condition_scenario.clone(),
            documentation_url,
            rule_description,
            phase,
            context,
        }
    }
}

/// Timing breakdown of the validation run, per pipeline phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct PerformanceMetrics {
    /// Time to load the provider schemas.
    pub schema_init: PhaseMetric,
    /// Time to initialize the rule evaluation engine.
    pub engine_init: PhaseMetric,
    /// Time to parse the template and build its model.
    pub model_build: PhaseMetric,
    pub schema_validate: PhaseMetric,
    pub rule_evaluation: PhaseMetric,
    /// Time spent enriching, filtering, sorting, and finalizing the diagnostics after rule evaluation.
    pub diagnostic_finalize: PhaseMetric,
    pub validate_total: PhaseMetric,
}

/// A single budget-exhaustion record in report metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct BudgetExhaustionRecord {
    /// Stable lower camelCase budget kind identifier.
    pub kind: String,
    /// Human-readable explanation of the exhausted budget.
    #[serde(default)]
    pub description: String,
    /// The numeric limit that was exhausted.
    pub limit: u64,
    /// Whether exhausting this budget makes the overall analysis incomplete.
    pub analysis_incomplete: bool,
}

fn budget_exhaustions_are_absent_or_empty(records: &Option<Vec<BudgetExhaustionRecord>>) -> bool {
    records.as_ref().is_none_or(Vec::is_empty)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ReportMetadata {
    /// Number of rules that were active for this run after any category exclusions.
    pub rules_evaluated: u32,
    /// Source-qualified cfn-lint version used to sync bundled derived data.
    pub cfn_lint_version: String,
    /// Source-qualified enhanced resource-schema version used for the bundled provider schemas.
    pub resource_schema_version: String,
    pub resources_scanned: u32,
    /// Tally of reported diagnostics by severity.
    pub counts: Summary,
    /// Number of diagnostics removed by filters and the severity threshold.
    pub suppressed: u32,
    /// Whether strict mode was enabled, promoting warnings to errors.
    pub strict: bool,
    /// Minimum severity included in the report; lower-severity findings are omitted.
    pub severity_level: Severity,
    /// Records of deterministic validation budgets exhausted during this run.
    /// Absent when no budget was exhausted.
    #[serde(default, skip_serializing_if = "budget_exhaustions_are_absent_or_empty")]
    pub budget_exhaustions: Option<Vec<BudgetExhaustionRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub fatal: u32,
    pub errors: u32,
    pub warnings: u32,
    pub informational: u32,
    pub debug: u32,
}

/// Outcome of a validation run. `Ok` means validation completed without
/// correctness-affecting curtailment. `AnalysisIncomplete` means a deterministic
/// budget curtailed analysis in a way that could omit findings. `Error` means
/// the validation pipeline could not run, such as when parsing fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportStatus {
    Ok,
    AnalysisIncomplete,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[must_use]
pub struct ValidationReport {
    pub file_path: String,
    pub status: ReportStatus,
    pub version: String,
    pub metadata: ReportMetadata,
    pub performance: PerformanceMetrics,
    pub diagnostics: Vec<Diagnostic>,
}

impl ValidationReport {
    /// Projects this report into its serializable shape, applying `detail_level`
    /// to every diagnostic.
    pub fn to_report(&self, detail_level: DetailLevel) -> output::ValidationReport {
        output::ValidationReport {
            file_path: self.file_path.clone(),
            status: self.status,
            version: self.version.clone(),
            diagnostics: self.diagnostics.iter().map(|d| d.to_report(detail_level.clone())).collect(),
            metadata: self.metadata.clone(),
            performance: self.performance.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_diagnostic() -> Diagnostic {
        Diagnostic {
            rule_id: "E3012".into(),
            severity: Severity::Error,
            message: "Property not allowed".into(),
            entity: Entity::resource("MyBucket", Some("AWS::S3::Bucket".into())),
            property_path: Some("/Resources/MyBucket/Properties/Foo".into()),
            suggested_fix: Some("Remove the property".into()),
            documentation_url: Some("https://example.com/E3012".into()),
            category: Some("schema".into()),
            location: Some(SourceSpan { start_line: 10, start_column: 5, end_line: 10, end_column: 20 }),
            related_resources: Some(vec![RelatedResource {
                resource: Some(ResourceRef {
                    id: Some("OtherResource".into()),
                    resource_type: Some("AWS::EC2::Instance".into()),
                }),
                location: Some(SourceSpan { start_line: 20, start_column: 1, end_line: 20, end_column: 30 }),
                message: "Referenced here".into(),
            }]),
            condition_scenario: Some(HashMap::from([("IsProduction".into(), true)])),
            rule_description: Some("Disallows extra properties".into()),
            phase: Some(Phase::Schema),
            context: Some(ViolationContext {
                actual_value: Some(JsonValue::from(serde_json::json!("bad"))),
                expected_constraint: Some("Must not exist".into()),
                property: Some("Foo".into()),
                lifecycle: None,
                resolution_source: None,
                extra: None,
            }),
            source: RuleOrigin::CfnLint,
        }
    }

    fn minimal_diagnostic() -> Diagnostic {
        Diagnostic {
            rule_id: String::new(),
            severity: Severity::Info,
            message: String::new(),
            entity: None,
            property_path: None,
            suggested_fix: None,
            documentation_url: None,
            category: None,
            location: None,
            related_resources: None,
            condition_scenario: None,
            rule_description: None,
            phase: None,
            context: None,
            source: RuleOrigin::Engine,
        }
    }

    #[test]
    fn standard_projection_carries_entity_flattens_location_and_drops_enrichment() {
        let d = sample_diagnostic();
        let s = d.to_report(DetailLevel::Standard);

        assert_eq!(s.rule_id, "E3012");
        let entity = s.entity.as_ref().expect("entity should be present");
        assert_eq!(entity.logical_id, "MyBucket");
        assert_eq!(entity.entity_type, EntityType::Resource);
        assert_eq!(entity.resource_type.as_deref(), Some("AWS::S3::Bucket"));
        assert_eq!(s.start_line, Some(10));
        assert_eq!(s.start_column, Some(5));
        assert_eq!(s.end_line, Some(10));
        assert_eq!(s.end_column, Some(20));
        assert_eq!(s.message, "Property not allowed");
        assert_eq!(s.category.as_deref(), Some("schema"));
        assert_eq!(s.suggested_fix.as_deref(), Some("Remove the property"));
        assert_eq!(s.related_resources.as_ref().unwrap().len(), 1);
        assert_ne!(s.condition_scenario, None, "condition_scenario should be present");

        assert_eq!(s.documentation_url, None, "standard projection must drop documentation_url");
        assert_eq!(s.rule_description, None, "standard projection must drop rule_description");
        assert_eq!(s.phase, None, "standard projection must drop phase");
        assert!(s.context.is_none(), "standard projection must drop context");
    }

    #[test]
    fn detailed_projection_includes_context_and_enrichment_fields() {
        let d = sample_diagnostic();
        let f = d.to_report(DetailLevel::Detailed);

        assert_eq!(f.rule_id, "E3012");
        assert_eq!(f.entity.as_ref().map(|e| e.logical_id.as_str()), Some("MyBucket"));
        assert_eq!(f.documentation_url.as_deref(), Some("https://example.com/E3012"));
        assert_eq!(f.rule_description.as_deref(), Some("Disallows extra properties"));
        assert_eq!(f.phase, Some(Phase::Schema));
        let ctx = f.context.as_ref().expect("detailed projection should include context");
        assert_eq!(ctx.property.as_deref(), Some("Foo"));
        assert_eq!(ctx.expected_constraint.as_deref(), Some("Must not exist"));
    }

    #[test]
    fn filterable_reads_identity_through_the_entity() {
        let d = sample_diagnostic();
        assert_eq!(d.rule_id(), "E3012");
        assert_eq!(d.category(), Some("schema"));
        assert_eq!(d.resource_id(), Some("MyBucket"));
        assert_eq!(d.resource_type(), Some("AWS::S3::Bucket"));
        assert_eq!(d.logical_id(), Some("MyBucket"));
    }

    #[test]
    fn filterable_resource_id_is_none_for_non_resource_entities() {
        let mut d = sample_diagnostic();
        d.entity =
            Some(Entity { logical_id: "MyParam".into(), entity_type: EntityType::Parameter, resource_type: None });
        assert_eq!(d.resource_id(), None, "a parameter is not a resource");
        assert_eq!(d.resource_type(), None);
        assert_eq!(d.logical_id(), Some("MyParam"));
    }

    #[test]
    fn entity_serializes_camel_case_with_pascal_case_type_and_omits_absent_resource_type() {
        let resource = Entity::resource("MyBucket", Some("AWS::S3::Bucket".into())).unwrap();
        let json = serde_json::to_string(&resource).unwrap();
        assert!(json.contains("\"logicalId\":\"MyBucket\""), "got: {json}");
        assert!(json.contains("\"entityType\":\"Resource\""), "got: {json}");
        assert!(json.contains("\"resourceType\":\"AWS::S3::Bucket\""), "got: {json}");

        let parameter =
            Entity { logical_id: "MyParam".into(), entity_type: EntityType::Parameter, resource_type: None };
        let json = serde_json::to_string(&parameter).unwrap();
        assert!(json.contains("\"entityType\":\"Parameter\""), "got: {json}");
        assert!(!json.contains("resourceType"), "absent resourceType must be omitted, got: {json}");
    }

    #[test]
    fn entity_resource_drops_empty_logical_id() {
        assert!(Entity::resource("", None).is_none(), "an empty logical ID must not create an entity");
    }

    #[test]
    fn diagnostic_serde_round_trips_all_fields() {
        let d = sample_diagnostic();
        let json = serde_json::to_string(&d).unwrap();
        let deserialized: Diagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.rule_id, d.rule_id);
        assert_eq!(deserialized.message, d.message);
        assert_eq!(deserialized.severity, d.severity);
        assert_eq!(deserialized.source, d.source);
        assert_eq!(deserialized.entity.as_ref().map(|e| e.logical_id.as_str()), Some("MyBucket"));
        assert_eq!(deserialized.location.as_ref().unwrap().start_line, d.location.as_ref().unwrap().start_line);
    }

    #[test]
    fn standard_projection_uses_camel_case_and_omits_enrichment_in_json() {
        let d = sample_diagnostic();
        let s = d.to_report(DetailLevel::Standard);
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("ruleId"), "expected camelCase 'ruleId' in JSON");
        assert!(json.contains("startLine"), "expected 'startLine' in JSON");
        assert!(json.contains("\"entity\""), "expected nested 'entity' in JSON");
        assert!(json.contains("logicalId"), "expected 'logicalId' in JSON");
        assert!(json.contains("entityType"), "expected 'entityType' in JSON");
        assert!(json.contains("resourceType"), "expected 'resourceType' in JSON");
        assert!(json.contains("propertyPath"), "expected 'propertyPath' in JSON");
        assert!(!json.contains("\"context\""), "standard projection must omit 'context'");
        assert!(!json.contains("documentationUrl"), "standard projection must omit 'documentationUrl'");
        assert!(!json.contains("ruleDescription"), "standard projection must omit 'ruleDescription'");
        assert!(!json.contains("\"phase\""), "standard projection must omit 'phase'");
    }

    #[test]
    fn detailed_projection_includes_enrichment_in_serialization() {
        let d = sample_diagnostic();
        let f = d.to_report(DetailLevel::Detailed);
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"context\""), "detailed projection should include 'context'");
        assert!(json.contains("actualValue"), "detailed projection should include 'actualValue'");
        assert!(json.contains("expectedConstraint"), "detailed projection should include 'expectedConstraint'");
        assert!(json.contains("documentationUrl"), "detailed projection should include 'documentationUrl'");
        assert!(json.contains("ruleDescription"), "detailed projection should include 'ruleDescription'");
        assert!(json.contains("\"phase\""), "detailed projection should include 'phase'");
    }

    #[test]
    fn standard_projection_is_detailed_projection_without_enrichment_fields() {
        let d = sample_diagnostic();
        let standard = serde_json::to_value(d.to_report(DetailLevel::Standard)).unwrap();
        let mut detailed = serde_json::to_value(d.to_report(DetailLevel::Detailed)).unwrap();

        let detailed_fields = detailed.as_object_mut().expect("diagnostic serializes as an object");
        for enrichment_field in ["documentationUrl", "ruleDescription", "phase", "context"] {
            detailed_fields.remove(enrichment_field);
        }

        assert_eq!(standard, detailed, "standard output must equal the detailed output minus the enrichment fields");
    }

    #[test]
    fn none_fields_are_omitted_from_serialization() {
        let d = minimal_diagnostic();
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("suggestedFix"), "None suggestedFix should be omitted");
        assert!(!json.contains("documentationUrl"), "None documentationUrl should be omitted");
        assert!(!json.contains("context"), "None context should be omitted");
        assert!(!json.contains("relatedResources"), "None relatedResources should be omitted");
        assert!(!json.contains("conditionScenario"), "None conditionScenario should be omitted");
        assert!(!json.contains("propertyPath"), "None propertyPath should be omitted");
        assert!(!json.contains("category"), "None category should be omitted");
    }

    #[test]
    fn report_metadata_serializes_all_required_fields() {
        let metadata = ReportMetadata {
            rules_evaluated: 0,
            cfn_lint_version: "https://github.com/aws-cloudformation/cfn-lint@1.54.0".to_string(),
            resource_schema_version:
                "https://github.com/aws-cloudformation/resource-provider-enhanced-schemas@2026-08-07T18:20:13Z"
                    .to_string(),
            resources_scanned: 0,
            counts: Summary { fatal: 0, errors: 0, warnings: 0, informational: 0, debug: 0 },
            suppressed: 0,
            strict: false,
            severity_level: Severity::Info,
            budget_exhaustions: None,
        };

        let json = serde_json::to_value(metadata).expect("metadata should serialize");
        assert_eq!(json["rulesEvaluated"], 0);
        assert_eq!(json["cfnLintVersion"], "https://github.com/aws-cloudformation/cfn-lint@1.54.0");
        assert_eq!(
            json["resourceSchemaVersion"],
            "https://github.com/aws-cloudformation/resource-provider-enhanced-schemas@2026-08-07T18:20:13Z"
        );
        assert!(json.get("budgetExhaustions").is_none());
    }

    #[test]
    fn budget_exhaustion_record_serializes_description() {
        let record = BudgetExhaustionRecord {
            kind: "resolverDepth".to_string(),
            description: "Resolving intrinsic functions exceeded the maximum supported nesting depth.".to_string(),
            limit: 64,
            analysis_incomplete: true,
        };

        let json = serde_json::to_value(record).expect("budget exhaustion record should serialize");
        assert_eq!(json["kind"], "resolverDepth");
        assert_eq!(json["description"], "Resolving intrinsic functions exceeded the maximum supported nesting depth.");
    }

    #[test]
    fn budget_exhaustion_record_accepts_legacy_input_without_description() {
        let record: BudgetExhaustionRecord = serde_json::from_value(serde_json::json!({
            "kind": "resolverDepth",
            "limit": 64,
            "analysisIncomplete": true
        }))
        .expect("legacy budget exhaustion record should deserialize");

        assert!(record.description.is_empty());
    }

    #[test]
    fn report_status_serializes_as_screaming_snake_case() {
        assert_eq!(serde_json::to_string(&ReportStatus::Ok).unwrap(), "\"OK\"");
        assert_eq!(serde_json::to_string(&ReportStatus::AnalysisIncomplete).unwrap(), "\"ANALYSIS_INCOMPLETE\"");
        assert_eq!(serde_json::to_string(&ReportStatus::Error).unwrap(), "\"ERROR\"");
    }

    #[test]
    fn report_metadata_rejects_missing_required_fields() {
        let complete = serde_json::json!({
            "rulesEvaluated": 0,
            "cfnLintVersion": "v",
            "resourceSchemaVersion": "v",
            "resourcesScanned": 0,
            "counts": {
                "fatal": 0,
                "errors": 0,
                "warnings": 0,
                "informational": 0,
                "debug": 0
            },
            "suppressed": 0,
            "strict": false,
            "severityLevel": "INFO"
        });

        for required_field in ["rulesEvaluated", "cfnLintVersion", "resourceSchemaVersion"] {
            let mut incomplete = complete.clone();
            incomplete.as_object_mut().unwrap().remove(required_field);
            let error = serde_json::from_value::<ReportMetadata>(incomplete).unwrap_err();
            assert!(
                error.to_string().contains(required_field),
                "missing field error must name {required_field}: {error}"
            );
        }
    }

    #[test]
    fn report_metadata_budget_exhaustions_defaults_to_none() {
        // Older reports without budget exhaustion metadata should still deserialize.
        let minimal = serde_json::json!({
            "rulesEvaluated": 0,
            "cfnLintVersion": "v",
            "resourceSchemaVersion": "v",
            "resourcesScanned": 0,
            "counts": {
                "fatal": 0,
                "errors": 0,
                "warnings": 0,
                "informational": 0,
                "debug": 0
            },
            "suppressed": 0,
            "strict": false,
            "severityLevel": "INFO"
        });
        let metadata: ReportMetadata = serde_json::from_value(minimal).unwrap();
        assert!(metadata.budget_exhaustions.is_none(), "missing metadata should deserialize to None");
    }
}
