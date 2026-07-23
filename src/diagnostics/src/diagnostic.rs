use crate::filter::Filterable;
use crate::metrics::PhaseMetric;
use crate::phase::Phase;
use rules::{RuleOrigin, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use template_model::{EntityType, JsonValue, SourceSpan};

fn serialize_sorted_optional_map<S, V>(map: &Option<HashMap<String, V>>, serializer: S) -> Result<S::Ok, S::Error>
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

/// Extra detail about a specific violation, present only in the detailed report.
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

/// Generates a report diagnostic struct that carries the targeted entity as a
/// nested `entity` struct and inlines `location` into individual line/column
/// fields. Used by `StandardDiagnostic` and `DetailedDiagnostic`.
macro_rules! define_flattened_diagnostic {
    ($(#[$struct_meta:meta])* $name:ident $(, $(#[$extra_meta:meta])* $extra_field:ident : $extra_ty:ty)*) => {
        $(#[$struct_meta])*
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
        #[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            /// Identifier of the rule that produced this finding; its leading letter encodes the severity.
            pub rule_id: String,
            pub severity: Severity,
            pub message: String,
            /// Where the rule came from, such as a provider schema, the built-in engine, or a user-supplied rule.
            pub source: RuleOrigin,
            /// The named template entity this finding targets — a resource, parameter, output, mapping, condition, or template rule — if any.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
            pub entity: Option<Entity>,
            /// Path to the offending property within the resource, such as 'Properties.Name'.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
            pub property_path: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
            pub suggested_fix: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
            pub category: Option<String>,
            /// Line in the source template where the finding begins (1-based).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
            pub start_line: Option<u32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
            pub start_column: Option<u32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
            pub end_line: Option<u32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
            pub end_column: Option<u32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
            pub related_resources: Option<Vec<RelatedResource>>,
            /// Condition name to boolean assignment under which this finding applies, when it depends on template conditions.
            #[serde(default, skip_serializing_if = "Option::is_none", serialize_with = "serialize_sorted_optional_map")]
            #[cfg_attr(feature = "wasm-bindings", tsify(type = "Record<string, boolean>"))]
            #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
            pub condition_scenario: Option<HashMap<String, bool>>,
            $(
                $(#[$extra_meta])*
                #[serde(default, skip_serializing_if = "Option::is_none")]
                #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
                pub $extra_field: $extra_ty,
            )*
        }
    };
}

define_flattened_diagnostic!(
    /// A single validation finding with its source location flattened into individual fields.
    StandardDiagnostic
);
define_flattened_diagnostic!(
    /// A validation finding with additional context and enrichment beyond the standard finding.
    DetailedDiagnostic,
    documentation_url: Option<String>,
    rule_description: Option<String>,
    phase: Option<Phase>,
    context: Option<ViolationContext>
);

/// Populates the shared fields of a report diagnostic from a `Diagnostic`.
macro_rules! flatten_diagnostic {
    ($self:expr $(, $extra_field:ident)* ) => {{
        let (start_line, start_column, end_line, end_column) = $self
            .location
            .map(|l| (Some(l.start_line), Some(l.start_column), Some(l.end_line), Some(l.end_column)))
            .unwrap_or((None, None, None, None));
        (
            $self.rule_id.clone(),
            $self.severity,
            $self.message.clone(),
            $self.entity.clone(),
            $self.property_path.clone(),
            $self.suggested_fix.clone(),
            $self.category.clone(),
            start_line,
            start_column,
            end_line,
            end_column,
            $self.related_resources.clone(),
            $self.condition_scenario.clone(),
            $self.source,
            $( $self.$extra_field.clone(), )*
        )
    }};
}

impl Diagnostic {
    pub fn to_standard(&self) -> StandardDiagnostic {
        let (
            rule_id,
            severity,
            message,
            entity,
            property_path,
            suggested_fix,
            category,
            start_line,
            start_column,
            end_line,
            end_column,
            related_resources,
            condition_scenario,
            source,
        ) = flatten_diagnostic!(self);
        StandardDiagnostic {
            rule_id,
            severity,
            message,
            entity,
            property_path,
            suggested_fix,
            category,
            start_line,
            start_column,
            end_line,
            end_column,
            related_resources,
            condition_scenario,
            source,
        }
    }

    pub fn to_detailed(&self) -> DetailedDiagnostic {
        let (
            rule_id,
            severity,
            message,
            entity,
            property_path,
            suggested_fix,
            category,
            start_line,
            start_column,
            end_line,
            end_column,
            related_resources,
            condition_scenario,
            source,
            documentation_url,
            rule_description,
            phase,
            context,
        ) = flatten_diagnostic!(self, documentation_url, rule_description, phase, context);
        DetailedDiagnostic {
            rule_id,
            severity,
            message,
            entity,
            property_path,
            suggested_fix,
            category,
            start_line,
            start_column,
            end_line,
            end_column,
            related_resources,
            condition_scenario,
            source,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ReportMetadata {
    /// Number of rules that were active for this run after any category exclusions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub rules_evaluated: Option<u32>,
    pub resources_scanned: u32,
    /// Tally of reported diagnostics by severity.
    pub counts: Summary,
    /// Number of diagnostics removed by filters and the severity threshold.
    pub suppressed: u32,
    /// Whether strict mode was enabled, promoting warnings to errors.
    pub strict: bool,
    /// Minimum severity included in the report; lower-severity findings are omitted.
    pub severity_level: Severity,
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

/// Outcome of a validation run. `Ok` means the engine completed; `Error` means
/// the pipeline could not run (e.g. parse failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportStatus {
    Ok,
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
    pub fn to_standard(&self) -> StandardReport {
        StandardReport {
            file_path: self.file_path.clone(),
            status: self.status,
            version: self.version.clone(),
            diagnostics: self.diagnostics.iter().map(|d| d.to_standard()).collect(),
            metadata: self.metadata.clone(),
            performance: self.performance.clone(),
        }
    }

    pub fn to_detailed(&self) -> DetailedReport {
        DetailedReport {
            file_path: self.file_path.clone(),
            status: self.status,
            version: self.version.clone(),
            diagnostics: self.diagnostics.iter().map(|d| d.to_detailed()).collect(),
            metadata: self.metadata.clone(),
            performance: self.performance.clone(),
        }
    }
}

/// Standard validation result: the report plus flattened diagnostics.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct StandardReport {
    pub file_path: String,
    pub status: ReportStatus,
    pub version: String,
    pub metadata: ReportMetadata,
    pub performance: PerformanceMetrics,
    pub diagnostics: Vec<StandardDiagnostic>,
}

/// Detailed validation result: like the standard report but with per-diagnostic context and enrichment.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DetailedReport {
    pub file_path: String,
    pub status: ReportStatus,
    pub version: String,
    pub metadata: ReportMetadata,
    pub performance: PerformanceMetrics,
    pub diagnostics: Vec<DetailedDiagnostic>,
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
    fn to_standard_carries_entity_and_flattens_location_fields() {
        let d = sample_diagnostic();
        let s = d.to_standard();

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
    }

    #[test]
    fn to_full_includes_context_and_enrichment_fields() {
        let d = sample_diagnostic();
        let f = d.to_detailed();

        assert_eq!(f.rule_id, "E3012");
        assert_eq!(f.entity.as_ref().map(|e| e.logical_id.as_str()), Some("MyBucket"));
        assert!(f.context.is_some(), "full diagnostic should include context");
        let ctx = f.context.unwrap();
        assert_eq!(ctx.property.as_deref(), Some("Foo"));
        assert_eq!(ctx.expected_constraint.as_deref(), Some("Must not exist"));
        assert_eq!(f.phase, Some(Phase::Schema));
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
    fn standard_diagnostic_uses_camel_case_and_excludes_context() {
        let d = sample_diagnostic();
        let s = d.to_standard();
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("ruleId"), "expected camelCase 'ruleId' in JSON");
        assert!(json.contains("startLine"), "expected 'startLine' in JSON");
        assert!(json.contains("\"entity\""), "expected nested 'entity' in JSON");
        assert!(json.contains("logicalId"), "expected 'logicalId' in JSON");
        assert!(json.contains("entityType"), "expected 'entityType' in JSON");
        assert!(json.contains("resourceType"), "expected 'resourceType' in JSON");
        assert!(json.contains("propertyPath"), "expected 'propertyPath' in JSON");
        assert!(!json.contains("\"context\""), "standard format should not include 'context'");
    }

    #[test]
    fn full_diagnostic_includes_context_in_serialization() {
        let d = sample_diagnostic();
        let f = d.to_detailed();
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"context\""), "full format should include 'context'");
        assert!(json.contains("actualValue"), "full format should include 'actualValue'");
        assert!(json.contains("expectedConstraint"), "full format should include 'expectedConstraint'");
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
    fn report_status_serializes_as_screaming_snake_case() {
        assert_eq!(serde_json::to_string(&ReportStatus::Ok).unwrap(), "\"OK\"");
        assert_eq!(serde_json::to_string(&ReportStatus::Error).unwrap(), "\"ERROR\"");
    }
}
