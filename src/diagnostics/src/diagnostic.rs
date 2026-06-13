use crate::filter::Filterable;
use crate::json_value::JsonValue;
use crate::metrics::PhaseMetric;
use crate::phase::Phase;
use crate::span::SourceSpan;
use rules::{RuleOrigin, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

fn serialize_sorted_optional_map<S, V>(
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ResourceRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ViolationContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "JsonValue | undefined"))]
    pub actual_value: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_constraint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", serialize_with = "serialize_sorted_optional_map")]
    #[cfg_attr(feature = "wasm-bindings", tsify(type = "Record<string, JsonValue>"))]
    pub extra: Option<HashMap<String, JsonValue>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct RelatedResource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceRef>,
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
    pub section: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ViolationContext>,
}

impl Filterable for Diagnostic {
    fn rule_id(&self) -> &str {
        &self.rule_id
    }
    fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }
    fn resource_id(&self) -> Option<&str> {
        self.resource.as_ref().and_then(|r| r.id.as_deref())
    }
    fn resource_type(&self) -> Option<&str> {
        self.resource
            .as_ref()
            .and_then(|r| r.resource_type.as_deref())
    }
}

/// Generates a flattened diagnostic struct that inlines `resource` into
/// `resource_id`/`resource_type` and `location` into individual line/column
/// fields. Used by `StandardDiagnostic` and `DetailedDiagnostic`.
macro_rules! define_flattened_diagnostic {
    ($name:ident $(, $extra_field:ident : $extra_ty:ty)*) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
        #[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub rule_id: String,
            pub severity: Severity,
            pub message: String,
            pub source: RuleOrigin,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub resource_id: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub resource_type: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub property_path: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub suggested_fix: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub category: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub start_line: Option<u32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub start_column: Option<u32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub end_line: Option<u32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub end_column: Option<u32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub related_resources: Option<Vec<RelatedResource>>,
            #[serde(default, skip_serializing_if = "Option::is_none", serialize_with = "serialize_sorted_optional_map")]
            #[cfg_attr(
                feature = "wasm-bindings",
                tsify(type = "Record<string, boolean> | undefined")
            )]
            pub condition_scenario: Option<HashMap<String, bool>>,
            $(
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub $extra_field: $extra_ty,
            )*
        }
    };
}

define_flattened_diagnostic!(StandardDiagnostic);
define_flattened_diagnostic!(DetailedDiagnostic,
    documentation_url: Option<String>,
    rule_description: Option<String>,
    phase: Option<Phase>,
    section: Option<String>,
    context: Option<ViolationContext>
);

/// Populates the shared fields of a flattened diagnostic from a `Diagnostic`.
macro_rules! flatten_diagnostic {
    ($self:expr $(, $extra_field:ident)* ) => {{
        let resource_id = $self.resource.as_ref().and_then(|r| r.id.clone());
        let resource_type = $self.resource.as_ref().and_then(|r| r.resource_type.clone());
        let (start_line, start_column, end_line, end_column) = $self
            .location
            .map(|l| (Some(l.start_line), Some(l.start_column), Some(l.end_line), Some(l.end_column)))
            .unwrap_or((None, None, None, None));
        (
            $self.rule_id.clone(),
            $self.severity,
            $self.message.clone(),
            resource_id,
            resource_type,
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
            resource_id,
            resource_type,
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
            resource_id,
            resource_type,
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
            resource_id,
            resource_type,
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
            section,
            context,
        ) = flatten_diagnostic!(
            self,
            documentation_url,
            rule_description,
            phase,
            section,
            context
        );
        DetailedDiagnostic {
            rule_id,
            severity,
            message,
            resource_id,
            resource_type,
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
            section,
            context,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct PerformanceMetrics {
    pub schema_init: PhaseMetric,
    pub engine_init: PhaseMetric,
    pub model_build: PhaseMetric,
    pub schema_validate: PhaseMetric,
    pub rule_evaluation: PhaseMetric,
    pub diagnostic_finalize: PhaseMetric,
    pub validate_total: PhaseMetric,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct ReportMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_evaluated: Option<u32>,
    pub resources_scanned: u32,
    pub counts: Summary,
    pub suppressed: u32,
    pub strict: bool,
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
    pub engine_version: String,
    pub metadata: ReportMetadata,
    pub performance: PerformanceMetrics,
    pub diagnostics: Vec<Diagnostic>,
}

impl ValidationReport {
    pub fn to_standard(&self) -> StandardReport {
        StandardReport {
            file_path: self.file_path.clone(),
            status: self.status,
            engine_version: self.engine_version.clone(),
            diagnostics: self.diagnostics.iter().map(|d| d.to_standard()).collect(),
            metadata: self.metadata.clone(),
            performance: self.performance.clone(),
        }
    }

    pub fn to_detailed(&self) -> DetailedReport {
        DetailedReport {
            file_path: self.file_path.clone(),
            status: self.status,
            engine_version: self.engine_version.clone(),
            diagnostics: self.diagnostics.iter().map(|d| d.to_detailed()).collect(),
            metadata: self.metadata.clone(),
            performance: self.performance.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct StandardReport {
    pub file_path: String,
    pub status: ReportStatus,
    pub engine_version: String,
    pub metadata: ReportMetadata,
    pub performance: PerformanceMetrics,
    pub diagnostics: Vec<StandardDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DetailedReport {
    pub file_path: String,
    pub status: ReportStatus,
    pub engine_version: String,
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
            resource: Some(ResourceRef {
                id: Some("MyBucket".into()),
                resource_type: Some("AWS::S3::Bucket".into()),
            }),
            property_path: Some("/Resources/MyBucket/Properties/Foo".into()),
            suggested_fix: Some("Remove the property".into()),
            documentation_url: Some("https://example.com/E3012".into()),
            category: Some("schema".into()),
            location: Some(SourceSpan {
                start_line: 10,
                start_column: 5,
                end_line: 10,
                end_column: 20,
            }),
            related_resources: Some(vec![RelatedResource {
                resource: Some(ResourceRef {
                    id: Some("OtherResource".into()),
                    resource_type: Some("AWS::EC2::Instance".into()),
                }),
                location: Some(SourceSpan {
                    start_line: 20,
                    start_column: 1,
                    end_line: 20,
                    end_column: 30,
                }),
                message: "Referenced here".into(),
            }]),
            condition_scenario: Some(HashMap::from([("IsProduction".into(), true)])),
            rule_description: Some("Disallows extra properties".into()),
            phase: Some(Phase::Schema),
            section: Some("Resources".into()),
            context: Some(ViolationContext {
                actual_value: Some(JsonValue::from(serde_json::json!("bad"))),
                expected_constraint: Some("Must not exist".into()),
                property: Some("Foo".into()),
                lifecycle: None,
                resolution_source: None,
                extra: None,
            }),
            source: rules::RuleOrigin::CfnLint,
        }
    }

    fn minimal_diagnostic() -> Diagnostic {
        Diagnostic {
            rule_id: String::new(),
            severity: Severity::Info,
            message: String::new(),
            resource: None,
            property_path: None,
            suggested_fix: None,
            documentation_url: None,
            category: None,
            location: None,
            related_resources: None,
            condition_scenario: None,
            rule_description: None,
            phase: None,
            section: None,
            context: None,
            source: RuleOrigin::Engine,
        }
    }

    #[test]
    fn to_standard_flattens_resource_and_location_fields() {
        let d = sample_diagnostic();
        let s = d.to_standard();

        assert_eq!(s.rule_id, "E3012");
        assert_eq!(s.resource_id.as_deref(), Some("MyBucket"));
        assert_eq!(s.resource_type.as_deref(), Some("AWS::S3::Bucket"));
        assert_eq!(s.start_line, Some(10));
        assert_eq!(s.start_column, Some(5));
        assert_eq!(s.end_line, Some(10));
        assert_eq!(s.end_column, Some(20));
        assert_eq!(s.message, "Property not allowed");
        assert_eq!(s.category.as_deref(), Some("schema"));
        assert_eq!(s.suggested_fix.as_deref(), Some("Remove the property"));
        assert_eq!(s.related_resources.as_ref().unwrap().len(), 1);
        assert_ne!(
            s.condition_scenario, None,
            "condition_scenario should be present"
        );
    }

    #[test]
    fn to_full_includes_context_and_enrichment_fields() {
        let d = sample_diagnostic();
        let f = d.to_detailed();

        assert_eq!(f.rule_id, "E3012");
        assert_eq!(f.resource_id.as_deref(), Some("MyBucket"));
        assert!(
            f.context.is_some(),
            "full diagnostic should include context"
        );
        let ctx = f.context.unwrap();
        assert_eq!(ctx.property.as_deref(), Some("Foo"));
        assert_eq!(ctx.expected_constraint.as_deref(), Some("Must not exist"));
        assert_eq!(f.phase, Some(Phase::Schema));
        assert_eq!(f.section.as_deref(), Some("Resources"));
    }

    #[test]
    fn filterable_returns_resource_and_category_from_diagnostic() {
        let d = sample_diagnostic();
        assert_eq!(d.rule_id(), "E3012");
        assert_eq!(d.category(), Some("schema"));
        assert_eq!(d.resource_id(), Some("MyBucket"));
        assert_eq!(d.resource_type(), Some("AWS::S3::Bucket"));
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
        assert_eq!(
            deserialized.location.as_ref().unwrap().start_line,
            d.location.as_ref().unwrap().start_line
        );
    }

    #[test]
    fn standard_diagnostic_uses_camel_case_and_excludes_context() {
        let d = sample_diagnostic();
        let s = d.to_standard();
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            json.contains("ruleId"),
            "expected camelCase 'ruleId' in JSON"
        );
        assert!(json.contains("startLine"), "expected 'startLine' in JSON");
        assert!(json.contains("resourceId"), "expected 'resourceId' in JSON");
        assert!(
            json.contains("resourceType"),
            "expected 'resourceType' in JSON"
        );
        assert!(
            json.contains("propertyPath"),
            "expected 'propertyPath' in JSON"
        );
        assert!(
            !json.contains("\"context\""),
            "standard format should not include 'context'"
        );
    }

    #[test]
    fn full_diagnostic_includes_context_in_serialization() {
        let d = sample_diagnostic();
        let f = d.to_detailed();
        let json = serde_json::to_string(&f).unwrap();
        assert!(
            json.contains("\"context\""),
            "full format should include 'context'"
        );
        assert!(
            json.contains("actualValue"),
            "full format should include 'actualValue'"
        );
        assert!(
            json.contains("expectedConstraint"),
            "full format should include 'expectedConstraint'"
        );
    }

    #[test]
    fn none_fields_are_omitted_from_serialization() {
        let d = minimal_diagnostic();
        let json = serde_json::to_string(&d).unwrap();
        assert!(
            !json.contains("suggestedFix"),
            "None suggestedFix should be omitted"
        );
        assert!(
            !json.contains("documentationUrl"),
            "None documentationUrl should be omitted"
        );
        assert!(!json.contains("context"), "None context should be omitted");
        assert!(
            !json.contains("relatedResources"),
            "None relatedResources should be omitted"
        );
        assert!(
            !json.contains("conditionScenario"),
            "None conditionScenario should be omitted"
        );
        assert!(
            !json.contains("propertyPath"),
            "None propertyPath should be omitted"
        );
        assert!(
            !json.contains("category"),
            "None category should be omitted"
        );
    }

    #[test]
    fn report_status_serializes_as_screaming_snake_case() {
        assert_eq!(serde_json::to_string(&ReportStatus::Ok).unwrap(), "\"OK\"");
        assert_eq!(
            serde_json::to_string(&ReportStatus::Error).unwrap(),
            "\"ERROR\""
        );
    }
}
