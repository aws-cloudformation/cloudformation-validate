//! Canonical validation for CloudFormation context metadata.

use data_source::embedded::METADATA_CONTEXT_V1_SCHEMA_BYTES;
use diagnostics::{Diagnostic, RegisteredDiagnostic, RelatedResource, ResourceRef};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::sync::OnceLock;
use template_model::{SemanticModel, UNKNOWN_SPAN};

const RULE_ID: &str = "W9100";
const CONTEXT_KEY: &str = "com.aws.cloudformation.Context";
const TEMPLATE_CONTEXT_PATH: &str = "Metadata/com.aws.cloudformation.Context";
const RESOURCE_CONTEXT_PATH: &str = "Metadata";
const TEMPLATE_SCHEMA_DEFINITION: &str = "TemplateContext";
const RESOURCE_SCHEMA_DEFINITION: &str = "ResourceContext";
const SCHEMA_ID: &str = "https://cloudformation.aws.dev/schema/metadata-context/v1.json";
const INCIDENTAL_RESOURCE_TYPE: &str = "AWS::CDK::Metadata";
const INCIDENTAL_LOGICAL_ID: &str = "CDKMetadata";
const INCIDENTAL_PATH_FRAGMENTS: &[&str] = &[
    "LogRetention",
    "Provider",
    "framework-onEvent",
    "framework-isComplete",
    "framework-onTimeout",
    "AWS679f53fac002430cb0da5b7982bd2287",
];
const TEMPLATE_SUGGESTED_FIX: &str =
    "Add or fix Metadata.com.aws.cloudformation.Context using template-level fields: arch, must, ref, and owner.";
const RESOURCE_SUGGESTED_FIX: &str = "Add or fix Metadata.com.aws.cloudformation.Context on each primary resource. Include why, or use gaps when the rationale is not known; add must only when a real binding rule exists.";

static CONTEXT_SCHEMA: OnceLock<Result<ContextSchema, String>> = OnceLock::new();

#[derive(Debug)]
struct ContextSchema {
    document: Value,
    template_fields: BTreeSet<String>,
    resource_fields: BTreeSet<String>,
}

impl ContextSchema {
    fn from_embedded() -> Result<Self, String> {
        let document: Value = serde_json::from_slice(&METADATA_CONTEXT_V1_SCHEMA_BYTES)
            .map_err(|error| format!("Failed to parse embedded metadata context schema: {error}"))?;
        let actual_id = document
            .get("$id")
            .and_then(Value::as_str)
            .ok_or_else(|| "Embedded metadata context schema is missing its required string '$id' field".to_string())?;
        if actual_id != SCHEMA_ID {
            return Err(format!(
                "Embedded metadata context schema has unexpected '$id': expected '{SCHEMA_ID}', found '{actual_id}'"
            ));
        }

        let template_fields = definition_fields(&document, TEMPLATE_SCHEMA_DEFINITION)?;
        let resource_fields = definition_fields(&document, RESOURCE_SCHEMA_DEFINITION)?;
        Ok(Self { document, template_fields, resource_fields })
    }

    fn definition(&self, definition_name: &str) -> Result<&Value, String> {
        self.document
            .pointer(&format!("/$defs/{definition_name}"))
            .ok_or_else(|| format!("Embedded metadata context schema is missing '$defs/{definition_name}'"))
    }

    fn validate(&self, definition_name: &str, instance: &Value) -> Result<Vec<SchemaViolation>, String> {
        let mut violations = Vec::new();
        validate_schema_node(instance, self.definition(definition_name)?, &self.document, "", &mut violations)?;
        violations.sort_by(|left, right| {
            left.path.cmp(&right.path).then_with(|| left.description().cmp(&right.description()))
        });
        Ok(violations)
    }
}

#[derive(Debug)]
struct ResourceContextIssues {
    logical_id: String,
    resource_type: String,
    findings: Vec<String>,
}

#[derive(Debug, Clone)]
struct SchemaViolation {
    path: String,
    kind: SchemaViolationKind,
}

impl SchemaViolation {
    fn description(&self) -> String {
        match &self.kind {
            SchemaViolationKind::InvalidType { expected } => format!("Expected {expected}."),
            SchemaViolationKind::InvalidEnum { value, allowed } => {
                format!("Value '{value}' is not recognized. Allowed values: {}.", allowed.join(", "))
            }
            SchemaViolationKind::MissingRequired => "Required field is missing.".to_string(),
            SchemaViolationKind::AdditionalProperty => "Field is not recognized.".to_string(),
            SchemaViolationKind::OneOf => "Expected exactly one supported shape.".to_string(),
        }
    }

    fn weight(&self) -> usize {
        match self.kind {
            SchemaViolationKind::InvalidType { .. } => 10,
            _ => 1,
        }
    }
}

#[derive(Debug, Clone)]
enum SchemaViolationKind {
    InvalidType { expected: String },
    InvalidEnum { value: String, allowed: Vec<String> },
    MissingRequired,
    AdditionalProperty,
    OneOf,
}

pub(crate) fn check_context(model: &SemanticModel) -> Result<Vec<Diagnostic>, String> {
    let schema = context_schema()?;
    let template_findings = validate_template_metadata(model.template_metadata.as_ref(), schema)?;
    let resource_issues = validate_primary_resource_metadata(model, schema)?;
    let mut diagnostics = Vec::with_capacity(2);

    if !template_findings.is_empty() {
        diagnostics.push(build_template_diagnostic(model, &template_findings));
    }
    if !resource_issues.is_empty() {
        diagnostics.push(build_resource_diagnostic(model, &resource_issues));
    }

    Ok(diagnostics)
}

fn context_schema() -> Result<&'static ContextSchema, String> {
    match CONTEXT_SCHEMA.get_or_init(ContextSchema::from_embedded) {
        Ok(schema) => Ok(schema),
        Err(error) => Err(error.clone()),
    }
}

fn definition_fields(document: &Value, definition_name: &str) -> Result<BTreeSet<String>, String> {
    let properties = document
        .pointer(&format!("/$defs/{definition_name}/properties"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            format!("Embedded metadata context schema definition '{definition_name}' is missing object 'properties'")
        })?;
    Ok(properties.keys().cloned().collect())
}

fn validate_template_metadata(metadata: Option<&Value>, schema: &ContextSchema) -> Result<Vec<String>, String> {
    let Some(metadata_object) = metadata.and_then(Value::as_object) else {
        return Ok(vec![format!("No top-level Metadata.{CONTEXT_KEY} block found.")]);
    };
    let Some(context) = metadata_object.get(CONTEXT_KEY) else {
        return Ok(vec![format!("No top-level Metadata.{CONTEXT_KEY} block found.")]);
    };

    let violations = schema.validate(TEMPLATE_SCHEMA_DEFINITION, context)?;
    Ok(format_schema_violations(
        violations,
        &schema.resource_fields,
        "template",
        "resource",
        &format!("Top-level Metadata.{CONTEXT_KEY}"),
    ))
}

fn validate_primary_resource_metadata(
    model: &SemanticModel,
    schema: &ContextSchema,
) -> Result<Vec<ResourceContextIssues>, String> {
    let mut logical_ids: Vec<&String> = model.resources.keys().collect();
    logical_ids.sort();
    let mut resource_issues = Vec::new();

    for logical_id in logical_ids {
        let Some(resource) = model.resources.get(logical_id) else {
            return Err(format!("Resource '{logical_id}' disappeared while validating context metadata"));
        };
        if is_incidental_resource(model, logical_id, &resource.resource_type, resource.metadata.as_deref()) {
            continue;
        }

        let findings = validate_resource_metadata(resource.metadata.as_deref(), schema)?;
        if !findings.is_empty() {
            resource_issues.push(ResourceContextIssues {
                logical_id: logical_id.clone(),
                resource_type: resource.resource_type.clone(),
                findings,
            });
        }
    }

    Ok(resource_issues)
}

fn validate_resource_metadata(metadata: Option<&Value>, schema: &ContextSchema) -> Result<Vec<String>, String> {
    let Some(metadata_object) = metadata.and_then(Value::as_object) else {
        return Ok(vec![format!("No Metadata.{CONTEXT_KEY} block found.")]);
    };
    let Some(context) = metadata_object.get(CONTEXT_KEY) else {
        return Ok(vec![format!("No Metadata.{CONTEXT_KEY} block found.")]);
    };

    let violations = schema.validate(RESOURCE_SCHEMA_DEFINITION, context)?;
    let mut findings = format_schema_violations(
        violations,
        &schema.template_fields,
        "resource",
        "template",
        &format!("Metadata.{CONTEXT_KEY}"),
    );
    if let Some(context_object) = context.as_object() {
        validate_resource_requirements(context_object, &mut findings);
    }
    Ok(findings)
}

fn format_schema_violations(
    violations: Vec<SchemaViolation>,
    opposite_placement_fields: &BTreeSet<String>,
    placement: &str,
    correct_placement: &str,
    block_label: &str,
) -> Vec<String> {
    violations
        .into_iter()
        .map(|violation| {
            if violation.path.is_empty() {
                return format!("{block_label} does not match the expected shape. {}", violation.description());
            }
            if matches!(violation.kind, SchemaViolationKind::AdditionalProperty)
                && !violation.path.contains('.')
                && !violation.path.contains('[')
                && opposite_placement_fields.contains(&violation.path)
            {
                return format!("'{}' belongs at {correct_placement} level.", violation.path);
            }
            match violation.kind {
                SchemaViolationKind::AdditionalProperty => {
                    format!("'{}' is not recognized by the {placement} context schema.", violation.path)
                }
                _ => format!("'{}' does not match the expected shape. {}", violation.path, violation.description()),
            }
        })
        .collect()
}

fn validate_schema_node(
    instance: &Value,
    schema: &Value,
    root_schema: &Value,
    path: &str,
    violations: &mut Vec<SchemaViolation>,
) -> Result<(), String> {
    let schema_object = schema
        .as_object()
        .ok_or_else(|| format!("Embedded metadata context schema node at '{}' is not an object", display_path(path)))?;

    if let Some(reference) = schema_object.get("$ref").and_then(Value::as_str) {
        let pointer = reference.strip_prefix('#').ok_or_else(|| {
            format!("Embedded metadata context schema contains unsupported external reference '{reference}'")
        })?;
        let referenced_schema = root_schema
            .pointer(pointer)
            .ok_or_else(|| format!("Embedded metadata context schema reference '{reference}' does not resolve"))?;
        return validate_schema_node(instance, referenced_schema, root_schema, path, violations);
    }

    if let Some(branches) = schema_object.get("oneOf").and_then(Value::as_array) {
        return validate_one_of(instance, branches, root_schema, path, violations);
    }

    if let Some(expected_type) = schema_object.get("type").and_then(Value::as_str)
        && !matches_json_type(instance, expected_type)
    {
        violations.push(SchemaViolation {
            path: path.to_string(),
            kind: SchemaViolationKind::InvalidType { expected: type_description(expected_type) },
        });
        return Ok(());
    }

    if let Some(allowed_values) = schema_object.get("enum").and_then(Value::as_array)
        && !allowed_values.contains(instance)
    {
        violations.push(SchemaViolation {
            path: path.to_string(),
            kind: SchemaViolationKind::InvalidEnum {
                value: display_value(instance),
                allowed: allowed_values.iter().map(display_value).collect(),
            },
        });
    }

    if let Some(instance_object) = instance.as_object() {
        validate_object(instance_object, schema_object, root_schema, path, violations)?;
    }
    if let Some(instance_array) = instance.as_array()
        && let Some(item_schema) = schema_object.get("items")
    {
        for (index, item) in instance_array.iter().enumerate() {
            validate_schema_node(item, item_schema, root_schema, &index_path(path, index), violations)?;
        }
    }

    Ok(())
}

fn validate_one_of(
    instance: &Value,
    branches: &[Value],
    root_schema: &Value,
    path: &str,
    violations: &mut Vec<SchemaViolation>,
) -> Result<(), String> {
    let mut branch_violations = Vec::with_capacity(branches.len());
    for branch in branches {
        let mut candidate_violations = Vec::new();
        validate_schema_node(instance, branch, root_schema, path, &mut candidate_violations)?;
        branch_violations.push(candidate_violations);
    }

    let matching_branches = branch_violations.iter().filter(|candidate| candidate.is_empty()).count();
    if matching_branches == 1 {
        return Ok(());
    }
    if matching_branches > 1 {
        violations.push(SchemaViolation { path: path.to_string(), kind: SchemaViolationKind::OneOf });
        return Ok(());
    }

    let best_candidate = branch_violations
        .into_iter()
        .min_by_key(|candidate| candidate.iter().map(SchemaViolation::weight).sum::<usize>())
        .unwrap_or_else(|| vec![SchemaViolation { path: path.to_string(), kind: SchemaViolationKind::OneOf }]);
    violations.extend(best_candidate);
    Ok(())
}

fn validate_object(
    instance: &Map<String, Value>,
    schema: &Map<String, Value>,
    root_schema: &Value,
    path: &str,
    violations: &mut Vec<SchemaViolation>,
) -> Result<(), String> {
    let properties = schema.get("properties").and_then(Value::as_object);
    if let Some(required_fields) = schema.get("required").and_then(Value::as_array) {
        for required_field in required_fields.iter().filter_map(Value::as_str) {
            if !instance.contains_key(required_field) {
                violations.push(SchemaViolation {
                    path: field_path(path, required_field),
                    kind: SchemaViolationKind::MissingRequired,
                });
            }
        }
    }

    for (field, value) in instance {
        let child_path = field_path(path, field);
        if let Some(property_schema) = properties.and_then(|known| known.get(field)) {
            validate_schema_node(value, property_schema, root_schema, &child_path, violations)?;
            continue;
        }
        match schema.get("additionalProperties") {
            Some(Value::Bool(false)) => {
                violations.push(SchemaViolation { path: child_path, kind: SchemaViolationKind::AdditionalProperty })
            }
            Some(additional_schema @ Value::Object(_)) => {
                validate_schema_node(value, additional_schema, root_schema, &child_path, violations)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn matches_json_type(value: &Value, expected_type: &str) -> bool {
    match expected_type {
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "object" => value.is_object(),
        "string" => value.is_string(),
        _ => false,
    }
}

fn type_description(schema_type: &str) -> String {
    match schema_type {
        "array" => "an array".to_string(),
        "object" => "an object".to_string(),
        other => format!("a {other}"),
    }
}

fn display_value(value: &Value) -> String {
    value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string())
}

fn display_path(path: &str) -> &str {
    if path.is_empty() { "(root)" } else { path }
}

fn field_path(parent: &str, field: &str) -> String {
    if parent.is_empty() { field.to_string() } else { format!("{parent}.{field}") }
}

fn index_path(parent: &str, index: usize) -> String {
    format!("{parent}[{index}]")
}

fn validate_resource_requirements(context: &Map<String, Value>, findings: &mut Vec<String>) {
    let has_why = context.contains_key("why");
    let has_acknowledged_gap = context
        .get("gaps")
        .and_then(Value::as_array)
        .is_some_and(|gaps| gaps.iter().any(|gap| gap.as_str().is_some_and(|text| !text.trim().is_empty())));
    if !has_why && !has_acknowledged_gap {
        findings.push("Metadata context has no 'why' and no non-empty 'gaps' entry.".to_string());
    }

    let restrictive_levels = restrictive_mutability_levels(context);
    let has_must_entry = context
        .get("must")
        .and_then(Value::as_array)
        .is_some_and(|rules| rules.iter().any(|rule| rule.as_str().is_some_and(|text| !text.trim().is_empty())));
    if !restrictive_levels.is_empty() && !has_must_entry {
        findings.push(format!(
            "Mutability level(s) {} require a non-empty 'must' entry stating the constraint.",
            restrictive_levels.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
}

fn restrictive_mutability_levels(context: &Map<String, Value>) -> BTreeSet<&str> {
    let mut levels = BTreeSet::new();
    if let Some(level) = context.get("mutable").and_then(Value::as_str)
        && is_restrictive_mutability_level(level)
    {
        levels.insert(level);
    }
    if let Some(overrides) = context.get("mutability").and_then(Value::as_object) {
        for level in overrides.values().filter_map(Value::as_str) {
            if is_restrictive_mutability_level(level) {
                levels.insert(level);
            }
        }
    }
    levels
}

fn is_restrictive_mutability_level(level: &str) -> bool {
    matches!(level, "must-never-change" | "change-with-constraints")
}

fn is_incidental_resource(
    model: &SemanticModel,
    logical_id: &str,
    resource_type: &str,
    metadata: Option<&Value>,
) -> bool {
    if model.sam_implicit_resources.contains(logical_id)
        || resource_type == INCIDENTAL_RESOURCE_TYPE
        || logical_id == INCIDENTAL_LOGICAL_ID
    {
        return true;
    }

    let cdk_path = metadata
        .and_then(Value::as_object)
        .and_then(|metadata_object| metadata_object.get("aws:cdk:path"))
        .and_then(Value::as_str);
    INCIDENTAL_PATH_FRAGMENTS
        .iter()
        .any(|fragment| logical_id.contains(fragment) || cdk_path.is_some_and(|path| path.contains(fragment)))
}

fn build_template_diagnostic(model: &SemanticModel, findings: &[String]) -> Diagnostic {
    let message = format!("Template context metadata issues: {}", findings.join(" "));
    let mut builder = RegisteredDiagnostic::new(RULE_ID, message)
        .property_path(TEMPLATE_CONTEXT_PATH)
        .suggested_fix(Some(TEMPLATE_SUGGESTED_FIX));
    if let Some(span) = model
        .diagnostic_span(None, TEMPLATE_CONTEXT_PATH)
        .or_else(|| model.source_location("Metadata").copied())
        .or_else(|| model.source_location("Resources").copied())
    {
        builder = builder.location(span);
    }
    builder.build()
}

fn build_resource_diagnostic(model: &SemanticModel, resource_issues: &[ResourceContextIssues]) -> Diagnostic {
    let first = &resource_issues[0];
    let issue_summaries = resource_issues
        .iter()
        .map(|resource| format!("{}: {}", resource.logical_id, resource.findings.join(" ")))
        .collect::<Vec<_>>()
        .join("; ");
    let message =
        format!("Primary resource context metadata issues ({} resource(s)): {issue_summaries}", resource_issues.len());
    let related_resources = resource_issues
        .iter()
        .skip(1)
        .map(|resource| {
            let span = model.resource_span(&resource.logical_id, RESOURCE_CONTEXT_PATH);
            RelatedResource {
                resource: Some(ResourceRef {
                    id: Some(resource.logical_id.clone()),
                    resource_type: Some(resource.resource_type.clone()),
                }),
                location: (span != UNKNOWN_SPAN).then_some(span),
                message: resource.findings.join(" "),
            }
        })
        .collect::<Vec<_>>();

    RegisteredDiagnostic::new(RULE_ID, message)
        .resource(first.logical_id.clone(), Some(first.resource_type.clone()))
        .property_path(RESOURCE_CONTEXT_PATH)
        .location(model.resource_span(&first.logical_id, RESOURCE_CONTEXT_PATH))
        .suggested_fix(Some(RESOURCE_SUGGESTED_FIX))
        .related_resources((!related_resources.is_empty()).then_some(related_resources))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(yaml: &str) -> SemanticModel {
        SemanticModel::from_bytes(yaml.as_bytes()).expect("template should parse")
    }

    fn check(yaml: &str) -> Vec<Diagnostic> {
        check_context(&model(yaml)).expect("embedded context schema should load")
    }

    fn valid_template_context() -> &'static str {
        r#"
Metadata:
  com.aws.cloudformation.Context:
    arch: "SQS to Lambda to DynamoDB"
    must:
      - "All data encrypted"
    ref:
      - "context/common.yaml"
      - at: "s3://example/context.yaml"
        has: "shared constraints"
        scope: "shared"
    owner: "payments-team"
"#
    }

    fn valid_resource_context() -> &'static str {
        r#"
    Metadata:
      com.aws.cloudformation.Context:
        why: "Buffers order events for asynchronous processing"
        must:
          - "Visibility timeout remains above function timeout"
        mutable: "change-with-constraints"
        mutability:
          QueueName: "must-never-change"
          Tags: "free-to-tune"
        trust:
          src: "authored"
          conf: "high"
          cite: "design.md"
          note: "Reviewed by service owner"
        ops: "Check queue age before changing throughput"
        gaps:
          - "Peak traffic profile not documented"
        deps:
          - "orders-events"
        failureModes:
          - "Consumer outage increases queue age"
"#
    }

    #[test]
    fn vendored_schema_has_canonical_id_and_placement_fields() {
        let schema = context_schema().expect("embedded context schema should load");

        assert_eq!(schema.document["$id"], SCHEMA_ID);
        assert_eq!(
            schema.template_fields,
            BTreeSet::from(["arch".to_string(), "must".to_string(), "owner".to_string(), "ref".to_string()])
        );
        assert_eq!(
            schema.resource_fields,
            BTreeSet::from([
                "deps".to_string(),
                "failureModes".to_string(),
                "gaps".to_string(),
                "must".to_string(),
                "mutability".to_string(),
                "mutable".to_string(),
                "ops".to_string(),
                "trust".to_string(),
                "why".to_string(),
            ])
        );
    }

    #[test]
    fn valid_context_at_both_placements_produces_no_diagnostics() {
        let template = format!(
            "AWSTemplateFormatVersion: '2010-09-09'\n{}Resources:\n  OrderQueue:\n    Type: AWS::SQS::Queue\n{}",
            valid_template_context(),
            valid_resource_context()
        );

        let diagnostics = check(&template);

        assert!(diagnostics.is_empty(), "valid canonical context should not be flagged: {diagnostics:?}");
    }

    #[test]
    fn legacy_bare_context_key_is_not_an_alias() {
        let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Metadata:
  Context:
    arch: "legacy"
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Metadata:
      Context:
        why: "legacy"
"#;

        let diagnostics = check(template);

        assert_eq!(diagnostics.len(), 2, "both canonical placements are missing");
        assert!(diagnostics.iter().all(|diagnostic| diagnostic.message.contains(CONTEXT_KEY)));
    }

    #[test]
    fn missing_template_and_multiple_primary_resources_produce_two_diagnostics() {
        let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
  Queue:
    Type: AWS::SQS::Queue
"#;

        let diagnostics = check(template);

        assert_eq!(diagnostics.len(), 2, "findings must be bounded by template and resource scope");
        let resource_diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.entity.is_some())
            .expect("resource aggregate should be present");
        assert!(resource_diagnostic.message.contains("Bucket"));
        assert!(resource_diagnostic.message.contains("Queue"));
        assert_eq!(resource_diagnostic.related_resources.as_ref().map(Vec::len), Some(1));
    }

    #[test]
    fn valid_resource_context_does_not_satisfy_missing_template_context() {
        let template = format!(
            "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  OrderQueue:\n    Type: AWS::SQS::Queue\n{}",
            valid_resource_context()
        );

        let diagnostics = check(&template);

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].entity.is_none(), "only the template scope should be flagged");
    }

    #[test]
    fn valid_template_context_does_not_satisfy_missing_resource_context() {
        let template = format!(
            "AWSTemplateFormatVersion: '2010-09-09'\n{}Resources:\n  OrderQueue:\n    Type: AWS::SQS::Queue\n",
            valid_template_context()
        );

        let diagnostics = check(&template);

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].resource_logical_id(), Some("OrderQueue"));
    }

    #[test]
    fn malformed_fields_are_aggregated_by_scope() {
        let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Metadata:
  com.aws.cloudformation.Context:
    arch: [not, a, string]
    why: "resource-only"
    ref:
      - has: "missing at"
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Metadata:
      com.aws.cloudformation.Context:
        why: 42
        must: "not an array"
        mutable: "yolo"
        mutability:
          QueueName: "sometimes"
        trust:
          conf: "certain"
          extra: true
        ref: []
        unknown: true
"#;

        let diagnostics = check(template);

        assert_eq!(diagnostics.len(), 2, "all issues must remain bounded to two diagnostics");
        let combined = diagnostics.iter().map(|diagnostic| diagnostic.message.as_str()).collect::<Vec<_>>().join(" ");
        for expected in [
            "arch",
            "why' belongs at resource level",
            "ref[0].at",
            "must",
            "mutable",
            "mutability.QueueName",
            "trust.src",
            "trust.conf",
            "trust.extra",
            "ref' belongs at template level",
            "unknown",
        ] {
            assert!(combined.contains(expected), "missing {expected:?} from {combined}");
        }
    }

    #[test]
    fn missing_why_can_be_acknowledged_with_gaps() {
        let template = format!(
            "AWSTemplateFormatVersion: '2010-09-09'\n{}Resources:\n  Queue:\n    Type: AWS::SQS::Queue\n    Metadata:\n      com.aws.cloudformation.Context:\n        gaps:\n          - 'rationale not documented'\n",
            valid_template_context()
        );

        let diagnostics = check(&template);

        assert!(diagnostics.is_empty(), "an honest non-empty gap is a valid alternative to why: {diagnostics:?}");
    }

    #[test]
    fn restrictive_mutability_requires_non_empty_must_entry() {
        let template = format!(
            "AWSTemplateFormatVersion: '2010-09-09'\n{}Resources:\n  Queue:\n    Type: AWS::SQS::Queue\n    Metadata:\n      com.aws.cloudformation.Context:\n        why: 'Buffers events'\n        mutable: 'must-never-change'\n",
            valid_template_context()
        );

        let diagnostics = check(&template);

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.contains("require a non-empty 'must' entry"));
    }

    #[test]
    fn cdk_incidental_resources_are_not_flagged() {
        let template = format!(
            "AWSTemplateFormatVersion: '2010-09-09'\n{}Resources:\n  CDKMetadata:\n    Type: AWS::CDK::Metadata\n  CustomProviderframeworkonEvent:\n    Type: AWS::Lambda::Function\n  Helper:\n    Type: AWS::Lambda::Function\n    Metadata:\n      aws:cdk:path: Stack/LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a/Resource\n",
            valid_template_context()
        );

        let diagnostics = check(&template);

        assert!(diagnostics.is_empty(), "framework resources must be excluded: {diagnostics:?}");
    }

    #[test]
    fn many_invalid_resources_still_produce_at_most_two_diagnostics() {
        let mut resources = String::new();
        for index in 0..20 {
            resources.push_str(&format!(
                "  Queue{index}:\n    Type: AWS::SQS::Queue\n    Metadata:\n      com.aws.cloudformation.Context:\n        mutable: invalid\n"
            ));
        }
        let template = format!("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n{resources}");

        let diagnostics = check(&template);

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics.iter().filter(|diagnostic| diagnostic.rule_id == RULE_ID).count(), 2);
        assert!(diagnostics.iter().any(|diagnostic| diagnostic.message.contains("Queue19")));
    }

    #[test]
    fn suggested_fix_preserves_the_honesty_alternative() {
        let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Queue:
    Type: AWS::SQS::Queue
"#;

        let diagnostics = check(template);
        let combined_fixes = diagnostics
            .iter()
            .filter_map(|diagnostic| diagnostic.suggested_fix.as_deref())
            .collect::<Vec<_>>()
            .join(" ");

        assert!(combined_fixes.contains(CONTEXT_KEY));
        assert!(combined_fixes.contains("gaps"));
        assert!(combined_fixes.contains("only when a real binding rule exists"));
    }
}
