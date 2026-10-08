//! Metadata Context checks shared by every engine. A Context block is expected on
//! the template and on each architecture-relevant resource, every supplied block
//! must record a rationale, and every supplied block must match the Metadata
//! Context schema published in the CloudFormation template reference.

use data_source::embedded::METADATA_CONTEXT_SCHEMA_BYTES;
use diagnostics::{Diagnostic, RegisteredDiagnostic, RelatedResource, ResourceRef};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::sync::OnceLock;
use template_model::consts::{CDK_METADATA_TYPE, KEY_METADATA, SECTION_METADATA, SECTION_RESOURCES};
use template_model::model::ResolvedResource;
use template_model::{SemanticModel, SourceSpan, UNKNOWN_SPAN, span_to_option};

const MISSING_CONTEXT_RULE_ID: &str = "I4010";
const MISSING_WHY_RULE_ID: &str = "W4011";
const SCHEMA_VIOLATION_RULE_ID: &str = "W4012";

const CONTEXT_KEY: &str = "com.aws.cloudformation.Context";
const CONTEXT_DISPLAY: &str = "Metadata.com.aws.cloudformation.Context";
const SCHEMA_ID: &str = "https://cloudformation.aws.dev/schema/metadata-context/v1.json";
const MODULE_TYPE_SUFFIX: &str = "::MODULE";
const LOW_CONFIDENCE: &str = "low";

/// Subordinate resource types that are not expected to carry their own Context.
/// A block they do carry is still validated.
const LOW_VALUE_TYPES: [&str; 7] = [
    "AWS::IAM::Policy",
    "AWS::Lambda::Permission",
    "AWS::Logs::LogGroup",
    "AWS::Logs::LogStream",
    "AWS::S3::BucketPolicy",
    "AWS::SNS::TopicPolicy",
    "AWS::SQS::QueuePolicy",
];

/// Logical-ID markers of CDK framework helpers (log-retention and custom-resource
/// provider handlers) that survive in hand-maintained templates. Logical IDs
/// cannot contain hyphens, so `framework-onEvent` appears as `frameworkonEvent`.
const INCIDENTAL_ID_PREFIX: &str = "LogRetention";
const INCIDENTAL_ID_FRAGMENTS: [&str; 3] = ["frameworkonEvent", "frameworkisComplete", "frameworkonTimeout"];
const INCIDENTAL_PROVIDER_FRAGMENT: &str = "Providerframework";
const CDK_AWS_CUSTOM_RESOURCE_SINGLETON_ID: &str = "AWS679f53fac002430cb0da5b7982bd2287";

const TEMPLATE_CONTEXT_FIX: &str = "Add a top-level Metadata.com.aws.cloudformation.Context block whose 'arch' \
                                    summarizes the template's resources and data flow; add 'must' only for known \
                                    cross-cutting constraints.";
const RESOURCE_CONTEXT_FIX: &str = "Add Metadata.com.aws.cloudformation.Context to each listed resource with 'why' \
                                    stating its purpose and design rationale; when the rationale is not documented, \
                                    set trust to {src: infer, conf: low, note: \"rationale not documented\"} rather \
                                    than guessing. Add 'must' only for known constraints whose violation would break \
                                    the system.";
const MISSING_WHY_FIX: &str = "Add 'why' stating the resource's purpose and notable design choices without restating \
                               its type or property values, or set trust to {src: infer, conf: low, note: \"rationale \
                               not documented\"} when the rationale is unknown.";

static CONTEXT_SCHEMA: OnceLock<Result<ContextSchema, String>> = OnceLock::new();

pub(crate) fn check_context(model: &SemanticModel) -> Result<Vec<Diagnostic>, String> {
    let schema = context_schema()?;
    let primaries = primary_resources(model);
    let mut diagnostics = missing_context_diagnostics(model, &primaries);

    for &(logical_id, resource) in &primaries {
        let Some(context) = resource_context(resource) else {
            continue;
        };
        diagnostics.extend(missing_why_diagnostic(model, logical_id, resource, context));
        diagnostics.extend(schema_violation_diagnostics(model, Some((logical_id, resource)), context, schema)?);
    }
    if let Some(context) = template_context(model) {
        diagnostics.extend(schema_violation_diagnostics(model, None, context, schema)?);
    }
    Ok(diagnostics)
}

fn context_schema() -> Result<&'static ContextSchema, String> {
    match CONTEXT_SCHEMA.get_or_init(ContextSchema::from_embedded) {
        Ok(schema) => Ok(schema),
        Err(error) => Err(error.clone()),
    }
}

/// Resources an author wrote and may annotate: everything with a usable type
/// except CDK framework helpers, in declaration order so aggregate findings read
/// like the template. A resource whose `Type` is missing or not a string is
/// reported by the resource-shape rules and cannot be architecture-relevant.
fn primary_resources(model: &SemanticModel) -> Vec<(&str, &ResolvedResource)> {
    let mut primaries: Vec<(&str, &ResolvedResource)> = model
        .resources
        .iter()
        .filter(|(logical_id, resource)| !resource.resource_type.is_empty() && !is_incidental(logical_id))
        .map(|(logical_id, resource)| (logical_id.as_str(), resource))
        .collect();
    primaries.sort_by_cached_key(|&(logical_id, _)| {
        let span = model.resource_span(logical_id, "");
        (span.start_line, span.start_column, logical_id.to_string())
    });
    primaries
}

fn is_incidental(logical_id: &str) -> bool {
    logical_id.starts_with(INCIDENTAL_ID_PREFIX)
        || logical_id == CDK_AWS_CUSTOM_RESOURCE_SINGLETON_ID
        || INCIDENTAL_ID_FRAGMENTS.iter().any(|fragment| logical_id.contains(fragment))
        || logical_id
            .match_indices(INCIDENTAL_PROVIDER_FRAGMENT)
            .any(|(index, _)| logical_id.as_bytes()[..index].last().is_some_and(u8::is_ascii_lowercase))
}

/// Whether a resource is expected to carry Context. Subordinate types describe
/// another resource, the CDK analytics record describes no component, and a
/// module's type says nothing about its significance.
fn requires_context(resource: &ResolvedResource) -> bool {
    let resource_type = resource.resource_type.as_str();
    !LOW_VALUE_TYPES.contains(&resource_type)
        && resource_type != CDK_METADATA_TYPE
        && !resource_type.ends_with(MODULE_TYPE_SUFFIX)
}

fn resource_context(resource: &ResolvedResource) -> Option<&Value> {
    resource.metadata.as_ref()?.as_object()?.get(CONTEXT_KEY)
}

fn template_context(model: &SemanticModel) -> Option<&Value> {
    model.template_metadata.as_ref()?.as_object()?.get(CONTEXT_KEY)
}

fn missing_context_diagnostics(model: &SemanticModel, primaries: &[(&str, &ResolvedResource)]) -> Vec<Diagnostic> {
    let missing: Vec<(&str, &ResolvedResource)> = primaries
        .iter()
        .copied()
        .filter(|&(_, resource)| requires_context(resource) && resource_context(resource).is_none())
        .collect();
    if missing.is_empty() {
        return Vec::new();
    }

    let mut diagnostics = Vec::with_capacity(2);
    // An architecture summary describes how components relate, so it is expected
    // only once more than one resource lacks its own rationale.
    if missing.len() >= 2 && template_context(model).is_none() {
        diagnostics.push(
            RegisteredDiagnostic::new(
                MISSING_CONTEXT_RULE_ID,
                format!("The template has no top-level {CONTEXT_DISPLAY} block describing its architecture."),
            )
            .property_path(SECTION_METADATA)
            .location(model.source_location(SECTION_METADATA).copied().unwrap_or(UNKNOWN_SPAN))
            .suggested_fix(Some(TEMPLATE_CONTEXT_FIX))
            .build(),
        );
    }
    diagnostics.push(missing_resource_aggregate(model, &missing));
    diagnostics
}

/// One finding anchored at the first resource without Context; the others are
/// listed in the message and attached as related resources with their own spans.
fn missing_resource_aggregate(model: &SemanticModel, missing: &[(&str, &ResolvedResource)]) -> Diagnostic {
    let summary = missing
        .iter()
        .map(|(logical_id, resource)| format!("{logical_id} ({})", resource.resource_type))
        .collect::<Vec<_>>()
        .join(", ");
    let (first_id, first) = missing[0];
    let related: Vec<RelatedResource> = missing[1..]
        .iter()
        .map(|&(logical_id, resource)| RelatedResource {
            resource: Some(ResourceRef {
                id: Some(logical_id.to_string()),
                resource_type: Some(resource.resource_type.clone()),
            }),
            location: span_to_option(model.resource_span(logical_id, "")),
            message: format!("No {CONTEXT_DISPLAY} block."),
        })
        .collect();

    RegisteredDiagnostic::new(
        MISSING_CONTEXT_RULE_ID,
        format!("Resources without a {CONTEXT_DISPLAY} block: {summary}."),
    )
    .resource(first_id, Some(first.resource_type.clone()))
    .location(model.resource_span(first_id, ""))
    .suggested_fix(Some(RESOURCE_CONTEXT_FIX))
    .related_resources((!related.is_empty()).then_some(related))
    .build()
}

fn missing_why_diagnostic(
    model: &SemanticModel,
    logical_id: &str,
    resource: &ResolvedResource,
    context: &Value,
) -> Option<Diagnostic> {
    // A block that is not a mapping is reported by the schema check instead.
    let block = context.as_object()?;
    let has_why = block.get("why").and_then(Value::as_str).is_some_and(|why| !why.trim().is_empty());
    // Only low confidence acknowledges an undocumented rationale; medium and high
    // assert that it is at least partly known.
    let acknowledges_unknown_rationale =
        block.get("trust").and_then(Value::as_object).and_then(|trust| trust.get("conf")).and_then(Value::as_str)
            == Some(LOW_CONFIDENCE);
    if has_why || acknowledges_unknown_rationale {
        return None;
    }
    Some(context_diagnostic(
        MISSING_WHY_RULE_ID,
        format!("{CONTEXT_DISPLAY} has no 'why' and no trust declaration with conf '{LOW_CONFIDENCE}'."),
        model,
        Some((logical_id, resource)),
        &[],
        Some(MISSING_WHY_FIX),
    ))
}

fn schema_violation_diagnostics(
    model: &SemanticModel,
    resource: Option<(&str, &ResolvedResource)>,
    context: &Value,
    schema: &ContextSchema,
) -> Result<Vec<Diagnostic>, String> {
    let placement = if resource.is_some() { Placement::Resource } else { Placement::Template };
    schema
        .violations(placement, context)?
        .iter()
        .map(|violation| {
            let message = schema.violation_message(placement, violation)?;
            Ok(context_diagnostic(SCHEMA_VIOLATION_RULE_ID, message, model, resource, &violation.path, None))
        })
        .collect()
}

/// Builds a diagnostic on a Context block or on a field inside it. The property
/// path is resource-relative for a resource block and section-absolute for the
/// template block; the span is the closest indexed ancestor of the field.
fn context_diagnostic(
    rule_id: &str,
    message: String,
    model: &SemanticModel,
    resource: Option<(&str, &ResolvedResource)>,
    field_path: &[String],
    suggested_fix: Option<&str>,
) -> Diagnostic {
    let (mut property_path, mut span_key) = match resource {
        Some((logical_id, _)) => (
            format!("{KEY_METADATA}.{CONTEXT_KEY}"),
            format!("{SECTION_RESOURCES}/{logical_id}/{KEY_METADATA}/{CONTEXT_KEY}"),
        ),
        None => {
            let key = format!("{SECTION_METADATA}/{CONTEXT_KEY}");
            (key.clone(), key)
        }
    };
    let separator = if resource.is_some() { '.' } else { '/' };
    for segment in field_path {
        property_path.push(separator);
        property_path.push_str(segment);
        span_key.push('/');
        span_key.push_str(segment);
    }

    let mut builder = RegisteredDiagnostic::new(rule_id, message)
        .property_path(property_path)
        .location(context_span(model, &span_key))
        .suggested_fix(suggested_fix);
    if let Some((logical_id, resource)) = resource {
        builder = builder.resource(logical_id, Some(resource.resource_type.clone()));
    }
    builder.build()
}

fn context_span(model: &SemanticModel, span_key: &str) -> SourceSpan {
    model.diagnostic_span(None, span_key).unwrap_or(UNKNOWN_SPAN)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    Template,
    Resource,
}

impl Placement {
    fn definition_name(self) -> &'static str {
        match self {
            Self::Template => "TemplateContext",
            Self::Resource => "ResourceContext",
        }
    }

    fn level(self) -> &'static str {
        match self {
            Self::Template => "template",
            Self::Resource => "resource",
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Template => Self::Resource,
            Self::Resource => Self::Template,
        }
    }
}

#[derive(Debug)]
struct ContextSchema {
    document: Value,
    template_fields: BTreeSet<String>,
    resource_fields: BTreeSet<String>,
}

impl ContextSchema {
    fn from_embedded() -> Result<Self, String> {
        let document: Value = serde_json::from_slice(&METADATA_CONTEXT_SCHEMA_BYTES)
            .map_err(|error| format!("Failed to parse embedded Metadata Context schema: {error}"))?;
        let actual_id = document
            .get("$id")
            .and_then(Value::as_str)
            .ok_or_else(|| "Embedded Metadata Context schema is missing its string '$id'".to_string())?;
        if actual_id != SCHEMA_ID {
            return Err(format!(
                "Embedded Metadata Context schema has unexpected '$id': expected '{SCHEMA_ID}', found '{actual_id}'"
            ));
        }
        let template_fields = definition_fields(&document, Placement::Template)?;
        let resource_fields = definition_fields(&document, Placement::Resource)?;
        Ok(Self { document, template_fields, resource_fields })
    }

    fn fields(&self, placement: Placement) -> &BTreeSet<String> {
        match placement {
            Placement::Template => &self.template_fields,
            Placement::Resource => &self.resource_fields,
        }
    }

    fn definition(&self, placement: Placement) -> Result<&Value, String> {
        let name = placement.definition_name();
        self.document
            .pointer(&format!("/$defs/{name}"))
            .ok_or_else(|| format!("Embedded Metadata Context schema is missing '$defs/{name}'"))
    }

    fn field_schema(&self, placement: Placement, field: &str) -> Result<&Value, String> {
        let name = placement.definition_name();
        self.document
            .pointer(&format!("/$defs/{name}/properties/{field}"))
            .ok_or_else(|| format!("Embedded Metadata Context schema definition '{name}' has no property '{field}'"))
    }

    /// Every way `block` departs from the schema definition for `placement`. A
    /// top-level key that the other placement defines is reported as misplaced
    /// rather than unknown.
    fn violations(&self, placement: Placement, block: &Value) -> Result<Vec<SchemaViolation>, String> {
        if !block.is_object() {
            return Ok(vec![SchemaViolation {
                path: Vec::new(),
                kind: SchemaViolationKind::NotAMapping { found: json_type_name(block) },
            }]);
        }
        let mut violations = Vec::new();
        validate_node(block, self.definition(placement)?, &self.document, &[], &mut violations)?;
        let other_fields = self.fields(placement.other());
        for violation in &mut violations {
            if matches!(violation.kind, SchemaViolationKind::UnknownField { .. })
                && let [field] = violation.path.as_slice()
                && other_fields.contains(field)
            {
                violation.kind = SchemaViolationKind::MisplacedField;
            }
        }
        Ok(violations)
    }

    fn violation_message(&self, placement: Placement, violation: &SchemaViolation) -> Result<String, String> {
        let field = violation.path.join(".");
        let shape = |top_field: &str| describe_shape(self.field_schema(placement, top_field)?, &self.document);
        let top_field = violation.path.first().map(String::as_str);
        let message = match (&violation.kind, top_field) {
            (SchemaViolationKind::NotAMapping { found }, _) => {
                format!("{CONTEXT_DISPLAY} must be a mapping of Context fields; found {found}.")
            }
            (kind, None) => {
                return Err(format!("Metadata Context violation {kind:?} was reported without a field path"));
            }
            (SchemaViolationKind::MisplacedField, Some(_)) => format!(
                "'{field}' belongs at {} level, not {} level. Template-level fields: {}; resource-level fields: {}.",
                placement.other().level(),
                placement.level(),
                render_list(&self.template_fields),
                render_list(&self.resource_fields),
            ),
            (SchemaViolationKind::UnknownField { allowed }, Some(_)) if violation.path.len() == 1 => {
                format!(
                    "'{field}' is not a recognized {}-level Context field; allowed fields: {allowed}.",
                    placement.level()
                )
            }
            (SchemaViolationKind::UnknownField { allowed }, Some(_)) => {
                let parent = violation.path[..violation.path.len() - 1].join(".");
                format!("'{field}' is not a recognized field of '{parent}'; allowed fields: {allowed}.")
            }
            (SchemaViolationKind::UnknownEnumValue { value, allowed }, Some(_)) => {
                format!("'{field}' value '{value}' is not recognized; allowed values: {allowed}.")
            }
            (SchemaViolationKind::WrongType { found }, Some(top)) if violation.path.len() == 1 => {
                format!("'{field}' is {found}; it must be {}.", shape(top)?)
            }
            (SchemaViolationKind::WrongType { found }, Some(top)) => {
                format!("'{field}' is {found}; '{top}' must be {}.", shape(top)?)
            }
            (SchemaViolationKind::MissingRequiredField { required }, Some(top)) => {
                format!("'{field}' is missing required field '{required}'; '{top}' must be {}.", shape(top)?)
            }
            (SchemaViolationKind::NoMatchingShape, Some(top)) => {
                format!("'{field}' does not match any supported shape; '{top}' must be {}.", shape(top)?)
            }
        };
        Ok(message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SchemaViolation {
    /// Path of the offending node inside the Context block; array indices are
    /// rendered as digits. Empty for the block itself.
    path: Vec<String>,
    kind: SchemaViolationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SchemaViolationKind {
    NotAMapping { found: &'static str },
    MisplacedField,
    UnknownField { allowed: String },
    WrongType { found: &'static str },
    UnknownEnumValue { value: String, allowed: String },
    MissingRequiredField { required: String },
    NoMatchingShape,
}

fn definition_fields(document: &Value, placement: Placement) -> Result<BTreeSet<String>, String> {
    let name = placement.definition_name();
    let properties = document
        .pointer(&format!("/$defs/{name}/properties"))
        .and_then(Value::as_object)
        .ok_or_else(|| format!("Embedded Metadata Context schema definition '{name}' has no object 'properties'"))?;
    Ok(properties.keys().cloned().collect())
}

fn validate_node(
    instance: &Value,
    schema: &Value,
    root: &Value,
    path: &[String],
    violations: &mut Vec<SchemaViolation>,
) -> Result<(), String> {
    let node = schema_object(schema, path)?;
    if let Some(reference) = node.get("$ref") {
        return validate_node(instance, resolve_reference(reference, root)?, root, path, violations);
    }
    if let Some(branches) = node.get("oneOf").and_then(Value::as_array) {
        return validate_one_of(instance, branches, root, path, violations);
    }
    if let Some(expected_type) = node.get("type").and_then(Value::as_str)
        && !matches_json_type(instance, expected_type)?
    {
        violations.push(SchemaViolation {
            path: path.to_vec(),
            kind: SchemaViolationKind::WrongType { found: json_type_name(instance) },
        });
        return Ok(());
    }
    if let Some(allowed) = node.get("enum").and_then(Value::as_array)
        && !allowed.contains(instance)
    {
        violations.push(SchemaViolation {
            path: path.to_vec(),
            kind: SchemaViolationKind::UnknownEnumValue {
                value: display_value(instance),
                allowed: allowed.iter().map(display_value).collect::<Vec<_>>().join(", "),
            },
        });
        return Ok(());
    }
    if let Some(object) = instance.as_object() {
        validate_object(object, node, root, path, violations)?;
    }
    if let Some(items) = instance.as_array()
        && let Some(item_schema) = node.get("items")
    {
        for (index, item) in items.iter().enumerate() {
            validate_node(item, item_schema, root, &child_path(path, &index.to_string()), violations)?;
        }
    }
    Ok(())
}

fn validate_object(
    object: &Map<String, Value>,
    node: &Map<String, Value>,
    root: &Value,
    path: &[String],
    violations: &mut Vec<SchemaViolation>,
) -> Result<(), String> {
    if let Some(required) = node.get("required").and_then(Value::as_array) {
        for field in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(field) {
                violations.push(SchemaViolation {
                    path: path.to_vec(),
                    kind: SchemaViolationKind::MissingRequiredField { required: field.to_string() },
                });
            }
        }
    }
    let properties = node.get("properties").and_then(Value::as_object);
    for (field, value) in object {
        let field_path = child_path(path, field);
        if let Some(property_schema) = properties.and_then(|properties| properties.get(field)) {
            validate_node(value, property_schema, root, &field_path, violations)?;
            continue;
        }
        match node.get("additionalProperties") {
            Some(Value::Bool(false)) => violations.push(SchemaViolation {
                path: field_path,
                kind: SchemaViolationKind::UnknownField {
                    allowed: render_list(
                        &properties
                            .map(|properties| properties.keys().cloned().collect::<BTreeSet<_>>())
                            .unwrap_or_default(),
                    ),
                },
            }),
            Some(additional_schema @ Value::Object(_)) => {
                validate_node(value, additional_schema, root, &field_path, violations)?;
            }
            Some(Value::Bool(true)) | None => {}
            Some(other) => {
                return Err(format!(
                    "Embedded Metadata Context schema node at '{}' has unsupported 'additionalProperties' {other}",
                    display_path(path)
                ));
            }
        }
    }
    Ok(())
}

/// A `oneOf` whose branches differ by JSON type. When no branch accepts the
/// value, the branch whose type the value has explains what is wrong inside it;
/// a value of a type no branch declares is reported as matching no shape.
fn validate_one_of(
    instance: &Value,
    branches: &[Value],
    root: &Value,
    path: &[String],
    violations: &mut Vec<SchemaViolation>,
) -> Result<(), String> {
    let mut branch_violations = Vec::with_capacity(branches.len());
    for branch in branches {
        let mut candidate = Vec::new();
        validate_node(instance, branch, root, path, &mut candidate)?;
        branch_violations.push(candidate);
    }
    if branch_violations.iter().any(Vec::is_empty) {
        return Ok(());
    }
    let mut same_type_branches = Vec::new();
    for (index, branch) in branches.iter().enumerate() {
        if let Some(branch_type) = schema_object(branch, path)?.get("type").and_then(Value::as_str)
            && matches_json_type(instance, branch_type)?
        {
            same_type_branches.push(index);
        }
    }
    match same_type_branches.as_slice() {
        [index] => violations.append(&mut branch_violations[*index]),
        _ => violations.push(SchemaViolation { path: path.to_vec(), kind: SchemaViolationKind::NoMatchingShape }),
    }
    Ok(())
}

/// Describes the shape a schema node accepts, for messages: `a string`, `an
/// array of strings`, `an object with required 'src' and 'conf'`, `one of: …`.
fn describe_shape(schema: &Value, root: &Value) -> Result<String, String> {
    let node = schema_object(schema, &[])?;
    if let Some(reference) = node.get("$ref") {
        return describe_shape(resolve_reference(reference, root)?, root);
    }
    if let Some(branches) = node.get("oneOf").and_then(Value::as_array) {
        let described = branches.iter().map(|branch| describe_shape(branch, root)).collect::<Result<Vec<_>, _>>()?;
        return Ok(described.join(" or "));
    }
    if let Some(allowed) = node.get("enum").and_then(Value::as_array) {
        return Ok(format!("one of: {}", allowed.iter().map(display_value).collect::<Vec<_>>().join(", ")));
    }
    match node.get("type").and_then(Value::as_str) {
        Some("string") => Ok("a string".to_string()),
        Some("boolean") => Ok("a boolean".to_string()),
        Some("number") => Ok("a number".to_string()),
        Some("integer") => Ok("an integer".to_string()),
        Some("null") => Ok("null".to_string()),
        Some("array") => match node.get("items") {
            Some(items) => {
                let item = describe_shape(items, root)?;
                Ok(if item == "a string" {
                    "an array of strings".to_string()
                } else {
                    format!("an array whose entries are each {item}")
                })
            }
            None => Ok("an array".to_string()),
        },
        Some("object") => {
            let required: Vec<String> = node
                .get("required")
                .and_then(Value::as_array)
                .map(|fields| fields.iter().filter_map(Value::as_str).map(|field| format!("'{field}'")).collect())
                .unwrap_or_default();
            if !required.is_empty() {
                return Ok(format!("an object with required {}", required.join(" and ")));
            }
            match node.get("additionalProperties") {
                Some(additional @ Value::Object(_)) => {
                    Ok(format!("a mapping of property name to {}", describe_shape(additional, root)?))
                }
                _ => Ok("an object".to_string()),
            }
        }
        Some(other) => Err(format!("Embedded Metadata Context schema uses unsupported type '{other}'")),
        None => Err("Embedded Metadata Context schema node declares no recognizable shape".to_string()),
    }
}

fn schema_object<'a>(schema: &'a Value, path: &[String]) -> Result<&'a Map<String, Value>, String> {
    schema
        .as_object()
        .ok_or_else(|| format!("Embedded Metadata Context schema node at '{}' is not an object", display_path(path)))
}

fn resolve_reference<'a>(reference: &Value, root: &'a Value) -> Result<&'a Value, String> {
    let reference = reference
        .as_str()
        .ok_or_else(|| format!("Embedded Metadata Context schema has a non-string '$ref' {reference}"))?;
    let pointer = reference.strip_prefix('#').ok_or_else(|| {
        format!("Embedded Metadata Context schema contains unsupported external reference '{reference}'")
    })?;
    root.pointer(pointer)
        .ok_or_else(|| format!("Embedded Metadata Context schema reference '{reference}' does not resolve"))
}

fn matches_json_type(value: &Value, expected_type: &str) -> Result<bool, String> {
    Ok(match expected_type {
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "object" => value.is_object(),
        "string" => value.is_string(),
        other => return Err(format!("Embedded Metadata Context schema uses unsupported type '{other}'")),
    })
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn display_value(value: &Value) -> String {
    value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string())
}

fn display_path(path: &[String]) -> String {
    if path.is_empty() { "(root)".to_string() } else { path.join(".") }
}

fn child_path(path: &[String], segment: &str) -> Vec<String> {
    let mut child = path.to_vec();
    child.push(segment.to_string());
    child
}

fn render_list(fields: &BTreeSet<String>) -> String {
    fields.iter().map(String::as_str).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Schema keywords the validator interprets. A vendored schema update that
    /// introduces another keyword must extend the validator, not be ignored.
    const SUPPORTED_KEYWORDS: [&str; 13] = [
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "description",
        "enum",
        "items",
        "oneOf",
        "properties",
        "required",
        "title",
        "type",
    ];

    fn model(template: &str) -> SemanticModel {
        SemanticModel::from_bytes(template.as_bytes()).expect("template should parse")
    }

    fn check(template: &str) -> Vec<Diagnostic> {
        check_context(&model(template)).expect("embedded Metadata Context schema should load")
    }

    fn rule_ids(diagnostics: &[Diagnostic]) -> Vec<&str> {
        diagnostics.iter().map(|diagnostic| diagnostic.rule_id.as_str()).collect()
    }

    fn with_rule<'a>(diagnostics: &'a [Diagnostic], rule_id: &str) -> Vec<&'a Diagnostic> {
        diagnostics.iter().filter(|diagnostic| diagnostic.rule_id == rule_id).collect()
    }

    fn collect_keywords(node: &Value, keywords: &mut BTreeSet<String>) {
        let Some(object) = node.as_object() else {
            return;
        };
        for (keyword, value) in object {
            keywords.insert(keyword.clone());
            match keyword.as_str() {
                "$defs" | "properties" => value.as_object().into_iter().flatten().for_each(|(_, child)| {
                    collect_keywords(child, keywords);
                }),
                "items" | "additionalProperties" => collect_keywords(value, keywords),
                "oneOf" => value.as_array().into_iter().flatten().for_each(|child| collect_keywords(child, keywords)),
                _ => {}
            }
        }
    }

    const TEMPLATE_CONTEXT: &str = r#"
Metadata:
  com.aws.cloudformation.Context:
    arch: "SQS buffer to Lambda consumer"
    must:
      - "All data remains encrypted"
    ref:
      - "context/common.yaml"
      - at: "s3://example/context.yaml"
        has: "shared constraints"
        scope: "shared"
    owner: "orders-team"
"#;

    const RESOURCE_CONTEXT: &str = r#"
    Metadata:
      com.aws.cloudformation.Context:
        why: "Buffers order events for asynchronous processing"
        must:
          - "Visibility timeout remains above function timeout"
        mutable: "change-with-constraints"
        mutability:
          QueueName: "must-never-change"
        trust:
          src: "authored"
          conf: "high"
          cite: "design.md"
          note: "Reviewed by service owner"
        deps:
          - "orders-events"
"#;

    #[test]
    fn vendored_schema_uses_only_supported_keywords() {
        let schema = context_schema().expect("embedded Metadata Context schema should load");
        let mut keywords = BTreeSet::new();
        collect_keywords(&schema.document, &mut keywords);

        let unsupported: Vec<&String> =
            keywords.iter().filter(|keyword| !SUPPORTED_KEYWORDS.contains(&keyword.as_str())).collect();
        assert!(unsupported.is_empty(), "validator does not interpret schema keywords {unsupported:?}");
    }

    #[test]
    fn vendored_schema_defines_the_published_placement_fields() {
        let schema = context_schema().expect("embedded Metadata Context schema should load");

        assert_eq!(render_list(&schema.template_fields), "arch, must, owner, ref");
        assert_eq!(render_list(&schema.resource_fields), "deps, must, mutability, mutable, trust, why");
    }

    #[test]
    fn complete_context_at_both_placements_is_clean() {
        let template = format!(
            "AWSTemplateFormatVersion: '2010-09-09'\n{TEMPLATE_CONTEXT}Resources:\n  OrderQueue:\n    Type: AWS::SQS::Queue\n{RESOURCE_CONTEXT}"
        );

        let diagnostics = check(&template);

        assert!(diagnostics.is_empty(), "complete context must not be flagged: {diagnostics:?}");
    }

    #[test]
    fn single_missing_resource_is_reported_without_a_template_finding() {
        let diagnostics = check("Resources:\n  OrderQueue:\n    Type: AWS::SQS::Queue\n");

        assert_eq!(rule_ids(&diagnostics), [MISSING_CONTEXT_RULE_ID]);
        assert_eq!(diagnostics[0].resource_logical_id(), Some("OrderQueue"));
        assert_eq!(
            diagnostics[0].message,
            format!("Resources without a {CONTEXT_DISPLAY} block: OrderQueue (AWS::SQS::Queue).")
        );
        assert!(diagnostics[0].related_resources.is_none());
        assert!(diagnostics[0].location.is_some());
    }

    #[test]
    fn two_missing_resources_add_a_template_finding_and_one_aggregate_in_declaration_order() {
        let template = r#"
Resources:
  OrdersTable:
    Type: AWS::DynamoDB::Table
  OrderQueue:
    Type: AWS::SQS::Queue
  ServiceLogGroup:
    Type: AWS::Logs::LogGroup
"#;

        let diagnostics = check(template);

        assert_eq!(rule_ids(&diagnostics), [MISSING_CONTEXT_RULE_ID, MISSING_CONTEXT_RULE_ID]);
        let template_finding = &diagnostics[0];
        assert!(template_finding.entity.is_none());
        assert_eq!(template_finding.property_path.as_deref(), Some(SECTION_METADATA));
        assert!(template_finding.location.is_none(), "no Metadata section exists to anchor at");
        let aggregate = &diagnostics[1];
        assert_eq!(aggregate.resource_logical_id(), Some("OrdersTable"), "anchored at the first declared resource");
        assert!(aggregate.message.contains("OrdersTable (AWS::DynamoDB::Table), OrderQueue (AWS::SQS::Queue)"));
        assert!(!aggregate.message.contains("ServiceLogGroup"), "subordinate types are not required to carry context");
        let related = aggregate.related_resources.as_ref().expect("the second resource is attached as related");
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].resource.as_ref().and_then(|resource| resource.id.as_deref()), Some("OrderQueue"));
        assert!(related[0].location.is_some());
    }

    #[test]
    fn template_context_suppresses_the_template_finding_only() {
        let template = format!(
            "{TEMPLATE_CONTEXT}Resources:\n  OrderQueue:\n    Type: AWS::SQS::Queue\n  AuditQueue:\n    Type: AWS::SQS::Queue\n"
        );

        let diagnostics = check(&template);

        assert_eq!(rule_ids(&diagnostics), [MISSING_CONTEXT_RULE_ID]);
        assert_eq!(diagnostics[0].resource_logical_id(), Some("OrderQueue"));
    }

    #[test]
    fn template_finding_is_anchored_at_an_existing_metadata_section() {
        let template = r#"
Metadata:
  AWS::CloudFormation::Interface:
    ParameterGroups: []
Resources:
  OrderQueue:
    Type: AWS::SQS::Queue
  AuditQueue:
    Type: AWS::SQS::Queue
"#;

        let diagnostics = check(template);

        assert_eq!(diagnostics[0].location.map(|span| span.start_line), Some(2));
    }

    #[test]
    fn exempt_resources_are_not_required_to_carry_context() {
        let template = r#"
Resources:
  ServiceLogGroup:
    Type: AWS::Logs::LogGroup
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
  SharedBucket:
    Type: AWS::S3::Bucket::MODULE
    Properties: {}
  LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a:
    Type: AWS::Lambda::Function
  StackframeworkonEventABC123:
    Type: AWS::Lambda::Function
  StackframeworkisCompleteABC123:
    Type: AWS::Lambda::Function
  StackframeworkonTimeoutABC123:
    Type: AWS::Lambda::Function
  AppProviderframeworkHandler123:
    Type: AWS::Lambda::Function
  AWS679f53fac002430cb0da5b7982bd2287:
    Type: AWS::Lambda::Function
  CDKMetadata:
    Type: AWS::CDK::Metadata
    Properties:
      Analytics: v2:deflate64:H4sIAAAAAAAA
"#;

        let diagnostics = check(template);

        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn resources_without_a_usable_type_are_left_to_the_shape_rules() {
        let template = r#"
Resources:
  MissingType:
    Properties:
      BucketName: my-bucket
  NonObjectBody: a string value
  NumericType:
    Type: 42
  Fn::ForEach::Buckets:
    - Name
    - [a, b]
    - Bucket${Name}:
        Type: AWS::S3::Bucket
  OrderQueue:
    Type: AWS::SQS::Queue
"#;

        let diagnostics = check(template);

        assert_eq!(rule_ids(&diagnostics), [MISSING_CONTEXT_RULE_ID], "{diagnostics:?}");
        assert_eq!(
            diagnostics[0].message,
            format!("Resources without a {CONTEXT_DISPLAY} block: OrderQueue (AWS::SQS::Queue).")
        );
    }

    #[test]
    fn provider_substring_alone_does_not_make_a_resource_incidental() {
        let template = r#"
Resources:
  DataProviderTable:
    Type: AWS::DynamoDB::Table
  OrderProviderQueue:
    Type: AWS::SQS::Queue
"#;

        let diagnostics = check(template);

        assert_eq!(rule_ids(&diagnostics), [MISSING_CONTEXT_RULE_ID, MISSING_CONTEXT_RULE_ID]);
        assert!(
            diagnostics[1].message.contains("DataProviderTable")
                && diagnostics[1].message.contains("OrderProviderQueue")
        );
    }

    #[test]
    fn missing_why_is_excused_only_by_low_confidence_trust() {
        let cases = [
            ("must:\n          - at least one subscriber", true),
            ("why: \"   \"", true),
            ("why: 42", true),
            ("trust:\n          src: infer\n          conf: low\n          note: rationale not documented", false),
            ("trust:\n          src: infer\n          conf: medium", true),
            ("trust:\n          src: authored\n          conf: high", true),
            ("why: buffers order events", false),
        ];
        for (body, expect_finding) in cases {
            let template = format!(
                "Resources:\n  Notifier:\n    Type: AWS::SNS::Topic\n    Metadata:\n      com.aws.cloudformation.Context:\n        {body}\n"
            );

            let diagnostics = check(&template);

            let findings = with_rule(&diagnostics, MISSING_WHY_RULE_ID);
            assert_eq!(findings.len(), usize::from(expect_finding), "context body {body:?}: {diagnostics:?}");
            if let Some(finding) = findings.first() {
                assert_eq!(finding.resource_logical_id(), Some("Notifier"));
                assert_eq!(finding.property_path.as_deref(), Some("Metadata.com.aws.cloudformation.Context"));
                assert_eq!(finding.location.map(|span| span.start_line), Some(5));
                assert!(finding.suggested_fix.is_some());
            }
        }
    }

    #[test]
    fn supplied_context_on_exempt_resources_is_still_validated() {
        let template = r#"
Resources:
  ServiceLogGroup:
    Type: AWS::Logs::LogGroup
    Metadata:
      com.aws.cloudformation.Context:
        must:
          - retain 30 days
  SharedBucket:
    Type: AWS::S3::Bucket::MODULE
    Properties: {}
    Metadata:
      com.aws.cloudformation.Context:
        why: wraps the shared bucket conventions
        must: not a list
"#;

        let diagnostics = check(template);

        assert_eq!(rule_ids(&diagnostics), [MISSING_WHY_RULE_ID, SCHEMA_VIOLATION_RULE_ID]);
        assert_eq!(diagnostics[0].resource_logical_id(), Some("ServiceLogGroup"));
        assert_eq!(diagnostics[1].resource_logical_id(), Some("SharedBucket"));
        assert_eq!(diagnostics[1].message, "'must' is a string; it must be an array of strings.");
    }

    #[test]
    fn schema_violations_are_reported_per_field_with_paths_and_spans() {
        let template = r#"
AWSTemplateFormatVersion: "2010-09-09"
Metadata:
  com.aws.cloudformation.Context:
    arch:
      - not-a-string
    why: "This field belongs on a resource"
    ref:
      - has: "Missing required at field"
      - 7
    gaps:
      - some gap
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Metadata:
      com.aws.cloudformation.Context:
        why: 42
        must: "not-an-array"
        mutable: "sometimes"
        mutability:
          QueueName: "never-ish"
        trust:
          conf: "certain"
          extra: true
        ref: []
        unknown: true
"#;

        let diagnostics = check(template);

        let findings: Vec<(Option<&str>, &str, &str, u32)> = with_rule(&diagnostics, SCHEMA_VIOLATION_RULE_ID)
            .into_iter()
            .map(|diagnostic| {
                (
                    diagnostic.resource_logical_id(),
                    diagnostic.property_path.as_deref().unwrap_or_default(),
                    diagnostic.message.as_str(),
                    diagnostic.location.map(|span| span.start_line).unwrap_or_default(),
                )
            })
            .collect();
        let expected: Vec<(Option<&str>, &str, &str, u32)> = vec![
            (
                Some("Queue"),
                "Metadata.com.aws.cloudformation.Context.why",
                "'why' is a number; it must be a string.",
                18,
            ),
            (
                Some("Queue"),
                "Metadata.com.aws.cloudformation.Context.must",
                "'must' is a string; it must be an array of strings.",
                19,
            ),
            (
                Some("Queue"),
                "Metadata.com.aws.cloudformation.Context.mutable",
                "'mutable' value 'sometimes' is not recognized; allowed values: must-never-change, change-with-constraints, review-required, free-to-tune.",
                20,
            ),
            (
                Some("Queue"),
                "Metadata.com.aws.cloudformation.Context.mutability.QueueName",
                "'mutability.QueueName' value 'never-ish' is not recognized; allowed values: must-never-change, change-with-constraints, review-required, free-to-tune.",
                22,
            ),
            (
                Some("Queue"),
                "Metadata.com.aws.cloudformation.Context.trust",
                "'trust' is missing required field 'src'; 'trust' must be an object with required 'src' and 'conf'.",
                23,
            ),
            (
                Some("Queue"),
                "Metadata.com.aws.cloudformation.Context.trust.conf",
                "'trust.conf' value 'certain' is not recognized; allowed values: high, medium, low.",
                24,
            ),
            (
                Some("Queue"),
                "Metadata.com.aws.cloudformation.Context.trust.extra",
                "'trust.extra' is not a recognized field of 'trust'; allowed fields: cite, conf, note, src.",
                25,
            ),
            (
                Some("Queue"),
                "Metadata.com.aws.cloudformation.Context.ref",
                "'ref' belongs at template level, not resource level. Template-level fields: arch, must, owner, ref; resource-level fields: deps, must, mutability, mutable, trust, why.",
                26,
            ),
            (
                Some("Queue"),
                "Metadata.com.aws.cloudformation.Context.unknown",
                "'unknown' is not a recognized resource-level Context field; allowed fields: deps, must, mutability, mutable, trust, why.",
                27,
            ),
            (None, "Metadata/com.aws.cloudformation.Context/arch", "'arch' is an array; it must be a string.", 5),
            (
                None,
                "Metadata/com.aws.cloudformation.Context/why",
                "'why' belongs at resource level, not template level. Template-level fields: arch, must, owner, ref; resource-level fields: deps, must, mutability, mutable, trust, why.",
                7,
            ),
            (
                None,
                "Metadata/com.aws.cloudformation.Context/ref/0",
                "'ref.0' is missing required field 'at'; 'ref' must be an array whose entries are each a string or an object with required 'at'.",
                9,
            ),
            (
                None,
                "Metadata/com.aws.cloudformation.Context/ref/1",
                "'ref.1' does not match any supported shape; 'ref' must be an array whose entries are each a string or an object with required 'at'.",
                10,
            ),
            (
                None,
                "Metadata/com.aws.cloudformation.Context/gaps",
                "'gaps' is not a recognized template-level Context field; allowed fields: arch, must, owner, ref.",
                11,
            ),
        ];
        assert_eq!(findings, expected);
        assert_eq!(with_rule(&diagnostics, MISSING_WHY_RULE_ID).len(), 1, "a numeric 'why' is no rationale");
        assert!(with_rule(&diagnostics, MISSING_CONTEXT_RULE_ID).is_empty());
    }

    #[test]
    fn non_mapping_context_blocks_are_reported_at_both_placements() {
        let template = r#"
Metadata:
  com.aws.cloudformation.Context: just a string
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Metadata:
      com.aws.cloudformation.Context:
        - a list
  Queue:
    Type: AWS::SQS::Queue
    Metadata:
      com.aws.cloudformation.Context:
"#;

        let diagnostics = check(template);

        assert!(with_rule(&diagnostics, MISSING_CONTEXT_RULE_ID).is_empty(), "a present block is not missing");
        assert!(with_rule(&diagnostics, MISSING_WHY_RULE_ID).is_empty(), "shape is reported once, by the schema rule");
        let messages: Vec<(Option<&str>, &str)> = with_rule(&diagnostics, SCHEMA_VIOLATION_RULE_ID)
            .into_iter()
            .map(|diagnostic| (diagnostic.resource_logical_id(), diagnostic.message.as_str()))
            .collect();
        assert_eq!(
            messages,
            [
                (
                    Some("Fn"),
                    "Metadata.com.aws.cloudformation.Context must be a mapping of Context fields; found an array."
                ),
                (
                    Some("Queue"),
                    "Metadata.com.aws.cloudformation.Context must be a mapping of Context fields; found null."
                ),
                (None, "Metadata.com.aws.cloudformation.Context must be a mapping of Context fields; found a string."),
            ]
        );
    }

    #[test]
    fn expected_shapes_are_derived_from_the_schema() {
        let template = r#"
Metadata:
  com.aws.cloudformation.Context:
    arch: ok
    ref: 5
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Metadata:
      com.aws.cloudformation.Context:
        why: ok
        trust: a string
        mutable:
          - must-never-change
        mutability: not-a-map
        must:
          - ok
          - 3
"#;

        let diagnostics = check(template);

        let messages: Vec<&str> =
            with_rule(&diagnostics, SCHEMA_VIOLATION_RULE_ID).into_iter().map(|d| d.message.as_str()).collect();
        assert_eq!(
            messages,
            [
                "'trust' is a string; it must be an object with required 'src' and 'conf'.",
                "'mutable' is an array; it must be one of: must-never-change, change-with-constraints, review-required, free-to-tune.",
                "'mutability' is a string; it must be a mapping of property name to one of: must-never-change, change-with-constraints, review-required, free-to-tune.",
                "'must.1' is a number; 'must' must be an array of strings.",
                "'ref' is a number; it must be an array whose entries are each a string or an object with required 'at'.",
            ]
        );
    }

    #[test]
    fn json_and_yaml_templates_yield_the_same_findings() {
        let yaml = r#"
Metadata:
  com.aws.cloudformation.Context:
    arch: ok
    why: misplaced
Resources:
  OrderQueue:
    Type: AWS::SQS::Queue
    Metadata:
      com.aws.cloudformation.Context:
        must: not a list
  OrdersTable:
    Type: AWS::DynamoDB::Table
"#;
        let json = r#"{
  "Metadata": {"com.aws.cloudformation.Context": {"arch": "ok", "why": "misplaced"}},
  "Resources": {
    "OrderQueue": {"Type": "AWS::SQS::Queue", "Metadata": {"com.aws.cloudformation.Context": {"must": "not a list"}}},
    "OrdersTable": {"Type": "AWS::DynamoDB::Table"}
  }
}"#;
        let summarize = |diagnostics: Vec<Diagnostic>| -> Vec<(String, Option<String>, Option<String>, String)> {
            diagnostics
                .into_iter()
                .map(|diagnostic| {
                    (
                        diagnostic.rule_id.clone(),
                        diagnostic.resource_logical_id().map(str::to_string),
                        diagnostic.property_path.clone(),
                        diagnostic.message.clone(),
                    )
                })
                .collect()
        };

        let from_yaml = check(yaml);
        let from_json = check(json);

        assert!(from_yaml.iter().chain(&from_json).all(|diagnostic| diagnostic.location.is_some()));
        assert_eq!(
            rule_ids(&from_yaml),
            [MISSING_CONTEXT_RULE_ID, MISSING_WHY_RULE_ID, SCHEMA_VIOLATION_RULE_ID, SCHEMA_VIOLATION_RULE_ID]
        );
        assert_eq!(summarize(from_yaml), summarize(from_json));
    }
}
