use diagnostics::{DetailLevel, Summary, ValidationReport, output};
use rules::Severity;
use schema_validator::{PropertyValueType, ResourceSchemaMetadata, SchemaValidator};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

use crate::{ValidateConfig, ValidationEngine, ValidationError, validate_bytes_with_path};

/// A recursively typed value from an AWS CLI command.
///
/// Unlike JSON, this model preserves byte strings such as CloudFormation's
/// `TemplateBody`. `Unsupported` lets language bindings carry an explicit marker
/// for a runtime value they cannot represent rather than coercing it silently.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AwsCliValue {
    Null,
    Boolean { value: bool },
    Integer { value: i64 },
    UnsignedInteger { value: u64 },
    Number { value: f64 },
    String { value: String },
    Bytes { value: Vec<u8> },
    Array { items: Vec<AwsCliValue> },
    Object { entries: HashMap<String, AwsCliValue> },
    Unsupported { type_name: String },
}

impl AwsCliValue {
    /// Converts a JSON value without losing integer width.
    pub fn from_json(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(value) => Self::Boolean { value },
            serde_json::Value::Number(value) => {
                if let Some(value) = value.as_i64() {
                    Self::Integer { value }
                } else if let Some(value) = value.as_u64() {
                    Self::UnsignedInteger { value }
                } else if let Some(value) = value.as_f64() {
                    Self::Number { value }
                } else {
                    Self::Unsupported { type_name: "JSON number".into() }
                }
            }
            serde_json::Value::String(value) => Self::String { value },
            serde_json::Value::Array(items) => Self::Array { items: items.into_iter().map(Self::from_json).collect() },
            serde_json::Value::Object(entries) => Self::Object {
                entries: entries.into_iter().map(|(key, value)| (key, Self::from_json(value))).collect(),
            },
        }
    }

    /// Converts to JSON when this value and all of its children are JSON-safe.
    pub fn to_json(&self) -> Result<serde_json::Value, String> {
        self.json_value().ok_or_else(|| match self {
            Self::Bytes { .. } => "byte strings are not JSON values".to_string(),
            Self::Number { .. } => "non-finite numbers are not JSON values".to_string(),
            Self::Unsupported { type_name } => format!("{type_name} is not a supported request value"),
            _ => "a nested request value is not JSON-compatible".to_string(),
        })
    }

    fn json_value(&self) -> Option<serde_json::Value> {
        match self {
            Self::Null => Some(serde_json::Value::Null),
            Self::Boolean { value } => Some(serde_json::Value::Bool(*value)),
            Self::Integer { value } => Some(serde_json::json!(value)),
            Self::UnsignedInteger { value } => Some(serde_json::json!(value)),
            Self::Number { value } => serde_json::Number::from_f64(*value).map(serde_json::Value::Number),
            Self::String { value } => Some(serde_json::Value::String(value.clone())),
            Self::Bytes { .. } | Self::Unsupported { .. } => None,
            Self::Array { items } => {
                items.iter().map(Self::json_value).collect::<Option<Vec<_>>>().map(serde_json::Value::Array)
            }
            Self::Object { entries } => entries
                .iter()
                .map(|(key, value)| value.json_value().map(|value| (key.clone(), value)))
                .collect::<Option<serde_json::Map<_, _>>>()
                .map(serde_json::Value::Object),
        }
    }
}

impl From<serde_json::Value> for AwsCliValue {
    fn from(value: serde_json::Value) -> Self {
        Self::from_json(value)
    }
}

/// AWS service, operation, and input values needed to model one AWS CLI command
/// as CloudFormation resource state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct AwsCliCommandContext {
    pub service_name: String,
    pub operation_name: String,
    pub parameters: HashMap<String, AwsCliValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub service_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub http_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub is_read_only: Option<bool>,
}

/// Idiomatic Rust name for the AWS CLI command record. The `Context`-suffixed
/// struct is the name UniFFI exports to the language bindings, which keeps the
/// generated native record distinct from each binding's friendly `AwsCliCommand`
/// wrapper so wildcard imports never collide.
pub type AwsCliCommand = AwsCliCommandContext;

impl AwsCliCommandContext {
    pub fn new(
        service_name: impl Into<String>,
        operation_name: impl Into<String>,
        parameters: impl IntoIterator<Item = (String, AwsCliValue)>,
    ) -> Self {
        Self {
            service_name: service_name.into(),
            operation_name: operation_name.into(),
            parameters: parameters.into_iter().collect(),
            service_prefix: None,
            http_method: None,
            is_read_only: None,
        }
    }

    pub fn with_service_prefix(mut self, service_prefix: impl Into<String>) -> Self {
        self.service_prefix = Some(service_prefix.into());
        self
    }

    pub fn with_http_method(mut self, http_method: impl Into<String>) -> Self {
        self.http_method = Some(http_method.into());
        self
    }

    pub fn with_read_only(mut self, is_read_only: bool) -> Self {
        self.is_read_only = Some(is_read_only);
        self
    }

    fn default_file_path(&self) -> String {
        format!("aws-cli://{}/{}", self.service_name, self.operation_name)
    }
}

/// Closed classification of an AWS API operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AwsCliOperationKind {
    ReadOnly,
    CloudFormationCreate,
    CloudFormationUpdate,
    CloudFormationDelete,
    DataPlaneMutation,
    UnmappedMutation,
}

/// Whether a request reached template validation or was conservatively skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AwsCliCommandValidationStatus {
    Validated,
    Skipped,
}

/// Provenance of the template validated for an AWS CLI command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AwsCliTemplateSource {
    TemplateBody,
    CloudControlDesiredState,
    SynthesizedCreate,
    SynthesizedUpdate,
}

/// Canonical result for AWS CLI command validation.
///
/// The report is projected at the `STANDARD` detail level — detailed enrichment
/// is not meaningful for synthesized command templates because there is no
/// user-authored source to annotate with context.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
#[must_use]
pub struct AwsCliCommandValidation {
    pub operation_kind: AwsCliOperationKind,
    pub status: AwsCliCommandValidationStatus,
    pub template_source: Option<AwsCliTemplateSource>,
    pub resource_types: Vec<String>,
    pub reason: String,
    pub report: Option<output::ValidationReport>,
    /// The exact template bytes that were validated, or `None` when the request
    /// was skipped. For `TemplateBody` requests, this is the caller's original
    /// bytes without reserializing. For synthesized requests, this is the
    /// generated JSON template. Consumers can display this to show the modeled
    /// template that produced the diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default))]
    pub template: Option<Vec<u8>>,
}

/// Classifies, models, and validates one AWS CLI command entirely offline.
pub fn validate_aws_cli_command(
    engine: &dyn ValidationEngine,
    schema_validator: &SchemaValidator,
    request: &AwsCliCommand,
    config: ValidateConfig,
) -> Result<AwsCliCommandValidation, ValidationError> {
    validate_aws_cli_command_with_path(engine, schema_validator, request, config, request.default_file_path())
}

/// Same as [`validate_aws_cli_command`], with an explicit report path supplied
/// by the embedding application.
pub fn validate_aws_cli_command_with_path(
    engine: &dyn ValidationEngine,
    schema_validator: &SchemaValidator,
    request: &AwsCliCommand,
    config: ValidateConfig,
    file_path: String,
) -> Result<AwsCliCommandValidation, ValidationError> {
    let classification = classify_operation(request, schema_validator)?;
    let synthesis = synthesize_request(request, &classification, schema_validator)?;
    let Some(template) = synthesis.template else {
        return Ok(AwsCliCommandValidation {
            operation_kind: classification.kind,
            status: AwsCliCommandValidationStatus::Skipped,
            template_source: None,
            resource_types: synthesis.resource_types,
            reason: synthesis.reason,
            report: None,
            template: None,
        });
    };

    // Force standard detail level — detailed enrichment is not meaningful for
    // synthesized command templates (no user-authored source to annotate).
    let standard_config = ValidateConfig { detail_level: DetailLevel::Standard, ..config };
    let mut report = validate_bytes_with_path(engine, schema_validator, &template, standard_config, file_path)?;
    if synthesis.source != Some(AwsCliTemplateSource::TemplateBody) {
        suppress_template_authoring_advice(&mut report);
    }
    if let Some(properties) = synthesis.diagnostic_properties.as_ref() {
        scope_synthesized_report(&mut report, properties);
    }
    Ok(AwsCliCommandValidation {
        operation_kind: classification.kind,
        status: AwsCliCommandValidationStatus::Validated,
        template_source: synthesis.source,
        resource_types: synthesis.resource_types,
        reason: synthesis.reason,
        report: Some(report.to_report(DetailLevel::Standard)),
        template: Some(template),
    })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum AdapterPhase {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct PropertyMapping {
    source: String,
    target: String,
    /// API-valid input values the CloudFormation schema cannot represent.
    #[serde(default)]
    unrepresentable: Option<UnrepresentableDomain>,
}

/// The part of an API input's value domain that the mapped CloudFormation
/// property rejects. A request value inside this domain is legal for the
/// service, so reporting the CloudFormation constraint against it would be a
/// false finding; synthesis is skipped instead. Each bound is the CloudFormation
/// constraint that the API range exceeds.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(default)]
struct UnrepresentableDomain {
    rejected_values: Vec<serde_json::Value>,
    minimum: Option<f64>,
    maximum: Option<f64>,
    min_length: Option<u64>,
    max_length: Option<u64>,
    items: Option<Box<UnrepresentableDomain>>,
    tag_key: Option<Box<UnrepresentableDomain>>,
    tag_value: Option<Box<UnrepresentableDomain>>,
}

impl UnrepresentableDomain {
    /// Describes why `value` has no CloudFormation representation, or `None`
    /// when every part of it is representable.
    fn rejection(&self, value: &AwsCliValue) -> Option<String> {
        if let Some(json_value) = value.json_value()
            && self.rejected_values.contains(&json_value)
        {
            return Some(format!("value {json_value} is valid for the API but not for CloudFormation"));
        }
        match value {
            AwsCliValue::String { value } => self.length_rejection(value.chars().count() as u64, "length"),
            AwsCliValue::Integer { value } => self.numeric_rejection(*value as f64),
            AwsCliValue::UnsignedInteger { value } => self.numeric_rejection(*value as f64),
            AwsCliValue::Number { value } => self.numeric_rejection(*value),
            AwsCliValue::Array { items } => self.length_rejection(items.len() as u64, "item count").or_else(|| {
                self.items.as_ref().and_then(|domain| items.iter().find_map(|item| domain.rejection(item)))
            }),
            AwsCliValue::Object { entries } => entries.iter().find_map(|(key, entry)| {
                let key_rejection = self
                    .tag_key
                    .as_ref()
                    .and_then(|domain| domain.rejection(&AwsCliValue::String { value: key.clone() }));
                key_rejection.or_else(|| self.tag_value.as_ref().and_then(|domain| domain.rejection(entry)))
            }),
            AwsCliValue::Null
            | AwsCliValue::Boolean { .. }
            | AwsCliValue::Bytes { .. }
            | AwsCliValue::Unsupported { .. } => None,
        }
    }

    fn numeric_rejection(&self, value: f64) -> Option<String> {
        if let Some(minimum) = self.minimum
            && value < minimum
        {
            return Some(format!("value {value} is valid for the API but below the CloudFormation minimum {minimum}"));
        }
        if let Some(maximum) = self.maximum
            && value > maximum
        {
            return Some(format!("value {value} is valid for the API but above the CloudFormation maximum {maximum}"));
        }
        None
    }

    fn length_rejection(&self, length: u64, measure: &str) -> Option<String> {
        if let Some(min_length) = self.min_length
            && length < min_length
        {
            return Some(format!(
                "{measure} {length} is valid for the API but below the CloudFormation minimum {min_length}"
            ));
        }
        if let Some(max_length) = self.max_length
            && length > max_length
        {
            return Some(format!(
                "{measure} {length} is valid for the API but above the CloudFormation maximum {max_length}"
            ));
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct OperationAdapter {
    service: String,
    operation: String,
    phase: AdapterPhase,
    cfn_type: String,
    mappings: Vec<PropertyMapping>,
    /// Request-control fields safe to ignore during all-or-nothing synthesis.
    #[serde(default)]
    ignored_inputs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OperationCatalog {
    format_version: u32,
    adapters: Vec<OperationAdapter>,
}

// These entries exposed dependent or ambiguous provider permissions in an
// older generated artifact. Filtering them here keeps shipped catalogs
// conservative while the maintenance pipeline catches up.
/// Generated by `data-source/scripts/generate_aws_cli_catalog.py`: each entry is
/// derived from the resource type's own provider handler metadata, resolved
/// against botocore service models, and structurally verified against the
/// compiled CloudFormation schemas. Each mapping also records the API value
/// domain the schema cannot represent, so a value that is valid for the service
/// but not for CloudFormation skips synthesis instead of producing a finding.
/// Only exact service+operation keys resolve; unregistered operations stay
/// unmapped.
static ADAPTER_REGISTRY: LazyLock<Result<HashMap<(String, String), OperationAdapter>, String>> =
    LazyLock::new(|| parse_adapter_registry(&data_source::embedded::AWS_CLI_OPERATION_CATALOG_BYTES));

fn parse_adapter_registry(bytes: &[u8]) -> Result<HashMap<(String, String), OperationAdapter>, String> {
    let catalog: OperationCatalog = serde_json::from_slice(bytes)
        .map_err(|error| format!("embedded AWS CLI operation catalog is invalid: {error}"))?;
    if catalog.format_version != 1 {
        return Err(format!("unsupported AWS CLI operation catalog format {}", catalog.format_version));
    }
    let mut registry = HashMap::new();
    for adapter in catalog.adapters {
        if adapter.service.trim().is_empty()
            || adapter.operation.trim().is_empty()
            || adapter.cfn_type.trim().is_empty()
        {
            return Err("AWS CLI operation catalog identities must not be blank".into());
        }
        let key = (normalize_service(&adapter.service), adapter.operation.clone());
        if let Some(previous) = registry.insert(key, adapter) {
            return Err(format!("duplicate AWS CLI operation catalog key {}:{}", previous.service, previous.operation));
        }
    }
    Ok(registry)
}

fn adapter_registry() -> Result<&'static HashMap<(String, String), OperationAdapter>, ValidationError> {
    ADAPTER_REGISTRY.as_ref().map_err(|message| ValidationError::Engine(message.clone()))
}

/// CloudFormation operations that accept TemplateBody per botocore service
/// definitions. Only these exact service+operation pairs treat a TemplateBody
/// parameter as a CloudFormation template.
const TEMPLATE_BODY_OPERATIONS: &[(&str, &str)] = &[
    ("cloudformation", "CreateChangeSet"),
    ("cloudformation", "CreateStack"),
    ("cloudformation", "CreateStackSet"),
    ("cloudformation", "EstimateTemplateCost"),
    ("cloudformation", "GetTemplateSummary"),
    ("cloudformation", "UpdateStack"),
    ("cloudformation", "UpdateStackSet"),
    ("cloudformation", "ValidateTemplate"),
];

/// Callers pass canonical botocore service names, so case-normalization is the only lookup adjustment.
fn normalize_service(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn lookup_adapter(service: &str, operation: &str) -> Result<Option<&'static OperationAdapter>, ValidationError> {
    let key = (normalize_service(service), operation.to_string());
    Ok(adapter_registry()?.get(&key))
}

fn is_template_body_operation(service: &str, operation: &str) -> bool {
    let normalized = normalize_service(service);
    TEMPLATE_BODY_OPERATIONS.iter().any(|(s, o)| normalize_service(s) == normalized && *o == operation)
}

fn template_body_operation_kind(service: &str, operation: &str) -> Option<AwsCliOperationKind> {
    if normalize_service(service) != "cloudformation" {
        return None;
    }
    match operation {
        "CreateChangeSet" | "CreateStack" | "CreateStackSet" => Some(AwsCliOperationKind::CloudFormationCreate),
        "UpdateStack" | "UpdateStackSet" => Some(AwsCliOperationKind::CloudFormationUpdate),
        "EstimateTemplateCost" | "GetTemplateSummary" | "ValidateTemplate" => Some(AwsCliOperationKind::ReadOnly),
        _ => None,
    }
}

fn is_cloud_control_service(service: &str) -> bool {
    normalize_service(service) == "cloudcontrol"
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationPhase {
    Read,
    Create,
    Update,
    Delete,
    Data,
    Unknown,
}

#[derive(Debug, Clone)]
struct Classification {
    kind: AwsCliOperationKind,
    candidates: Vec<String>,
}

const READ_VERBS: &[&str] = &[
    "Calculate",
    "Check",
    "Compare",
    "Contains",
    "Count",
    "Decode",
    "Describe",
    "Discover",
    "Estimate",
    "Filter",
    "Find",
    "Forecast",
    "Get",
    "Head",
    "Is",
    "List",
    "Lookup",
    "Preview",
    "Query",
    "Read",
    "Resolve",
    "Retrieve",
    "Sample",
    "Scan",
    "Search",
    "Select",
    "Simulate",
    "Validate",
    "Verify",
    "View",
];
const DATA_PLANE_VERBS: &[&str] = &[
    "Analyze",
    "Chat",
    "Complete",
    "Convert",
    "Converse",
    "Decrypt",
    "Deliver",
    "Encrypt",
    "Execute",
    "Generate",
    "Infer",
    "Invoke",
    "Meter",
    "Notify",
    "Post",
    "Predict",
    "Publish",
    "Receive",
    "Recognize",
    "Render",
    "Respond",
    "Send",
    "Signal",
    "Sign",
    "Stream",
    "Synthesize",
    "Test",
    "Translate",
    "Upload",
    "Write",
];

const MODIFIER_PREFIXES: &[&str] = &["Admin", "Batch", "Bulk", "Transact"];

fn classify_operation(
    request: &AwsCliCommand,
    schema_validator: &SchemaValidator,
) -> Result<Classification, ValidationError> {
    if let Some(kind) = template_body_operation_kind(&request.service_name, &request.operation_name) {
        return Ok(Classification { kind, candidates: Vec::new() });
    }

    // The modeled read-only trait is authoritative even over a registered adapter.
    if request.is_read_only == Some(true) {
        return Ok(Classification { kind: AwsCliOperationKind::ReadOnly, candidates: Vec::new() });
    }

    if let Some(adapter) = lookup_adapter(&request.service_name, &request.operation_name)? {
        let kind = match adapter.phase {
            AdapterPhase::Create => AwsCliOperationKind::CloudFormationCreate,
            AdapterPhase::Update => AwsCliOperationKind::CloudFormationUpdate,
            AdapterPhase::Delete => AwsCliOperationKind::CloudFormationDelete,
        };
        return Ok(Classification { kind, candidates: vec![adapter.cfn_type.clone()] });
    }

    let words = operation_words(&request.operation_name);
    let verb = effective_verb(&words);
    let phase = operation_phase(request, verb);

    if phase == OperationPhase::Read {
        return Ok(Classification { kind: AwsCliOperationKind::ReadOnly, candidates: Vec::new() });
    }
    if phase == OperationPhase::Data {
        return Ok(Classification { kind: AwsCliOperationKind::DataPlaneMutation, candidates: Vec::new() });
    }

    if is_cloud_control_service(&request.service_name) {
        let is_resource_op =
            matches!(request.operation_name.as_str(), "CreateResource" | "UpdateResource" | "DeleteResource");
        if is_resource_op && let Some(type_name) = explicit_valid_type_name(request, schema_validator) {
            let kind = match request.operation_name.as_str() {
                "CreateResource" => AwsCliOperationKind::CloudFormationCreate,
                "DeleteResource" => AwsCliOperationKind::CloudFormationDelete,
                _ => AwsCliOperationKind::UnmappedMutation,
            };
            return Ok(Classification { kind, candidates: vec![type_name] });
        }
    }

    // Unknown mutation: classify by verb family but never assign resource types.
    let kind = if DATA_PLANE_IF_UNMAPPED_VERBS.contains(&verb) {
        AwsCliOperationKind::DataPlaneMutation
    } else {
        AwsCliOperationKind::UnmappedMutation
    };
    Ok(Classification { kind, candidates: Vec::new() })
}

const DATA_PLANE_IF_UNMAPPED_VERBS: &[&str] =
    &["Execute", "Invoke", "Post", "Publish", "Put", "Send", "Upload", "Write"];

fn operation_phase(request: &AwsCliCommand, verb: &str) -> OperationPhase {
    if request.is_read_only == Some(true) || READ_VERBS.contains(&verb) {
        return OperationPhase::Read;
    }
    if DATA_PLANE_VERBS.contains(&verb) {
        return OperationPhase::Data;
    }
    if CREATE_VERBS.contains(&verb) {
        return OperationPhase::Create;
    }
    if UPDATE_VERBS.contains(&verb) {
        return OperationPhase::Update;
    }
    if DELETE_VERBS.contains(&verb) {
        return OperationPhase::Delete;
    }
    match request.http_method.as_deref().map(str::to_ascii_uppercase).as_deref() {
        Some("GET" | "HEAD") => return OperationPhase::Read,
        Some("DELETE") => return OperationPhase::Delete,
        _ => {}
    }
    OperationPhase::Unknown
}

const CREATE_VERBS: &[&str] = &[
    "Add",
    "Allocate",
    "Build",
    "Clone",
    "Copy",
    "Create",
    "Define",
    "Deploy",
    "Import",
    "Index",
    "Initialize",
    "Install",
    "Instantiate",
    "Invite",
    "Issue",
    "Join",
    "Launch",
    "Provision",
    "Purchase",
    "Register",
    "Request",
    "Restore",
    "Run",
    "Schedule",
    "Start",
    "Submit",
];
const UPDATE_VERBS: &[&str] = &[
    "Accept",
    "Activate",
    "Apply",
    "Approve",
    "Assign",
    "Associate",
    "Attach",
    "Authorize",
    "Change",
    "Configure",
    "Connect",
    "Deactivate",
    "Decrease",
    "Disable",
    "Disassociate",
    "Dissociate",
    "Detach",
    "Enable",
    "Grant",
    "Increase",
    "Link",
    "Lock",
    "Merge",
    "Modify",
    "Move",
    "Promote",
    "Put",
    "Reboot",
    "Refresh",
    "Replace",
    "Reset",
    "Resize",
    "Restart",
    "Resume",
    "Rotate",
    "Set",
    "Share",
    "Subscribe",
    "Suspend",
    "Swap",
    "Tag",
    "Transfer",
    "Unassign",
    "Unlock",
    "Unshare",
    "Unsubscribe",
    "Untag",
    "Update",
    "Upgrade",
];
const DELETE_VERBS: &[&str] = &[
    "Abort",
    "Block",
    "Cancel",
    "Close",
    "Decline",
    "Delete",
    "Deny",
    "Deprovision",
    "Deregister",
    "Destroy",
    "Discard",
    "Dispose",
    "Expire",
    "Forget",
    "Leave",
    "Purge",
    "Reject",
    "Release",
    "Remove",
    "Retire",
    "Revoke",
    "Shutdown",
    "Stop",
    "Terminate",
    "Unregister",
];

fn operation_words(operation_name: &str) -> Vec<String> {
    let characters: Vec<char> = operation_name.chars().collect();
    if characters.is_empty() {
        return Vec::new();
    }
    let mut words = Vec::new();
    let mut start = 0;
    for index in 1..characters.len() {
        let previous = characters[index - 1];
        let current = characters[index];
        let next = characters.get(index + 1).copied();
        let boundary = (current.is_ascii_digit() && !previous.is_ascii_digit())
            || (!current.is_ascii_digit() && previous.is_ascii_digit())
            || (current.is_ascii_uppercase() && previous.is_ascii_lowercase())
            || (current.is_ascii_uppercase()
                && previous.is_ascii_uppercase()
                && next.is_some_and(|next| next.is_ascii_lowercase()));
        if boundary {
            words.push(characters[start..index].iter().collect());
            start = index;
        }
    }
    words.push(characters[start..].iter().collect());
    words
}

fn effective_verb(words: &[String]) -> &str {
    if words.len() > 1 && MODIFIER_PREFIXES.contains(&words[0].as_str()) {
        &words[1]
    } else {
        words.first().map(String::as_str).unwrap_or("")
    }
}

fn explicit_valid_type_name(request: &AwsCliCommand, schema_validator: &SchemaValidator) -> Option<String> {
    match request.parameters.get("TypeName") {
        Some(AwsCliValue::String { value }) if schema_validator.has_resource_type(value) => Some(value.clone()),
        _ => None,
    }
}
struct Synthesis {
    template: Option<Vec<u8>>,
    source: Option<AwsCliTemplateSource>,
    reason: String,
    resource_types: Vec<String>,
    diagnostic_properties: Option<BTreeSet<String>>,
}

impl Synthesis {
    fn skipped(reason: impl Into<String>, resource_types: Vec<String>) -> Self {
        Self { template: None, source: None, reason: reason.into(), resource_types, diagnostic_properties: None }
    }
}

fn synthesize_request(
    request: &AwsCliCommand,
    classification: &Classification,
    schema_validator: &SchemaValidator,
) -> Result<Synthesis, ValidationError> {
    let is_cfn_op = is_template_body_operation(&request.service_name, &request.operation_name);

    if is_cfn_op {
        if let Some(template) = template_body_bytes(request.parameters.get("TemplateBody")) {
            return Ok(Synthesis {
                template: Some(template),
                source: Some(AwsCliTemplateSource::TemplateBody),
                reason: "using exact request TemplateBody".into(),
                resource_types: Vec::new(),
                diagnostic_properties: None,
            });
        }
        if request.parameters.contains_key("TemplateURL") {
            return Ok(Synthesis::skipped("TemplateURL content is unavailable to the offline validator", Vec::new()));
        }
    }

    if classification.kind == AwsCliOperationKind::ReadOnly {
        return Ok(Synthesis::skipped("read-only calls do not need validation", Vec::new()));
    }

    let is_cloud_control = is_cloud_control_service(&request.service_name);
    if is_cloud_control
        && request.operation_name == "CreateResource"
        && request.parameters.contains_key("TypeName")
        && request.parameters.contains_key("DesiredState")
    {
        return desired_state_template(request, schema_validator);
    }

    if is_cloud_control && request.operation_name == "UpdateResource" {
        let type_names = explicit_valid_type_name(request, schema_validator).map(|t| vec![t]).unwrap_or_default();
        return Ok(Synthesis::skipped(
            "Cloud Control UpdateResource uses PatchDocument and cannot be synthesized",
            type_names,
        ));
    }

    adapter_template(request, classification, schema_validator)
}

fn template_body_bytes(value: Option<&AwsCliValue>) -> Option<Vec<u8>> {
    match value {
        Some(AwsCliValue::Bytes { value }) if !value.is_empty() => Some(value.clone()),
        Some(AwsCliValue::String { value }) if !value.is_empty() => Some(value.as_bytes().to_vec()),
        _ => None,
    }
}

fn desired_state_template(
    request: &AwsCliCommand,
    schema_validator: &SchemaValidator,
) -> Result<Synthesis, ValidationError> {
    let Some(AwsCliValue::String { value: type_name }) = request.parameters.get("TypeName") else {
        return Ok(Synthesis::skipped("DesiredState has no known CloudFormation TypeName", Vec::new()));
    };
    if !schema_validator.has_resource_type(type_name) {
        return Ok(Synthesis::skipped("DesiredState has no known CloudFormation TypeName", Vec::new()));
    }
    let Some(desired_state) = request.parameters.get("DesiredState") else {
        return Ok(Synthesis::skipped("DesiredState is missing", vec![type_name.clone()]));
    };
    let properties = match desired_state {
        AwsCliValue::String { value } if !value.is_empty() => serde_json::from_str(value),
        AwsCliValue::Bytes { value } if !value.is_empty() => serde_json::from_slice(value),
        _ => return Ok(Synthesis::skipped("DesiredState is missing", vec![type_name.clone()])),
    };
    let properties: serde_json::Value = match properties {
        Ok(properties) => properties,
        Err(_) => return Ok(Synthesis::skipped("DesiredState is not valid JSON", vec![type_name.clone()])),
    };
    let Some(properties) = properties.as_object() else {
        return Ok(Synthesis::skipped("DesiredState is not a JSON object", vec![type_name.clone()]));
    };
    Ok(Synthesis {
        template: Some(resource_template(type_name, properties)?),
        source: Some(AwsCliTemplateSource::CloudControlDesiredState),
        reason: "wrapped exact Cloud Control desired state".into(),
        resource_types: vec![type_name.clone()],
        diagnostic_properties: None,
    })
}

fn adapter_template(
    request: &AwsCliCommand,
    classification: &Classification,
    schema_validator: &SchemaValidator,
) -> Result<Synthesis, ValidationError> {
    if !matches!(
        classification.kind,
        AwsCliOperationKind::CloudFormationCreate | AwsCliOperationKind::CloudFormationUpdate
    ) {
        return Ok(Synthesis::skipped(
            "classification has no representable resource state",
            classification.candidates.clone(),
        ));
    }
    if classification.candidates.len() != 1 {
        return Ok(Synthesis::skipped(
            "no adapter maps this operation to a CloudFormation resource",
            classification.candidates.clone(),
        ));
    }

    let type_name = &classification.candidates[0];
    let Some(schema) = schema_validator.resource_schema_metadata(type_name) else {
        return Ok(Synthesis::skipped("CloudFormation resource type is unknown", vec![type_name.clone()]));
    };

    let adapter = lookup_adapter(&request.service_name, &request.operation_name)?;
    let Some(adapter) = adapter else {
        return Ok(Synthesis::skipped(
            "no adapter maps this operation to a CloudFormation resource",
            vec![type_name.clone()],
        ));
    };

    let properties = match map_adapter_properties(&request.parameters, &schema, adapter)? {
        AdapterMappingResult::Mapped(properties) => properties,
        AdapterMappingResult::Skip(reason) => {
            return Ok(Synthesis::skipped(reason, vec![type_name.clone()]));
        }
    };

    if properties.is_empty() {
        return Ok(Synthesis::skipped("no request parameters map to resource properties", vec![type_name.clone()]));
    }

    let diagnostic_properties = Some(properties.keys().cloned().collect::<BTreeSet<_>>());
    let source = if adapter.phase == AdapterPhase::Update {
        AwsCliTemplateSource::SynthesizedUpdate
    } else {
        AwsCliTemplateSource::SynthesizedCreate
    };
    let reason = if adapter.phase == AdapterPhase::Update {
        "synthesized explicitly updated CloudFormation properties"
    } else {
        "synthesized one unambiguous CloudFormation resource"
    };
    let template_properties: serde_json::Map<String, serde_json::Value> = properties.into_iter().collect();
    Ok(Synthesis {
        template: Some(resource_template(type_name, &template_properties)?),
        source: Some(source),
        reason: reason.into(),
        resource_types: vec![type_name.clone()],
        diagnostic_properties,
    })
}

#[derive(Debug)]
enum AdapterMappingResult {
    Mapped(BTreeMap<String, serde_json::Value>),
    Skip(String),
}

fn map_adapter_properties(
    parameters: &HashMap<String, AwsCliValue>,
    schema: &ResourceSchemaMetadata,
    adapter: &OperationAdapter,
) -> Result<AdapterMappingResult, ValidationError> {
    let mut excluded = schema.read_only_properties.clone();
    if adapter.phase == AdapterPhase::Update {
        excluded.extend(schema.primary_identifier_properties.iter().cloned());
    }

    let mut sources = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut mapped_sources: BTreeSet<&str> = BTreeSet::new();
    let mut mapped = BTreeMap::new();
    for mapping in &adapter.mappings {
        if !sources.insert(mapping.source.as_str()) {
            return Err(ValidationError::Engine(format!(
                "adapter {}:{} has duplicate source parameter '{}'",
                adapter.service, adapter.operation, mapping.source
            )));
        }
        if !targets.insert(mapping.target.as_str()) {
            return Err(ValidationError::Engine(format!(
                "adapter {}:{} has duplicate target property '{}'",
                adapter.service, adapter.operation, mapping.target
            )));
        }
        let Some(accepted_types) = schema.property_types.get(&mapping.target) else {
            return Err(ValidationError::Engine(format!(
                "adapter {}:{} targets property '{}' which does not exist on {}",
                adapter.service, adapter.operation, mapping.target, adapter.cfn_type
            )));
        };
        if excluded.contains(&mapping.target) {
            return Err(ValidationError::Engine(format!(
                "adapter {}:{} targets excluded property '{}' on {}",
                adapter.service, adapter.operation, mapping.target, adapter.cfn_type
            )));
        }
        let Some(value) = parameters.get(&mapping.source) else {
            continue;
        };
        mapped_sources.insert(&mapping.source);
        if let Some(domain) = mapping.unrepresentable.as_ref()
            && let Some(rejection) = domain.rejection(value)
        {
            return Ok(AdapterMappingResult::Skip(format!(
                "parameter '{}' {rejection}, so it has no representation as property '{}' on {}",
                mapping.source, mapping.target, adapter.cfn_type
            )));
        }
        match mapped_value(value, accepted_types, &mapping.target) {
            Some(json_value) => {
                mapped.insert(mapping.target.clone(), json_value);
            }
            None => {
                return Ok(AdapterMappingResult::Skip(format!(
                    "parameter '{}' cannot be represented as property '{}' on {}",
                    mapping.source, mapping.target, adapter.cfn_type
                )));
            }
        }
    }

    // Build the set of parameters that are safe to ignore: explicitly declared
    // ignored_inputs, plus primary identifier properties for update adapters.
    let mut ignored: BTreeSet<&str> = adapter.ignored_inputs.iter().map(String::as_str).collect();
    if adapter.phase == AdapterPhase::Update {
        ignored.extend(schema.primary_identifier_properties.iter().map(String::as_str));
    }

    // All-or-nothing: every supplied parameter must either be mapped or
    // in the ignored set.
    for param_name in parameters.keys() {
        if mapped_sources.contains(param_name.as_str()) {
            continue;
        }
        if ignored.contains(param_name.as_str()) {
            continue;
        }
        return Ok(AdapterMappingResult::Skip(format!(
            "parameter '{}' has no mapping to a property on {}",
            param_name, adapter.cfn_type
        )));
    }
    Ok(AdapterMappingResult::Mapped(mapped))
}

fn resource_template(
    type_name: &str,
    properties: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<u8>, ValidationError> {
    serde_json::to_vec(&serde_json::json!({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Resource": {
                "Type": type_name,
                "Properties": properties,
            }
        }
    }))
    .map_err(|error| ValidationError::Engine(format!("failed to serialize synthesized template: {error}")))
}

fn mapped_value(
    value: &AwsCliValue,
    accepted_types: &BTreeSet<PropertyValueType>,
    property_name: &str,
) -> Option<serde_json::Value> {
    // Many AWS APIs use string maps for tags, while CloudFormation uses
    // Key/Value object arrays for the same resource state.
    if property_name == "Tags"
        && accepts_type(accepted_types, PropertyValueType::Array)
        && let AwsCliValue::Object { entries } = value
        && entries.values().all(|value| matches!(value, AwsCliValue::String { .. }))
    {
        let mut tags: Vec<(&String, &AwsCliValue)> = entries.iter().collect();
        tags.sort_by_key(|(key, _)| key.as_str());
        return Some(serde_json::Value::Array(
            tags.into_iter()
                .filter_map(|(key, value)| match value {
                    AwsCliValue::String { value } => Some(serde_json::json!({"Key": key, "Value": value})),
                    _ => None,
                })
                .collect(),
        ));
    }
    if value_matches_types(value, accepted_types) {
        return value.json_value();
    }
    None
}

fn accepts_type(types: &BTreeSet<PropertyValueType>, expected: PropertyValueType) -> bool {
    types.contains(&PropertyValueType::Any) || types.contains(&expected)
}

fn value_matches_types(value: &AwsCliValue, types: &BTreeSet<PropertyValueType>) -> bool {
    let accepts_any = types.contains(&PropertyValueType::Any);
    match value {
        AwsCliValue::Array { items } => {
            (accepts_any || types.contains(&PropertyValueType::Array)) && items.iter().all(is_scalar_api_value)
        }
        AwsCliValue::Object { .. } => false,
        AwsCliValue::Boolean { .. } => accepts_any || types.contains(&PropertyValueType::Boolean),
        AwsCliValue::Integer { .. } | AwsCliValue::UnsignedInteger { .. } => {
            accepts_any || types.contains(&PropertyValueType::Integer) || types.contains(&PropertyValueType::Number)
        }
        AwsCliValue::Number { .. } => accepts_any || types.contains(&PropertyValueType::Number),
        AwsCliValue::String { .. } => accepts_any || types.contains(&PropertyValueType::String),
        AwsCliValue::Null | AwsCliValue::Bytes { .. } | AwsCliValue::Unsupported { .. } => false,
    }
}

fn is_scalar_api_value(value: &AwsCliValue) -> bool {
    matches!(
        value,
        AwsCliValue::Boolean { .. }
            | AwsCliValue::Integer { .. }
            | AwsCliValue::UnsignedInteger { .. }
            | AwsCliValue::Number { .. }
            | AwsCliValue::String { .. }
    )
}
/// Rules whose only remediation is a template-authoring construct: replace a
/// literal ARN, AMI ID, account ID, availability zone, password, or
/// pseudo-parameter lookalike with a parameter, `Ref`/`GetAtt`, mapping, or
/// dynamic reference. They judge how a template author expressed a value, not
/// whether the value is valid resource state.
const TEMPLATE_AUTHORING_ADVICE_RULES: &[&str] = &["W1054", "W2501", "W3010", "W9002", "W9010", "W9013"];

/// Resource state modeled from an API request never had a template, so advice
/// about how a template author should have expressed a literal cannot be acted
/// on and is dropped. Findings about the values themselves are kept.
fn suppress_template_authoring_advice(report: &mut ValidationReport) {
    retain_diagnostics(report, |diagnostic| !TEMPLATE_AUTHORING_ADVICE_RULES.contains(&diagnostic.rule_id.as_str()));
}

fn scope_synthesized_report(report: &mut ValidationReport, properties: &BTreeSet<String>) {
    retain_diagnostics(report, |diagnostic| {
        diagnostic.property_path.as_deref().is_some_and(|path| diagnostic_in_scope(path, properties))
    });
}

fn retain_diagnostics(report: &mut ValidationReport, keep: impl FnMut(&diagnostics::Diagnostic) -> bool) {
    let before = report.diagnostics.len();
    report.diagnostics.retain(keep);
    let removed = before.saturating_sub(report.diagnostics.len()) as u32;
    report.metadata.suppressed = report.metadata.suppressed.saturating_add(removed);
    report.metadata.counts = summarize_diagnostics(&report.diagnostics);
}

fn diagnostic_in_scope(property_path: &str, properties: &BTreeSet<String>) -> bool {
    properties.iter().any(|property_name| {
        [format!("Properties.{property_name}"), format!("/Properties/{property_name}")].into_iter().any(|marker| {
            property_path.find(&marker).is_some_and(|start| {
                let end = start + marker.len();
                end == property_path.len()
                    || property_path[end..].chars().next().is_some_and(|separator| matches!(separator, '.' | '[' | '/'))
            })
        })
    })
}

fn summarize_diagnostics(diagnostics: &[diagnostics::Diagnostic]) -> Summary {
    let fatal = diagnostics.iter().filter(|diagnostic| diagnostic.severity == Severity::Fatal).count() as u32;
    let errors = diagnostics.iter().filter(|diagnostic| diagnostic.severity == Severity::Error).count() as u32;
    let warnings = diagnostics.iter().filter(|diagnostic| diagnostic.severity == Severity::Warn).count() as u32;
    let debug = diagnostics.iter().filter(|diagnostic| diagnostic.severity == Severity::Debug).count() as u32;
    let informational = diagnostics.len() as u32 - fatal - errors - warnings - debug;
    Summary { fatal, errors, warnings, informational, debug }
}
#[cfg(test)]
mod tests {
    use super::*;
    use diagnostics::{Diagnostic, PhaseMetric, RegisteredDiagnostic};
    use rules::{RuleInfo, RuleMetadataEntry};
    use std::sync::Arc;
    use template_model::SemanticModel;

    struct NoopEngine {
        metadata: HashMap<String, RuleMetadataEntry>,
        init_metric: PhaseMetric,
    }

    impl Default for NoopEngine {
        fn default() -> Self {
            Self { metadata: HashMap::new(), init_metric: PhaseMetric { duration_ms: 0.0 } }
        }
    }

    impl ValidationEngine for NoopEngine {
        fn engine_name(&self) -> &str {
            "noop"
        }

        fn evaluate_rules(
            &self,
            _model: &Arc<SemanticModel>,
            _config: &ValidateConfig,
        ) -> Result<Vec<Diagnostic>, ValidationError> {
            Ok(Vec::new())
        }

        fn list_rules(&self) -> Vec<RuleInfo> {
            Vec::new()
        }

        fn rule_metadata(&self) -> &HashMap<String, RuleMetadataEntry> {
            &self.metadata
        }

        fn external_rule_metadata(&self) -> HashMap<String, RuleMetadataEntry> {
            HashMap::new()
        }

        fn init_metric(&self) -> &PhaseMetric {
            &self.init_metric
        }
    }

    fn value(value: serde_json::Value) -> AwsCliValue {
        AwsCliValue::from_json(value)
    }

    fn request(service: &str, operation: &str, parameters: serde_json::Value) -> AwsCliCommand {
        let parameters: HashMap<String, AwsCliValue> = parameters
            .as_object()
            .expect("test parameters must be an object")
            .iter()
            .map(|(name, value)| (name.clone(), AwsCliValue::from_json(value.clone())))
            .collect();
        AwsCliCommand::new(service, operation, parameters).with_http_method("POST")
    }

    fn synthesized_json(request: &AwsCliCommand) -> (Classification, Synthesis, serde_json::Value) {
        let schema_validator = SchemaValidator::default();
        let classification = classify_operation(request, &schema_validator).expect("classification succeeds");
        let synthesis = synthesize_request(request, &classification, &schema_validator).expect("synthesis succeeds");
        let template = synthesis.template.as_ref().expect("request must synthesize");
        let document = serde_json::from_slice(template).expect("template must be JSON");
        (classification, synthesis, document)
    }

    fn mapping(source: &str, target: &str) -> PropertyMapping {
        PropertyMapping { source: source.into(), target: target.into(), unrepresentable: None }
    }

    fn s3_create_bucket_adapter(mappings: Vec<PropertyMapping>) -> OperationAdapter {
        OperationAdapter {
            service: "s3".into(),
            operation: "CreateBucket".into(),
            phase: AdapterPhase::Create,
            cfn_type: "AWS::S3::Bucket".into(),
            mappings,
            ignored_inputs: Vec::new(),
        }
    }

    fn map_s3_create_bucket(adapter: &OperationAdapter, parameters: serde_json::Value) -> AdapterMappingResult {
        let schema_validator = SchemaValidator::default();
        let schema = schema_validator.resource_schema_metadata("AWS::S3::Bucket").expect("S3 bucket schema must exist");
        let parameters: HashMap<String, AwsCliValue> = parameters
            .as_object()
            .expect("test parameters must be an object")
            .iter()
            .map(|(name, value)| (name.clone(), AwsCliValue::from_json(value.clone())))
            .collect();
        map_adapter_properties(&parameters, &schema, adapter).expect("well-formed adapter must not error")
    }

    fn skip_reason(result: AdapterMappingResult) -> String {
        match result {
            AdapterMappingResult::Skip(reason) => reason,
            AdapterMappingResult::Mapped(properties) => panic!("expected skip, got mapped properties {properties:?}"),
        }
    }

    fn malformed_adapter_error(mappings: Vec<PropertyMapping>) -> String {
        let schema_validator = SchemaValidator::default();
        let schema = schema_validator.resource_schema_metadata("AWS::S3::Bucket").expect("S3 bucket schema must exist");
        let adapter = s3_create_bucket_adapter(mappings);
        match map_adapter_properties(&HashMap::new(), &schema, &adapter)
            .expect_err("malformed adapter must return an error")
        {
            ValidationError::Engine(message) => message,
            error => panic!("expected engine error, got {error:?}"),
        }
    }

    #[test]
    fn catalog_parser_reads_unrepresentable_domains() {
        let catalog = br#"{
            "format_version": 1,
            "adapters": [{
                "service": "s3", "operation": "CreateBucket", "phase": "create", "cfn_type": "AWS::S3::Bucket",
                "mappings": [
                    {"source": "Bucket", "target": "BucketName",
                     "unrepresentable": {"rejected_values": ["legacy"], "min_length": 3, "max_length": 63}},
                    {"source": "Tags", "target": "Tags",
                     "unrepresentable": {"tag_value": {"min_length": 1}, "items": {"maximum": 10.0}}}
                ]
            }]
        }"#;
        let registry = parse_adapter_registry(catalog).expect("catalog with domains parses");
        let adapter = &registry[&("s3".to_string(), "CreateBucket".to_string())];
        assert_eq!(
            adapter.mappings[0].unrepresentable,
            Some(UnrepresentableDomain {
                rejected_values: vec![serde_json::json!("legacy")],
                min_length: Some(3),
                max_length: Some(63),
                ..UnrepresentableDomain::default()
            })
        );
        let tags = adapter.mappings[1].unrepresentable.as_ref().expect("tags domain parses");
        assert_eq!(tags.tag_value.as_deref().and_then(|domain| domain.min_length), Some(1));
        assert_eq!(tags.items.as_deref().and_then(|domain| domain.maximum), Some(10.0));
    }

    #[test]
    fn unrepresentable_domain_rejects_only_values_outside_cloudformation_bounds() {
        let enumeration = UnrepresentableDomain {
            rejected_values: vec![serde_json::json!("MANAGED_INSTANCES")],
            ..UnrepresentableDomain::default()
        };
        assert!(enumeration.rejection(&value(serde_json::json!("MANAGED_INSTANCES"))).is_some());
        assert!(enumeration.rejection(&value(serde_json::json!("FARGATE"))).is_none());

        let numeric =
            UnrepresentableDomain { minimum: Some(1.0), maximum: Some(10.0), ..UnrepresentableDomain::default() };
        assert!(numeric.rejection(&value(serde_json::json!(0))).is_some());
        assert!(numeric.rejection(&value(serde_json::json!(50))).is_some());
        assert!(numeric.rejection(&value(serde_json::json!(10))).is_none());
        assert!(numeric.rejection(&value(serde_json::json!(1))).is_none());
        assert!(numeric.rejection(&AwsCliValue::UnsignedInteger { value: 11 }).is_some());
        assert!(numeric.rejection(&AwsCliValue::Number { value: 0.5 }).is_some());

        let text_length =
            UnrepresentableDomain { min_length: Some(5), max_length: Some(6), ..UnrepresentableDomain::default() };
        assert!(text_length.rejection(&value(serde_json::json!("abc"))).is_some());
        assert!(text_length.rejection(&value(serde_json::json!("abcdefg"))).is_some());
        assert!(text_length.rejection(&value(serde_json::json!("abcde"))).is_none());
        assert!(text_length.rejection(&value(serde_json::json!("ééééé"))).is_none(), "length counts characters");

        let list = UnrepresentableDomain {
            max_length: Some(2),
            items: Some(Box::new(UnrepresentableDomain {
                rejected_values: vec![serde_json::json!("SUPER_USER")],
                ..UnrepresentableDomain::default()
            })),
            ..UnrepresentableDomain::default()
        };
        assert!(list.rejection(&value(serde_json::json!(["a", "b", "c"]))).is_some(), "item count above maximum");
        assert!(list.rejection(&value(serde_json::json!(["SELECT", "SUPER_USER"]))).is_some(), "rejected item");
        assert!(list.rejection(&value(serde_json::json!(["SELECT", "ALTER"]))).is_none());

        let tags = UnrepresentableDomain {
            tag_key: Some(Box::new(UnrepresentableDomain { max_length: Some(3), ..UnrepresentableDomain::default() })),
            tag_value: Some(Box::new(UnrepresentableDomain {
                min_length: Some(1),
                ..UnrepresentableDomain::default()
            })),
            ..UnrepresentableDomain::default()
        };
        assert!(tags.rejection(&value(serde_json::json!({"Team": "cli"}))).is_some(), "key too long");
        assert!(tags.rejection(&value(serde_json::json!({"Env": ""}))).is_some(), "empty value");
        assert!(tags.rejection(&value(serde_json::json!({"Env": "prod"}))).is_none());

        let empty = UnrepresentableDomain::default();
        assert!(empty.rejection(&value(serde_json::json!(true))).is_none());
        assert!(empty.rejection(&value(serde_json::json!(null))).is_none());
    }

    #[test]
    fn adapter_skips_when_supplied_value_is_valid_for_the_api_but_not_for_cloudformation() {
        let adapter = s3_create_bucket_adapter(vec![PropertyMapping {
            source: "Bucket".into(),
            target: "BucketName".into(),
            unrepresentable: Some(UnrepresentableDomain {
                rejected_values: vec![serde_json::json!("legacy")],
                min_length: Some(3),
                ..UnrepresentableDomain::default()
            }),
        }]);

        let reason = skip_reason(map_s3_create_bucket(&adapter, serde_json::json!({"Bucket": "legacy"})));
        assert!(reason.contains("parameter 'Bucket'"), "{reason}");
        assert!(reason.contains("valid for the API"), "{reason}");
        assert!(reason.contains("property 'BucketName' on AWS::S3::Bucket"), "{reason}");

        let reason = skip_reason(map_s3_create_bucket(&adapter, serde_json::json!({"Bucket": "ab"})));
        assert!(reason.contains("length 2"), "{reason}");
        assert!(reason.contains("minimum 3"), "{reason}");

        match map_s3_create_bucket(&adapter, serde_json::json!({"Bucket": "my-bucket"})) {
            AdapterMappingResult::Mapped(properties) => {
                assert_eq!(properties.get("BucketName"), Some(&serde_json::json!("my-bucket")));
            }
            AdapterMappingResult::Skip(reason) => panic!("representable value must map: {reason}"),
        }
    }

    #[test]
    fn adapter_skips_tag_maps_whose_entries_have_no_cloudformation_representation() {
        let adapter = s3_create_bucket_adapter(vec![PropertyMapping {
            source: "Tags".into(),
            target: "Tags".into(),
            unrepresentable: Some(UnrepresentableDomain {
                tag_value: Some(Box::new(UnrepresentableDomain {
                    min_length: Some(1),
                    ..UnrepresentableDomain::default()
                })),
                ..UnrepresentableDomain::default()
            }),
        }]);

        let reason = skip_reason(map_s3_create_bucket(&adapter, serde_json::json!({"Tags": {"Env": ""}})));
        assert!(reason.contains("parameter 'Tags'"), "{reason}");
        assert!(reason.contains("length 0"), "{reason}");

        match map_s3_create_bucket(&adapter, serde_json::json!({"Tags": {"Env": "prod"}})) {
            AdapterMappingResult::Mapped(properties) => {
                assert_eq!(properties.get("Tags"), Some(&serde_json::json!([{"Key": "Env", "Value": "prod"}])));
            }
            AdapterMappingResult::Skip(reason) => panic!("representable tags must map: {reason}"),
        }
    }
    #[test]
    fn catalog_parser_rejects_invalid_formats_and_normalized_duplicates() {
        assert!(parse_adapter_registry(b"not json").expect_err("invalid JSON must fail").contains("invalid"));
        assert!(
            parse_adapter_registry(br#"{"format_version":2,"adapters":[]}"#)
                .expect_err("unsupported format must fail")
                .contains("unsupported")
        );
        let duplicate = br#"{
            "format_version": 1,
            "adapters": [
                {"service":"S3","operation":"CreateBucket","phase":"create","cfn_type":"AWS::S3::Bucket","mappings":[]},
                {"service":"s3","operation":"CreateBucket","phase":"create","cfn_type":"AWS::S3::Bucket","mappings":[]}
            ]
        }"#;
        assert!(
            parse_adapter_registry(duplicate).expect_err("case-normalized duplicate must fail").contains("duplicate")
        );
        let blank = br#"{
            "format_version": 1,
            "adapters": [
                {"service":"","operation":"CreateBucket","phase":"create","cfn_type":"AWS::S3::Bucket","mappings":[]}
            ]
        }"#;
        assert!(parse_adapter_registry(blank).expect_err("blank identity must fail").contains("blank"));
    }

    #[test]
    fn catalog_covers_the_generated_resource_universe() {
        let registry = adapter_registry().expect("catalog loads");
        let creates = registry.values().filter(|a| a.phase == AdapterPhase::Create).count();
        let deletes = registry.values().filter(|a| a.phase == AdapterPhase::Delete).count();
        assert!(registry.len() >= 2000, "catalog unexpectedly small: {}", registry.len());
        assert!(creates >= 1000, "create adapters unexpectedly few: {creates}");
        assert!(deletes >= 900, "delete adapters unexpectedly few: {deletes}");
    }

    #[test]
    fn catalog_operations_synthesize_beyond_the_original_services() {
        let cases = [
            ("ec2", "RunInstances", "AWS::EC2::Instance"),
            ("kms", "CreateKey", "AWS::KMS::Key"),
            ("logs", "CreateLogGroup", "AWS::Logs::LogGroup"),
            ("stepfunctions", "CreateStateMachine", "AWS::StepFunctions::StateMachine"),
            ("cloudwatch", "PutMetricAlarm", "AWS::CloudWatch::Alarm"),
            ("secretsmanager", "CreateSecret", "AWS::SecretsManager::Secret"),
        ];
        let schema_validator = SchemaValidator::default();
        for (service, operation, expected_type) in cases {
            let req = request(service, operation, serde_json::json!({}));
            let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
            assert_eq!(classification.candidates, [expected_type], "{service}:{operation} must map to {expected_type}");
        }
    }

    #[test]
    fn catalog_never_contains_forbidden_or_ambiguous_operations() {
        let forbidden = [
            ("ecs", "RunTask"),
            ("ec2", "StartInstances"),
            ("ec2", "StopInstances"),
            ("iot", "StartThingRegistrationTask"),
            ("lambda", "Invoke"),
            ("sns", "Publish"),
            ("sqs", "SendMessage"),
            ("s3", "PutObject"),
            ("dynamodb", "PutItem"),
            ("logs", "StartQuery"),
            ("acm", "RemoveTagsFromCertificate"),
            ("robomaker", "DeregisterRobot"),
            ("quicksight", "CreateTopic"),
            ("quicksight", "DeleteTopic"),
        ];
        let registry = adapter_registry().expect("catalog loads");
        for (service, operation) in forbidden {
            let key = (service.to_string(), operation.to_string());
            assert!(!registry.contains_key(&key), "{service}:{operation} must never be a registered adapter");
        }
    }

    #[test]
    fn every_catalog_adapter_maps_cleanly_with_empty_requests() {
        let schema_validator = SchemaValidator::default();
        let empty = HashMap::new();
        for adapter in adapter_registry().expect("catalog loads").values() {
            let schema = schema_validator
                .resource_schema_metadata(&adapter.cfn_type)
                .unwrap_or_else(|| panic!("{} missing schema metadata", adapter.cfn_type));
            let result = map_adapter_properties(&empty, &schema, adapter).unwrap_or_else(|error| {
                panic!("adapter {}:{} violates registry invariants: {error}", adapter.service, adapter.operation)
            });
            // Empty parameters always produce Mapped (no supplied params to conflict).
            assert!(
                matches!(result, AdapterMappingResult::Mapped(_)),
                "adapter {}:{} must accept empty parameters",
                adapter.service,
                adapter.operation
            );
        }
    }

    #[test]
    fn nested_values_are_rejected_without_recursive_shape_mappings() {
        let object_types = BTreeSet::from([PropertyValueType::Object]);
        let array_types = BTreeSet::from([PropertyValueType::Array]);
        let object = AwsCliValue::from_json(serde_json::json!({"lowerCamel": "value"}));
        let object_array = AwsCliValue::from_json(serde_json::json!([{"lowerCamel": "value"}]));
        let scalar_array = AwsCliValue::from_json(serde_json::json!(["one", "two"]));

        assert!(mapped_value(&object, &object_types, "Configuration").is_none());
        assert!(mapped_value(&object_array, &array_types, "Configurations").is_none());
        assert_eq!(mapped_value(&scalar_array, &array_types, "Names"), Some(serde_json::json!(["one", "two"])));
    }

    #[test]
    fn registry_has_unique_service_operation_keys() {
        let mut seen = BTreeSet::new();
        for adapter in adapter_registry().expect("catalog loads").values() {
            let key = (normalize_service(&adapter.service), adapter.operation.clone());
            assert!(seen.insert(key.clone()), "duplicate adapter key: {}:{}", key.0, key.1);
        }
    }

    #[test]
    fn registry_types_exist_in_schema_validator() {
        let schema_validator = SchemaValidator::default();
        for adapter in adapter_registry().expect("catalog loads").values() {
            assert!(
                schema_validator.has_resource_type(&adapter.cfn_type),
                "adapter {}:{} references unknown type {}",
                adapter.service,
                adapter.operation,
                adapter.cfn_type
            );
        }
    }

    #[test]
    fn registry_property_mappings_target_real_properties() {
        let schema_validator = SchemaValidator::default();
        for adapter in adapter_registry().expect("catalog loads").values() {
            let Some(schema) = schema_validator.resource_schema_metadata(&adapter.cfn_type) else {
                continue;
            };
            for mapping in &adapter.mappings {
                assert!(
                    schema.property_types.contains_key(&mapping.target),
                    "adapter {}:{} maps to non-existent property {}.{}",
                    adapter.service,
                    adapter.operation,
                    adapter.cfn_type,
                    mapping.target
                );
            }
        }
    }

    #[test]
    fn registry_has_no_read_only_property_mappings() {
        let schema_validator = SchemaValidator::default();
        for adapter in adapter_registry().expect("catalog loads").values() {
            let Some(schema) = schema_validator.resource_schema_metadata(&adapter.cfn_type) else {
                continue;
            };
            for mapping in &adapter.mappings {
                assert!(
                    !schema.read_only_properties.contains(&mapping.target),
                    "adapter {}:{} maps to read-only property {}.{}",
                    adapter.service,
                    adapter.operation,
                    adapter.cfn_type,
                    mapping.target
                );
            }
        }
    }

    #[test]
    fn registry_update_mappings_exclude_primary_identifiers() {
        let schema_validator = SchemaValidator::default();
        for adapter in adapter_registry().expect("catalog loads").values() {
            if adapter.phase != AdapterPhase::Update {
                continue;
            }
            let Some(schema) = schema_validator.resource_schema_metadata(&adapter.cfn_type) else {
                continue;
            };
            for mapping in &adapter.mappings {
                assert!(
                    !schema.primary_identifier_properties.contains(&mapping.target),
                    "update adapter {}:{} maps to primary identifier property {}.{}",
                    adapter.service,
                    adapter.operation,
                    adapter.cfn_type,
                    mapping.target
                );
            }
        }
    }

    #[test]
    fn registry_has_no_duplicate_source_or_target_mappings() {
        for adapter in adapter_registry().expect("catalog loads").values() {
            let mut sources = BTreeSet::new();
            let mut targets = BTreeSet::new();
            for mapping in &adapter.mappings {
                assert!(
                    sources.insert(mapping.source.as_str()),
                    "adapter {}:{} has duplicate source mapping: {}",
                    adapter.service,
                    adapter.operation,
                    mapping.source
                );
                assert!(
                    targets.insert(mapping.target.as_str()),
                    "adapter {}:{} has duplicate target mapping: {}",
                    adapter.service,
                    adapter.operation,
                    mapping.target
                );
            }
        }
    }

    #[test]
    fn malformed_adapter_mappings_fail_without_request_values() {
        assert!(malformed_adapter_error(vec![mapping("Bucket", "NotAProperty")]).contains("does not exist"));
        assert!(malformed_adapter_error(vec![mapping("Bucket", "Arn")]).contains("excluded property"));
        assert!(
            malformed_adapter_error(vec![mapping("Bucket", "BucketName"), mapping("Bucket", "Tags")])
                .contains("duplicate source parameter")
        );
        assert!(
            malformed_adapter_error(vec![mapping("Bucket", "BucketName"), mapping("OtherBucket", "BucketName")])
                .contains("duplicate target property")
        );
    }

    #[test]
    fn s3_create_bucket_synthesizes_with_explicit_mappings() {
        let request = request("s3", "CreateBucket", serde_json::json!({"Bucket": "synthetic-bucket"}));
        let (classification, synthesis, document) = synthesized_json(&request);
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationCreate);
        assert_eq!(classification.candidates, ["AWS::S3::Bucket"]);
        assert_eq!(synthesis.source, Some(AwsCliTemplateSource::SynthesizedCreate));
        assert_eq!(document["Resources"]["Resource"]["Properties"]["BucketName"], "synthetic-bucket");
    }

    #[test]
    fn s3_delete_bucket_identifies_type_without_synthesizing() {
        let schema_validator = SchemaValidator::default();
        let request = request("s3", "DeleteBucket", serde_json::json!({"Bucket": "synthetic-bucket"}));
        let classification = classify_operation(&request, &schema_validator).expect("classification succeeds");
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationDelete);
        assert_eq!(classification.candidates, ["AWS::S3::Bucket"]);
        let synthesis = synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
    }

    #[test]
    fn dynamodb_create_table_skips_when_unmapped_nested_parameters_are_present() {
        let schema_validator = SchemaValidator::default();
        let request = request(
            "dynamodb",
            "CreateTable",
            serde_json::json!({
                "TableName": "Synthetic",
                "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
                "BillingMode": "PAY_PER_REQUEST"
            }),
        );
        let classification = classify_operation(&request, &schema_validator).expect("classification succeeds");
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationCreate);
        assert_eq!(classification.candidates, ["AWS::DynamoDB::Table"]);
        let synthesis = synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none(), "unmapped nested parameters must skip synthesis");
        assert!(
            synthesis.reason.contains("has no mapping"),
            "reason must explain the unmapped parameter: {}",
            synthesis.reason
        );
    }

    #[test]
    fn dynamodb_create_table_synthesizes_with_scalar_only_parameters() {
        let request = request(
            "dynamodb",
            "CreateTable",
            serde_json::json!({"TableName": "Synthetic", "BillingMode": "PAY_PER_REQUEST"}),
        );
        let (classification, synthesis, document) = synthesized_json(&request);
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationCreate);
        assert_eq!(classification.candidates, ["AWS::DynamoDB::Table"]);
        assert_eq!(synthesis.source, Some(AwsCliTemplateSource::SynthesizedCreate));
        assert_eq!(document["Resources"]["Resource"]["Properties"]["TableName"], "Synthetic");
        assert_eq!(document["Resources"]["Resource"]["Properties"]["BillingMode"], "PAY_PER_REQUEST");
    }

    #[test]
    fn dynamodb_delete_table_identifies_type_without_synthesizing() {
        let schema_validator = SchemaValidator::default();
        let request = request("dynamodb", "DeleteTable", serde_json::json!({"TableName": "Synthetic"}));
        let classification = classify_operation(&request, &schema_validator).expect("classification succeeds");
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationDelete);
        assert_eq!(classification.candidates, ["AWS::DynamoDB::Table"]);
        let synthesis = synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
    }

    #[test]
    fn iam_create_role_synthesizes_with_explicit_mappings() {
        let request = request(
            "iam",
            "CreateRole",
            serde_json::json!({
                "RoleName": "Synthetic",
                "AssumeRolePolicyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
            }),
        );
        let (classification, synthesis, document) = synthesized_json(&request);
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationCreate);
        assert_eq!(classification.candidates, ["AWS::IAM::Role"]);
        assert_eq!(synthesis.source, Some(AwsCliTemplateSource::SynthesizedCreate));
        assert_eq!(document["Resources"]["Resource"]["Properties"]["RoleName"], "Synthetic");
    }

    #[test]
    fn iam_delete_role_identifies_type_without_synthesizing() {
        let schema_validator = SchemaValidator::default();
        let request = request("iam", "DeleteRole", serde_json::json!({"RoleName": "Synthetic"}));
        let classification = classify_operation(&request, &schema_validator).expect("classification succeeds");
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationDelete);
        assert_eq!(classification.candidates, ["AWS::IAM::Role"]);
        let synthesis = synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
    }

    #[test]
    fn lambda_create_function_synthesizes_all_supplied_scalar_properties() {
        let request =
            request("lambda", "CreateFunction", serde_json::json!({"FunctionName": "Synthetic", "MemorySize": 128}));
        let (classification, synthesis, document) = synthesized_json(&request);
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationCreate);
        assert_eq!(classification.candidates, ["AWS::Lambda::Function"]);
        assert_eq!(synthesis.source, Some(AwsCliTemplateSource::SynthesizedCreate));
        assert_eq!(synthesis.diagnostic_properties, Some(BTreeSet::from(["FunctionName".into(), "MemorySize".into()])));
        assert_eq!(document["Resources"]["Resource"]["Properties"]["FunctionName"], "Synthetic");
        assert_eq!(document["Resources"]["Resource"]["Properties"]["MemorySize"], 128);
    }

    #[test]
    fn lambda_update_function_configuration_maps_all_supplied_mutable_properties() {
        let request = request(
            "lambda",
            "UpdateFunctionConfiguration",
            serde_json::json!({"FunctionName": "Synthetic", "MemorySize": 128}),
        );
        let (classification, synthesis, document) = synthesized_json(&request);
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationUpdate);
        assert_eq!(classification.candidates, ["AWS::Lambda::Function"]);
        assert_eq!(synthesis.source, Some(AwsCliTemplateSource::SynthesizedUpdate));
        assert_eq!(document["Resources"]["Resource"]["Properties"], serde_json::json!({"MemorySize": 128}));
        assert_eq!(synthesis.diagnostic_properties, Some(BTreeSet::from(["MemorySize".into()])));
    }

    #[test]
    fn lambda_delete_function_identifies_type_without_synthesizing() {
        let schema_validator = SchemaValidator::default();
        let request = request("lambda", "DeleteFunction", serde_json::json!({"FunctionName": "Synthetic"}));
        let classification = classify_operation(&request, &schema_validator).expect("classification succeeds");
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationDelete);
        assert_eq!(classification.candidates, ["AWS::Lambda::Function"]);
        let synthesis = synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
    }

    #[test]
    fn sns_create_topic_synthesizes_with_explicit_mappings() {
        let request = request("sns", "CreateTopic", serde_json::json!({"Name": "Synthetic"}));
        let (classification, synthesis, document) = synthesized_json(&request);
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationCreate);
        assert_eq!(classification.candidates, ["AWS::SNS::Topic"]);
        assert_eq!(synthesis.source, Some(AwsCliTemplateSource::SynthesizedCreate));
        assert_eq!(document["Resources"]["Resource"]["Properties"]["TopicName"], "Synthetic");
    }

    #[test]
    fn sns_delete_topic_identifies_type_without_synthesizing() {
        let schema_validator = SchemaValidator::default();
        let request = request("sns", "DeleteTopic", serde_json::json!({"TopicArn": "arn:aws:sns:us-east-1:123:Topic"}));
        let classification = classify_operation(&request, &schema_validator).expect("classification succeeds");
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationDelete);
        assert_eq!(classification.candidates, ["AWS::SNS::Topic"]);
        let synthesis = synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
    }

    #[test]
    fn sqs_create_queue_synthesizes_with_explicit_mappings() {
        let request =
            request("sqs", "CreateQueue", serde_json::json!({"QueueName": "Synthetic", "tags": {"Team": "CLI"}}));
        let (classification, synthesis, document) = synthesized_json(&request);
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationCreate);
        assert_eq!(classification.candidates, ["AWS::SQS::Queue"]);
        assert_eq!(synthesis.source, Some(AwsCliTemplateSource::SynthesizedCreate));
        assert_eq!(document["Resources"]["Resource"]["Properties"]["QueueName"], "Synthetic");
    }

    #[test]
    fn sqs_delete_queue_identifies_type_without_synthesizing() {
        let schema_validator = SchemaValidator::default();
        let request =
            request("sqs", "DeleteQueue", serde_json::json!({"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123/Q"}));
        let classification = classify_operation(&request, &schema_validator).expect("classification succeeds");
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationDelete);
        assert_eq!(classification.candidates, ["AWS::SQS::Queue"]);
        let synthesis = synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
    }
    #[test]
    fn canonical_service_name_matching_is_case_insensitive() {
        let schema_validator = SchemaValidator::default();
        // Non-lowercase spellings of the canonical botocore service name must
        // normalize to the same adapter; service_name is ASCII case-normalized only.
        for (service, operation, expected_type) in [
            ("S3", "CreateBucket", "AWS::S3::Bucket"),
            ("DynamoDb", "CreateTable", "AWS::DynamoDB::Table"),
            ("Iam", "CreateRole", "AWS::IAM::Role"),
            ("Lambda", "CreateFunction", "AWS::Lambda::Function"),
            ("Sns", "CreateTopic", "AWS::SNS::Topic"),
            ("Sqs", "CreateQueue", "AWS::SQS::Queue"),
        ] {
            let req = request(service, operation, serde_json::json!({}));
            let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
            assert_eq!(
                classification.candidates,
                [expected_type],
                "canonical service name {service}:{operation} must resolve case-insensitively to {expected_type}"
            );
        }
    }
    #[test]
    fn template_body_is_accepted_only_for_cloudformation_operations() {
        let schema_validator = SchemaValidator::default();
        let template = br#"{"Resources":{}}"#.to_vec();

        let mut cfn_request = request("cloudformation", "CreateChangeSet", serde_json::json!({}));
        cfn_request.parameters.insert("TemplateBody".into(), AwsCliValue::Bytes { value: template.clone() });
        let classification = classify_operation(&cfn_request, &schema_validator).expect("classification succeeds");
        let synthesis =
            synthesize_request(&cfn_request, &classification, &schema_validator).expect("synthesis succeeds");
        assert_eq!(synthesis.source, Some(AwsCliTemplateSource::TemplateBody));
        assert_eq!(synthesis.template, Some(template.clone()));

        let mut s3_request = request("s3", "PutObject", serde_json::json!({}));
        s3_request.parameters.insert("TemplateBody".into(), AwsCliValue::Bytes { value: template.clone() });
        let classification = classify_operation(&s3_request, &schema_validator).expect("classification succeeds");
        let synthesis =
            synthesize_request(&s3_request, &classification, &schema_validator).expect("synthesis succeeds");
        assert_ne!(synthesis.source, Some(AwsCliTemplateSource::TemplateBody));
    }

    #[test]
    fn template_url_skip_only_for_cloudformation_operations() {
        let schema_validator = SchemaValidator::default();
        let cfn_request = request(
            "cloudformation",
            "CreateStack",
            serde_json::json!({"TemplateURL": "https://example.com/template.json"}),
        );
        let classification = classify_operation(&cfn_request, &schema_validator).expect("classification succeeds");
        let synthesis =
            synthesize_request(&cfn_request, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
        assert!(synthesis.reason.contains("unavailable"));
    }

    #[test]
    fn all_closed_template_body_operations_are_accepted() {
        let schema_validator = SchemaValidator::default();
        let template = br#"{"Resources":{}}"#.to_vec();
        for (service, operation) in TEMPLATE_BODY_OPERATIONS {
            let mut req = request(service, operation, serde_json::json!({}));
            req.parameters.insert("TemplateBody".into(), AwsCliValue::Bytes { value: template.clone() });
            let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
            let synthesis = synthesize_request(&req, &classification, &schema_validator).expect("synthesis succeeds");
            assert_eq!(
                synthesis.source,
                Some(AwsCliTemplateSource::TemplateBody),
                "{service}:{operation} should accept TemplateBody"
            );
        }
    }
    #[test]
    fn cloud_control_create_resource_wraps_desired_state() {
        let known = request(
            "cloudcontrol",
            "CreateResource",
            serde_json::json!({"TypeName": "AWS::SNS::Topic", "DesiredState": "{\"TopicName\":\"Synthetic\"}"}),
        );
        let (classification, synthesis, document) = synthesized_json(&known);
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationCreate);
        assert_eq!(classification.candidates, ["AWS::SNS::Topic"]);
        assert_eq!(synthesis.source, Some(AwsCliTemplateSource::CloudControlDesiredState));
        assert_eq!(document["Resources"]["Resource"]["Properties"]["TopicName"], "Synthetic");
    }

    #[test]
    fn cloud_control_with_signing_prefix_cloudcontrolapi() {
        let parameters: HashMap<String, AwsCliValue> = serde_json::json!({
            "TypeName": "AWS::SNS::Topic",
            "DesiredState": "{\"TopicName\":\"Synthetic\"}"
        })
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), AwsCliValue::from_json(v.clone())))
        .collect();
        let req =
            AwsCliCommand::new("cloudcontrol", "CreateResource", parameters).with_service_prefix("cloudcontrolapi");
        let (classification, synthesis, document) = synthesized_json(&req);
        assert_eq!(classification.kind, AwsCliOperationKind::CloudFormationCreate);
        assert_eq!(classification.candidates, ["AWS::SNS::Topic"]);
        assert_eq!(synthesis.source, Some(AwsCliTemplateSource::CloudControlDesiredState));
        assert_eq!(document["Resources"]["Resource"]["Properties"]["TopicName"], "Synthetic");
    }

    #[test]
    fn cloud_control_rejects_unknown_type_name() {
        let schema_validator = SchemaValidator::default();
        let unknown = request(
            "cloudcontrol",
            "CreateResource",
            serde_json::json!({"TypeName": "AWS::Unknown::Type", "DesiredState": "{}"}),
        );
        let classification = classify_operation(&unknown, &schema_validator).expect("classification succeeds");
        let synthesis = synthesize_request(&unknown, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
        assert!(synthesis.reason.contains("known CloudFormation TypeName"));
    }

    #[test]
    fn cloud_control_update_resource_reports_type_but_does_not_synthesize() {
        let schema_validator = SchemaValidator::default();
        let update = request(
            "cloudcontrol",
            "UpdateResource",
            serde_json::json!({"TypeName": "AWS::SNS::Topic", "PatchDocument": "[{\"op\":\"replace\"}]"}),
        );
        let classification = classify_operation(&update, &schema_validator).expect("classification succeeds");
        assert_eq!(classification.kind, AwsCliOperationKind::UnmappedMutation);
        assert_eq!(classification.candidates, ["AWS::SNS::Topic"]);
        let synthesis = synthesize_request(&update, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
        assert!(synthesis.reason.contains("PatchDocument"));
        assert_eq!(synthesis.resource_types, ["AWS::SNS::Topic"]);
    }
    #[test]
    fn explicit_readonly_and_http_get_are_authoritative_read_signals() {
        let schema_validator = SchemaValidator::default();
        let mut explicitly_readonly = request("test", "CreateThing", serde_json::json!({}));
        explicitly_readonly.is_read_only = Some(true);
        assert_eq!(
            classify_operation(&explicitly_readonly, &schema_validator).expect("classification succeeds").kind,
            AwsCliOperationKind::ReadOnly
        );
        let mut get_request = request("test", "FrobnicateThing", serde_json::json!({}));
        get_request.http_method = Some("GET".into());
        assert_eq!(
            classify_operation(&get_request, &schema_validator).expect("classification succeeds").kind,
            AwsCliOperationKind::ReadOnly
        );
    }

    #[test]
    fn data_plane_verbs_are_classified_correctly() {
        let schema_validator = SchemaValidator::default();
        let lambda_invoke = request("lambda", "Invoke", serde_json::json!({}));
        assert_eq!(
            classify_operation(&lambda_invoke, &schema_validator).expect("classification succeeds").kind,
            AwsCliOperationKind::DataPlaneMutation
        );
    }
    #[test]
    fn ecs_run_task_never_maps_to_resource() {
        let schema_validator = SchemaValidator::default();
        let req = request("ecs", "RunTask", serde_json::json!({"TaskDefinition": "my-task"}));
        let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
        assert!(classification.candidates.is_empty(), "ecs:RunTask must not map to any resource type");
        assert_ne!(classification.kind, AwsCliOperationKind::CloudFormationCreate);
        let synthesis = synthesize_request(&req, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
    }

    #[test]
    fn ec2_start_instances_never_maps_to_resource() {
        let schema_validator = SchemaValidator::default();
        let req = request("ec2", "StartInstances", serde_json::json!({"InstanceIds": ["i-12345"]}));
        let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
        assert!(classification.candidates.is_empty(), "ec2:StartInstances must not map to any resource type");
        assert_ne!(classification.kind, AwsCliOperationKind::CloudFormationCreate);
        let synthesis = synthesize_request(&req, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
    }

    #[test]
    fn iot_start_thing_registration_task_never_maps_to_resource() {
        let schema_validator = SchemaValidator::default();
        let req = request("iot", "StartThingRegistrationTask", serde_json::json!({"TemplateBody": "{}"}));
        let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
        assert!(
            classification.candidates.is_empty(),
            "iot:StartThingRegistrationTask must not map to any resource type"
        );
        let synthesis = synthesize_request(&req, &classification, &schema_validator).expect("synthesis succeeds");
        assert_ne!(synthesis.source, Some(AwsCliTemplateSource::TemplateBody));
    }

    #[test]
    fn wrong_service_template_body_is_not_treated_as_cfn_template() {
        let schema_validator = SchemaValidator::default();
        let template = br#"{"Resources":{}}"#.to_vec();
        for service in ["s3", "lambda", "iot", "dynamodb"] {
            let mut req = request(service, "SomeOperation", serde_json::json!({}));
            req.parameters.insert("TemplateBody".into(), AwsCliValue::Bytes { value: template.clone() });
            let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
            let synthesis = synthesize_request(&req, &classification, &schema_validator).expect("synthesis succeeds");
            assert_ne!(
                synthesis.source,
                Some(AwsCliTemplateSource::TemplateBody),
                "{service}:SomeOperation should not treat TemplateBody as CFN template"
            );
        }
    }

    #[test]
    fn wrong_service_type_name_desired_state_is_not_wrapped() {
        let schema_validator = SchemaValidator::default();
        let req = request(
            "s3",
            "CreateResource",
            serde_json::json!({"TypeName": "AWS::SNS::Topic", "DesiredState": "{\"TopicName\":\"Synthetic\"}"}),
        );
        let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
        let synthesis = synthesize_request(&req, &classification, &schema_validator).expect("synthesis succeeds");
        assert_ne!(synthesis.source, Some(AwsCliTemplateSource::CloudControlDesiredState));
    }

    #[test]
    fn near_match_operation_names_never_map_or_synthesize() {
        let schema_validator = SchemaValidator::default();
        for (service, operation) in [
            ("s3", "CreateBuckets"),
            ("s3", "createBucket"),
            ("dynamodb", "CreateTables"),
            ("lambda", "CreateFunctions"),
            ("lambda", "UpdateFunctionConfigurations"),
        ] {
            let req = request(service, operation, serde_json::json!({}));
            let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
            assert!(
                classification.candidates.is_empty(),
                "{service}:{operation} near-match must not resolve to any adapter"
            );
        }
    }
    #[test]
    fn incompatible_property_value_skips_synthesis() {
        let schema_validator = SchemaValidator::default();
        // MaxSessionDuration is mapped and expects integer; pass a boolean.
        let request = request(
            "iam",
            "CreateRole",
            serde_json::json!({
                "RoleName": "Synthetic",
                "AssumeRolePolicyDocument": "{}",
                "MaxSessionDuration": true
            }),
        );
        let classification = classify_operation(&request, &schema_validator).expect("classification succeeds");
        let synthesis = synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none(), "incompatible value must skip synthesis");
        assert!(
            synthesis.reason.contains("cannot be represented"),
            "reason must explain the type mismatch: {}",
            synthesis.reason
        );
    }

    #[test]
    fn high_level_api_validates_exact_template_and_reports_skips() {
        let engine = NoopEngine::default();
        let schema_validator = SchemaValidator::default();
        let mut exact = request("cloudformation", "CreateChangeSet", serde_json::json!({}));
        exact.parameters.insert("TemplateBody".into(), AwsCliValue::Bytes { value: br#"{"Resources":{}}"#.to_vec() });
        let validation = validate_aws_cli_command(&engine, &schema_validator, &exact, ValidateConfig::default())
            .expect("validation succeeds");
        assert_eq!(validation.status, AwsCliCommandValidationStatus::Validated);
        assert_eq!(validation.template_source, Some(AwsCliTemplateSource::TemplateBody));
        assert!(validation.report.is_some());
        assert_eq!(
            validation.template,
            Some(br#"{"Resources":{}}"#.to_vec()),
            "exact TemplateBody bytes must be preserved without reserializing"
        );

        let read = request("iam", "GetRole", serde_json::json!({"RoleName": "Synthetic"}));
        let validation = validate_aws_cli_command(&engine, &schema_validator, &read, ValidateConfig::default())
            .expect("classification succeeds");
        assert_eq!(validation.status, AwsCliCommandValidationStatus::Skipped);
        assert_eq!(validation.operation_kind, AwsCliOperationKind::ReadOnly);
        assert!(validation.report.is_none());
        assert_eq!(validation.template, None, "skipped requests must have template=None");
    }

    /// Emits one template-authoring advice diagnostic and one value-validity
    /// diagnostic on `Properties.QueueName` of every resource.
    struct AdviceEngine(NoopEngine);

    impl ValidationEngine for AdviceEngine {
        fn engine_name(&self) -> &str {
            "advice"
        }

        fn evaluate_rules(
            &self,
            model: &Arc<SemanticModel>,
            _config: &ValidateConfig,
        ) -> Result<Vec<Diagnostic>, ValidationError> {
            Ok(model
                .resources
                .keys()
                .flat_map(|logical_id| {
                    ["W9002", "W3030"].into_iter().map(move |rule_id| {
                        RegisteredDiagnostic::new(rule_id, format!("{rule_id} on {logical_id}"))
                            .resource(logical_id.clone(), None)
                            .property_path("Properties.QueueName")
                            .build()
                    })
                })
                .collect())
        }

        fn list_rules(&self) -> Vec<RuleInfo> {
            self.0.list_rules()
        }

        fn rule_metadata(&self) -> &HashMap<String, RuleMetadataEntry> {
            self.0.rule_metadata()
        }

        fn external_rule_metadata(&self) -> HashMap<String, RuleMetadataEntry> {
            self.0.external_rule_metadata()
        }

        fn init_metric(&self) -> &PhaseMetric {
            self.0.init_metric()
        }
    }

    fn reported_rule_ids(validation: &AwsCliCommandValidation) -> BTreeSet<String> {
        let report = validation.report.as_ref().expect("request must be validated");
        report.diagnostics.iter().map(|diagnostic| diagnostic.rule_id.clone()).collect()
    }

    #[test]
    fn template_authoring_advice_is_dropped_for_modeled_state_but_kept_for_template_bodies() {
        let engine = AdviceEngine(NoopEngine::default());
        let schema_validator = SchemaValidator::default();

        let mut template_body = request("cloudformation", "CreateStack", serde_json::json!({"StackName": "s"}));
        template_body.parameters.insert(
            "TemplateBody".into(),
            AwsCliValue::String {
                value: r#"{"Resources":{"Q":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"orders"}}}}"#.into(),
            },
        );
        let validation =
            validate_aws_cli_command(&engine, &schema_validator, &template_body, ValidateConfig::default())
                .expect("validation succeeds");
        assert_eq!(validation.template_source, Some(AwsCliTemplateSource::TemplateBody));
        let reported = reported_rule_ids(&validation);
        assert!(reported.contains("W9002"), "a real template keeps authoring advice: {reported:?}");
        assert!(reported.contains("W3030"), "{reported:?}");

        let synthesized = request("sqs", "CreateQueue", serde_json::json!({"QueueName": "orders"}));
        let validation = validate_aws_cli_command(&engine, &schema_validator, &synthesized, ValidateConfig::default())
            .expect("validation succeeds");
        assert_eq!(validation.template_source, Some(AwsCliTemplateSource::SynthesizedCreate));
        let reported = reported_rule_ids(&validation);
        assert!(!reported.contains("W9002"), "modeled API state drops authoring advice: {reported:?}");
        assert!(reported.contains("W3030"), "value findings are kept: {reported:?}");
        let report = validation.report.as_ref().expect("validated");
        assert!(report.metadata.suppressed >= 1, "dropped advice is counted as suppressed");
        assert_eq!(report.metadata.counts.warnings, 1);

        let desired_state = request(
            "cloudcontrol",
            "CreateResource",
            serde_json::json!({"TypeName": "AWS::SQS::Queue", "DesiredState": "{\"QueueName\":\"orders\"}"}),
        );
        let validation =
            validate_aws_cli_command(&engine, &schema_validator, &desired_state, ValidateConfig::default())
                .expect("validation succeeds");
        assert_eq!(validation.template_source, Some(AwsCliTemplateSource::CloudControlDesiredState));
        let reported = reported_rule_ids(&validation);
        assert!(!reported.contains("W9002"), "Cloud Control desired state drops authoring advice: {reported:?}");
        assert!(reported.contains("W3030"), "{reported:?}");
    }

    #[test]
    fn partial_update_scoping_keeps_report_counts_consistent() {
        let engine = NoopEngine::default();
        let schema_validator = SchemaValidator::default();
        let update = request(
            "lambda",
            "UpdateFunctionConfiguration",
            serde_json::json!({"FunctionName": "Synthetic", "MemorySize": 0}),
        );
        let validation = validate_aws_cli_command(&engine, &schema_validator, &update, ValidateConfig::default())
            .expect("validation succeeds");
        let report = validation.report.expect("update is validated");
        assert!(
            report
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.property_path.as_deref().is_some_and(|path| path.contains("MemorySize")))
        );
        let counts = &report.metadata.counts;
        assert_eq!(
            report.diagnostics.len() as u32,
            counts.fatal + counts.errors + counts.warnings + counts.informational + counts.debug
        );
    }

    #[test]
    fn request_parameters_are_not_mutated() {
        let parameters = HashMap::from([
            ("TableName".into(), value(serde_json::json!("Synthetic"))),
            ("KeySchema".into(), value(serde_json::json!([{"AttributeName": "id", "KeyType": "HASH"}]))),
            ("AttributeDefinitions".into(), value(serde_json::json!([{"AttributeName": "id", "AttributeType": "S"}]))),
        ]);
        let original = parameters.clone();
        let request = AwsCliCommand::new("dynamodb", "CreateTable", parameters);
        let schema_validator = SchemaValidator::default();
        let classification = classify_operation(&request, &schema_validator).expect("classification succeeds");
        let _ = synthesize_request(&request, &classification, &schema_validator);
        assert_eq!(request.parameters, original);
    }

    #[test]
    fn json_conversion_rejects_non_json_values_without_coercion() {
        assert!(AwsCliValue::Bytes { value: vec![1, 2] }.to_json().is_err());
        assert!(AwsCliValue::Number { value: f64::NAN }.to_json().is_err());
        assert!(AwsCliValue::Unsupported { type_name: "timestamp".into() }.to_json().is_err());
    }

    #[test]
    fn operation_words_preserve_acronyms_for_verb_classification() {
        assert_eq!(operation_words("BatchCreateDB2Cluster"), ["Batch", "Create", "DB", "2", "Cluster"]);
        assert_eq!(effective_verb(&operation_words("BatchCreateDB2Cluster")), "Create");
    }

    #[test]
    fn normalize_service_changes_ascii_case_only() {
        assert_eq!(normalize_service("s3"), "s3");
        assert_eq!(normalize_service("S3"), "s3");
        assert_eq!(normalize_service("DynamoDb"), "dynamodb");
        assert_eq!(normalize_service("dynamodb"), "dynamodb");
        assert_eq!(normalize_service("cloud-control"), "cloud-control");
        assert_eq!(normalize_service("CloudControl"), "cloudcontrol");
        assert_eq!(normalize_service("cloudcontrolapi"), "cloudcontrolapi");
    }

    #[test]
    fn conflicting_service_prefix_does_not_map_adapter() {
        let schema_validator = SchemaValidator::default();
        let parameters: HashMap<String, AwsCliValue> = serde_json::json!({"Bucket": "test"})
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), AwsCliValue::from_json(v.clone())))
            .collect();
        let req = AwsCliCommand::new("ecs", "CreateBucket", parameters).with_service_prefix("s3");
        let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
        assert!(
            classification.candidates.is_empty(),
            "service_name=ecs with service_prefix=s3 must not map CreateBucket"
        );

        let punctuated = request("s-3", "CreateBucket", serde_json::json!({"Bucket": "test"}));
        let classification = classify_operation(&punctuated, &schema_validator).expect("classification succeeds");
        assert!(classification.candidates.is_empty(), "punctuated service names must not map adapters");
    }

    #[test]
    fn conflicting_service_prefix_does_not_validate_template_body() {
        let schema_validator = SchemaValidator::default();
        let template = br#"{"Resources":{}}"#.to_vec();
        let parameters: HashMap<String, AwsCliValue> =
            [("TemplateBody".to_string(), AwsCliValue::Bytes { value: template })].into_iter().collect();
        let req = AwsCliCommand::new("iot", "CreateStack", parameters).with_service_prefix("cloudformation");
        let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
        let synthesis = synthesize_request(&req, &classification, &schema_validator).expect("synthesis succeeds");
        assert_ne!(
            synthesis.source,
            Some(AwsCliTemplateSource::TemplateBody),
            "service_name=iot with service_prefix=cloudformation must not validate TemplateBody"
        );
    }

    #[test]
    fn arbitrary_cloudcontrol_operation_with_valid_type_name_has_no_candidates() {
        let schema_validator = SchemaValidator::default();
        let req = request("cloudcontrol", "ListResources", serde_json::json!({"TypeName": "AWS::SNS::Topic"}));
        let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
        assert!(
            classification.candidates.is_empty(),
            "arbitrary cloudcontrol operations must not produce resource_types even with valid TypeName"
        );
    }

    #[test]
    fn lambda_create_partial_scopes_to_mapped_properties_only() {
        let engine = NoopEngine::default();
        let schema_validator = SchemaValidator::default();
        let req = request("lambda", "CreateFunction", serde_json::json!({"MemorySize": 0}));
        let validation = validate_aws_cli_command(&engine, &schema_validator, &req, ValidateConfig::default())
            .expect("validation succeeds");
        assert_eq!(validation.status, AwsCliCommandValidationStatus::Validated);
        assert_eq!(validation.template_source, Some(AwsCliTemplateSource::SynthesizedCreate));
        let report = validation.report.expect("create is validated");
        for diagnostic in &report.diagnostics {
            assert!(
                diagnostic.property_path.as_deref().is_some_and(|p| p.contains("MemorySize")),
                "diagnostic must be scoped to MemorySize, got: {:?}",
                diagnostic.property_path
            );
        }
        let counts = &report.metadata.counts;
        assert_eq!(
            report.diagnostics.len() as u32,
            counts.fatal + counts.errors + counts.warnings + counts.informational + counts.debug,
        );
        // The template field carries the synthesized JSON used for validation.
        let template_bytes = validation.template.expect("validated requests carry template bytes");
        let template_json: serde_json::Value =
            serde_json::from_slice(&template_bytes).expect("template must be valid JSON");
        assert_eq!(template_json["Resources"]["Resource"]["Type"], "AWS::Lambda::Function");
        assert_eq!(template_json["Resources"]["Resource"]["Properties"]["MemorySize"], 0);
    }

    #[test]
    fn template_body_create_operations_have_cloud_formation_create_kind() {
        let schema_validator = SchemaValidator::default();
        for operation in ["CreateChangeSet", "CreateStack", "CreateStackSet"] {
            let req = request("cloudformation", operation, serde_json::json!({}));
            let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
            assert_eq!(
                classification.kind,
                AwsCliOperationKind::CloudFormationCreate,
                "cloudformation:{operation} must be CloudFormationCreate"
            );
        }
    }

    #[test]
    fn template_body_update_operations_have_cloud_formation_update_kind() {
        let schema_validator = SchemaValidator::default();
        for operation in ["UpdateStack", "UpdateStackSet"] {
            let req = request("cloudformation", operation, serde_json::json!({}));
            let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
            assert_eq!(
                classification.kind,
                AwsCliOperationKind::CloudFormationUpdate,
                "cloudformation:{operation} must be CloudFormationUpdate"
            );
        }
    }

    #[test]
    fn template_body_readonly_operations_have_readonly_kind() {
        let schema_validator = SchemaValidator::default();
        for operation in ["EstimateTemplateCost", "GetTemplateSummary", "ValidateTemplate"] {
            let req = request("cloudformation", operation, serde_json::json!({}));
            let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
            assert_eq!(
                classification.kind,
                AwsCliOperationKind::ReadOnly,
                "cloudformation:{operation} must be ReadOnly"
            );
        }
    }

    #[test]
    fn template_body_readonly_operations_still_validate_payload() {
        let engine = NoopEngine::default();
        let schema_validator = SchemaValidator::default();
        let template = br#"{"Resources":{}}"#.to_vec();
        for operation in ["EstimateTemplateCost", "GetTemplateSummary", "ValidateTemplate"] {
            let parameters: HashMap<String, AwsCliValue> =
                [("TemplateBody".to_string(), AwsCliValue::Bytes { value: template.clone() })].into_iter().collect();
            let req = AwsCliCommand::new("cloudformation", operation, parameters);
            let validation = validate_aws_cli_command(&engine, &schema_validator, &req, ValidateConfig::default())
                .expect("validation succeeds");
            assert_eq!(
                validation.status,
                AwsCliCommandValidationStatus::Validated,
                "cloudformation:{operation} with TemplateBody must still validate"
            );
            assert_eq!(validation.template_source, Some(AwsCliTemplateSource::TemplateBody));
        }
    }

    #[test]
    fn unknown_cloudformation_verbs_remain_unmapped() {
        let schema_validator = SchemaValidator::default();
        let req = request("cloudformation", "DeleteChangeSet", serde_json::json!({}));
        let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
        assert_eq!(classification.kind, AwsCliOperationKind::UnmappedMutation);
        assert!(classification.candidates.is_empty());
    }

    #[test]
    fn unmapped_parameter_skips_synthesis_with_reason() {
        let schema_validator = SchemaValidator::default();
        let req = request("s3", "CreateBucket", serde_json::json!({"Bucket": "test-bucket", "UnknownParam": "value"}));
        let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
        let synthesis = synthesize_request(&req, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none(), "unmapped parameter must skip synthesis");
        assert!(
            synthesis.reason.contains("UnknownParam") && synthesis.reason.contains("no mapping"),
            "reason must name the unmapped parameter: {}",
            synthesis.reason
        );
    }

    #[test]
    fn ignored_input_does_not_block_synthesis() {
        let schema_validator = SchemaValidator::default();
        let schema = schema_validator.resource_schema_metadata("AWS::S3::Bucket").expect("S3 bucket schema must exist");
        let adapter = OperationAdapter {
            service: "s3".into(),
            operation: "CreateBucket".into(),
            phase: AdapterPhase::Create,
            cfn_type: "AWS::S3::Bucket".into(),
            mappings: vec![mapping("Bucket", "BucketName")],
            ignored_inputs: vec!["ClientToken".into()],
        };
        let parameters: HashMap<String, AwsCliValue> = [
            ("Bucket".into(), AwsCliValue::String { value: "test".into() }),
            ("ClientToken".into(), AwsCliValue::String { value: "idempotent-token".into() }),
        ]
        .into_iter()
        .collect();
        let result = map_adapter_properties(&parameters, &schema, &adapter).expect("mapping must succeed");
        match result {
            AdapterMappingResult::Mapped(properties) => {
                assert_eq!(properties.len(), 1);
                assert_eq!(properties["BucketName"], serde_json::json!("test"));
            }
            AdapterMappingResult::Skip(reason) => {
                panic!("ignored input should not skip synthesis: {reason}");
            }
        }
    }

    #[test]
    fn update_adapter_ignores_primary_identifier_parameters() {
        let schema_validator = SchemaValidator::default();
        let schema = schema_validator
            .resource_schema_metadata("AWS::Lambda::Function")
            .expect("Lambda function schema must exist");
        let adapter = OperationAdapter {
            service: "lambda".into(),
            operation: "UpdateFunctionConfiguration".into(),
            phase: AdapterPhase::Update,
            cfn_type: "AWS::Lambda::Function".into(),
            mappings: vec![mapping("MemorySize", "MemorySize")],
            ignored_inputs: Vec::new(),
        };
        // FunctionName is a primary identifier for AWS::Lambda::Function
        let parameters: HashMap<String, AwsCliValue> = [
            ("MemorySize".into(), AwsCliValue::Integer { value: 256 }),
            ("FunctionName".into(), AwsCliValue::String { value: "my-func".into() }),
        ]
        .into_iter()
        .collect();
        let result = map_adapter_properties(&parameters, &schema, &adapter).expect("mapping must succeed");
        match result {
            AdapterMappingResult::Mapped(properties) => {
                assert_eq!(properties.len(), 1);
                assert_eq!(properties["MemorySize"], serde_json::json!(256));
            }
            AdapterMappingResult::Skip(reason) => {
                panic!("primary identifier on update must be ignored: {reason}");
            }
        }
    }

    #[test]
    fn all_mapped_parameters_produce_successful_synthesis() {
        let schema_validator = SchemaValidator::default();
        let req = request("s3", "CreateBucket", serde_json::json!({"Bucket": "all-mapped"}));
        let classification = classify_operation(&req, &schema_validator).expect("classification succeeds");
        let synthesis = synthesize_request(&req, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_some(), "all-mapped parameters must synthesize");
    }

    #[test]
    fn catalog_ignored_inputs_deserialize_from_missing_field() {
        let json = br#"{
            "format_version": 1,
            "adapters": [
                {"service":"test","operation":"Create","phase":"create","cfn_type":"AWS::Test::Type","mappings":[]}
            ]
        }"#;
        let registry = parse_adapter_registry(json).expect("catalog without ignored_inputs must parse");
        let adapter = registry.get(&("test".to_string(), "Create".to_string())).expect("adapter must exist");
        assert!(adapter.ignored_inputs.is_empty(), "missing field defaults to empty");
    }

    #[test]
    fn catalog_ignored_inputs_deserialize_from_explicit_field() {
        let json = br#"{
            "format_version": 1,
            "adapters": [
                {"service":"test","operation":"Create","phase":"create","cfn_type":"AWS::Test::Type",
                 "mappings":[],"ignored_inputs":["ClientToken","DryRun"]}
            ]
        }"#;
        let registry = parse_adapter_registry(json).expect("catalog with ignored_inputs must parse");
        let adapter = registry.get(&("test".to_string(), "Create".to_string())).expect("adapter must exist");
        assert_eq!(adapter.ignored_inputs, vec!["ClientToken", "DryRun"]);
    }
}
