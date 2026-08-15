use data_source::embedded::AWS_API_ACTIONS_BYTES;
use diagnostics::{DetailedReport, StandardReport, Summary, ValidationReport};
use rules::Severity;
use schema_validator::{PropertyValueType, ResourceSchemaMetadata, SchemaValidator};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

use crate::{ValidateConfig, ValidationEngine, ValidationError, validate_bytes_with_path};

/// A recursively typed value from an AWS API request.
///
/// Unlike JSON, this model preserves byte strings such as CloudFormation's
/// `TemplateBody`. `Unsupported` lets language bindings carry an explicit marker
/// for a runtime value they cannot represent rather than coercing it silently.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AwsApiValue {
    Null,
    Boolean { value: bool },
    Integer { value: i64 },
    UnsignedInteger { value: u64 },
    Number { value: f64 },
    String { value: String },
    Bytes { value: Vec<u8> },
    Array { items: Vec<AwsApiValue> },
    Object { entries: HashMap<String, AwsApiValue> },
    Unsupported { type_name: String },
}

impl AwsApiValue {
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

impl From<serde_json::Value> for AwsApiValue {
    fn from(value: serde_json::Value) -> Self {
        Self::from_json(value)
    }
}

/// AWS service, operation, and input values needed to model one API request as
/// CloudFormation resource state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct AwsApiRequestContext {
    pub service_name: String,
    pub operation_name: String,
    pub parameters: HashMap<String, AwsApiValue>,
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

/// Idiomatic Rust name for the AWS API request context record.
pub type AwsApiRequest = AwsApiRequestContext;

impl AwsApiRequestContext {
    pub fn new(
        service_name: impl Into<String>,
        operation_name: impl Into<String>,
        parameters: impl IntoIterator<Item = (String, AwsApiValue)>,
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

    fn effective_service_prefix(&self) -> &str {
        self.service_prefix.as_deref().filter(|prefix| !prefix.is_empty()).unwrap_or(&self.service_name)
    }

    fn default_file_path(&self) -> String {
        format!("aws-api://{}/{}", self.service_name, self.operation_name)
    }
}

/// Closed classification of an AWS API operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AwsApiOperationKind {
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
pub enum AwsApiRequestValidationStatus {
    Validated,
    Skipped,
}

/// Provenance of the template validated for an AWS API request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AwsApiTemplateSource {
    TemplateBody,
    CloudControlDesiredState,
    SynthesizedCreate,
    SynthesizedUpdate,
}

/// Full Rust result for AWS API request validation.
#[derive(Debug, Clone)]
#[must_use]
pub struct AwsApiRequestValidation {
    pub operation_kind: AwsApiOperationKind,
    pub status: AwsApiRequestValidationStatus,
    pub template_source: Option<AwsApiTemplateSource>,
    pub resource_types: Vec<String>,
    pub reason: String,
    pub report: Option<ValidationReport>,
}

/// AWS API request result containing standard diagnostics.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct StandardAwsApiRequestValidation {
    pub operation_kind: AwsApiOperationKind,
    pub status: AwsApiRequestValidationStatus,
    pub template_source: Option<AwsApiTemplateSource>,
    pub resource_types: Vec<String>,
    pub reason: String,
    pub report: Option<StandardReport>,
}

/// AWS API request result containing detailed diagnostics and context.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct DetailedAwsApiRequestValidation {
    pub operation_kind: AwsApiOperationKind,
    pub status: AwsApiRequestValidationStatus,
    pub template_source: Option<AwsApiTemplateSource>,
    pub resource_types: Vec<String>,
    pub reason: String,
    pub report: Option<DetailedReport>,
}

impl AwsApiRequestValidation {
    pub fn to_standard(&self) -> StandardAwsApiRequestValidation {
        StandardAwsApiRequestValidation {
            operation_kind: self.operation_kind,
            status: self.status,
            template_source: self.template_source,
            resource_types: self.resource_types.clone(),
            reason: self.reason.clone(),
            report: self.report.as_ref().map(ValidationReport::to_standard),
        }
    }

    pub fn to_detailed(&self) -> DetailedAwsApiRequestValidation {
        DetailedAwsApiRequestValidation {
            operation_kind: self.operation_kind,
            status: self.status,
            template_source: self.template_source,
            resource_types: self.resource_types.clone(),
            reason: self.reason.clone(),
            report: self.report.as_ref().map(ValidationReport::to_detailed),
        }
    }
}

/// Classifies, models, and validates one AWS API request entirely offline.
pub fn validate_aws_api_request(
    engine: &dyn ValidationEngine,
    schema_validator: &SchemaValidator,
    request: &AwsApiRequest,
    config: ValidateConfig,
) -> Result<AwsApiRequestValidation, ValidationError> {
    validate_aws_api_request_with_path(engine, schema_validator, request, config, request.default_file_path())
}

/// Same as [`validate_aws_api_request`], with an explicit report path supplied
/// by the embedding application.
pub fn validate_aws_api_request_with_path(
    engine: &dyn ValidationEngine,
    schema_validator: &SchemaValidator,
    request: &AwsApiRequest,
    config: ValidateConfig,
    file_path: String,
) -> Result<AwsApiRequestValidation, ValidationError> {
    let catalog = action_catalog()?;
    let classification = classify_operation(request, schema_validator, catalog);
    let synthesis = synthesize_request(request, &classification, schema_validator)?;
    let Some(template) = synthesis.template else {
        return Ok(AwsApiRequestValidation {
            operation_kind: classification.kind,
            status: AwsApiRequestValidationStatus::Skipped,
            template_source: None,
            resource_types: synthesis.resource_types,
            reason: synthesis.reason,
            report: None,
        });
    };

    let mut report = validate_bytes_with_path(engine, schema_validator, &template, config, file_path)?;
    if let Some(properties) = synthesis.diagnostic_properties.as_ref() {
        scope_partial_update_report(&mut report, properties);
    }
    Ok(AwsApiRequestValidation {
        operation_kind: classification.kind,
        status: AwsApiRequestValidationStatus::Validated,
        template_source: synthesis.source,
        resource_types: synthesis.resource_types,
        reason: synthesis.reason,
        report: Some(report),
    })
}

type HandlerRoles = HashMap<String, Vec<String>>;
type ActionCatalog = HashMap<String, HandlerRoles>;

static ACTION_CATALOG: LazyLock<Result<ActionCatalog, String>> = LazyLock::new(|| {
    serde_json::from_slice(&AWS_API_ACTIONS_BYTES)
        .map_err(|error| format!("embedded AWS API action catalog is invalid: {error}"))
});

fn action_catalog() -> Result<&'static ActionCatalog, ValidationError> {
    ACTION_CATALOG.as_ref().map_err(|message| ValidationError::Engine(message.clone()))
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

impl OperationPhase {
    fn handler_role(self) -> Option<&'static str> {
        match self {
            Self::Create => Some("create"),
            Self::Update => Some("update"),
            Self::Delete => Some("delete"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct Classification {
    kind: AwsApiOperationKind,
    phase: OperationPhase,
    candidates: Vec<String>,
}

const MODIFIER_PREFIXES: &[&str] = &["Admin", "Batch", "Bulk", "Transact"];
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
const DATA_PLANE_IF_UNMAPPED_VERBS: &[&str] =
    &["Execute", "Invoke", "Post", "Publish", "Put", "Send", "Upload", "Write"];

fn classify_operation(
    request: &AwsApiRequest,
    schema_validator: &SchemaValidator,
    catalog: &ActionCatalog,
) -> Classification {
    let prefix = request.effective_service_prefix();
    let words = operation_words(&request.operation_name);
    let verb = effective_verb(&words);
    let action_key = format!("{prefix}:{}", request.operation_name).to_ascii_lowercase();
    let action_roles = catalog.get(&action_key);
    let phase = operation_phase(request, action_roles, verb);

    match phase {
        OperationPhase::Read => Classification { kind: AwsApiOperationKind::ReadOnly, phase, candidates: Vec::new() },
        OperationPhase::Data => {
            Classification { kind: AwsApiOperationKind::DataPlaneMutation, phase, candidates: Vec::new() }
        }
        OperationPhase::Create | OperationPhase::Update | OperationPhase::Delete => {
            let candidates =
                explicit_resource_type(request, schema_validator).map(|type_name| vec![type_name]).unwrap_or_else(
                    || candidate_types(schema_validator, action_roles, phase, prefix, operation_noun(&words)),
                );
            if candidates.is_empty() {
                let is_data_plane = DATA_PLANE_IF_UNMAPPED_VERBS.contains(&verb);
                Classification {
                    kind: if is_data_plane {
                        AwsApiOperationKind::DataPlaneMutation
                    } else {
                        AwsApiOperationKind::UnmappedMutation
                    },
                    phase: if is_data_plane { OperationPhase::Data } else { phase },
                    candidates,
                }
            } else {
                let kind = match phase {
                    OperationPhase::Create => AwsApiOperationKind::CloudFormationCreate,
                    OperationPhase::Update => AwsApiOperationKind::CloudFormationUpdate,
                    OperationPhase::Delete => AwsApiOperationKind::CloudFormationDelete,
                    _ => AwsApiOperationKind::UnmappedMutation,
                };
                Classification { kind, phase, candidates }
            }
        }
        OperationPhase::Unknown => {
            Classification { kind: AwsApiOperationKind::UnmappedMutation, phase, candidates: Vec::new() }
        }
    }
}

fn operation_phase(request: &AwsApiRequest, action_roles: Option<&HandlerRoles>, verb: &str) -> OperationPhase {
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
    action_roles.and_then(phase_from_roles).unwrap_or(OperationPhase::Unknown)
}

fn phase_from_roles(action_roles: &HandlerRoles) -> Option<OperationPhase> {
    if action_roles.contains_key("read") || action_roles.contains_key("list") {
        return None;
    }
    let write_roles: Vec<&str> =
        ["create", "update", "delete"].into_iter().filter(|role| action_roles.contains_key(*role)).collect();
    match write_roles.as_slice() {
        ["create"] => Some(OperationPhase::Create),
        ["update"] => Some(OperationPhase::Update),
        ["delete"] => Some(OperationPhase::Delete),
        _ => None,
    }
}

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

fn operation_noun(words: &[String]) -> String {
    let words =
        if words.first().is_some_and(|word| MODIFIER_PREFIXES.contains(&word.as_str())) { &words[1..] } else { words };
    words.iter().skip(1).map(String::as_str).collect()
}

fn explicit_resource_type(request: &AwsApiRequest, schema_validator: &SchemaValidator) -> Option<String> {
    match request.parameters.get("TypeName") {
        Some(AwsApiValue::String { value }) if schema_validator.has_resource_type(value) => Some(value.clone()),
        _ => None,
    }
}

fn candidate_types(
    schema_validator: &SchemaValidator,
    action_roles: Option<&HandlerRoles>,
    phase: OperationPhase,
    prefix: &str,
    noun: String,
) -> Vec<String> {
    let mut role_candidates = BTreeSet::new();
    if let (Some(action_roles), Some(role)) = (action_roles, phase.handler_role()) {
        if let Some(candidates) = action_roles.get(role) {
            role_candidates
                .extend(candidates.iter().filter(|candidate| schema_validator.has_resource_type(candidate)).cloned());
        }
        if phase == OperationPhase::Update
            && let Some(candidates) = action_roles.get("create")
        {
            role_candidates
                .extend(candidates.iter().filter(|candidate| schema_validator.has_resource_type(candidate)).cloned());
        }
    }

    let mut resource_candidates = role_candidates.clone();
    resource_candidates.extend(
        schema_validator
            .resource_type_names()
            .filter(|type_name| score_candidate(type_name, prefix, &noun) > 0)
            .map(str::to_string),
    );
    let scores: BTreeMap<String, u32> = resource_candidates
        .into_iter()
        .map(|type_name| {
            let score = score_candidate(&type_name, prefix, &noun);
            (type_name, score)
        })
        .collect();
    let best_score = scores.values().copied().max().unwrap_or(0);
    if best_score < 120 {
        return Vec::new();
    }
    scores.into_iter().filter_map(|(type_name, score)| (score == best_score).then_some(type_name)).collect()
}

fn normalize(value: &str) -> String {
    value.chars().filter(char::is_ascii_alphanumeric).flat_map(char::to_lowercase).collect()
}

fn namespace_score(namespace: &str, prefix: &str) -> u32 {
    let namespace = normalize(namespace);
    let prefix = normalize(prefix);
    if namespace == prefix {
        100
    } else if !namespace.is_empty()
        && !prefix.is_empty()
        && (namespace.contains(&prefix) || prefix.contains(&namespace))
    {
        70
    } else {
        0
    }
}

fn resource_score(resource_name: &str, noun: &str) -> u32 {
    let resource = normalize(resource_name);
    let noun = normalize(noun);
    if resource.is_empty() || noun.is_empty() {
        0
    } else if resource == noun {
        100
    } else if noun.contains(&resource) {
        40 + (40 * resource.len() / noun.len()) as u32
    } else if resource.contains(&noun) {
        30 + (30 * noun.len() / resource.len()) as u32
    } else {
        0
    }
}

fn score_candidate(type_name: &str, prefix: &str, noun: &str) -> u32 {
    let parts: Vec<&str> = type_name.split("::").collect();
    if parts.len() != 3 {
        return 0;
    }
    let namespace = namespace_score(parts[1], prefix);
    let resource = resource_score(parts[2], noun);
    if namespace == 0 || resource == 0 { 0 } else { namespace + resource }
}

struct Synthesis {
    template: Option<Vec<u8>>,
    source: Option<AwsApiTemplateSource>,
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
    request: &AwsApiRequest,
    classification: &Classification,
    schema_validator: &SchemaValidator,
) -> Result<Synthesis, ValidationError> {
    if classification.kind == AwsApiOperationKind::ReadOnly {
        return Ok(Synthesis::skipped("read-only calls do not need validation", Vec::new()));
    }
    if let Some(template) = template_body_bytes(request.parameters.get("TemplateBody")) {
        return Ok(Synthesis {
            template: Some(template),
            source: Some(AwsApiTemplateSource::TemplateBody),
            reason: "using exact request TemplateBody".into(),
            resource_types: Vec::new(),
            diagnostic_properties: None,
        });
    }
    if request.parameters.contains_key("TemplateURL") {
        return Ok(Synthesis::skipped("TemplateURL content is unavailable to the offline validator", Vec::new()));
    }
    if request.parameters.contains_key("TypeName") && request.parameters.contains_key("DesiredState") {
        return desired_state_template(request, schema_validator);
    }
    generic_template(request, classification, schema_validator)
}

fn template_body_bytes(value: Option<&AwsApiValue>) -> Option<Vec<u8>> {
    match value {
        Some(AwsApiValue::Bytes { value }) if !value.is_empty() => Some(value.clone()),
        Some(AwsApiValue::String { value }) if !value.is_empty() => Some(value.as_bytes().to_vec()),
        _ => None,
    }
}

fn desired_state_template(
    request: &AwsApiRequest,
    schema_validator: &SchemaValidator,
) -> Result<Synthesis, ValidationError> {
    let Some(AwsApiValue::String { value: type_name }) = request.parameters.get("TypeName") else {
        return Ok(Synthesis::skipped("DesiredState has no known CloudFormation TypeName", Vec::new()));
    };
    if !schema_validator.has_resource_type(type_name) {
        return Ok(Synthesis::skipped("DesiredState has no known CloudFormation TypeName", Vec::new()));
    }
    let Some(desired_state) = request.parameters.get("DesiredState") else {
        return Ok(Synthesis::skipped("DesiredState is missing", vec![type_name.clone()]));
    };
    let properties = match desired_state {
        AwsApiValue::String { value } if !value.is_empty() => serde_json::from_str(value),
        AwsApiValue::Bytes { value } if !value.is_empty() => serde_json::from_slice(value),
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
        source: Some(AwsApiTemplateSource::CloudControlDesiredState),
        reason: "wrapped exact Cloud Control desired state".into(),
        resource_types: vec![type_name.clone()],
        diagnostic_properties: None,
    })
}

fn generic_template(
    request: &AwsApiRequest,
    classification: &Classification,
    schema_validator: &SchemaValidator,
) -> Result<Synthesis, ValidationError> {
    if !matches!(
        classification.kind,
        AwsApiOperationKind::CloudFormationCreate | AwsApiOperationKind::CloudFormationUpdate
    ) {
        return Ok(Synthesis::skipped(
            "classification has no representable resource state",
            classification.candidates.clone(),
        ));
    }
    if classification.candidates.len() != 1 {
        return Ok(Synthesis::skipped(
            "CloudFormation resource candidate is ambiguous",
            classification.candidates.clone(),
        ));
    }
    let type_name = &classification.candidates[0];
    let Some(schema) = schema_validator.resource_schema_metadata(type_name) else {
        return Ok(Synthesis::skipped("CloudFormation resource candidate is unknown", vec![type_name.clone()]));
    };
    let properties = match map_properties(&request.parameters, &schema, classification.phase) {
        Ok(properties) => properties,
        Err(reason) => return Ok(Synthesis::skipped(reason, vec![type_name.clone()])),
    };
    let diagnostic_properties =
        (classification.phase == OperationPhase::Update).then(|| properties.keys().cloned().collect::<BTreeSet<_>>());
    let source = if classification.phase == OperationPhase::Update {
        AwsApiTemplateSource::SynthesizedUpdate
    } else {
        AwsApiTemplateSource::SynthesizedCreate
    };
    let reason = if classification.phase == OperationPhase::Update {
        "synthesized explicitly updated CloudFormation properties"
    } else {
        "synthesized one unambiguous CloudFormation resource"
    };
    let properties: serde_json::Map<String, serde_json::Value> = properties.into_iter().collect();
    Ok(Synthesis {
        template: Some(resource_template(type_name, &properties)?),
        source: Some(source),
        reason: reason.into(),
        resource_types: vec![type_name.clone()],
        diagnostic_properties,
    })
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

fn map_properties(
    parameters: &HashMap<String, AwsApiValue>,
    schema: &ResourceSchemaMetadata,
    phase: OperationPhase,
) -> Result<BTreeMap<String, serde_json::Value>, String> {
    let resource_name = schema.type_name.rsplit("::").next().unwrap_or(&schema.type_name);
    let mut excluded = schema.read_only_properties.clone();
    if phase == OperationPhase::Update {
        excluded.extend(schema.primary_identifier_properties.iter().cloned());
    }
    let mut mapped = BTreeMap::new();
    let mut parameters: Vec<(&String, &AwsApiValue)> = parameters.iter().collect();
    parameters.sort_by_key(|(name, _)| name.as_str());

    for (parameter_name, value) in parameters {
        let matches: Vec<&String> = schema
            .property_types
            .keys()
            .filter(|property_name| {
                !excluded.contains(*property_name) && property_matches(parameter_name, property_name, resource_name)
            })
            .collect();
        if matches.len() > 1 {
            return Err(format!("parameter {parameter_name} maps to multiple resource properties"));
        }
        let Some(property_name) = matches.first().copied() else {
            continue;
        };
        if mapped.contains_key(property_name) {
            return Err(format!("multiple parameters map to {property_name}"));
        }
        let accepted_types = &schema.property_types[property_name];
        if let Some(value) = mapped_value(value, accepted_types, property_name) {
            mapped.insert(property_name.clone(), value);
        }
    }

    if mapped.is_empty() {
        return Err("no request parameters map to resource properties".into());
    }
    if phase == OperationPhase::Create {
        let mapped_properties: BTreeSet<String> = mapped.keys().cloned().collect();
        let missing: Vec<&String> = schema.required_properties.difference(&mapped_properties).collect();
        if !missing.is_empty() {
            return Err(format!(
                "required resource properties are absent: {}",
                missing.into_iter().map(String::as_str).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    Ok(mapped)
}

fn property_matches(parameter_name: &str, property_name: &str, resource_name: &str) -> bool {
    let parameter = normalize(parameter_name);
    let property = normalize(property_name);
    let resource = normalize(resource_name);
    parameter == property
        || property == format!("{resource}{parameter}")
        || (property == format!("{parameter}name") && parameter == resource)
}

fn mapped_value(
    value: &AwsApiValue,
    accepted_types: &BTreeSet<PropertyValueType>,
    property_name: &str,
) -> Option<serde_json::Value> {
    if value_matches_types(value, accepted_types) {
        return value.json_value();
    }
    if property_name == "Tags"
        && accepts_type(accepted_types, PropertyValueType::Array)
        && let AwsApiValue::Object { entries } = value
        && entries.values().all(|value| matches!(value, AwsApiValue::String { .. }))
    {
        let mut tags: Vec<(&String, &AwsApiValue)> = entries.iter().collect();
        tags.sort_by_key(|(key, _)| key.as_str());
        return Some(serde_json::Value::Array(
            tags.into_iter()
                .filter_map(|(key, value)| match value {
                    AwsApiValue::String { value } => Some(serde_json::json!({"Key": key, "Value": value})),
                    _ => None,
                })
                .collect(),
        ));
    }
    if accepts_type(accepted_types, PropertyValueType::String) {
        let value = match value {
            AwsApiValue::Boolean { value } => Some(value.to_string()),
            AwsApiValue::Integer { value } => Some(value.to_string()),
            AwsApiValue::UnsignedInteger { value } => Some(value.to_string()),
            AwsApiValue::Number { value } => serde_json::Number::from_f64(*value).map(|value| value.to_string()),
            _ => None,
        };
        return value.map(serde_json::Value::String);
    }
    None
}

fn accepts_type(types: &BTreeSet<PropertyValueType>, expected: PropertyValueType) -> bool {
    types.contains(&PropertyValueType::Any) || types.contains(&expected)
}

fn value_matches_types(value: &AwsApiValue, types: &BTreeSet<PropertyValueType>) -> bool {
    if types.contains(&PropertyValueType::Any) {
        return !matches!(value, AwsApiValue::Null | AwsApiValue::Bytes { .. } | AwsApiValue::Unsupported { .. });
    }
    match value {
        AwsApiValue::Array { .. } => types.contains(&PropertyValueType::Array),
        AwsApiValue::Object { .. } => types.contains(&PropertyValueType::Object),
        AwsApiValue::Boolean { .. } => types.contains(&PropertyValueType::Boolean),
        AwsApiValue::Integer { .. } | AwsApiValue::UnsignedInteger { .. } => {
            types.contains(&PropertyValueType::Integer) || types.contains(&PropertyValueType::Number)
        }
        AwsApiValue::Number { .. } => types.contains(&PropertyValueType::Number),
        AwsApiValue::String { .. } => types.contains(&PropertyValueType::String),
        AwsApiValue::Null | AwsApiValue::Bytes { .. } | AwsApiValue::Unsupported { .. } => false,
    }
}

fn scope_partial_update_report(report: &mut ValidationReport, properties: &BTreeSet<String>) {
    let before = report.diagnostics.len();
    report.diagnostics.retain(|diagnostic| {
        diagnostic.property_path.as_deref().is_some_and(|path| diagnostic_in_scope(path, properties))
    });
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
    use diagnostics::{Diagnostic, PhaseMetric};
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

    fn value(value: serde_json::Value) -> AwsApiValue {
        AwsApiValue::from_json(value)
    }

    fn request(service: &str, operation: &str, parameters: serde_json::Value) -> AwsApiRequest {
        let parameters: HashMap<String, AwsApiValue> = parameters
            .as_object()
            .expect("test parameters must be an object")
            .iter()
            .map(|(name, value)| (name.clone(), AwsApiValue::from_json(value.clone())))
            .collect();
        AwsApiRequest::new(service, operation, parameters).with_service_prefix(service).with_http_method("POST")
    }

    fn synthesized_json(request: &AwsApiRequest) -> (Classification, Synthesis, serde_json::Value) {
        let schema_validator = SchemaValidator::default();
        let classification = classify_operation(request, &schema_validator, action_catalog().expect("catalog loads"));
        let synthesis = synthesize_request(request, &classification, &schema_validator).expect("synthesis succeeds");
        let template = synthesis.template.as_ref().expect("request must synthesize");
        let document = serde_json::from_slice(template).expect("template must be JSON");
        (classification, synthesis, document)
    }

    #[test]
    fn operation_words_preserve_acronyms_for_noun_matching() {
        assert_eq!(operation_words("BatchCreateDB2Cluster"), ["Batch", "Create", "DB", "2", "Cluster"]);
        assert_eq!(effective_verb(&operation_words("BatchCreateDB2Cluster")), "Create");
        assert_eq!(operation_noun(&operation_words("BatchCreateDB2Cluster")), "DB2Cluster");
    }

    #[test]
    fn representative_operations_have_closed_classifications() {
        let schema_validator = SchemaValidator::default();
        let catalog = action_catalog().expect("catalog loads");
        for (service, operation, expected, candidate) in [
            ("s3", "CreateBucket", AwsApiOperationKind::CloudFormationCreate, Some("AWS::S3::Bucket")),
            ("dynamodb", "CreateTable", AwsApiOperationKind::CloudFormationCreate, Some("AWS::DynamoDB::Table")),
            ("iam", "GetRole", AwsApiOperationKind::ReadOnly, None),
            ("lambda", "Invoke", AwsApiOperationKind::DataPlaneMutation, None),
            ("s3", "DeleteBucket", AwsApiOperationKind::CloudFormationDelete, Some("AWS::S3::Bucket")),
        ] {
            let classification =
                classify_operation(&request(service, operation, serde_json::json!({})), &schema_validator, catalog);
            assert_eq!(classification.kind, expected, "{service}:{operation}");
            if let Some(candidate) = candidate {
                assert_eq!(classification.candidates, [candidate], "{service}:{operation}");
            }
        }
    }

    #[test]
    fn explicit_readonly_and_http_get_are_authoritative_read_signals() {
        let schema_validator = SchemaValidator::default();
        let catalog = ActionCatalog::new();
        let mut explicitly_readonly = request("test", "CreateThing", serde_json::json!({}));
        explicitly_readonly.is_read_only = Some(true);
        assert_eq!(
            classify_operation(&explicitly_readonly, &schema_validator, &catalog).kind,
            AwsApiOperationKind::ReadOnly
        );
        let mut get_request = request("test", "FrobnicateThing", serde_json::json!({}));
        get_request.http_method = Some("GET".into());
        assert_eq!(classify_operation(&get_request, &schema_validator, &catalog).kind, AwsApiOperationKind::ReadOnly);
    }

    #[test]
    fn exact_template_body_bytes_are_not_rewritten() {
        let schema_validator = SchemaValidator::default();
        let mut request = request("cloudformation", "CreateChangeSet", serde_json::json!({}));
        let template = br#"{"Resources":{}}"#.to_vec();
        request.parameters.insert("TemplateBody".into(), AwsApiValue::Bytes { value: template.clone() });
        let classification = classify_operation(&request, &schema_validator, action_catalog().expect("catalog loads"));
        let synthesis = synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
        assert_eq!(synthesis.source, Some(AwsApiTemplateSource::TemplateBody));
        assert_eq!(synthesis.template, Some(template));
    }

    #[test]
    fn template_url_is_not_fetched() {
        let schema_validator = SchemaValidator::default();
        let request = request(
            "cloudformation",
            "CreateStack",
            serde_json::json!({"TemplateURL": "https://example.com/template.json"}),
        );
        let classification = classify_operation(&request, &schema_validator, action_catalog().expect("catalog loads"));
        let synthesis = synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
        assert!(synthesis.reason.contains("unavailable"));
    }

    #[test]
    fn desired_state_wraps_any_known_type_and_rejects_unknown_types() {
        let known = request(
            "cloudcontrol",
            "CreateResource",
            serde_json::json!({"TypeName": "AWS::SNS::Topic", "DesiredState": "{\"TopicName\":\"Synthetic\"}"}),
        );
        let (classification, synthesis, document) = synthesized_json(&known);
        assert_eq!(classification.kind, AwsApiOperationKind::CloudFormationCreate);
        assert_eq!(classification.candidates, ["AWS::SNS::Topic"]);
        assert_eq!(synthesis.source, Some(AwsApiTemplateSource::CloudControlDesiredState));
        assert_eq!(document["Resources"]["Resource"]["Properties"]["TopicName"], "Synthetic");

        let schema_validator = SchemaValidator::default();
        let unknown = request(
            "cloudcontrol",
            "CreateResource",
            serde_json::json!({"TypeName": "AWS::Unknown::Type", "DesiredState": "{}"}),
        );
        let classification = classify_operation(&unknown, &schema_validator, action_catalog().expect("catalog loads"));
        let synthesis = synthesize_request(&unknown, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
        assert!(synthesis.reason.contains("known CloudFormation TypeName"));
    }

    #[test]
    fn generic_create_maps_aliases_and_tag_objects() {
        let request =
            request("s3", "CreateBucket", serde_json::json!({"Bucket": "synthetic-bucket", "Tags": {"Team": "CLI"}}));
        let (classification, synthesis, document) = synthesized_json(&request);
        assert_eq!(classification.candidates, ["AWS::S3::Bucket"]);
        assert_eq!(synthesis.source, Some(AwsApiTemplateSource::SynthesizedCreate));
        assert_eq!(document["Resources"]["Resource"]["Properties"]["BucketName"], "synthetic-bucket");
        assert_eq!(
            document["Resources"]["Resource"]["Properties"]["Tags"],
            serde_json::json!([{"Key": "Team", "Value": "CLI"}])
        );
    }

    #[test]
    fn generic_create_requires_complete_resource_state() {
        let schema_validator = SchemaValidator::default();
        let request =
            request("lambda", "CreateFunction", serde_json::json!({"FunctionName": "Synthetic", "MemorySize": 128}));
        let classification = classify_operation(&request, &schema_validator, action_catalog().expect("catalog loads"));
        let synthesis = synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
        assert!(synthesis.template.is_none());
        assert!(synthesis.reason.contains("Code, Role"), "{}", synthesis.reason);
    }

    #[test]
    fn generic_update_excludes_primary_identifier_and_tracks_changed_properties() {
        let request = request(
            "lambda",
            "UpdateFunctionConfiguration",
            serde_json::json!({"FunctionName": "Synthetic", "MemorySize": 128}),
        );
        let (_, synthesis, document) = synthesized_json(&request);
        assert_eq!(synthesis.source, Some(AwsApiTemplateSource::SynthesizedUpdate));
        assert_eq!(document["Resources"]["Resource"]["Properties"], serde_json::json!({"MemorySize": 128}));
        assert_eq!(synthesis.diagnostic_properties, Some(BTreeSet::from(["MemorySize".into()])));
    }

    #[test]
    fn incompatible_optional_property_is_omitted() {
        let request =
            request("s3", "CreateBucket", serde_json::json!({"Bucket": "synthetic-bucket", "Tags": {"Key": 42}}));
        let (_, _, document) = synthesized_json(&request);
        assert_eq!(
            document["Resources"]["Resource"]["Properties"],
            serde_json::json!({"BucketName": "synthetic-bucket"})
        );
    }

    #[test]
    fn data_plane_and_delete_requests_do_not_fabricate_resource_state() {
        let schema_validator = SchemaValidator::default();
        for request in [
            request("dynamodb", "PutItem", serde_json::json!({"TableName": "Synthetic"})),
            request("s3", "DeleteBucket", serde_json::json!({"Bucket": "synthetic-bucket"})),
        ] {
            let classification =
                classify_operation(&request, &schema_validator, action_catalog().expect("catalog loads"));
            let synthesis =
                synthesize_request(&request, &classification, &schema_validator).expect("synthesis succeeds");
            assert!(synthesis.template.is_none());
            assert!(synthesis.reason.contains("representable resource state"));
        }
    }

    #[test]
    fn high_level_api_validates_exact_template_and_reports_skips() {
        let engine = NoopEngine::default();
        let schema_validator = SchemaValidator::default();
        let mut exact = request("cloudformation", "CreateChangeSet", serde_json::json!({}));
        exact.parameters.insert("TemplateBody".into(), AwsApiValue::Bytes { value: br#"{"Resources":{}}"#.to_vec() });
        let validation = validate_aws_api_request(&engine, &schema_validator, &exact, ValidateConfig::default())
            .expect("validation succeeds");
        assert_eq!(validation.status, AwsApiRequestValidationStatus::Validated);
        assert_eq!(validation.template_source, Some(AwsApiTemplateSource::TemplateBody));
        assert!(validation.report.is_some());

        let read = request("iam", "GetRole", serde_json::json!({"RoleName": "Synthetic"}));
        let validation = validate_aws_api_request(&engine, &schema_validator, &read, ValidateConfig::default())
            .expect("classification succeeds");
        assert_eq!(validation.status, AwsApiRequestValidationStatus::Skipped);
        assert_eq!(validation.operation_kind, AwsApiOperationKind::ReadOnly);
        assert!(validation.report.is_none());
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
        let validation = validate_aws_api_request(&engine, &schema_validator, &update, ValidateConfig::default())
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
        let request = AwsApiRequest::new("dynamodb", "CreateTable", parameters).with_service_prefix("dynamodb");
        let _ = synthesized_json(&request);
        assert_eq!(request.parameters, original);
    }

    #[test]
    fn json_conversion_rejects_non_json_values_without_coercion() {
        assert!(AwsApiValue::Bytes { value: vec![1, 2] }.to_json().is_err());
        assert!(AwsApiValue::Number { value: f64::NAN }.to_json().is_err());
        assert!(AwsApiValue::Unsupported { type_name: "timestamp".into() }.to_json().is_err());
    }
}
