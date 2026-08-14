//! Structural validation of embedded IAM identity policy documents.
//!
//! IAM identity policies are embedded JSON inside CloudFormation properties
//! (`PolicyDocument`, `InlinePolicy`). IAM rejects a malformed document at
//! deploy time, so the shape is validated here: allowed top-level keys, the
//! `Version` enum, the `Statement` list, and each statement's keys, `Effect`
//! enum, exactly-one-of `Action`/`NotAction` and `Resource`/`NotResource`
//! pairs, value types, `Sid` uniqueness, the `Condition` operator/value schema,
//! and the resource-ARN format.
//!
//! This engine-agnostic implementation lets every consumer apply the same
//! policy-document semantics. Marker-bearing fields are skipped individually:
//! independent literal fields remain statically verifiable.
//! Intrinsic-generated descendants are recognized by path ancestry in the
//! `substituted` set so they suppress only checks depending on their
//! generated value.

use crate::conditions::Satisfiability;
use crate::consts::{
    MARKER_CONDITIONAL, MARKER_DYNAMIC, MARKER_ENUM, MARKER_IF_FALSE, MARKER_IF_TRUE, MARKER_INTRINSIC, MARKER_REF,
};
use crate::message::render_str_list;
use crate::model::SemanticModel;
use crate::serialization::resolved_value_to_json;
use serde_json::Value;
use std::collections::HashSet;

/// One structural defect in a policy document. `path` is relative to the
/// document root (empty for a document-level finding), dot-separated with
/// numeric list indices, e.g. `Statement.0.Effect`.
#[derive(Debug, Clone)]
pub struct PolicyFinding {
    pub path: String,
    pub message: String,
}

const IDENTITY_DOCUMENT_KEYS: &[&str] = &["Statement", "Version"];
const VERSION_VALUES: &[&str] = &["2008-10-17", "2012-10-17"];
const EFFECT_VALUES: &[&str] = &["Allow", "Deny"];
const IDENTITY_STATEMENT_KEYS: &[&str] =
    &["Action", "Condition", "Effect", "NotAction", "NotResource", "Resource", "Sid"];

/// The ARN shape IAM accepts in a `Resource`/`NotResource` entry: a full ARN
/// or the lone `*`. Wildcards may appear in the partition but not the service.
const RESOURCE_ARN_PATTERN: &str =
    "^(arn:(aws[A-Za-z\\-]*?|[A-Za-z?*\\-]*[?*][A-Za-z?*\\-]*):[^:*?]+:[^:]*(:(?:\\d{12}|\\*|aws)?:.+|)|\\*)$";

const CONDITION_OPERATORS: &[&str] = &[
    "ArnEquals",
    "ArnLike",
    "ArnNotEquals",
    "ArnNotLike",
    "BinaryEquals",
    "Bool",
    "DateEquals",
    "DateGreaterThan",
    "DateGreaterThanEquals",
    "DateLessThan",
    "DateLessThanEquals",
    "DateNotEquals",
    "IpAddress",
    "NotIpAddress",
    "Null",
    "NumericEquals",
    "NumericGreaterThan",
    "NumericGreaterThanEquals",
    "NumericLessThan",
    "NumericLessThanEquals",
    "NumericNotEquals",
    "StringEquals",
    "StringEqualsIgnoreCase",
    "StringLike",
    "StringNotEquals",
    "StringNotEqualsIgnoreCase",
    "StringNotLike",
];

fn resource_arn_matches(value: &str) -> bool {
    if value == "*" {
        return true;
    }
    let Some(fields) = split_arn_fields(value) else {
        return false;
    };
    if fields.len() < 3 || fields[0] != "arn" {
        return false;
    }
    if !arn_partition_is_valid(&fields[1]) || !arn_service_is_valid(&fields[2]) {
        return false;
    }

    // IAM policy variables are expanded by IAM and are permitted only in the
    // resource-identifying portion. CloudFormation placeholders such as
    // `${AWS::Partition}` and `${AWS::AccountId}` remain valid in ARN fields.
    if fields.iter().take(5).any(|field| field_has_iam_policy_variable(field)) {
        return false;
    }

    if let Some(account) = fields.get(4)
        && !account.is_empty()
        && account != "*"
        && account != "aws"
        && !field_has_placeholder(account)
        && !(account.len() == 12 && account.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    fields.get(5).is_none_or(|resource| !resource.is_empty())
}

/// Splits an ARN on colons outside `${...}` placeholders. IAM accepts
/// incomplete ARNs (for example `arn:aws:sqs`) and wildcard-completes omitted
/// trailing fields, so only the partition and service fields are mandatory.
fn split_arn_fields(value: &str) -> Option<Vec<String>> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = value.chars().peekable();
    let mut in_placeholder = false;
    while let Some(character) = chars.next() {
        if character == '$' && chars.peek() == Some(&'{') {
            in_placeholder = true;
            current.push(character);
        } else if character == '}' && in_placeholder {
            in_placeholder = false;
            current.push(character);
        } else if character == ':' && !in_placeholder {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
    }
    if in_placeholder {
        return None;
    }
    fields.push(current);
    Some(fields)
}

fn field_has_placeholder(field: &str) -> bool {
    field.contains("${")
}

fn field_has_iam_policy_variable(field: &str) -> bool {
    let mut remaining = field;
    while let Some(start) = remaining.find("${") {
        let content = &remaining[start + 2..];
        let Some(end) = content.find('}') else {
            return true;
        };
        let name = &content[..end];
        if name.contains(':') && !name.starts_with("AWS::") {
            return true;
        }
        remaining = &content[end + 1..];
    }
    false
}

fn field_without_placeholders(field: &str) -> Option<String> {
    let mut output = String::new();
    let mut remaining = field;
    while let Some(start) = remaining.find("${") {
        output.push_str(&remaining[..start]);
        let content = &remaining[start + 2..];
        let end = content.find('}')?;
        remaining = &content[end + 1..];
    }
    output.push_str(remaining);
    Some(output)
}

fn arn_partition_is_valid(partition: &str) -> bool {
    if field_has_iam_policy_variable(partition) {
        return false;
    }
    let Some(literal) = field_without_placeholders(partition) else {
        return false;
    };
    if literal.is_empty() {
        return field_has_placeholder(partition);
    }

    let uses_only_partition_characters =
        literal.chars().all(|character| character.is_ascii_alphabetic() || matches!(character, '-' | '*' | '?'));
    let contains_wildcard = literal.contains(['*', '?']);
    uses_only_partition_characters && (contains_wildcard || literal.starts_with("aws"))
}

fn arn_service_is_valid(service: &str) -> bool {
    if service.contains(['*', '?']) || field_has_iam_policy_variable(service) {
        return false;
    }
    let Some(literal) = field_without_placeholders(service) else {
        return false;
    };
    !literal.is_empty() || field_has_placeholder(service)
}

fn condition_operator_is_valid(operator: &str) -> bool {
    let without_set_operator =
        operator.strip_prefix("ForAnyValue:").or_else(|| operator.strip_prefix("ForAllValues:")).unwrap_or(operator);
    let base = without_set_operator.strip_suffix("IfExists").unwrap_or(without_set_operator);
    CONDITION_OPERATORS.contains(&base)
}

/// Indexes paths whose values came from intrinsic resolution. Exact paths and
/// ancestors use hash lookups; descendants use a sorted-prefix lookup.
struct SubstitutedPathIndex<'a> {
    paths: &'a HashSet<String>,
    sorted_paths: Vec<&'a str>,
}

impl<'a> SubstitutedPathIndex<'a> {
    fn new(paths: &'a HashSet<String>) -> Self {
        let mut sorted_paths: Vec<&str> = paths.iter().map(String::as_str).collect();
        sorted_paths.sort_unstable();
        Self { paths, sorted_paths }
    }

    /// Whether `path` is equal to, an ancestor of, or a descendant of an
    /// indexed path, with dots treated as component boundaries.
    ///
    /// A descendant only suppresses the ancestor when the immediate next path
    /// component is non-numeric (an intrinsic like `Fn::Join`). A numeric
    /// descendant (a list item index) means only that one array element was
    /// generated — it must not suppress the entire list or its other items.
    fn covers(&self, path: &str) -> bool {
        if self.paths.contains("") || self.paths.contains(path) {
            return true;
        }

        if path.match_indices('.').any(|(separator, _)| self.paths.contains(&path[..separator])) {
            return true;
        }

        // Find the first candidate at or beyond the conceptual `path + "."`
        // lower bound without allocating that temporary string. Candidates
        // such as `path-name` sort before `path.name` and must be skipped.
        let descendant_index = self.sorted_paths.partition_point(|candidate| {
            candidate
                .strip_prefix(path)
                .map_or(*candidate < path, |suffix| suffix.as_bytes().first().is_none_or(|first| *first < b'.'))
        });
        self.sorted_paths.get(descendant_index).is_some_and(|candidate| {
            candidate.strip_prefix(path).is_some_and(|suffix| {
                // The suffix starts with '.'; the component after the dot
                // determines whether the descendant generated the ancestor's
                // scalar value or is merely one item of the ancestor's array.
                // Only non-numeric components (intrinsic names like `Fn::Join`)
                // indicate the ancestor was generated.
                if !suffix.starts_with('.') {
                    return false;
                }
                let next_component = &suffix[1..];
                let component_end = next_component.find('.').unwrap_or(next_component.len());
                let first_component = &next_component[..component_end];
                !first_component.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
    }
}

fn path_is_intrinsic_generated(path: &str, substituted: &SubstitutedPathIndex<'_>) -> bool {
    substituted.covers(path)
}

fn is_resolution_marker(value: &Value) -> bool {
    value.as_object().is_some_and(|object| {
        object.contains_key(MARKER_DYNAMIC)
            || object.contains_key(MARKER_REF)
            || object.contains_key(MARKER_INTRINSIC)
            || object.contains_key(MARKER_CONDITIONAL)
            || object.contains_key(MARKER_ENUM)
    })
}

/// Validates an IAM *identity* policy document (no `Principal` allowed).
/// The document must already be concrete JSON; values containing
/// resolved-intrinsic markers are skipped rather than judged.
///
/// `substituted` holds document-relative paths whose values were produced by
/// resolving an intrinsic (a `Ref` to a defaulted parameter, say) rather than
/// written literally. String-content checks are withheld at those paths: the
/// author wrote a reference, not the substituted text.
pub fn validate_identity_policy(doc: &Value, substituted: &HashSet<String>) -> Vec<PolicyFinding> {
    let substituted_index = SubstitutedPathIndex::new(substituted);
    let mut out = Vec::new();
    if is_resolution_marker(doc) {
        return out;
    }
    let Some(obj) = doc.as_object() else {
        out.push(PolicyFinding {
            path: String::new(),
            message: format!("{} is not of type 'object'", describe_value(doc)),
        });
        return out;
    };

    for key in obj.keys() {
        if !IDENTITY_DOCUMENT_KEYS.contains(&key.as_str()) {
            out.push(PolicyFinding {
                path: key.clone(),
                message: format!("Additional properties are not allowed ('{}' was unexpected)", key),
            });
        }
    }

    if let Some(version) = obj.get("Version")
        && !is_resolution_marker(version)
    {
        if let Some(v) = version.as_str() {
            if !VERSION_VALUES.contains(&v) {
                out.push(PolicyFinding {
                    path: "Version".to_string(),
                    message: format!("'{}' is not one of {}", v, render_str_list(VERSION_VALUES)),
                });
            }
        } else {
            out.push(PolicyFinding {
                path: "Version".to_string(),
                message: format!("{} is not of type 'string'", describe_value(version)),
            });
        }
    }

    match obj.get("Statement") {
        None => {
            out.push(PolicyFinding { path: String::new(), message: "'Statement' is a required property".to_string() })
        }
        Some(Value::Array(stmts)) => {
            if stmts.is_empty() {
                out.push(PolicyFinding {
                    path: "Statement".to_string(),
                    message: "[] is too short (minimum 1 item)".to_string(),
                });
            }
            let mut seen_sids: Vec<(String, usize)> = Vec::new();
            for (idx, stmt) in stmts.iter().enumerate() {
                validate_identity_statement(stmt, &format!("Statement.{}", idx), &substituted_index, &mut out);
                if let Some(statement) = stmt.as_object()
                    && let Some(Value::String(sid)) = statement.get("Sid")
                    && !sid.is_empty()
                    && !path_is_intrinsic_generated(&format!("Statement.{}.Sid", idx), &substituted_index)
                {
                    if let Some((_, first_index)) = seen_sids.iter().find(|(seen_sid, _)| seen_sid == sid) {
                        out.push(PolicyFinding {
                            path: format!("Statement.{}.Sid", idx),
                            message: format!("'{}' is a duplicate of Statement.{}.Sid", sid, first_index),
                        });
                    } else {
                        seen_sids.push((sid.clone(), idx));
                    }
                }
            }
        }
        Some(stmt @ Value::Object(_)) => validate_identity_statement(stmt, "Statement", &substituted_index, &mut out),
        Some(other) => {
            if !is_resolution_marker(other) {
                out.push(PolicyFinding {
                    path: "Statement".to_string(),
                    message: format!("{} is not of type 'object', 'array'", describe_value(other)),
                });
            }
        }
    }

    out
}

/// Validates every proven-reachable scenario of one identity-policy document.
/// Raw scenarios retain dynamic marker subtrees, allowing literal siblings to
/// be checked without judging deployment-time values. Findings produced from an
/// intrinsic-generated authored path are discarded per scenario, so an
/// intrinsic in one conditional branch cannot suppress a literal sibling branch.
pub fn validate_identity_policy_scenarios(
    model: &SemanticModel,
    resource_id: &str,
    document_path: &str,
) -> Vec<PolicyFinding> {
    if model.scenario_budget_exhausted() {
        return Vec::new();
    }
    let scenarios = model.resolve_scenarios(resource_id, document_path);
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let no_substitutions = HashSet::new();

    for (document, conditions) in scenarios {
        let mut assumptions: Vec<(String, bool)> =
            conditions.iter().map(|(name, value)| (name.clone(), *value)).collect();
        if let Some(resource_condition) =
            model.resources.get(resource_id).and_then(|resource| resource.condition.as_ref())
        {
            match conditions.get(resource_condition) {
                Some(false) => continue,
                Some(true) => {}
                None => assumptions.push((resource_condition.clone(), true)),
            }
        }
        assumptions.sort_unstable();
        if !assumptions.is_empty() && model.conditions.satisfiability(&assumptions) != Satisfiability::Satisfiable {
            continue;
        }

        let document = resolved_value_to_json(&document);
        for finding in validate_identity_policy(&document, &no_substitutions) {
            let effective_path = if finding.path.is_empty() {
                document_path.to_string()
            } else {
                format!("{document_path}.{}", finding.path)
            };
            let source_path = model
                .scenario_source_path(resource_id, &effective_path, &conditions)
                .unwrap_or_else(|| effective_path.clone());
            if model.is_from_intrinsic(resource_id, &source_path) {
                continue;
            }
            if seen.insert((finding.path.clone(), finding.message.clone())) {
                findings.push(finding);
            }
        }
    }
    findings
}

fn validate_identity_statement(
    stmt: &Value,
    path: &str,
    substituted: &SubstitutedPathIndex<'_>,
    out: &mut Vec<PolicyFinding>,
) {
    if is_resolution_marker(stmt) {
        return;
    }
    let Some(obj) = stmt.as_object() else {
        out.push(PolicyFinding {
            path: path.to_string(),
            message: format!("{} is not of type 'object'", describe_value(stmt)),
        });
        return;
    };

    for key in obj.keys() {
        if !IDENTITY_STATEMENT_KEYS.contains(&key.as_str()) {
            out.push(PolicyFinding {
                path: format!("{}.{}", path, key),
                message: format!("Additional properties are not allowed ('{}' was unexpected)", key),
            });
        }
    }

    match obj.get("Effect") {
        None => {
            out.push(PolicyFinding { path: path.to_string(), message: "'Effect' is a required property".to_string() })
        }
        Some(effect_val) => {
            if !is_resolution_marker(effect_val) {
                match effect_val.as_str() {
                    Some(effect) => {
                        if !EFFECT_VALUES.contains(&effect)
                            && !path_is_intrinsic_generated(&format!("{}.Effect", path), substituted)
                        {
                            out.push(PolicyFinding {
                                path: format!("{}.Effect", path),
                                message: format!("'{}' is not one of {}", effect, render_str_list(EFFECT_VALUES)),
                            });
                        }
                    }
                    None => out.push(PolicyFinding {
                        path: format!("{}.Effect", path),
                        message: format!("{} is not of type 'string'", describe_value(effect_val)),
                    }),
                }
            }
        }
    }

    check_required_xor(obj, path, &["Action", "NotAction"], out);
    check_required_xor(obj, path, &["Resource", "NotResource"], out);

    for key in ["Action", "NotAction"] {
        if let Some(value) = obj.get(key)
            && !is_resolution_marker(value)
        {
            check_string_or_string_list_with_min_items(value, &format!("{}.{}", path, key), substituted, out);
        }
    }
    for key in ["Resource", "NotResource"] {
        if let Some(value) = obj.get(key) {
            // Allow conditional markers through — the recursive validation of
            // each branch happens inside check_resource_string_or_list.
            let is_non_conditional_marker =
                is_resolution_marker(value) && !value.as_object().is_some_and(|o| o.contains_key(MARKER_CONDITIONAL));
            if is_non_conditional_marker {
                continue;
            }
            check_resource_string_or_list(value, &format!("{}.{}", path, key), substituted, out);
        }
    }

    if let Some(sid) = obj.get("Sid")
        && !is_resolution_marker(sid)
    {
        match sid.as_str() {
            Some(s) if s.is_empty() || !s.chars().all(|c| c.is_ascii_alphanumeric()) => {
                out.push(PolicyFinding {
                    path: format!("{}.Sid", path),
                    message: format!("'{}' does not match '^[A-Za-z0-9]+$'", s),
                });
            }
            Some(_) => {}
            None => out.push(PolicyFinding {
                path: format!("{}.Sid", path),
                message: format!("{} is not of type 'string'", describe_value(sid)),
            }),
        }
    }

    if let Some(condition) = obj.get("Condition") {
        validate_condition_block(condition, &format!("{}.Condition", path), out);
    }
}

/// Validates the IAM Condition block structure and each context value that can
/// be decided statically.
fn validate_condition_block(condition: &Value, path: &str, out: &mut Vec<PolicyFinding>) {
    if is_resolution_marker(condition) {
        return;
    }
    let Some(operators) = condition.as_object() else {
        out.push(PolicyFinding {
            path: path.to_string(),
            message: format!("{} is not of type 'object'", describe_value(condition)),
        });
        return;
    };

    for (operator, context_values) in operators {
        let operator_path = format!("{}.{}", path, operator);
        if !condition_operator_is_valid(operator) {
            out.push(PolicyFinding {
                path: operator_path.clone(),
                message: format!("'{}' is not a valid IAM condition operator", operator),
            });
        }
        if is_resolution_marker(context_values) {
            continue;
        }
        let Some(context_map) = context_values.as_object() else {
            out.push(PolicyFinding {
                path: operator_path,
                message: format!("{} is not of type 'object'", describe_value(context_values)),
            });
            continue;
        };
        let is_null_operator = operator == "Null";
        for (context_key, context_value) in context_map {
            if is_resolution_marker(context_value) {
                continue;
            }
            let context_path = format!("{}.{}", operator_path, context_key);
            if is_null_operator {
                validate_null_condition_value(context_value, &context_path, out);
            } else {
                validate_condition_value(context_value, &context_path, out);
            }
        }
    }
}

fn validate_condition_value(value: &Value, path: &str, out: &mut Vec<PolicyFinding>) {
    match value {
        Value::String(_) | Value::Number(_) | Value::Bool(_) => {}
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if is_resolution_marker(item) {
                    continue;
                }
                if !item.is_string() {
                    out.push(PolicyFinding {
                        path: format!("{}.{}", path, index),
                        message: format!("{} is not of type 'string'", describe_value(item)),
                    });
                }
            }
        }
        _ => out.push(PolicyFinding {
            path: path.to_string(),
            message: format!("{} is not of type 'boolean', 'number', 'string', 'array'", describe_value(value)),
        }),
    }
}

fn validate_null_condition_value(value: &Value, path: &str, out: &mut Vec<PolicyFinding>) {
    let is_boolean = |candidate: &Value| candidate.is_boolean() || matches!(candidate.as_str(), Some("true" | "false"));
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if is_resolution_marker(item) {
                    continue;
                }
                if !is_boolean(item) {
                    out.push(PolicyFinding {
                        path: format!("{}.{}", path, index),
                        message: format!("{} is not one of ['true', 'false', true, false]", describe_value(item)),
                    });
                }
            }
        }
        candidate if is_boolean(candidate) => {}
        _ => out.push(PolicyFinding {
            path: path.to_string(),
            message: format!("{} is not one of ['true', 'false', true, false]", describe_value(value)),
        }),
    }
}

fn check_string_or_string_list_with_min_items(
    value: &Value,
    path: &str,
    substituted: &SubstitutedPathIndex<'_>,
    out: &mut Vec<PolicyFinding>,
) {
    if path_is_intrinsic_generated(path, substituted) {
        return;
    }
    match value {
        Value::String(_) => {}
        Value::Array(items) => {
            if items.is_empty() {
                out.push(PolicyFinding {
                    path: path.to_string(),
                    message: "[] is too short (minimum 1 item)".to_string(),
                });
                return;
            }
            for (index, item) in items.iter().enumerate() {
                let item_path = format!("{}.{}", path, index);
                if is_resolution_marker(item) || path_is_intrinsic_generated(&item_path, substituted) {
                    continue;
                }
                if !item.is_string() {
                    out.push(PolicyFinding {
                        path: item_path,
                        message: format!("{} is not of type 'string'", describe_value(item)),
                    });
                }
            }
        }
        other => out.push(PolicyFinding {
            path: path.to_string(),
            message: format!("{} is not of type 'string', 'array'", describe_value(other)),
        }),
    }
}

/// Exactly one of `pair` must be present: zero present is reported at the
/// statement, more than one at each present member.
fn check_required_xor(
    obj: &serde_json::Map<String, Value>,
    path: &str,
    pair: &[&str; 2],
    out: &mut Vec<PolicyFinding>,
) {
    let present: Vec<&str> = pair.iter().copied().filter(|k| obj.contains_key(*k)).collect();
    let message = format!("Only one of {} is a required property", render_str_list(pair));
    if present.is_empty() {
        out.push(PolicyFinding { path: path.to_string(), message });
    } else if present.len() > 1 {
        for key in present {
            out.push(PolicyFinding { path: format!("{}.{}", path, key), message: message.clone() });
        }
    }
}

fn check_resource_string_or_list(
    value: &Value,
    path: &str,
    substituted: &SubstitutedPathIndex<'_>,
    out: &mut Vec<PolicyFinding>,
) {
    if path_is_intrinsic_generated(path, substituted) {
        return;
    }
    // Recurse into conditional branches so every reachable static value
    // is validated — a conditional marker wrapping a Resource/NotResource
    // field must not suppress validation of both branches entirely.
    if let Some(obj) = value.as_object()
        && obj.contains_key(MARKER_CONDITIONAL)
    {
        if let Some(if_true) = obj.get(MARKER_IF_TRUE) {
            check_resource_string_or_list(if_true, path, substituted, out);
        }
        if let Some(if_false) = obj.get(MARKER_IF_FALSE) {
            check_resource_string_or_list(if_false, path, substituted, out);
        }
        return;
    }
    if is_resolution_marker(value) {
        return;
    }
    match value {
        Value::String(resource) => check_resource_arn(resource, path, out),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let item_path = format!("{}.{}", path, index);
                if path_is_intrinsic_generated(&item_path, substituted) {
                    continue;
                }
                if item.as_object().is_some_and(|object| object.contains_key(MARKER_CONDITIONAL)) {
                    check_resource_string_or_list(item, &item_path, substituted, out);
                    continue;
                }
                if is_resolution_marker(item) {
                    continue;
                }
                match item {
                    Value::String(resource) => check_resource_arn(resource, &item_path, out),
                    other => out.push(PolicyFinding {
                        path: item_path,
                        message: format!("{} is not of type 'string'", describe_value(other)),
                    }),
                }
            }
        }
        other => out.push(PolicyFinding {
            path: path.to_string(),
            message: format!("{} is not of type 'string', 'array'", describe_value(other)),
        }),
    }
}

/// Validates an ARN value from a Resource/NotResource field.
fn check_resource_arn(resource: &str, path: &str, out: &mut Vec<PolicyFinding>) {
    if resource_arn_matches(resource) {
        return;
    }
    out.push(PolicyFinding {
        path: path.to_string(),
        message: format!("'{}' does not match '{}'", resource, RESOURCE_ARN_PATTERN),
    });
}

/// The compact rendering of a JSON value for a diagnostic message: strings are
/// quoted, composites are shown as JSON.
fn describe_value(value: &Value) -> String {
    match value {
        Value::String(s) => format!("'{}'", s),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn findings(doc: serde_json::Value) -> Vec<(String, String)> {
        let none = std::collections::HashSet::new();
        validate_identity_policy(&doc, &none).into_iter().map(|f| (f.path, f.message)).collect()
    }

    /// A value substituted from an intrinsic is not judged on its content: the
    /// author wrote a reference, not the substituted text.
    #[test]
    fn substituted_paths_are_not_judged_on_content() {
        let doc = json!({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": [""]}]});
        let substituted: std::collections::HashSet<String> =
            [String::from("Statement.0.Resource.0")].into_iter().collect();
        assert!(
            validate_identity_policy(&doc, &substituted).is_empty(),
            "a parameter-substituted resource entry must not be held to the ARN pattern"
        );
    }

    #[test]
    fn well_formed_document_is_clean() {
        let doc = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowRead",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-bucket/*"
            }]
        });
        assert!(findings(doc).is_empty());
    }

    #[test]
    fn resource_arn_validation_accepts_representative_forms() {
        for resource in [
            "arn:aws:s3:::my-bucket/*",
            "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "arn:aws:lambda:us-east-1:123456789012:function:worker",
            "arn:aws-us-gov:service:region:*:resource",
        ] {
            assert!(resource_arn_matches(resource), "expected valid resource ARN: {resource}");
        }
        for resource in [
            "not-an-arn",
            "arn:example:s3:::bucket",
            "arn:aws::region:123456789012:resource",
            "arn:aws:s3::named-account:bucket",
            "arn:aws:s3:::",
        ] {
            assert!(!resource_arn_matches(resource), "expected invalid resource ARN: {resource}");
        }
    }

    #[test]
    fn missing_statement_is_required() {
        assert_eq!(
            findings(json!({"Version": "2012-10-17"})),
            [(String::new(), "'Statement' is a required property".into())]
        );
    }

    #[test]
    fn invalid_version_and_unknown_document_key() {
        let doc = json!({"Version": "blah", "BadProperty": 1, "Statement": []});
        let found = findings(doc);
        assert!(found.contains(&("Version".into(), "'blah' is not one of ['2008-10-17', '2012-10-17']".into())));
        assert!(found.contains(&(
            "BadProperty".into(),
            "Additional properties are not allowed ('BadProperty' was unexpected)".into()
        )));
    }

    #[test]
    fn statement_wrong_type_is_reported() {
        assert_eq!(
            findings(json!({"Statement": "Test"})),
            [("Statement".into(), "'Test' is not of type 'object', 'array'".into())]
        );
    }

    #[test]
    fn statement_structure_defects_are_reported() {
        let doc = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "NotAllow",
                "Action": "s3:*",
                "Principal": {"AWS": "*"},
                "Resource": [{"Effect": "Allow"}, "not-an-arn"]
            }]
        });
        let found = findings(doc);
        assert!(found.contains(&("Statement.0.Effect".into(), "'NotAllow' is not one of ['Allow', 'Deny']".into())));
        assert!(found.contains(&(
            "Statement.0.Principal".into(),
            "Additional properties are not allowed ('Principal' was unexpected)".into()
        )));
        assert!(
            found.contains(&("Statement.0.Resource.0".into(), "{\"Effect\":\"Allow\"} is not of type 'string'".into()))
        );
        assert!(
            found.iter().any(|(p, m)| p == "Statement.0.Resource.1" && m.starts_with("'not-an-arn' does not match"))
        );
    }

    #[test]
    fn missing_effect_and_action_xor() {
        let doc = json!({"Statement": [{"Resource": "*"}]});
        let found = findings(doc);
        assert!(found.contains(&("Statement.0".into(), "'Effect' is a required property".into())));
        assert!(
            found
                .contains(&("Statement.0".into(), "Only one of ['Action', 'NotAction'] is a required property".into()))
        );
    }

    #[test]
    fn both_action_and_notaction_flagged_at_each_member() {
        let doc =
            json!({"Statement": [{"Effect": "Allow", "Action": "s3:*", "NotAction": "s3:Get*", "Resource": "*"}]});
        let found = findings(doc);
        assert!(found.contains(&(
            "Statement.0.Action".into(),
            "Only one of ['Action', 'NotAction'] is a required property".into()
        )));
        assert!(found.contains(&(
            "Statement.0.NotAction".into(),
            "Only one of ['Action', 'NotAction'] is a required property".into()
        )));
    }

    #[test]
    fn substitution_placeholders_are_not_judged_against_the_arn_pattern() {
        let doc = json!({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:iam::${AWS::AccountId}:user/x"}]});
        assert!(findings(doc).is_empty());
    }

    #[test]
    fn marker_bearing_field_is_skipped_when_literal_siblings_are_valid() {
        let doc = json!({"Statement": [{"Effect": "Allow", "Action": {"__dynamic": "unknown"}, "Resource": "*"}]});
        assert!(findings(doc).is_empty(), "a document carrying resolution markers must not be judged");
    }

    /// Dynamic subtrees are skipped per field, but sibling literals
    /// are still validated.
    #[test]
    fn dynamic_subtrees_are_skipped_but_sibling_literals_are_validated() {
        let doc = json!({
            "Statement": [{
                "Effect": "Invalid",
                "Action": {"__dynamic": "unknown"},
                "Resource": "*"
            }]
        });
        let found = findings(doc);
        assert!(
            found.iter().any(|(p, m)| p == "Statement.0.Effect" && m.contains("'Invalid'")),
            "an invalid literal Effect alongside dynamic Action must still be reported: {:?}",
            found
        );
    }

    #[test]
    fn wholly_dynamic_document_is_skipped() {
        assert!(findings(json!({"__dynamic": "unknown policy"})).is_empty());
    }

    /// A dynamic array item does not hide invalid literal siblings.
    #[test]
    fn dynamic_array_item_does_not_hide_invalid_literal_sibling() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": [{"__dynamic": "unknown action"}, 7],
                "Resource": "*"
            }]
        });
        let found = findings(doc);
        assert!(
            found
                .iter()
                .any(|(path, message)| { path == "Statement.0.Action.1" && message.contains("not of type 'string'") }),
            "a dynamic array item must not hide an invalid literal sibling: {found:?}"
        );
    }

    #[test]
    fn whole_document_with_markers_only_skips_marked_subtrees() {
        let doc = json!({
            "Version": "invalid",
            "Statement": [{
                "Effect": "Allow",
                "Action": {"__dynamic": "ref"},
                "Resource": "*"
            }]
        });
        let found = findings(doc);
        assert!(
            found.iter().any(|(p, _)| p == "Version"),
            "literal Version must still be validated even when Statement has markers"
        );
    }

    /// Empty Action/NotAction arrays report a minimum-size violation.
    #[test]
    fn empty_action_array_reports_min_items() {
        let doc = json!({"Statement": [{"Effect": "Allow", "Action": [], "Resource": "*"}]});
        let found = findings(doc);
        assert!(
            found.iter().any(|(p, m)| p == "Statement.0.Action" && m.contains("too short")),
            "empty Action array must report minItems violation: {:?}",
            found
        );
    }

    #[test]
    fn empty_not_action_array_reports_min_items() {
        let doc = json!({"Statement": [{"Effect": "Allow", "NotAction": [], "Resource": "*"}]});
        let found = findings(doc);
        assert!(
            found.iter().any(|(p, m)| p == "Statement.0.NotAction" && m.contains("too short")),
            "empty NotAction array must report minItems violation: {:?}",
            found
        );
    }

    /// Sid values must be unique across statements.
    #[test]
    fn duplicate_sid_across_statements_is_reported() {
        let doc = json!({
            "Statement": [
                {"Sid": "ReadOnly", "Effect": "Allow", "Action": "s3:Get*", "Resource": "*"},
                {"Sid": "ReadOnly", "Effect": "Deny", "Action": "s3:Put*", "Resource": "*"}
            ]
        });
        let found = findings(doc);
        assert!(
            found.iter().any(|(p, m)| p == "Statement.1.Sid" && m.contains("duplicate")),
            "duplicate Sid must be reported: {:?}",
            found
        );
    }

    #[test]
    fn identity_policy_id_is_rejected_regardless_of_scalar_type() {
        for id in [json!("my-policy"), json!(123), json!(true)] {
            let doc = json!({"Id": id, "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]});
            assert_eq!(
                findings(doc),
                [("Id".to_string(), "Additional properties are not allowed ('Id' was unexpected)".to_string())],
                "identity-policy Id must be rejected regardless of value type"
            );
        }
    }

    /// Condition operators are validated.
    #[test]
    fn valid_condition_operators_are_accepted() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:RequestedRegion": ["us-east-1"]},
                    "ForAnyValue:ArnLike": {"aws:PrincipalOrgPaths": ["o-*/r-*/ou-*"]},
                    "Null": {"aws:TokenIssueTime": ["true"]}
                }
            }]
        });
        assert!(findings(doc).is_empty());
    }

    #[test]
    fn invalid_condition_operator_is_reported() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "InvalidOperator": {"key": ["value"]}
                }
            }]
        });
        let found = findings(doc);
        assert!(
            found.iter().any(|(_, m)| m.contains("not a valid IAM condition operator")),
            "invalid operator must be reported: {:?}",
            found
        );
    }

    #[test]
    fn condition_operator_value_must_be_object() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": "not-an-object"
                }
            }]
        });
        let found = findings(doc);
        assert!(
            found.iter().any(|(_, m)| m.contains("is not of type 'object'")),
            "non-object operator value must be reported: {:?}",
            found
        );
    }

    #[test]
    fn condition_context_values_follow_operator_schema() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:RequestedRegion": ["us-east-1", 7],
                        "aws:PrincipalTag/dynamic": {"__dynamic": "unknown"}
                    },
                    "Null": {"aws:TokenIssueTime": "not-a-boolean"}
                }
            }]
        });
        let found = findings(doc);
        assert!(
            found
                .iter()
                .any(|(path, message)| path.ends_with("aws:RequestedRegion.1")
                    && message.contains("not of type 'string'")),
            "non-string array member must be reported: {:?}",
            found
        );
        assert!(
            found.iter().any(|(path, message)| path.ends_with("aws:TokenIssueTime") && message.contains("not one of")),
            "Null values must be boolean spellings: {:?}",
            found
        );
        assert!(
            found.iter().all(|(path, _)| !path.contains("aws:PrincipalTag/dynamic")),
            "a dynamic context value must not suppress or create sibling findings: {:?}",
            found
        );
    }

    #[test]
    fn sid_must_be_non_empty() {
        let doc = json!({
            "Statement": [{"Sid": "", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
        });
        let found = findings(doc);
        assert!(
            found.iter().any(|(path, message)| path == "Statement.0.Sid" && message.contains("does not match")),
            "empty Sid must be rejected: {:?}",
            found
        );
    }

    /// An ancestor in the substituted set suppresses descendant checks.
    #[test]
    fn substituted_ancestor_path_suppresses_descendant_check() {
        let doc = json!({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": ["not-an-arn"]}]});
        let substituted: HashSet<String> = [String::from("Statement.0.Resource")].into_iter().collect();
        let found = validate_identity_policy(&doc, &substituted);
        assert!(
            !found.iter().any(|f| f.path.starts_with("Statement.0.Resource")),
            "descendant of substituted path must be suppressed: {:?}",
            found
        );
    }

    /// A descendant in the substituted set, such as one from Fn::Join,
    /// recognizes that the ancestor value was generated by the intrinsic.
    #[test]
    fn substituted_descendant_path_suppresses_generated_ancestor_check() {
        let doc = json!({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "not-an-arn"}]});
        let substituted: HashSet<String> = [String::from("Statement.0.Resource.Fn::Join.1.0")].into_iter().collect();
        let found = validate_identity_policy(&doc, &substituted);
        assert!(
            !found.iter().any(|finding| finding.path == "Statement.0.Resource"),
            "an intrinsic nested beneath the checked path generated the ancestor value: {:?}",
            found
        );
    }

    #[test]
    fn substituted_path_index_respects_component_boundaries() {
        let substituted: HashSet<String> = [
            "Statement.0.Action.0",
            "Statement.0.Resource-qualifier",
            "Statement.0.Resource.Fn::Join.1.0",
            "Statement.10.Condition",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let index = SubstitutedPathIndex::new(&substituted);

        // A numeric list descendant does NOT cover the parent array/scalar path.
        assert!(!index.covers("Statement.0.Action"));
        // Exact match and descendants of exact matches are still covered.
        assert!(index.covers("Statement.0.Action.0"));
        assert!(index.covers("Statement.0.Action.0.Value"));
        // A non-numeric (intrinsic) descendant DOES cover the ancestor scalar.
        assert!(index.covers("Statement.0.Resource"));
        assert!(!index.covers("Statement.0.Condition"));
        assert!(!index.covers("Statement.0.Actionable"));
        assert!(!index.covers("Statement.1"));
    }

    /// A large substituted-path set must suppress only the corresponding
    /// generated values, without hiding invalid literal siblings.
    #[test]
    fn many_substituted_policy_paths_preserve_literal_findings() {
        const STATEMENT_COUNT: usize = 2_000;
        let mut statements = Vec::with_capacity(STATEMENT_COUNT);
        let mut substituted = HashSet::with_capacity(STATEMENT_COUNT / 2);
        let mut expected_paths = HashSet::with_capacity(STATEMENT_COUNT / 2);

        for index in 0..STATEMENT_COUNT {
            statements.push(json!({
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "not-an-arn"
            }));
            let resource_path = format!("Statement.{index}.Resource");
            if index.is_multiple_of(2) {
                substituted.insert(resource_path);
            } else {
                expected_paths.insert(resource_path);
            }
        }

        let doc = json!({"Statement": statements});
        let found = validate_identity_policy(&doc, &substituted);
        let actual_paths: HashSet<String> = found.iter().map(|finding| finding.path.clone()).collect();

        assert_eq!(found.len(), expected_paths.len());
        assert_eq!(actual_paths, expected_paths);
        assert!(found.iter().all(|finding| finding.message.contains("does not match")));
    }

    /// A dynamic Action must not suppress Effect validation.
    #[test]
    fn dynamic_action_does_not_suppress_effect_validation() {
        let doc = json!({
            "Statement": [{
                "Effect": "BadValue",
                "Action": {"__dynamic": "generated by Fn::Join"},
                "Resource": "*"
            }]
        });
        let found = findings(doc);
        assert!(
            found.iter().any(|(p, m)| p == "Statement.0.Effect" && m.contains("'BadValue'")),
            "invalid Effect must still be reported when Action is dynamic: {:?}",
            found
        );
    }

    // --- Substituted numeric list descendant must not suppress literal siblings ---

    /// A substituted item at a numeric list index must not suppress validation
    /// of other literal items at sibling indices.
    #[test]
    fn substituted_numeric_list_descendant_does_not_suppress_literal_siblings() {
        let doc = json!({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": ["not-an-arn", "also-bad"]}]});
        let substituted: HashSet<String> = [String::from("Statement.0.Resource.1")].into_iter().collect();
        let found = validate_identity_policy(&doc, &substituted);
        assert!(
            found.iter().any(|f| f.path == "Statement.0.Resource.0" && f.message.contains("does not match")),
            "a substituted numeric sibling must not suppress validation of literal siblings: {:?}",
            found
        );
        assert!(
            !found.iter().any(|f| f.path == "Statement.0.Resource.1"),
            "the substituted item itself must be suppressed: {:?}",
            found
        );
    }

    /// A non-numeric descendant (intrinsic path) still suppresses the ancestor.
    #[test]
    fn non_numeric_descendant_still_suppresses_ancestor() {
        let doc = json!({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "not-an-arn"}]});
        let substituted: HashSet<String> = [String::from("Statement.0.Resource.Fn::Sub.0")].into_iter().collect();
        let found = validate_identity_policy(&doc, &substituted);
        assert!(
            !found.iter().any(|f| f.path == "Statement.0.Resource"),
            "an intrinsic descendant path must suppress the ancestor scalar: {:?}",
            found
        );
    }

    // --- Conditional Resource/NotResource branches are validated ---

    /// A conditional marker wrapping a Resource field must validate both
    /// branches for static values.
    #[test]
    fn conditional_resource_branches_are_validated() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": {
                    "__conditional": "IsProd",
                    "__if_true": "not-an-arn",
                    "__if_false": "arn:aws:s3:::bucket/*"
                }
            }]
        });
        let found = findings(doc);
        assert!(
            found.iter().any(|(p, m)| p == "Statement.0.Resource" && m.contains("does not match")),
            "invalid ARN in a conditional branch must be reported: {:?}",
            found
        );
    }

    /// Both branches of a conditional Resource are validated independently.
    #[test]
    fn conditional_resource_both_branches_valid_is_clean() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": {
                    "__conditional": "IsProd",
                    "__if_true": "arn:aws:s3:::prod-bucket/*",
                    "__if_false": "arn:aws:s3:::dev-bucket/*"
                }
            }]
        });
        assert!(findings(doc).is_empty());
    }

    /// A conditional with a valid array branch and an invalid scalar branch.
    #[test]
    fn conditional_resource_invalid_branch_among_valid_array_reported() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": {
                    "__conditional": "UseWildcard",
                    "__if_true": "*",
                    "__if_false": "bad-arn"
                }
            }]
        });
        let found = findings(doc);
        assert!(
            found.iter().any(|(p, m)| p == "Statement.0.Resource" && m.contains("does not match")),
            "invalid false-branch must be reported: {:?}",
            found
        );
    }

    // --- ARN skeleton validation with ${...} variables ---

    /// Valid CloudFormation placeholders in partition and account are accepted.
    #[test]
    fn arn_with_cfn_partition_placeholder_is_valid() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "arn:${AWS::Partition}:iam::${AWS::AccountId}:user/x"
            }]
        });
        assert!(findings(doc).is_empty());
    }

    /// Trailing IAM policy variables are accepted.
    #[test]
    fn arn_with_trailing_iam_variable_is_valid() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::bucket/${aws:username}/*"
            }]
        });
        assert!(findings(doc).is_empty());
    }

    /// A wildcard partition remains valid when the resource portion uses an IAM variable.
    #[test]
    fn arn_with_wildcard_partition_and_trailing_iam_variable_is_valid() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:*:s3:::bucket/${aws:username}"
            }]
        });
        assert!(findings(doc).is_empty());
    }

    /// Wildcard service `arn:aws:*:...` is rejected even with placeholders.
    #[test]
    fn arn_with_wildcard_service_is_rejected() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:*:us-east-1:${AWS::AccountId}:thing"
            }]
        });
        let found = findings(doc);
        assert!(
            found.iter().any(|(p, m)| p == "Statement.0.Resource" && m.contains("does not match")),
            "wildcard service must be rejected: {:?}",
            found
        );
    }

    /// Literal wildcard `*` (all resources) remains valid.
    #[test]
    fn literal_wildcard_star_remains_valid() {
        let doc = json!({
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
        });
        assert!(findings(doc).is_empty());
    }

    /// ARN with valid iso partition family is accepted.
    #[test]
    fn arn_with_iso_partition_is_valid() {
        assert!(resource_arn_matches("arn:aws-iso:s3:::bucket/key"));
        assert!(resource_arn_matches("arn:aws-iso-b:kms:us-isob-east-1:123456789012:key/id"));
    }

    /// ARN partition wildcards are accepted in both complete and partial patterns.
    #[test]
    fn resource_arn_accepts_wildcard_partition() {
        for resource in [
            "arn:*:s3:::bucket",
            "arn:*:iam::123456789012:role/test",
            "arn:aw?:s3:::bucket",
            "arn:aws-*:kms:us-east-1:123456789012:key/test",
        ] {
            assert!(resource_arn_matches(resource), "partition wildcard must be accepted in {resource}");
        }
    }

    /// ARN with wildcard service is rejected by resource_arn_matches.
    #[test]
    fn resource_arn_rejects_wildcard_service() {
        assert!(!resource_arn_matches("arn:aws:*:us-east-1:123456789012:thing"));
        assert!(!resource_arn_matches("arn:aws:*:::bucket"));
        assert!(!resource_arn_matches("arn:aws:s?:::bucket"));
    }

    /// Malformed prefix before placeholder is rejected.
    #[test]
    fn arn_skeleton_rejects_malformed_prefix() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "not-arn:${AWS::Partition}:s3:::bucket"
            }]
        });
        let found = findings(doc);
        assert!(
            found.iter().any(|(p, m)| p == "Statement.0.Resource" && m.contains("does not match")),
            "malformed prefix must be rejected: {:?}",
            found
        );
    }

    /// An incomplete identity-policy ARN (just `arn:partition:service`) with a
    /// trailing variable is valid.
    #[test]
    fn incomplete_arn_with_trailing_variable_is_valid() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:${AWS::Region}:${AWS::AccountId}:bucket"
            }]
        });
        assert!(findings(doc).is_empty());
    }

    /// The exact incomplete ARN form is valid because IAM wildcard-completes
    /// omitted trailing fields.
    #[test]
    fn exact_incomplete_arn_is_valid() {
        assert!(resource_arn_matches("arn:aws:sqs"));
    }

    /// An IAM policy variable cannot make a malformed non-ARN prefix valid.
    #[test]
    fn malformed_prefix_with_iam_variable_is_rejected() {
        assert!(!resource_arn_matches("not-an-arn-${aws:username}"));
    }

    /// IAM policy variables are valid only in the trailing resource portion.
    #[test]
    fn iam_variables_in_arn_prefix_fields_are_rejected() {
        for resource in [
            "arn:${aws:username}:s3:::bucket/key",
            "arn:aws:${aws:username}:::bucket/key",
            "arn:aws:s3:${aws:username}:123456789012:bucket/key",
            "arn:aws:s3:us-east-1:${aws:username}:bucket/key",
        ] {
            assert!(!resource_arn_matches(resource), "expected invalid resource ARN: {resource}");
        }
    }

    #[test]
    fn unbalanced_placeholder_is_rejected() {
        assert!(!resource_arn_matches("arn:aws:s3:::bucket/${aws:username"));
    }

    /// Scenario-aware validation must ignore an intrinsic-generated branch
    /// without allowing it to suppress an invalid literal sibling branch.
    #[test]
    fn scenario_validation_checks_literal_branch_beside_intrinsic_branch() {
        let template = r#"
Conditions:
  UseGenerated: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  Policy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      ManagedPolicyName: test
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action: s3:GetObject
            Resource: !If
              - UseGenerated
              - !Sub 'bad-${AWS::AccountId}'
              - not-an-arn
"#;
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template must parse");
        let generated_conditions = std::collections::HashMap::from([("UseGenerated".to_string(), true)]);
        let generated_source_path = model
            .scenario_source_path("Policy", "Properties.PolicyDocument.Statement.0.Resource", &generated_conditions)
            .expect("generated branch must have an authored source path");
        assert_eq!(generated_source_path, "Properties.PolicyDocument.Statement.0.Resource.Fn::If.1");
        assert!(
            model.is_from_intrinsic("Policy", &generated_source_path),
            "generated branch must retain intrinsic provenance at {generated_source_path}"
        );

        let found = validate_identity_policy_scenarios(&model, "Policy", "Properties.PolicyDocument");

        assert_eq!(found.len(), 1, "only the authored literal branch should be reported: {found:?}");
        assert_eq!(found[0].path, "Statement.0.Resource");
        assert!(found[0].message.starts_with("'not-an-arn' does not match"));
    }

    /// Service placeholder is accepted.
    #[test]
    fn arn_with_service_placeholder_is_valid() {
        let doc = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:${ServiceName}:us-east-1:123456789012:resource"
            }]
        });
        assert!(findings(doc).is_empty());
    }
}
