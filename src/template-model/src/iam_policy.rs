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

use crate::consts::{MARKER_CONDITIONAL, MARKER_DYNAMIC, MARKER_ENUM, MARKER_INTRINSIC, MARKER_REF};
use crate::message::render_str_list;
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

const DOCUMENT_KEYS: &[&str] = &["Id", "Statement", "Version"];
const VERSION_VALUES: &[&str] = &["2008-10-17", "2012-10-17"];
const EFFECT_VALUES: &[&str] = &["Allow", "Deny"];
const IDENTITY_STATEMENT_KEYS: &[&str] =
    &["Action", "Condition", "Effect", "NotAction", "NotResource", "Resource", "Sid"];

/// The ARN shape IAM accepts in a `Resource`/`NotResource` entry: a full ARN
/// (with wildcards) or the lone `*`.
const RESOURCE_ARN_PATTERN: &str = "^(arn:(aws[A-Za-z\\-]*?|\\*):[^:]+:[^:]*(:(?:\\d{12}|\\*|aws)?:.+|)|\\*)$";

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
    let mut parts = value.splitn(6, ':');
    if parts.next() != Some("arn") {
        return false;
    }
    let Some(partition) = parts.next() else {
        return false;
    };
    if partition != "*"
        && (!partition.starts_with("aws")
            || !partition.chars().all(|character| character.is_ascii_alphabetic() || character == '-'))
    {
        return false;
    }
    if parts.next().is_none_or(str::is_empty) || parts.next().is_none() {
        return false;
    }
    let Some(account) = parts.next() else {
        return true;
    };
    let Some(resource) = parts.next() else {
        return false;
    };
    (account.is_empty()
        || account == "*"
        || account == "aws"
        || (account.len() == 12 && account.bytes().all(|byte| byte.is_ascii_digit())))
        && !resource.is_empty()
}

fn condition_operator_is_valid(operator: &str) -> bool {
    let without_set_operator =
        operator.strip_prefix("ForAnyValue:").or_else(|| operator.strip_prefix("ForAllValues:")).unwrap_or(operator);
    let base = without_set_operator.strip_suffix("IfExists").unwrap_or(without_set_operator);
    CONDITION_OPERATORS.contains(&base)
}

/// Whether a path is covered by (equal to, an ancestor of, or a descendant of)
/// any substituted path. This treats any subtree touched by intrinsic resolution
/// as generated, suppressing literal-content checks on the whole subtree.
fn path_is_intrinsic_generated(path: &str, substituted: &HashSet<String>) -> bool {
    for sub_path in substituted {
        if sub_path.is_empty()
            || path == sub_path
            || path.starts_with(&format!("{}.", sub_path))
            || sub_path.starts_with(&format!("{}.", path))
        {
            return true;
        }
    }
    false
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
        if !DOCUMENT_KEYS.contains(&key.as_str()) {
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

    if let Some(id) = obj.get("Id")
        && !is_resolution_marker(id)
        && !id.is_string()
    {
        out.push(PolicyFinding {
            path: "Id".to_string(),
            message: format!("{} is not of type 'string'", describe_value(id)),
        });
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
                validate_identity_statement(stmt, &format!("Statement.{}", idx), substituted, &mut out);
                if let Some(statement) = stmt.as_object()
                    && let Some(Value::String(sid)) = statement.get("Sid")
                    && !sid.is_empty()
                    && !path_is_intrinsic_generated(&format!("Statement.{}.Sid", idx), substituted)
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
        Some(stmt @ Value::Object(_)) => validate_identity_statement(stmt, "Statement", substituted, &mut out),
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

fn validate_identity_statement(stmt: &Value, path: &str, substituted: &HashSet<String>, out: &mut Vec<PolicyFinding>) {
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
        if let Some(value) = obj.get(key)
            && !is_resolution_marker(value)
        {
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
    substituted: &HashSet<String>,
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
    substituted: &HashSet<String>,
    out: &mut Vec<PolicyFinding>,
) {
    if path_is_intrinsic_generated(path, substituted) {
        return;
    }
    match value {
        Value::String(resource) => check_resource_arn(resource, path, out),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let item_path = format!("{}.{}", path, index);
                if is_resolution_marker(item) || path_is_intrinsic_generated(&item_path, substituted) {
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

fn check_resource_arn(resource: &str, path: &str, out: &mut Vec<PolicyFinding>) {
    if resource.contains("${") || resource_arn_matches(resource) {
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

    /// A non-string Id is reported.
    #[test]
    fn non_string_id_is_reported() {
        let doc = json!({"Id": 123, "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]});
        let found = findings(doc);
        assert!(
            found.iter().any(|(p, m)| p == "Id" && m.contains("'string'")),
            "non-string Id must be reported: {:?}",
            found
        );
    }

    #[test]
    fn string_id_is_accepted() {
        let doc = json!({"Id": "my-policy", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]});
        assert!(findings(doc).is_empty());
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
}
