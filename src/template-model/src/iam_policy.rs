//! Structural validation of embedded IAM policy documents.
//!
//! IAM identity policies are embedded JSON inside CloudFormation properties
//! (`PolicyDocument`, `InlinePolicy`). IAM rejects a malformed document at
//! deploy time, so the shape is validated here: allowed top-level keys, the
//! `Version` enum, the `Statement` list, and each statement's keys, `Effect`
//! enum, exactly-one-of `Action`/`NotAction` and `Resource`/`NotResource`
//! pairs, value types, and the resource-ARN format.
//!
//! Both rule engines evaluate through this one implementation so their
//! findings are identical. Values carrying resolved-intrinsic markers (a
//! `Ref` that could not be resolved, a conditional, or any dynamic value) are
//! skipped: only what the author literally wrote is judged.

use crate::message::render_str_list;
use crate::resolved_value::json_contains_markers;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::LazyLock;

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

static RESOURCE_ARN_RE: LazyLock<Option<regex::Regex>> = LazyLock::new(|| regex::Regex::new(RESOURCE_ARN_PATTERN).ok());

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
    let Some(obj) = doc.as_object() else {
        return out;
    };
    if json_contains_markers(doc) {
        // Any unresolved intrinsic anywhere in the document leaves its true
        // shape unknown; judging the rest risks flagging what CloudFormation
        // would accept once the intrinsic resolves.
        return out;
    }

    for key in obj.keys() {
        if !DOCUMENT_KEYS.contains(&key.as_str()) {
            out.push(PolicyFinding {
                path: key.clone(),
                message: format!("Additional properties are not allowed ('{}' was unexpected)", key),
            });
        }
    }

    if let Some(version) = obj.get("Version") {
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
            for (idx, stmt) in stmts.iter().enumerate() {
                validate_identity_statement(stmt, &format!("Statement.{}", idx), substituted, &mut out);
            }
        }
        Some(stmt @ Value::Object(_)) => validate_identity_statement(stmt, "Statement", substituted, &mut out),
        Some(other) => out.push(PolicyFinding {
            path: "Statement".to_string(),
            message: format!("{} is not of type 'object', 'array'", describe_value(other)),
        }),
    }

    out
}

fn validate_identity_statement(stmt: &Value, path: &str, substituted: &HashSet<String>, out: &mut Vec<PolicyFinding>) {
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
        Some(Value::String(effect)) => {
            if !EFFECT_VALUES.contains(&effect.as_str()) && !substituted.contains(&format!("{}.Effect", path)) {
                out.push(PolicyFinding {
                    path: format!("{}.Effect", path),
                    message: format!("'{}' is not one of {}", effect, render_str_list(EFFECT_VALUES)),
                });
            }
        }
        Some(other) => out.push(PolicyFinding {
            path: format!("{}.Effect", path),
            message: format!("{} is not of type 'string'", describe_value(other)),
        }),
    }

    check_required_xor(obj, path, &["Action", "NotAction"], out);
    check_required_xor(obj, path, &["Resource", "NotResource"], out);

    for key in ["Action", "NotAction"] {
        if let Some(value) = obj.get(key) {
            check_string_or_string_list(value, &format!("{}.{}", path, key), None, substituted, out);
        }
    }
    for key in ["Resource", "NotResource"] {
        if let Some(value) = obj.get(key) {
            check_string_or_string_list(
                value,
                &format!("{}.{}", path, key),
                RESOURCE_ARN_RE.as_ref(),
                substituted,
                out,
            );
        }
    }

    if let Some(sid) = obj.get("Sid") {
        match sid.as_str() {
            Some(s) if !s.chars().all(|c| c.is_ascii_alphanumeric()) => out.push(PolicyFinding {
                path: format!("{}.Sid", path),
                message: format!("'{}' does not match '^[A-Za-z0-9]+$'", s),
            }),
            Some(_) => {}
            None => out.push(PolicyFinding {
                path: format!("{}.Sid", path),
                message: format!("{} is not of type 'string'", describe_value(sid)),
            }),
        }
    }

    if let Some(cond) = obj.get("Condition")
        && !cond.is_object()
    {
        out.push(PolicyFinding {
            path: format!("{}.Condition", path),
            message: format!("{} is not of type 'object'", describe_value(cond)),
        });
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

/// A value that must be a string or a list of strings; each string may
/// additionally be held to a pattern. Strings carrying `${` placeholders are
/// exempt from the pattern: they are substitution templates whose final text
/// is not knowable here.
fn check_string_or_string_list(
    value: &Value,
    path: &str,
    pattern: Option<&regex::Regex>,
    substituted: &HashSet<String>,
    out: &mut Vec<PolicyFinding>,
) {
    match value {
        Value::String(s) => check_string_pattern(s, path, pattern, substituted, out),
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                match item {
                    Value::String(s) => {
                        check_string_pattern(s, &format!("{}.{}", path, idx), pattern, substituted, out)
                    }
                    other => out.push(PolicyFinding {
                        path: format!("{}.{}", path, idx),
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

fn check_string_pattern(
    s: &str,
    path: &str,
    pattern: Option<&regex::Regex>,
    substituted: &HashSet<String>,
    out: &mut Vec<PolicyFinding>,
) {
    if s.contains("${") || substituted.contains(path) {
        return;
    }
    if let Some(re) = pattern
        && !re.is_match(s)
    {
        out.push(PolicyFinding {
            path: path.to_string(),
            message: format!("'{}' does not match '{}'", s, RESOURCE_ARN_PATTERN),
        });
    }
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
    fn dynamic_documents_are_skipped() {
        let doc = json!({"Statement": [{"Effect": "Allow", "Action": {"__dynamic": "unknown"}, "Resource": "*"}]});
        assert!(findings(doc).is_empty(), "a document carrying resolution markers must not be judged");
    }
}
