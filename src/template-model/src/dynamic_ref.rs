//! Dynamic-reference format and location validation.
//!
//! A dynamic reference is a `{{resolve:<service>:<...>}}` string that
//! CloudFormation resolves at deploy time. This module validates its structure
//! and its location:
//!
//! * Only the **last** `{{resolve:...}}` occurrence in a string is structurally
//!   validated: extraction is greedy from the last `{{` to the last `}}`, so a
//!   string with several references is judged by its final one (CloudFormation's
//!   own behavior).
//! * A dynamic reference that appears as an argument to another intrinsic
//!   function (e.g. inside `Fn::Sub` or `Fn::Join`) is **not** structurally
//!   validated — the enclosing function owns it. `Fn::If` is the sole exception.
//! * The `resolve:` payload is split on `:` and validated per service:
//!   `ssm`/`ssm-secure`, `secretsmanager` (bare secret-id form), and
//!   `secretsmanager` ARN form.
//! * Location rules mirror the reference implementation's allowlists:
//!   `ssm-secure` is only supported at a fixed set of resource property paths,
//!   `secretsmanager` only in resource properties and parameter defaults, and
//!   plain `ssm` only in parameter defaults/allowed values, resource
//!   properties/metadata, and output values. Sections the reference
//!   implementation never walks for dynamic references (Conditions, DependsOn,
//!   Mappings) are not checked, so no finding is produced where it produces
//!   none.
//!
//! The checks run over the raw IR arena so both engines surface identical
//! diagnostics from the shared model, rather than each re-deriving the format
//! from the serialized model.

use crate::consts::{
    FN_IF, FN_SUB, INTRINSIC_FN_PATH_SEGMENTS, KEY_TYPE, SECTION_OUTPUTS, SECTION_PARAMETERS, SECTION_RESOURCES,
    SSM_SECURE_ALLOWED_PROPERTY_PATHS,
};
use crate::ir::{Arena, Node, NodeRef};
use diagnostics::Diagnostic;
use std::collections::HashMap;

const RULE_DYNAMIC_REFERENCE: &str = "E1050";
const RULE_SSM_SECURE_LOCATION: &str = "E1027";
const RULE_SECRETSMANAGER_LOCATION: &str = "E1051";
const RULE_SSM_LOCATION: &str = "E1052";

const ALLOWED_SERVICES: &[&str] = &["ssm", "ssm-secure", "secretsmanager"];

pub fn validate_dynamic_references(arena: &Arena, resources: NodeRef) -> Vec<Diagnostic> {
    let resource_types = collect_resource_types(arena, resources);
    let mut out = Vec::new();
    for idx in 0..arena.len() {
        let node_ref = idx as NodeRef;
        let spanned = arena.get(node_ref);
        let Node::String(s) = &spanned.node else {
            continue;
        };
        // A dynamic reference that is an argument to another intrinsic function
        // is validated by that function's own rules, not here. The build path
        // records the enclosing functions as `.../Fn::<name>/...` segments; the
        // presence of any such segment other than `Fn::If` means the string is a
        // function argument and its structure is not checked.
        if !string_is_function_argument(&spanned.path)
            && let Some(message) = dynamic_reference_error(s)
        {
            out.push(crate::make_parse_diagnostic_at(RULE_DYNAMIC_REFERENCE, message, spanned.span, &spanned.path));
        }
        if let Some((rule, message)) = dynamic_reference_location_error(s, &spanned.path, &resource_types) {
            out.push(crate::make_parse_diagnostic_at(rule, message, spanned.span, &spanned.path));
        }
    }
    out
}

/// Maps each resource logical ID to its `Type` string, for resolving the
/// type-keyed `ssm-secure` property allowlist.
fn collect_resource_types(arena: &Arena, resources: NodeRef) -> HashMap<String, String> {
    let mut types = HashMap::new();
    if resources == crate::ir::NULL_REF {
        return types;
    }
    if let Some(entries) = arena.as_map(resources) {
        for (logical_id, resource_ref) in entries {
            if let Some(type_ref) = arena.map_get(*resource_ref, KEY_TYPE)
                && let Some(type_name) = arena.as_str(type_ref)
            {
                types.insert(logical_id.clone(), type_name.to_string());
            }
        }
    }
    types
}

/// True if the build path shows the string is nested inside an intrinsic
/// function other than `Fn::If` (whose branches are treated transparently).
/// Only known function names count: a user map key that merely starts with
/// `Fn::` (e.g. a Lambda environment variable named `Fn::Custom`) is data, not
/// a function.
fn string_is_function_argument(path: &str) -> bool {
    path.split('/').any(|segment| segment != FN_IF && INTRINSIC_FN_PATH_SEGMENTS.contains(&segment))
}

/// Checks the *location* of every dynamic reference in `s` against the
/// reference implementation's per-service allowlists. Returns the rule ID and
/// message for the first violation.
///
/// Only sections the reference implementation walks are checked — parameter
/// `Default`/`AllowedValues`, resource `Properties`/`Metadata`, and output
/// `Value`/`Export` — so no finding is produced in sections it never validates
/// (Conditions, DependsOn, Mappings). `Fn::Sub` and `Fn::If` wrappers are
/// transparent (the location of the string is what matters); any other
/// enclosing function owns its arguments and is skipped.
fn dynamic_reference_location_error(
    s: &str,
    path: &str,
    resource_types: &HashMap<String, String>,
) -> Option<(&'static str, String)> {
    if !s.contains("{{resolve:") {
        return None;
    }
    let location = classify_location(path, resource_types)?;
    if path
        .split('/')
        .any(|segment| segment != FN_IF && segment != FN_SUB && INTRINSIC_FN_PATH_SEGMENTS.contains(&segment))
    {
        return None;
    }

    if contains_service_ref(s, "ssm-secure") && !location_allows_ssm_secure(&location) {
        return Some((
            RULE_SSM_SECURE_LOCATION,
            format!("Dynamic reference '{}' to SSM secure strings can only be used in resource properties", s),
        ));
    }
    if contains_service_ref(s, "secretsmanager") && !location_allows_secretsmanager(&location) {
        return Some((
            RULE_SECRETSMANAGER_LOCATION,
            format!("Dynamic reference '{}' to secrets manager can only be used in resource properties", s),
        ));
    }
    if contains_service_ref(s, "ssm") && !location_allows_ssm(&location) {
        return Some((RULE_SSM_LOCATION, format!("Dynamic reference '{}' to SSM parameters is not allowed here", s)));
    }
    None
}

/// A location the reference implementation walks for dynamic references,
/// classified from a build path.
enum DynRefLocation {
    /// `Parameters/<name>/Default` or `Parameters/<name>/AllowedValues/...`.
    ParameterDefaultOrAllowed,
    /// `Resources/<id>/Properties/...`, with the type-keyed normalized property
    /// path (`Resources/<Type>/Properties/<segments>`, array indices as `*`)
    /// for the `ssm-secure` allowlist.
    ResourceProperty { normalized: String },
    /// `Resources/<id>/Metadata/...`.
    ResourceMetadata,
    /// `Outputs/<name>/Value`.
    OutputValue,
    /// `Outputs/<name>/Export/...`.
    OutputExport,
}

fn classify_location(path: &str, resource_types: &HashMap<String, String>) -> Option<DynRefLocation> {
    let segments: Vec<&str> = path.split('/').collect();
    match (segments.first().copied(), segments.get(2).copied()) {
        (Some(s), Some("Default" | "AllowedValues")) if s == SECTION_PARAMETERS => {
            Some(DynRefLocation::ParameterDefaultOrAllowed)
        }
        (Some(s), Some("Properties")) if s == SECTION_RESOURCES => {
            let resource_type = resource_types.get(segments[1]).map(String::as_str).unwrap_or("");
            let mut normalized = format!("{}/{}/Properties", SECTION_RESOURCES, resource_type);
            // Function wrappers are transparent for the property path (the
            // reference implementation's path is schema-based), and so are their
            // argument indices (e.g. the branch index after `Fn::If`). A numeric
            // segment that follows a plain property name is a real array
            // position and generalizes to `*`.
            let mut previous_was_function = false;
            for segment in &segments[3..] {
                if INTRINSIC_FN_PATH_SEGMENTS.contains(segment) {
                    previous_was_function = true;
                    continue;
                }
                if segment.parse::<usize>().is_ok() {
                    if !previous_was_function {
                        normalized.push_str("/*");
                    }
                    continue;
                }
                previous_was_function = false;
                normalized.push('/');
                normalized.push_str(segment);
            }
            Some(DynRefLocation::ResourceProperty { normalized })
        }
        (Some(s), Some("Metadata")) if s == SECTION_RESOURCES => Some(DynRefLocation::ResourceMetadata),
        (Some(s), Some("Value")) if s == SECTION_OUTPUTS => Some(DynRefLocation::OutputValue),
        (Some(s), Some("Export")) if s == SECTION_OUTPUTS => Some(DynRefLocation::OutputExport),
        _ => None,
    }
}

/// True when `s` contains a `{{resolve:<service>:...}}` reference for exactly
/// the given service (`ssm` does not match `ssm-secure`).
fn contains_service_ref(s: &str, service: &str) -> bool {
    s.contains(&format!("{{{{resolve:{}:", service))
}

fn location_allows_ssm_secure(location: &DynRefLocation) -> bool {
    match location {
        DynRefLocation::ResourceProperty { normalized } => {
            SSM_SECURE_ALLOWED_PROPERTY_PATHS.contains(&normalized.as_str())
        }
        _ => false,
    }
}

fn location_allows_secretsmanager(location: &DynRefLocation) -> bool {
    matches!(location, DynRefLocation::ResourceProperty { .. } | DynRefLocation::ParameterDefaultOrAllowed)
}

fn location_allows_ssm(location: &DynRefLocation) -> bool {
    matches!(
        location,
        DynRefLocation::ParameterDefaultOrAllowed
            | DynRefLocation::ResourceProperty { .. }
            | DynRefLocation::ResourceMetadata
            | DynRefLocation::OutputValue
    )
}

/// Returns `Some(message)` when the last `{{resolve:...}}` in `s` is malformed.
/// Returns `None` when there is no dynamic reference or it is well-formed.
fn dynamic_reference_error(s: &str) -> Option<String> {
    let payload = extract_last_resolve_payload(s)?;
    let parts: Vec<&str> = payload.split(':').collect();

    // `_all`: parts[0] == "resolve", parts[1] in the allowed services, and at
    // least three components overall.
    if parts.len() < 3 {
        return Some(format!("Dynamic reference '{{{{{}}}}}' must have at least 3 parts", payload));
    }
    if parts[0] != "resolve" {
        return Some(format!("'{}' is not 'resolve' in dynamic reference '{{{{{}}}}}'", parts[0], payload));
    }
    if !ALLOWED_SERVICES.contains(&parts[1]) {
        return Some(format!("'{}' is not one of {:?}", parts[1], ALLOWED_SERVICES));
    }

    match parts[1] {
        "ssm" | "ssm-secure" => ssm_error(&parts, payload),
        // parts[1] == "secretsmanager"
        _ if parts.get(2) == Some(&"arn") => secretsmanager_arn_error(&parts, payload),
        _ => secretsmanager_error(&parts, payload),
    }
}

/// `_ssm`: `["resolve", service, name, version]` with `name` containing an
/// allowed character (the reference schema uses an unanchored search, so any
/// substring match is accepted — spaces and other characters are tolerated as
/// long as one allowed character is present), `version` all digits, maxItems 4.
fn ssm_error(parts: &[&str], payload: &str) -> Option<String> {
    if parts.len() > 4 {
        return Some(format!("Dynamic reference '{{{{{}}}}}' has too many parts for '{}'", payload, parts[1]));
    }
    let name = parts.get(2).copied().unwrap_or("");
    if !name.chars().any(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/')) {
        return Some(format!("'{}' does not contain a valid SSM parameter name character", name));
    }
    if let Some(version) = parts.get(3)
        && (version.is_empty() || !version.chars().all(|c| c.is_ascii_digit()))
    {
        return Some(format!("'{}' does not match '\\d+'", version));
    }
    None
}

/// `_secrets_manager` (bare secret-id form): `["resolve", "secretsmanager",
/// secret-id, secret-string?, json-key?, version?, version?]` — secret-id may be
/// any printable string (including empty), secret-string is `SecretString` or
/// empty, minItems 3, maxItems 7.
fn secretsmanager_error(parts: &[&str], payload: &str) -> Option<String> {
    if parts.len() > 7 {
        return Some(format!("Dynamic reference '{{{{{}}}}}' has too many parts for 'secretsmanager'", payload));
    }
    if let Some(secret_string) = parts.get(3)
        && !matches!(*secret_string, "SecretString" | "")
    {
        return Some(format!("'{}' is not one of ['SecretString', '']", secret_string));
    }
    None
}

/// `_secrets_manager_arn`: `["resolve", "secretsmanager", "arn", partition,
/// service, region, account, "secret", secret-id, secret-string?, ...]` —
/// parts[7] is the literal `secret`, minItems 9, maxItems 13.
fn secretsmanager_arn_error(parts: &[&str], payload: &str) -> Option<String> {
    if parts.len() < 9 {
        return Some(format!("Dynamic reference ARN '{{{{{}}}}}' must have at least 9 parts", payload));
    }
    if parts.len() > 13 {
        return Some(format!("Dynamic reference ARN '{{{{{}}}}}' has too many parts", payload));
    }
    if parts[7] != "secret" {
        return Some(format!("'{}' was expected to be 'secret'", parts[7]));
    }
    if let Some(secret_string) = parts.get(9)
        && !matches!(*secret_string, "SecretString" | "")
    {
        return Some(format!("'{}' is not one of ['SecretString', '']", secret_string));
    }
    None
}

/// Extracts the `resolve:...` payload of the **last** `{{resolve:...}}` in `s`,
/// mirroring the greedy reference regex `^.*{{(resolve:.+)}}.*$`: the leading
/// `.*` consumes up to the last `{{`, and the trailing `}}.*$` anchors to the
/// last `}}`. Returns `None` when the string has no such reference.
fn extract_last_resolve_payload(s: &str) -> Option<&str> {
    let open = s.rfind("{{")?;
    let after_open = &s[open + 2..];
    let close_rel = after_open.rfind("}}")?;
    let inner = &after_open[..close_rel];
    if inner.starts_with("resolve:") { Some(inner) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(s: &str) -> Option<String> {
        dynamic_reference_error(s)
    }

    #[test]
    fn valid_ssm_forms_are_accepted() {
        assert!(err("{{resolve:ssm:/my/param}}").is_none());
        assert!(err("{{resolve:ssm:/my/param:1}}").is_none());
        assert!(err("{{resolve:ssm-secure:/my/param}}").is_none());
        // Spaces are tolerated: the reference schema search is unanchored.
        assert!(err("{{resolve:ssm:my param with spaces}}").is_none());
    }

    #[test]
    fn ssm_non_numeric_version_is_rejected() {
        assert!(err("{{resolve:ssm:/my/param:notanum}}").is_some());
    }

    #[test]
    fn unknown_service_is_rejected() {
        assert!(err("{{resolve:not-a-service:foo}}").is_some());
    }

    #[test]
    fn secretsmanager_bare_forms_are_accepted() {
        assert!(err("{{resolve:secretsmanager:my-secret}}").is_none());
        assert!(err("{{resolve:secretsmanager:my-secret:SecretString}}").is_none());
        // Full non-ARN tail (secret-id + SecretString + json-key + stage + id).
        assert!(err("{{resolve:secretsmanager:my-secret:SecretString:key:AWSCURRENT:versionid}}").is_none());
        // Empty secret-id is accepted by the reference schema.
        assert!(err("{{resolve:secretsmanager:}}").is_none());
    }

    #[test]
    fn secretsmanager_too_many_parts_is_rejected() {
        assert!(err("{{resolve:secretsmanager:a:SecretString:k:s:i:extra}}").is_some());
    }

    #[test]
    fn secretsmanager_arn_requires_secret_segment() {
        assert!(err("{{resolve:secretsmanager:arn:aws:secretsmanager:us-east-1:123456789012:secret:name}}").is_none());
        // ARN whose 8th segment is not the literal "secret" is rejected.
        assert!(err("{{resolve:secretsmanager:arn:aws:s3:us-east-1:123456789012:notsecret:name}}").is_some());
    }

    #[test]
    fn only_the_last_reference_is_validated() {
        // First ref malformed, last ref valid: the reference tooling validates
        // only the last, so this is accepted.
        assert!(err("{{resolve:ssm:p:notanum}}-{{resolve:ssm:goodparam:1}}").is_none());
        // Last ref malformed: rejected.
        assert!(err("{{resolve:ssm:goodparam:1}}-{{resolve:ssm:p:notanum}}").is_some());
    }

    #[test]
    fn function_argument_paths_are_skipped() {
        assert!(string_is_function_argument("Resources/R/Properties/X/Fn::Sub"));
        assert!(string_is_function_argument("Resources/R/Properties/X/Fn::Join/1/0"));
        assert!(!string_is_function_argument("Resources/R/Properties/X"));
        // Fn::If branches are transparent.
        assert!(!string_is_function_argument("Resources/R/Properties/X/Fn::If/1"));
    }

    #[test]
    fn plain_string_without_reference_is_ignored() {
        assert!(err("just a normal string").is_none());
        assert!(err("").is_none());
    }

    fn model_rule_ids(yaml: &str) -> Vec<String> {
        let model = crate::SemanticModel::from_bytes(yaml.as_bytes()).expect("model builds");
        let mut ids: Vec<String> = model.diagnostics.iter().map(|d| d.rule_id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    }

    #[test]
    fn validate_over_model_reports_e1050() {
        let ids = model_rule_ids(
            "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: \"{{resolve:not-a-service:foo}}\"\n",
        );
        assert!(ids.contains(&"E1050".to_string()));
    }

    #[test]
    fn fn_named_map_key_is_not_a_function_wrapper() {
        // A user map key that merely starts with `Fn::` is data; the dynamic
        // reference under it must still be format-checked.
        let ids = model_rule_ids(
            "Resources:\n  L:\n    Type: AWS::S3::Bucket\n    Metadata:\n      Vars:\n        \"Fn::Custom\": \"{{resolve:ssm:/p:notanum}}\"\n",
        );
        assert!(ids.contains(&"E1050".to_string()), "Fn::-named data key must not suppress the check: {:?}", ids);
    }

    #[test]
    fn ssm_secure_location_rule_matches_reference_allowlist() {
        // Not on the allowlist: S3 BucketName.
        let ids = model_rule_ids(
            "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: \"{{resolve:ssm-secure:/sec}}\"\n",
        );
        assert!(ids.contains(&"E1027".to_string()), "ssm-secure in a non-allowlisted property: {:?}", ids);

        // On the allowlist: RDS MasterUserPassword.
        let ids = model_rule_ids(
            "Resources:\n  D:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      MasterUserPassword: \"{{resolve:ssm-secure:/sec}}\"\n",
        );
        assert!(!ids.contains(&"E1027".to_string()), "allowlisted property must not fire: {:?}", ids);

        // Parameter default and output value are not resource properties.
        let ids = model_rule_ids(
            "Parameters:\n  P:\n    Type: String\n    Default: \"{{resolve:ssm-secure:/sec}}\"\nResources:\n  B:\n    Type: AWS::S3::Bucket\n",
        );
        assert!(ids.contains(&"E1027".to_string()), "ssm-secure in parameter default: {:?}", ids);
    }

    #[test]
    fn secretsmanager_location_rule_allows_properties_and_defaults() {
        // Allowed: resource property.
        let ids = model_rule_ids(
            "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: \"{{resolve:secretsmanager:s}}\"\n",
        );
        assert!(!ids.contains(&"E1051".to_string()), "secretsmanager in a property is allowed: {:?}", ids);

        // Allowed: parameter default (the reference allowlist includes it).
        let ids = model_rule_ids(
            "Parameters:\n  Q:\n    Type: String\n    Default: \"{{resolve:secretsmanager:s}}\"\nResources:\n  B:\n    Type: AWS::S3::Bucket\n",
        );
        assert!(!ids.contains(&"E1051".to_string()), "secretsmanager in a parameter default is allowed: {:?}", ids);

        // Not allowed: output value.
        let ids = model_rule_ids(
            "Resources:\n  B:\n    Type: AWS::S3::Bucket\nOutputs:\n  O:\n    Value: \"{{resolve:secretsmanager:s}}\"\n",
        );
        assert!(ids.contains(&"E1051".to_string()), "secretsmanager in an output value must fire: {:?}", ids);
    }

    #[test]
    fn ssm_location_rule_allows_output_values_and_defaults() {
        // Allowed: output value (the reference allowlist includes it).
        let ids = model_rule_ids(
            "Resources:\n  B:\n    Type: AWS::S3::Bucket\nOutputs:\n  O:\n    Value: \"{{resolve:ssm:/p}}\"\n",
        );
        assert!(!ids.contains(&"E1052".to_string()), "ssm in an output value is allowed: {:?}", ids);

        // Not walked by the reference implementation: Conditions — no finding.
        let ids = model_rule_ids(
            "Parameters:\n  P:\n    Type: String\nConditions:\n  C: !Equals [\"{{resolve:ssm:/p}}\", x]\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    Condition: C\n",
        );
        assert!(!ids.contains(&"E1052".to_string()), "Conditions are not walked: {:?}", ids);

        // Not allowed: output export name.
        let ids = model_rule_ids(
            "Resources:\n  B:\n    Type: AWS::S3::Bucket\nOutputs:\n  O:\n    Value: x\n    Export:\n      Name: \"{{resolve:ssm:/p}}\"\n",
        );
        assert!(ids.contains(&"E1052".to_string()), "ssm in an export name must fire: {:?}", ids);
    }
}
