//! Keys that two template values share only when they are provably the same value.
//!
//! A rule that reports two entries of a list as duplicates asserts that both
//! entries hold one value. A value known before deployment establishes that by
//! its own contents. A value known only at deploy time cannot, so it establishes
//! it by the expression that produces it: two entries written as the same
//! expression always read the same thing, while two entries written differently
//! may read the same thing or different things, and must never be reported as
//! duplicates.
//!
//! The fingerprint below is therefore built from the authored expression rather
//! than from any human-readable description of the resolved value. A description
//! is lossy - several unrelated expressions share one wording - and two distinct
//! reads that share a wording would otherwise look like a duplicate.
//!
//! ## Canonicalization
//!
//! `expression_fingerprint` normalizes the authored AST before fingerprinting so
//! that syntactically different but semantically identical expressions produce the
//! same fingerprint. The accepted equivalences are:
//!
//! - Implicit Sub whose entire template is exactly `${X}` → Ref(X)
//! - Implicit Sub whose entire template is exactly `${R.Attr}` → GetAtt(R, Attr)
//! - Explicit Sub whose template is exactly `${V}` and whose map provides V →
//!   the mapped node (recursively canonicalized)
//! - Empty-delimiter Join with exactly one element → that element
//!
//! All other forms (multi-element Join, compound/multi-variable Sub, escaped
//! `${!Literal}`, whitespace surrounding variables) remain distinct.

use crate::consts::KEY_ROLE_ARN;
use crate::ir::{Arena, IntrinsicFn, NULL_REF, Node, NodeRef, cfn_function_name};

/// Nesting depth walked while building a fingerprint. A subtree deeper than this
/// yields no fingerprint at all rather than a truncated one, because a truncated
/// fingerprint could be shared by two expressions that differ only below the cut
/// and would turn into a duplicate report about values that were never compared.
const MAX_FINGERPRINT_DEPTH: u32 = 64;

/// A fingerprint of the expression at `node`, or `None` when the expression
/// cannot be fingerprinted in full. Two expressions share a fingerprint exactly
/// when they are structurally the same after canonicalization, so a shared
/// fingerprint proves the two produce the same value and a differing one proves
/// nothing either way.
///
/// Object keys are ordered, so the same call written with its arguments in a
/// different order keeps one fingerprint.
pub(crate) fn expression_fingerprint(arena: &Arena, node: NodeRef) -> Option<String> {
    let mut fingerprint = String::new();
    if write_node(arena, node, 0, &mut fingerprint) { Some(fingerprint) } else { None }
}

/// A canonical fingerprint of a resolved JSON value. Object keys are sorted so
/// identity follows JSON object equality rather than source insertion order.
pub(crate) fn concrete_value_fingerprint(value: &serde_json::Value) -> String {
    let mut fingerprint = String::new();
    write_json_value(value, &mut fingerprint);
    fingerprint
}

fn write_json_value(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(value) => {
            out.push_str("bool:");
            out.push_str(if *value { "true" } else { "false" });
        }
        serde_json::Value::Number(value) => {
            out.push_str("number:");
            out.push_str(&value.to_string());
        }
        serde_json::Value::String(value) => {
            out.push_str("str:");
            write_literal(value, out);
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_value(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(entries) => {
            out.push('{');
            let mut ordered: Vec<_> = entries.iter().collect();
            ordered.sort_by_key(|(left, _)| *left);
            for (index, (key, item)) in ordered.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_literal(key, out);
                out.push('=');
                write_json_value(item, out);
            }
            out.push('}');
        }
    }
}

fn write_node(arena: &Arena, node: NodeRef, depth: u32, out: &mut String) -> bool {
    if node == NULL_REF || depth > MAX_FINGERPRINT_DEPTH {
        return false;
    }
    match &arena.get(node).node {
        Node::Null => {
            out.push_str("null");
            true
        }
        Node::Bool(value) => {
            out.push_str("bool:");
            out.push_str(if *value { "true" } else { "false" });
            true
        }
        Node::Int(value) => {
            out.push_str("int:");
            out.push_str(&value.to_string());
            true
        }
        Node::Float(value) => {
            out.push_str("float:");
            out.push_str(&value.to_string());
            true
        }
        Node::String(value) => {
            out.push_str("str:");
            write_literal(value, out);
            true
        }
        Node::List(items) => {
            out.push('[');
            let written = write_nodes(arena, items, depth, out);
            out.push(']');
            written
        }
        Node::Map(entries) => {
            out.push('{');
            let written = write_keyed(arena, entries, depth, out, &[]);
            out.push('}');
            written
        }
        Node::Intrinsic(intrinsic) => write_intrinsic(arena, intrinsic, depth, out),
    }
}

fn write_intrinsic(arena: &Arena, intrinsic: &IntrinsicFn, depth: u32, out: &mut String) -> bool {
    match canonicalize(arena, intrinsic) {
        Canonical::Ref(target) => {
            out.push_str(cfn_function_name(&IntrinsicFn::Ref(String::new())));
            out.push('(');
            write_literal(&target, out);
            out.push(')');
            true
        }
        Canonical::GetAtt(resource, attribute) => {
            out.push_str(cfn_function_name(&IntrinsicFn::GetAtt(String::new(), String::new())));
            out.push('(');
            write_literal(&resource, out);
            out.push(',');
            write_literal(&attribute, out);
            out.push(')');
            true
        }
        Canonical::Unwrap(inner_ref) => write_node(arena, inner_ref, depth + 1, out),
        Canonical::None => write_intrinsic_verbatim(arena, intrinsic, depth, out),
    }
}

/// The result of attempting to canonicalize an intrinsic to a simpler form.
enum Canonical {
    /// Canonicalize to Ref(target).
    Ref(String),
    /// Canonicalize to GetAtt(resource, attribute).
    GetAtt(String, String),
    /// Canonicalize by unwrapping to the inner node (recursively fingerprinted).
    Unwrap(NodeRef),
    /// No canonicalization applies; fingerprint verbatim.
    None,
}

/// Attempts to canonicalize an intrinsic to a simpler equivalent form.
///
/// Accepted equivalences:
/// - Implicit Sub `${X}` (no extra text) → Ref(X)
/// - Implicit Sub `${R.Attr}` (no extra text) → GetAtt(R, Attr)
/// - Explicit Sub `${V}` with map providing V to a node → that node
/// - Empty-delimiter Join with exactly one element → that element
fn canonicalize(arena: &Arena, intrinsic: &IntrinsicFn) -> Canonical {
    match intrinsic {
        IntrinsicFn::Sub(template, variables) => canonicalize_sub(arena, template, variables.as_deref()),
        IntrinsicFn::Join(delimiter_ref, list_ref) => canonicalize_join(arena, *delimiter_ref, *list_ref),
        _ => Canonical::None,
    }
}

/// Canonicalize a Sub intrinsic. Only a template that is exactly one variable
/// reference with no surrounding text qualifies.
fn canonicalize_sub(_arena: &Arena, template: &str, variables: Option<&[(String, NodeRef)]>) -> Canonical {
    let Some(var_name) = extract_single_variable(template) else {
        return Canonical::None;
    };

    match variables {
        None => {
            // Implicit Sub: `${X}` → Ref(X), `${R.Attr}` → GetAtt(R, Attr)
            if let Some((resource, attribute)) = var_name.split_once('.') {
                Canonical::GetAtt(resource.to_string(), attribute.to_string())
            } else {
                Canonical::Ref(var_name.to_string())
            }
        }
        Some(entries) => {
            // Explicit Sub: template is `${V}` and map provides exactly that V
            if let Some((_, node_ref)) = entries.iter().find(|(key, _)| key == var_name) {
                Canonical::Unwrap(*node_ref)
            } else {
                Canonical::None
            }
        }
    }
}

/// Extracts the variable name from a Sub template that is exactly `${Name}`
/// with no extra text (no whitespace trimming, no escape sequences).
/// Returns `None` for compound templates, multi-variable templates, or escaped
/// sequences like `${!Literal}`.
fn extract_single_variable(template: &str) -> Option<&str> {
    let rest = template.strip_prefix("${")?;
    let name = rest.strip_suffix('}')?;
    // Reject if there's another `${` inside (multi-variable)
    if name.contains("${") {
        return None;
    }
    // Reject escaped form `${!...}`
    if name.starts_with('!') {
        return None;
    }
    // Reject empty variable name
    if name.is_empty() {
        return None;
    }
    Some(name)
}

/// Canonicalize a Join intrinsic. Only an empty-string delimiter with exactly
/// one element in the value list qualifies.
fn canonicalize_join(arena: &Arena, delimiter_ref: NodeRef, list_ref: NodeRef) -> Canonical {
    if delimiter_ref == NULL_REF || list_ref == NULL_REF {
        return Canonical::None;
    }
    let is_empty_delimiter = matches!(arena.node(delimiter_ref), Node::String(s) if s.is_empty());
    if !is_empty_delimiter {
        return Canonical::None;
    }
    let Node::List(items) = arena.node(list_ref) else {
        return Canonical::None;
    };
    if items.len() == 1 { Canonical::Unwrap(items[0]) } else { Canonical::None }
}

fn write_intrinsic_verbatim(arena: &Arena, intrinsic: &IntrinsicFn, depth: u32, out: &mut String) -> bool {
    out.push_str(cfn_function_name(intrinsic));
    out.push('(');
    let written = match intrinsic {
        IntrinsicFn::Ref(target) | IntrinsicFn::RefAll(target) => {
            write_literal(target, out);
            true
        }
        IntrinsicFn::GetAtt(target, attribute)
        | IntrinsicFn::ValueOf(target, attribute)
        | IntrinsicFn::ValueOfAll(target, attribute) => {
            write_literal(target, out);
            out.push(',');
            write_literal(attribute, out);
            true
        }
        IntrinsicFn::Sub(template, variables) => {
            write_literal(template, out);
            match variables {
                Some(entries) => {
                    out.push(',');
                    write_keyed(arena, entries, depth, out, &[])
                }
                None => true,
            }
        }
        IntrinsicFn::Join(first, second)
        | IntrinsicFn::Select(first, second)
        | IntrinsicFn::Split(first, second)
        | IntrinsicFn::Equals(first, second)
        | IntrinsicFn::Contains(first, second)
        | IntrinsicFn::EachMemberEquals(first, second)
        | IntrinsicFn::EachMemberIn(first, second) => write_nodes(arena, &[*first, *second], depth, out),
        IntrinsicFn::If(condition, when_true, when_false) => {
            write_literal(condition, out);
            out.push(',');
            write_nodes(arena, &[*when_true, *when_false], depth, out)
        }
        IntrinsicFn::IfExpr(condition, when_true, when_false) | IntrinsicFn::Cidr(condition, when_true, when_false) => {
            write_nodes(arena, &[*condition, *when_true, *when_false], depth, out)
        }
        IntrinsicFn::FindInMap(map_name, first_key, second_key, default_value) => {
            let mut refs = vec![*map_name, *first_key, *second_key];
            if let Some(default_value) = default_value {
                refs.push(*default_value);
            }
            write_nodes(arena, &refs, depth, out)
        }
        IntrinsicFn::Base64(argument)
        | IntrinsicFn::GetAZs(argument)
        | IntrinsicFn::ImportValue(argument)
        | IntrinsicFn::Not(argument)
        | IntrinsicFn::ToJsonString(argument)
        | IntrinsicFn::Length(argument) => write_nodes(arena, &[*argument], depth, out),
        IntrinsicFn::GetStackOutput(arguments) => write_keyed(arena, arguments, depth, out, &[KEY_ROLE_ARN]),
        IntrinsicFn::Transform(name, parameters) => {
            write_literal(name, out);
            out.push(',');
            write_keyed(arena, parameters, depth, out, &[])
        }
        IntrinsicFn::And(operands) | IntrinsicFn::Or(operands) => write_nodes(arena, operands, depth, out),
        IntrinsicFn::ForEach(identifier, unique_id, collection, body) => {
            write_literal(identifier, out);
            out.push(',');
            write_literal(unique_id, out);
            out.push(',');
            write_nodes(arena, &[*collection, *body], depth, out)
        }
    };
    out.push(')');
    written
}

fn write_nodes(arena: &Arena, refs: &[NodeRef], depth: u32, out: &mut String) -> bool {
    for (index, node) in refs.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        if !write_node(arena, *node, depth + 1, out) {
            return false;
        }
    }
    true
}

/// Writes `entries` in key order, skipping `ignored_keys`, so that argument order
/// in the template does not change the fingerprint.
fn write_keyed(
    arena: &Arena,
    entries: &[(String, NodeRef)],
    depth: u32,
    out: &mut String,
    ignored_keys: &[&str],
) -> bool {
    let mut ordered: Vec<&(String, NodeRef)> =
        entries.iter().filter(|(key, _)| !ignored_keys.contains(&key.as_str())).collect();
    ordered.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (index, (key, node)) in ordered.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_literal(key, out);
        out.push('=');
        if !write_node(arena, *node, depth + 1, out) {
            return false;
        }
    }
    true
}

/// Writes `value` quoted, with quotes and backslashes escaped, so that a
/// separator appearing inside a value cannot read as a field boundary and make
/// two different expressions share a fingerprint.
fn write_literal(value: &str, out: &mut String) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(character),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SemanticModel;

    /// Identity of the value written at `path` of resource `R` in `template`.
    fn identity_of(template: &str, path: &str) -> Option<String> {
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        model.value_identity("R", path)
    }

    fn two_item_template(first: &str, second: &str) -> String {
        format!(r#"{{"Resources":{{"R":{{"Type":"T","Properties":{{"V":[{first},{second}]}}}}}}}}"#)
    }

    /// The two entries of `V` share an identity - they are provably one value.
    fn entries_share_identity(first: &str, second: &str) -> bool {
        let template = two_item_template(first, second);
        let left = identity_of(&template, "Properties.V.0");
        let right = identity_of(&template, "Properties.V.1");
        assert!(left.is_some(), "left entry must have an identity: {first}");
        assert!(right.is_some(), "right entry must have an identity: {second}");
        left == right
    }

    #[test]
    fn equal_literals_share_an_identity() {
        assert!(entries_share_identity(r#""subnet-a""#, r#""subnet-a""#));
    }

    #[test]
    fn different_literals_have_distinct_identities() {
        assert!(!entries_share_identity(r#""subnet-a""#, r#""subnet-b""#));
    }

    #[test]
    fn equal_objects_with_different_key_order_share_an_identity() {
        assert!(entries_share_identity(
            r#"{"Type":"memberOf","Expression":"attribute:ecs.instance-type =~ t3.*"}"#,
            r#"{"Expression":"attribute:ecs.instance-type =~ t3.*","Type":"memberOf"}"#
        ));
    }

    #[test]
    fn a_literal_and_an_intrinsic_producing_it_share_an_identity() {
        assert!(entries_share_identity(r#""a-b""#, r#"{"Fn::Join":["-",["a","b"]]}"#));
    }

    #[test]
    fn repeated_import_of_one_export_shares_an_identity() {
        assert!(entries_share_identity(r#"{"Fn::ImportValue":"Export"}"#, r#"{"Fn::ImportValue":"Export"}"#));
    }

    #[test]
    fn imports_of_different_exports_have_distinct_identities() {
        assert!(!entries_share_identity(r#"{"Fn::ImportValue":"ExportOne"}"#, r#"{"Fn::ImportValue":"ExportTwo"}"#));
    }

    #[test]
    fn imports_of_exports_named_by_different_parameters_have_distinct_identities() {
        let template = r#"{"Parameters":{"First":{"Type":"String"},"Second":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Fn::ImportValue":{"Ref":"First"}},
                {"Fn::ImportValue":{"Ref":"Second"}}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("left identity");
        let right = identity_of(template, "Properties.V.1").expect("right identity");
        assert_ne!(left, right, "imports named by different parameters must not collapse");
    }

    #[test]
    fn one_export_named_by_one_parameter_shares_an_identity() {
        let template = r#"{"Parameters":{"Only":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Fn::ImportValue":{"Ref":"Only"}},
                {"Fn::ImportValue":{"Ref":"Only"}}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("left identity");
        let right = identity_of(template, "Properties.V.1").expect("right identity");
        assert_eq!(left, right, "one export read twice is one value");
    }

    #[test]
    fn stack_outputs_of_different_outputs_have_distinct_identities() {
        assert!(!entries_share_identity(
            r#"{"Fn::GetStackOutput":{"StackName":"S","OutputName":"One"}}"#,
            r#"{"Fn::GetStackOutput":{"StackName":"S","OutputName":"Two"}}"#
        ));
    }

    #[test]
    fn stack_outputs_of_different_stacks_have_distinct_identities() {
        assert!(!entries_share_identity(
            r#"{"Fn::GetStackOutput":{"StackName":"One","OutputName":"O"}}"#,
            r#"{"Fn::GetStackOutput":{"StackName":"Two","OutputName":"O"}}"#
        ));
    }

    #[test]
    fn stack_outputs_of_different_regions_have_distinct_identities() {
        assert!(!entries_share_identity(
            r#"{"Fn::GetStackOutput":{"StackName":"S","Region":"us-east-1","OutputName":"O"}}"#,
            r#"{"Fn::GetStackOutput":{"StackName":"S","Region":"eu-west-1","OutputName":"O"}}"#
        ));
    }

    #[test]
    fn stack_outputs_named_by_different_parameters_have_distinct_identities() {
        let template = r#"{"Parameters":{"First":{"Type":"String"},"Second":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Fn::GetStackOutput":{"StackName":{"Ref":"First"},"OutputName":"O"}},
                {"Fn::GetStackOutput":{"StackName":{"Ref":"Second"},"OutputName":"O"}}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("left identity");
        let right = identity_of(template, "Properties.V.1").expect("right identity");
        assert_ne!(left, right, "stacks named by different parameters must not collapse");
    }

    #[test]
    fn argument_order_does_not_change_a_stack_output_identity() {
        assert!(entries_share_identity(
            r#"{"Fn::GetStackOutput":{"StackName":"S","Region":"us-east-1","OutputName":"O"}}"#,
            r#"{"Fn::GetStackOutput":{"OutputName":"O","Region":"us-east-1","StackName":"S"}}"#
        ));
    }

    #[test]
    fn a_differing_role_arn_does_not_change_a_stack_output_identity() {
        assert!(entries_share_identity(
            r#"{"Fn::GetStackOutput":{"StackName":"S","OutputName":"O","RoleArn":"arn:aws:iam::111111111111:role/A"}}"#,
            r#"{"Fn::GetStackOutput":{"StackName":"S","OutputName":"O","RoleArn":"arn:aws:iam::222222222222:role/B"}}"#
        ));
    }

    #[test]
    fn different_macros_have_distinct_identities() {
        assert!(!entries_share_identity(
            r#"{"Fn::Transform":{"Name":"MacroOne","Parameters":{"Key":"V"}}}"#,
            r#"{"Fn::Transform":{"Name":"MacroTwo","Parameters":{"Key":"V"}}}"#
        ));
    }

    #[test]
    fn selects_of_different_indices_have_distinct_identities() {
        let template = r#"{"Parameters":{"List":{"Type":"CommaDelimitedList"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Fn::Select":["0",{"Fn::GetAZs":{"Ref":"AWS::Region"}}]},
                {"Fn::Select":["1",{"Fn::GetAZs":{"Ref":"AWS::Region"}}]}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0");
        let right = identity_of(template, "Properties.V.1");
        assert!(left.is_some() && right.is_some(), "both selects must have an identity");
        assert_ne!(left, right, "selects of different indices must not collapse");
    }

    #[test]
    fn references_to_different_resources_have_distinct_identities() {
        let template = r#"{"Resources":{
            "A":{"Type":"AWS::EC2::Subnet"},
            "B":{"Type":"AWS::EC2::Subnet"},
            "R":{"Type":"T","Properties":{"V":[{"Ref":"A"},{"Ref":"B"}]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("left identity");
        let right = identity_of(template, "Properties.V.1").expect("right identity");
        assert_ne!(left, right, "references to different resources must not collapse");
    }

    #[test]
    fn different_parameters_with_equal_defaults_have_distinct_identities() {
        let template = r#"{"Parameters":{
            "A":{"Type":"String","Default":"subnet-1"},
            "B":{"Type":"String","Default":"subnet-1"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[{"Ref":"A"},{"Ref":"B"}]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("left identity");
        let right = identity_of(template, "Properties.V.1").expect("right identity");
        assert_ne!(left, right, "overrideable defaults must not establish one value");
    }

    #[test]
    fn one_reference_written_twice_shares_an_identity() {
        let template = r#"{"Resources":{
            "A":{"Type":"AWS::EC2::Subnet"},
            "R":{"Type":"T","Properties":{"V":[{"Ref":"A"},{"Ref":"A"}]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("left identity");
        let right = identity_of(template, "Properties.V.1").expect("right identity");
        assert_eq!(left, right, "one reference written twice is one value");
    }

    #[test]
    fn a_path_with_no_value_has_no_identity() {
        let template = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":["only"]}}}}"#;
        assert_eq!(identity_of(template, "Properties.Missing.4"), None);
    }

    // --- Canonicalization tests ---

    #[test]
    fn implicit_sub_single_variable_canonicalizes_to_ref() {
        let template = r#"{"Parameters":{"X":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Sub":"${X}"}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("Sub identity");
        assert_eq!(left, right, "implicit Sub '${{X}}' must canonicalize to Ref(X)");
    }

    #[test]
    fn implicit_sub_getatt_canonicalizes_to_getatt() {
        let template = r#"{"Resources":{
            "Bucket":{"Type":"AWS::S3::Bucket"},
            "R":{"Type":"T","Properties":{"V":[
                {"Fn::GetAtt":["Bucket","Arn"]},
                {"Fn::Sub":"${Bucket.Arn}"}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("GetAtt identity");
        let right = identity_of(template, "Properties.V.1").expect("Sub identity");
        assert_eq!(left, right, "implicit Sub '${{R.Attr}}' must canonicalize to GetAtt(R,Attr)");
    }

    #[test]
    fn explicit_sub_single_variable_mapped_to_ref_canonicalizes() {
        let template = r#"{"Parameters":{"X":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Sub":["${V}",{"V":{"Ref":"X"}}]}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("explicit Sub identity");
        assert_eq!(left, right, "explicit Sub ['${{V}}', {{V: !Ref X}}] must canonicalize to Ref(X)");
    }

    #[test]
    fn empty_delimiter_single_element_join_canonicalizes() {
        let template = r#"{"Parameters":{"X":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Join":["", [{"Ref":"X"}]]}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("Join identity");
        assert_eq!(left, right, "Join ['', [Ref X]] must canonicalize to Ref(X)");
    }

    #[test]
    fn all_four_forms_share_one_identity() {
        let template = r#"{"Parameters":{"X":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Sub":"${X}"},
                {"Fn::Sub":["${V}",{"V":{"Ref":"X"}}]},
                {"Fn::Join":["", [{"Ref":"X"}]]}
            ]}}}}"#;
        let a = identity_of(template, "Properties.V.0").expect("Ref identity");
        let b = identity_of(template, "Properties.V.1").expect("implicit Sub identity");
        let c = identity_of(template, "Properties.V.2").expect("explicit Sub identity");
        let d = identity_of(template, "Properties.V.3").expect("Join identity");
        assert_eq!(a, b, "Ref == implicit Sub");
        assert_eq!(a, c, "Ref == explicit Sub");
        assert_eq!(a, d, "Ref == Join");
    }

    // --- Rejected near-misses ---

    #[test]
    fn multi_element_join_remains_distinct() {
        let template = r#"{"Parameters":{"X":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Join":["", [{"Ref":"X"}, "extra"]]}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("Join identity");
        assert_ne!(left, right, "multi-element Join must NOT canonicalize");
    }

    #[test]
    fn non_empty_delimiter_join_remains_distinct() {
        let template = r#"{"Parameters":{"X":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Join":["-", [{"Ref":"X"}]]}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("Join identity");
        assert_ne!(left, right, "non-empty-delimiter Join must NOT canonicalize");
    }

    #[test]
    fn compound_sub_template_remains_distinct() {
        let template = r#"{"Parameters":{"X":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Sub":"${X}-suffix"}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("Sub identity");
        assert_ne!(left, right, "compound Sub must NOT canonicalize");
    }

    #[test]
    fn multi_variable_sub_remains_distinct() {
        let template = r#"{"Parameters":{"X":{"Type":"String"},"Y":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Sub":"${X}${Y}"}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("Sub identity");
        assert_ne!(left, right, "multi-variable Sub must NOT canonicalize");
    }

    #[test]
    fn escaped_literal_sub_remains_distinct() {
        let template = r#"{"Parameters":{"X":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Sub":"${!X}"}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("Sub identity");
        assert_ne!(left, right, "escaped literal Sub must NOT canonicalize");
    }

    #[test]
    fn whitespace_around_variable_in_sub_remains_distinct() {
        let template = r#"{"Parameters":{"X":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Sub":" ${X}"}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("Sub identity");
        assert_ne!(left, right, "whitespace around variable must NOT be trimmed");
    }

    #[test]
    fn explicit_sub_with_missing_mapping_remains_distinct() {
        let template = r#"{"Parameters":{"X":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Sub":["${Missing}",{"Other":{"Ref":"X"}}]}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("Sub identity");
        assert_ne!(left, right, "explicit Sub with missing mapping must NOT canonicalize");
    }

    #[test]
    fn explicit_sub_multi_entry_map_single_variable_canonicalizes() {
        // Extra entries in the map don't prevent canonicalization if the template
        // references exactly one variable and the map provides it.
        let template = r#"{"Parameters":{"X":{"Type":"String"},"Y":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Sub":["${V}",{"V":{"Ref":"X"},"Unused":{"Ref":"Y"}}]}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("explicit Sub identity");
        assert_eq!(left, right, "extra unused entries do not prevent canonicalization");
    }

    #[test]
    fn recursive_canonicalization_through_nested_join() {
        let template = r#"{"Parameters":{"X":{"Type":"String"}},
            "Resources":{"R":{"Type":"T","Properties":{"V":[
                {"Ref":"X"},
                {"Fn::Join":["", [{"Fn::Sub":"${X}"}]]}
            ]}}}}"#;
        let left = identity_of(template, "Properties.V.0").expect("Ref identity");
        let right = identity_of(template, "Properties.V.1").expect("nested Join/Sub identity");
        assert_eq!(left, right, "recursive canonicalization must apply through nesting");
    }

    #[test]
    fn canonical_wrappers_respect_fingerprint_depth_limit() {
        use crate::ir::SpannedNode;

        let mut arena = Arena::new();
        let delimiter = arena.alloc(SpannedNode {
            node: Node::String(String::new()),
            span: crate::UNKNOWN_SPAN,
            path: String::new(),
        });
        let mut current = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Ref("X".to_string())),
            span: crate::UNKNOWN_SPAN,
            path: String::new(),
        });
        for _ in 0..=MAX_FINGERPRINT_DEPTH {
            let list = arena.alloc(SpannedNode {
                node: Node::List(vec![current]),
                span: crate::UNKNOWN_SPAN,
                path: String::new(),
            });
            current = arena.alloc(SpannedNode {
                node: Node::Intrinsic(IntrinsicFn::Join(delimiter, list)),
                span: crate::UNKNOWN_SPAN,
                path: String::new(),
            });
        }

        assert_eq!(expression_fingerprint(&arena, current), None);
    }

    // --- extract_single_variable unit tests ---

    #[test]
    fn extract_single_variable_valid() {
        assert_eq!(extract_single_variable("${Foo}"), Some("Foo"));
        assert_eq!(extract_single_variable("${Bucket.Arn}"), Some("Bucket.Arn"));
    }

    #[test]
    fn extract_single_variable_rejects_compound() {
        assert_eq!(extract_single_variable("prefix-${X}"), None);
        assert_eq!(extract_single_variable("${X}-suffix"), None);
        assert_eq!(extract_single_variable("${X}${Y}"), None);
    }

    #[test]
    fn extract_single_variable_rejects_escaped() {
        assert_eq!(extract_single_variable("${!Literal}"), None);
    }

    #[test]
    fn extract_single_variable_rejects_empty() {
        assert_eq!(extract_single_variable("${}"), None);
    }

    #[test]
    fn extract_single_variable_no_whitespace_trimming() {
        assert_eq!(extract_single_variable(" ${X}"), None);
        assert_eq!(extract_single_variable("${X} "), None);
    }
}
