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

use crate::consts::KEY_ROLE_ARN;
use crate::ir::{Arena, IntrinsicFn, NULL_REF, Node, NodeRef, cfn_function_name};

/// Nesting depth walked while building a fingerprint. A subtree deeper than this
/// yields no fingerprint at all rather than a truncated one, because a truncated
/// fingerprint could be shared by two expressions that differ only below the cut
/// and would turn into a duplicate report about values that were never compared.
const MAX_FINGERPRINT_DEPTH: u32 = 64;

/// A fingerprint of the expression at `node`, or `None` when the expression
/// cannot be fingerprinted in full. Two expressions share a fingerprint exactly
/// when they are structurally the same, so a shared fingerprint proves the two
/// produce the same value and a differing one proves nothing either way.
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
        // `RoleArn` names the credentials used to perform the read, not which
        // output is read, so two calls that differ only there still read one
        // value and stay a duplicate.
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
        // Both resolve before deployment, so their contents settle the question
        // and the authored form does not matter.
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
        // Neither export name is known before deployment, so nothing shows the
        // two imports read one export.
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
        // The role performs the read; it does not select which output is read.
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
}
