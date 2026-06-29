//! Rules section validation — structural checks, function allowlisting, and
//! static assertion evaluation.
//!
//! CloudFormation Rules validate parameter values at stack-creation time.
//! Each rule has an optional `RuleCondition` and a required `Assertions` array.
//! Only a restricted set of intrinsic functions is allowed inside Rules.

use crate::consts::*;
use crate::ir::cfn_function_name;
use crate::ir::*;
use diagnostics::{Phase, RegisteredDiagnostic};

const VALID_RULE_KEYS: &[&str] = &[KEY_RULE_CONDITION, KEY_ASSERTIONS];
const VALID_ASSERTION_KEYS: &[&str] = &[KEY_ASSERT, KEY_ASSERT_DESCRIPTION];

const ALLOWED_RULE_FUNCTIONS: &[&str] = &[
    FN_REF,
    FN_VALUE_OF,
    FN_VALUE_OF_ALL,
    FN_REF_ALL,
    FN_CONTAINS,
    FN_EACH_MEMBER_EQUALS,
    FN_EACH_MEMBER_IN,
    FN_EQUALS,
    FN_AND,
    FN_OR,
    FN_NOT,
    FN_IF,
    FN_SELECT,
];

pub fn validate_rules(
    rules_json: &Option<serde_json::Value>,
    arena: &Arena,
    rules_node: NodeRef,
) -> Vec<diagnostics::Diagnostic> {
    let mut out = Vec::new();
    validate_structure(rules_json, &mut out);
    validate_allowed_functions(arena, rules_node, &mut out);
    out
}

fn validate_structure(rules_json: &Option<serde_json::Value>, out: &mut Vec<diagnostics::Diagnostic>) {
    let Some(rules) = rules_json else {
        return;
    };
    let Some(rules_obj) = rules.as_object() else {
        out.push(rule_diag("F8600", "Rules section must be an object".into()));
        return;
    };

    for (rule_name, rule_value) in rules_obj {
        validate_single_rule(rule_name, rule_value, out);
    }
}

fn validate_single_rule(rule_name: &str, rule_value: &serde_json::Value, out: &mut Vec<diagnostics::Diagnostic>) {
    let Some(rule_obj) = rule_value.as_object() else {
        out.push(rule_diag("F8601", format!("Rule '{}' must be an object", rule_name)));
        return;
    };

    for key in rule_obj.keys() {
        if !VALID_RULE_KEYS.contains(&key.as_str()) {
            out.push(rule_diag(
                "W8602",
                format!("Rule '{}' has unknown property '{}' — expected one of {:?}", rule_name, key, VALID_RULE_KEYS),
            ));
        }
    }

    let Some(assertions_val) = rule_obj.get(KEY_ASSERTIONS) else {
        out.push(rule_diag("F8603", format!("Rule '{}' is missing required '{}' property", rule_name, KEY_ASSERTIONS)));
        return;
    };

    let Some(assertions_arr) = assertions_val.as_array() else {
        out.push(rule_diag("F8604", format!("Rule '{}' {} must be an array", rule_name, KEY_ASSERTIONS)));
        return;
    };

    if assertions_arr.is_empty() {
        out.push(rule_diag("F8605", format!("Rule '{}' {} must not be empty", rule_name, KEY_ASSERTIONS)));
        return;
    }

    for (idx, assertion) in assertions_arr.iter().enumerate() {
        validate_single_assertion(rule_name, idx, assertion, out);
    }

    if let Some(condition) = rule_obj.get(KEY_RULE_CONDITION)
        && !condition.is_object()
    {
        out.push(rule_diag(
            "F8606",
            format!(
                "Rule '{}' {} must be a condition function (object), not {}",
                rule_name,
                KEY_RULE_CONDITION,
                json_type_name(condition)
            ),
        ));
    }
}

fn validate_single_assertion(
    rule_name: &str,
    idx: usize,
    assertion: &serde_json::Value,
    out: &mut Vec<diagnostics::Diagnostic>,
) {
    let Some(assertion_obj) = assertion.as_object() else {
        out.push(rule_diag("F8607", format!("Rule '{}' {}[{}] must be an object", rule_name, KEY_ASSERTIONS, idx)));
        return;
    };

    for key in assertion_obj.keys() {
        if !VALID_ASSERTION_KEYS.contains(&key.as_str()) {
            out.push(rule_diag(
                "W8608",
                format!(
                    "Rule '{}' {}[{}] has unknown property '{}' — expected one of {:?}",
                    rule_name, KEY_ASSERTIONS, idx, key, VALID_ASSERTION_KEYS
                ),
            ));
        }
    }

    let Some(assert_val) = assertion_obj.get(KEY_ASSERT) else {
        out.push(rule_diag(
            "F8609",
            format!("Rule '{}' {}[{}] is missing required '{}' property", rule_name, KEY_ASSERTIONS, idx, KEY_ASSERT),
        ));
        return;
    };

    if !assert_val.is_object() {
        out.push(rule_diag(
            "F8610",
            format!(
                "Rule '{}' {}[{}] {} must be a condition function (object), not {}",
                rule_name,
                KEY_ASSERTIONS,
                idx,
                KEY_ASSERT,
                json_type_name(assert_val)
            ),
        ));
    }
}

fn validate_allowed_functions(arena: &Arena, rules_node: NodeRef, out: &mut Vec<diagnostics::Diagnostic>) {
    if rules_node == NULL_REF {
        return;
    }
    walk_for_disallowed_functions(arena, rules_node, out);
}

fn walk_for_disallowed_functions(arena: &Arena, node_ref: NodeRef, out: &mut Vec<diagnostics::Diagnostic>) {
    if !arena.is_valid(node_ref) {
        return;
    }
    match &arena.get(node_ref).node {
        Node::Intrinsic(intrinsic) => {
            let fn_name = cfn_function_name(intrinsic);
            if !ALLOWED_RULE_FUNCTIONS.contains(&fn_name) {
                out.push(rule_diag(
                    "F8611",
                    format!(
                        "'{}' is not supported in the Rules section — allowed: {:?}",
                        fn_name, ALLOWED_RULE_FUNCTIONS
                    ),
                ));
            }
            walk_intrinsic_children(arena, intrinsic, out);
        }
        Node::Map(entries) => {
            for (_, child_ref) in entries {
                walk_for_disallowed_functions(arena, *child_ref, out);
            }
        }
        Node::List(items) => {
            for child_ref in items {
                walk_for_disallowed_functions(arena, *child_ref, out);
            }
        }
        _ => {}
    }
}

fn walk_intrinsic_children(arena: &Arena, intrinsic: &IntrinsicFn, out: &mut Vec<diagnostics::Diagnostic>) {
    let mut children = Vec::new();
    match intrinsic {
        IntrinsicFn::Ref(_)
        | IntrinsicFn::RefAll(_)
        | IntrinsicFn::ValueOf(_, _)
        | IntrinsicFn::ValueOfAll(_, _)
        | IntrinsicFn::GetAtt(_, _) => {}
        IntrinsicFn::Sub(_, subs) => {
            if let Some(entries) = subs {
                children.extend(entries.iter().map(|(_, r)| *r));
            }
        }
        IntrinsicFn::Join(a, b)
        | IntrinsicFn::Select(a, b)
        | IntrinsicFn::Split(a, b)
        | IntrinsicFn::Equals(a, b)
        | IntrinsicFn::Contains(a, b)
        | IntrinsicFn::EachMemberEquals(a, b)
        | IntrinsicFn::EachMemberIn(a, b) => {
            children.push(*a);
            children.push(*b);
        }
        IntrinsicFn::If(_, t, f) => {
            children.push(*t);
            children.push(*f);
        }
        IntrinsicFn::IfExpr(c, t, f) | IntrinsicFn::Cidr(c, t, f) => {
            children.push(*c);
            children.push(*t);
            children.push(*f);
        }
        IntrinsicFn::FindInMap(map_name_ref, k1, k2, default_ref) => {
            children.push(*map_name_ref);
            children.push(*k1);
            children.push(*k2);
            if let Some(d) = default_ref {
                children.push(*d);
            }
        }
        IntrinsicFn::Base64(c)
        | IntrinsicFn::GetAZs(c)
        | IntrinsicFn::ImportValue(c)
        | IntrinsicFn::Not(c)
        | IntrinsicFn::ToJsonString(c)
        | IntrinsicFn::Length(c) => {
            children.push(*c);
        }
        IntrinsicFn::And(nodes) | IntrinsicFn::Or(nodes) => {
            children.extend(nodes.iter().copied());
        }
        IntrinsicFn::Transform(_, params) => {
            children.extend(params.iter().map(|(_, r)| *r));
        }
        IntrinsicFn::ForEach(_, _, collection, body) => {
            children.push(*collection);
            children.push(*body);
        }
    }
    for child in children {
        walk_for_disallowed_functions(arena, child, out);
    }
}

fn json_type_name(val: &serde_json::Value) -> &'static str {
    match val {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn rule_diag(rule_id: &str, message: String) -> diagnostics::Diagnostic {
    RegisteredDiagnostic::new(rule_id, message).phase(Phase::Parse).build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_rule_produces_no_errors() {
        let rules = json!({
            "ProdRule": {
                "RuleCondition": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
                "Assertions": [{
                    "Assert": {"Fn::Contains": [["m5.large"], {"Fn::ValueOf": ["InstanceType", "GroupName"]}]},
                    "AssertDescription": "Must use approved instance type"
                }]
            }
        });
        let diags = validate_rules(&Some(rules), &Arena::new(), NULL_REF);
        let errors: Vec<_> = diags.iter().filter(|d| d.severity == rules::Severity::Error).collect();
        assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);
    }

    #[test]
    fn missing_assertions_produces_f8603() {
        let rules = json!({
            "BadRule": {
                "RuleCondition": {"Fn::Equals": [{"Ref": "Env"}, "prod"]}
            }
        });
        let diags = validate_rules(&Some(rules), &Arena::new(), NULL_REF);
        assert!(diags.iter().any(|d| d.rule_id == "F8603"));
    }

    #[test]
    fn empty_assertions_produces_f8605() {
        let rules = json!({ "BadRule": { "Assertions": [] } });
        let diags = validate_rules(&Some(rules), &Arena::new(), NULL_REF);
        assert!(diags.iter().any(|d| d.rule_id == "F8605"));
    }

    #[test]
    fn missing_assert_key_produces_f8609() {
        let rules = json!({ "BadRule": { "Assertions": [{"AssertDescription": "oops"}] } });
        let diags = validate_rules(&Some(rules), &Arena::new(), NULL_REF);
        assert!(diags.iter().any(|d| d.rule_id == "F8609"));
    }

    #[test]
    fn scalar_assert_produces_f8610() {
        let rules = json!({ "BadRule": { "Assertions": [{"Assert": "not-an-object"}] } });
        let diags = validate_rules(&Some(rules), &Arena::new(), NULL_REF);
        assert!(diags.iter().any(|d| d.rule_id == "F8610"));
    }

    #[test]
    fn unknown_rule_property_produces_w8602() {
        let rules = json!({
            "MyRule": {
                "Assertions": [{"Assert": {"Fn::Equals": [{"Ref": "A"}, "B"]}}],
                "SomethingElse": true
            }
        });
        let diags = validate_rules(&Some(rules), &Arena::new(), NULL_REF);
        assert!(diags.iter().any(|d| d.rule_id == "W8602"));
    }

    #[test]
    fn scalar_rule_condition_produces_f8606() {
        let rules = json!({
            "BadRule": {
                "RuleCondition": "not-an-object",
                "Assertions": [{"Assert": {"Fn::Equals": [{"Ref": "A"}, "B"]}}]
            }
        });
        let diags = validate_rules(&Some(rules), &Arena::new(), NULL_REF);
        assert!(diags.iter().any(|d| d.rule_id == "F8606"));
    }

    #[test]
    fn disallowed_function_in_rules_ir_produces_e8611() {
        let mut arena = Arena::new();
        let getatt = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::GetAtt("Res".into(), "Arn".into())),
            span: diagnostics::UNKNOWN_SPAN,
            path: "Rules/MyRule".into(),
        });
        let rule_map = arena.alloc(SpannedNode {
            node: Node::Map(vec![(KEY_ASSERT.into(), getatt)]),
            span: diagnostics::UNKNOWN_SPAN,
            path: "Rules".into(),
        });

        let diags = validate_rules(&None, &arena, rule_map);
        assert!(
            diags.iter().any(|d| d.rule_id == "F8611" && d.message.contains("Fn::GetAtt")),
            "Expected F8611 for Fn::GetAtt, got: {:?}",
            diags
        );
    }

    #[test]
    fn allowed_functions_in_rules_ir_produce_no_e8611() {
        let mut arena = Arena::new();
        let ref_node = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Ref("Env".into())),
            span: diagnostics::UNKNOWN_SPAN,
            path: "Rules/R/0".into(),
        });
        let lit = arena.alloc(SpannedNode {
            node: Node::String("prod".into()),
            span: diagnostics::UNKNOWN_SPAN,
            path: "Rules/R/1".into(),
        });
        let equals = arena.alloc(SpannedNode {
            node: Node::Intrinsic(IntrinsicFn::Equals(ref_node, lit)),
            span: diagnostics::UNKNOWN_SPAN,
            path: "Rules/R".into(),
        });

        let diags = validate_rules(&None, &arena, equals);
        let errors: Vec<_> = diags.iter().filter(|d| d.rule_id == "F8611").collect();
        assert!(errors.is_empty(), "Expected no F8611 errors, got: {:?}", errors);
    }
}
