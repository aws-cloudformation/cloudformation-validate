//! Item count and uniqueness checks over lists whose members are gated by
//! conditions or carry values that resolve only at deploy time.

use diagnostics::Diagnostic;
use schema_validator::SchemaValidator;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use template_model::{BudgetKind, SemanticModel};

const LIST_TYPE: &str = "AWS::Test::ItemCardinality";

fn list_validator(values_schema: Value) -> SchemaValidator {
    SchemaValidator::try_with_additional_schemas(vec![(
        LIST_TYPE,
        json!({"properties": {"Values": values_schema}, "required": ["Values"], "additionalProperties": false}),
    )])
    .expect("test overlay must apply")
}

fn string_list_schema(constraint: &str, value: Value) -> Value {
    let mut schema = json!({"type": "array", "items": {"type": "string"}});
    schema[constraint] = value;
    schema
}

fn list_template(sections: Value, members: Value) -> String {
    let mut template = sections;
    template["Resources"] = json!({"Resource": {"Type": LIST_TYPE, "Properties": {"Values": members}}});
    template.to_string()
}

fn model(template: &str) -> Arc<SemanticModel> {
    Arc::new(SemanticModel::from_bytes(template.as_bytes()).expect("template must parse"))
}

fn validate(validator: &SchemaValidator, semantic_model: &Arc<SemanticModel>) -> Vec<Diagnostic> {
    validator.validate(semantic_model, Some("us-east-1")).diagnostics
}

fn findings<'a>(diagnostics: &'a [Diagnostic], rule_id: &str) -> Vec<&'a Diagnostic> {
    diagnostics.iter().filter(|diagnostic| diagnostic.rule_id == rule_id).collect()
}

fn scenario(literals: &[(&str, bool)]) -> Option<HashMap<String, bool>> {
    Some(literals.iter().map(|(condition, holds)| (condition.to_string(), *holds)).collect())
}

fn toggle_parameter() -> Value {
    json!({"Type": "String", "AllowedValues": ["true", "false"]})
}

fn toggled_on(parameter: &str) -> Value {
    json!({"Fn::Equals": [{"Ref": parameter}, "true"]})
}

fn if_condition(condition: &str, if_true: Value, if_false: Value) -> Value {
    json!({"Fn::If": [condition, if_true, if_false]})
}

fn no_value() -> Value {
    json!({"Ref": "AWS::NoValue"})
}

fn imported_value() -> Value {
    json!({"Fn::ImportValue": "SharedValue"})
}

fn toggles(names: &[&str]) -> Value {
    let parameters: serde_json::Map<String, Value> =
        names.iter().map(|name| (format!("{name}Value"), toggle_parameter())).collect();
    let conditions: serde_json::Map<String, Value> =
        names.iter().map(|name| (name.to_string(), toggled_on(&format!("{name}Value")))).collect();
    json!({"Parameters": parameters, "Conditions": conditions})
}

/// Members present only when their own condition holds, where every condition
/// selects a different value of one parameter that may also select none.
fn mutually_exclusive_members_template(member_count: usize) -> String {
    let mut allowed_values = vec!["none".to_string()];
    let mut conditions = serde_json::Map::new();
    let mut members = Vec::new();
    for index in 0..member_count {
        let choice = format!("choice-{index:02}");
        let condition = format!("Chooses{index:02}");
        conditions.insert(condition.clone(), json!({"Fn::Equals": [{"Ref": "Choice"}, choice]}));
        allowed_values.push(choice);
        members.push(if_condition(&condition, json!(format!("value-{index:02}")), no_value()));
    }
    list_template(
        json!({
            "Parameters": {"Choice": {"Type": "String", "AllowedValues": allowed_values}},
            "Conditions": conditions
        }),
        Value::Array(members),
    )
}

/// Tag-like members whose key and value each select one of
/// `allowed_value_count` parameter values, giving every member
/// `allowed_value_count^2` alternatives with keys that never collide.
fn nested_enum_members_template(member_count: usize, allowed_value_count: usize) -> String {
    let allowed_values: Vec<String> = (0..allowed_value_count).map(|index| format!("v{index:02}")).collect();
    let members: Vec<Value> = (0..member_count)
        .map(|index| {
            json!({
                "Key": {"Fn::Join": ["", [format!("k{index:02}-"), {"Ref": "KeySuffix"}]]},
                "Value": {"Ref": "TagValue"}
            })
        })
        .collect();
    list_template(
        json!({"Parameters": {
            "KeySuffix": {"Type": "String", "AllowedValues": allowed_values},
            "TagValue": {"Type": "String", "AllowedValues": allowed_values}
        }}),
        Value::Array(members),
    )
}

fn unique_tag_list_validator() -> SchemaValidator {
    list_validator(json!({
        "type": "array",
        "items": {"type": "object", "properties": {"Key": {"type": "string"}, "Value": {"type": "string"}}},
        "uniqueItems": true
    }))
}

#[test]
fn max_items_counts_members_whose_conditions_exclude_each_other() {
    const MEMBER_COUNT: usize = 13;
    let mut parameters = serde_json::Map::new();
    let mut conditions = serde_json::Map::new();
    let mut members = Vec::new();
    for index in 0..MEMBER_COUNT {
        let condition = format!("Skip{index:02}");
        if index == 1 {
            conditions.insert(condition.clone(), json!({"Fn::Not": [{"Condition": "Skip00"}]}));
        } else {
            let parameter = format!("Skip{index:02}Value");
            conditions.insert(condition.clone(), toggled_on(&parameter));
            parameters.insert(parameter, toggle_parameter());
        }
        members.push(if_condition(&condition, no_value(), json!(format!("value-{index:02}"))));
    }
    let template = list_template(json!({"Parameters": parameters, "Conditions": conditions}), Value::Array(members));
    let validator = list_validator(string_list_schema("maxItems", json!(5)));
    let mut expected_witness: HashMap<String, bool> =
        (0..MEMBER_COUNT).map(|index| (format!("Skip{index:02}"), false)).collect();
    expected_witness.insert("Skip01".to_string(), true);

    let diagnostics = validate(&validator, &model(&template));

    let violations = findings(&diagnostics, "F3032");
    assert_eq!(violations.len(), 1, "twelve members survive together in one deployment: {diagnostics:#?}");
    assert_eq!(violations[0].message, "expected maximum item count: 5, found: 12");
    assert_eq!(violations[0].condition_scenario, Some(expected_witness));
}

#[test]
fn min_items_counts_a_surviving_member_whose_value_is_unresolved() {
    let template = list_template(
        toggles(&["UseImported"]),
        json!([
            if_condition("UseImported", no_value(), json!("value-a")),
            if_condition("UseImported", no_value(), json!("value-b")),
            if_condition("UseImported", imported_value(), no_value()),
        ]),
    );
    let validator = list_validator(string_list_schema("minItems", json!(2)));

    let diagnostics = validate(&validator, &model(&template));

    let violations = findings(&diagnostics, "F3032");
    assert_eq!(violations.len(), 1, "only the imported member survives when importing: {diagnostics:#?}");
    assert_eq!(violations[0].message, "expected minimum item count: 2, found: 1");
    assert_eq!(violations[0].condition_scenario, scenario(&[("UseImported", true)]));
}

#[test]
fn max_items_counts_an_always_present_member_whose_value_is_unresolved() {
    let mut members: Vec<Value> = (1..=5).map(|index| json!(format!("value-{index}"))).collect();
    members.push(if_condition("UseShared", imported_value(), json!("value-6")));
    let template = list_template(toggles(&["UseShared"]), Value::Array(members));
    let validator = list_validator(string_list_schema("maxItems", json!(5)));

    let diagnostics = validate(&validator, &model(&template));

    let violations = findings(&diagnostics, "F3032");
    assert_eq!(violations.len(), 1, "six members survive in every deployment: {diagnostics:#?}");
    assert_eq!(violations[0].message, "expected maximum item count: 5, found: 6");
    assert_eq!(violations[0].condition_scenario, None);
}

#[test]
fn unique_items_is_checked_beside_a_member_whose_value_is_unresolved() {
    let template = list_template(json!({}), json!(["value-a", "value-a", imported_value()]));
    let validator = list_validator(string_list_schema("uniqueItems", json!(true)));

    let diagnostics = validate(&validator, &model(&template));

    let violations = findings(&diagnostics, "F3037");
    assert_eq!(violations.len(), 1, "the two literal members are equal in every deployment: {diagnostics:#?}");
    assert_eq!(violations[0].condition_scenario, None);
}

#[test]
fn unique_items_over_nested_enum_alternatives_stays_bounded_and_reports_incomplete_analysis() {
    let semantic_model = model(&nested_enum_members_template(50, 64));

    let diagnostics = validate(&unique_tag_list_validator(), &semantic_model);

    assert!(
        findings(&diagnostics, "F3037").is_empty(),
        "a curtailed expansion must not conclude a duplicate: {diagnostics:#?}"
    );
    assert!(
        semantic_model.exhausted_budget_kinds().contains(&BudgetKind::SchemaScenarioAssignments),
        "4096 alternatives per member exceed the bounded expansion and must be recorded: {:?}",
        semantic_model.exhausted_budget_kinds()
    );
    assert!(semantic_model.budget_analysis_incomplete());
}

#[test]
fn unique_items_over_nested_enum_alternatives_within_the_bound_is_complete() {
    let semantic_model = model(&nested_enum_members_template(50, 4));

    let diagnostics = validate(&unique_tag_list_validator(), &semantic_model);

    assert!(findings(&diagnostics, "F3037").is_empty(), "member keys never collide: {diagnostics:#?}");
    assert!(
        !semantic_model.exhausted_budget_kinds().contains(&BudgetKind::SchemaScenarioAssignments),
        "sixteen alternatives per member are analyzed in full: {:?}",
        semantic_model.exhausted_budget_kinds()
    );
}

#[test]
fn max_items_search_reports_incomplete_analysis_when_its_budget_is_spent() {
    let semantic_model = model(&mutually_exclusive_members_template(80));
    let validator = list_validator(string_list_schema("maxItems", json!(1)));

    let diagnostics = validate(&validator, &semantic_model);

    assert!(
        findings(&diagnostics, "F3032").is_empty(),
        "at most one member survives in any deployment: {diagnostics:#?}"
    );
    assert!(
        semantic_model.exhausted_budget_kinds().contains(&BudgetKind::SchemaScenarioMergeAttempts),
        "proving no deployment keeps two members exceeds the merge-attempt budget and must be recorded: {:?}",
        semantic_model.exhausted_budget_kinds()
    );
}

#[test]
fn min_items_search_over_mutually_exclusive_members_finds_the_empty_deployment() {
    const MEMBER_COUNT: usize = 80;
    let semantic_model = model(&mutually_exclusive_members_template(MEMBER_COUNT));
    let validator = list_validator(string_list_schema("minItems", json!(1)));
    let expected_witness: HashMap<String, bool> =
        (0..MEMBER_COUNT).map(|index| (format!("Chooses{index:02}"), false)).collect();

    let diagnostics = validate(&validator, &semantic_model);

    let violations = findings(&diagnostics, "F3032");
    assert_eq!(violations.len(), 1, "choosing none removes every member: {diagnostics:#?}");
    assert_eq!(violations[0].message, "expected minimum item count: 1, found: 0");
    assert_eq!(violations[0].condition_scenario, Some(expected_witness));
    assert!(
        !semantic_model.exhausted_budget_kinds().contains(&BudgetKind::SchemaScenarioAssignments),
        "the witness is found without exhausting the search budget: {:?}",
        semantic_model.exhausted_budget_kinds()
    );
}

#[test]
fn min_items_decides_each_branch_of_a_member_with_nested_conditions() {
    let template = list_template(
        toggles(&["UseOuter", "UseInner"]),
        json!([
            "fixed",
            if_condition("UseOuter", if_condition("UseInner", json!("inner"), no_value()), json!("outer"))
        ]),
    );
    let validator = list_validator(string_list_schema("minItems", json!(2)));

    let diagnostics = validate(&validator, &model(&template));

    let violations = findings(&diagnostics, "F3032");
    assert_eq!(violations.len(), 1, "the nested member is absent only on its inner false branch: {diagnostics:#?}");
    assert_eq!(violations[0].message, "expected minimum item count: 2, found: 1");
    assert_eq!(violations[0].condition_scenario, scenario(&[("UseOuter", true), ("UseInner", false)]));
}

#[test]
fn unique_items_reports_equal_alternatives_in_their_joint_world() {
    let template = list_template(
        toggles(&["ShareFirst", "ShareSecond"]),
        json!([
            if_condition("ShareFirst", json!("shared"), json!("first")),
            if_condition("ShareSecond", json!("shared"), json!("second")),
        ]),
    );
    let validator = list_validator(string_list_schema("uniqueItems", json!(true)));

    let diagnostics = validate(&validator, &model(&template));

    let violations = findings(&diagnostics, "F3037");
    assert_eq!(violations.len(), 1, "both members hold the shared value together: {diagnostics:#?}");
    assert_eq!(violations[0].condition_scenario, scenario(&[("ShareFirst", true), ("ShareSecond", true)]));
}

#[test]
fn unique_items_ignores_equal_alternatives_whose_conditions_exclude_each_other() {
    let template = list_template(
        json!({
            "Parameters": {"ShareFirstValue": toggle_parameter()},
            "Conditions": {
                "ShareFirst": toggled_on("ShareFirstValue"),
                "ShareSecond": {"Fn::Not": [{"Condition": "ShareFirst"}]}
            }
        }),
        json!([
            if_condition("ShareFirst", json!("shared"), json!("first")),
            if_condition("ShareSecond", json!("shared"), json!("second")),
        ]),
    );
    let validator = list_validator(string_list_schema("uniqueItems", json!(true)));

    let diagnostics = validate(&validator, &model(&template));

    assert!(
        findings(&diagnostics, "F3037").is_empty(),
        "the members never hold the shared value in one deployment: {diagnostics:#?}"
    );
}

#[test]
fn unique_items_does_not_pair_alternatives_of_one_member() {
    let template = list_template(
        toggles(&["UseFirst", "UseSecond"]),
        json!([
            if_condition("UseFirst", json!("shared"), if_condition("UseSecond", json!("shared"), json!("other"))),
            "distinct",
        ]),
    );
    let validator = list_validator(string_list_schema("uniqueItems", json!(true)));

    let diagnostics = validate(&validator, &model(&template));

    assert!(
        findings(&diagnostics, "F3037").is_empty(),
        "one member holding one value under several conditions is a single item: {diagnostics:#?}"
    );
}

#[test]
fn unique_items_compares_object_members_regardless_of_key_order() {
    let template = list_template(
        toggles(&["AddExtra"]),
        json!([
            {"Key": "team", "Value": "a"},
            {"Value": "a", "Key": "team"},
            if_condition("AddExtra", json!({"Key": "extra", "Value": "b"}), no_value()),
        ]),
    );
    let validator = list_validator(json!({"type": "array", "items": {"type": "object"}, "uniqueItems": true}));

    let diagnostics = validate(&validator, &model(&template));

    let violations = findings(&diagnostics, "F3037");
    assert_eq!(violations.len(), 1, "objects with the same entries are equal items: {diagnostics:#?}");
    assert_eq!(violations[0].condition_scenario, None);
}

#[test]
fn unique_items_compares_numbers_by_mathematical_value() {
    let template = list_template(json!({}), json!([1, 1.0]));
    let validator = list_validator(json!({"type": "array", "items": {"type": "number"}, "uniqueItems": true}));

    let diagnostics = validate(&validator, &model(&template));

    let violations = findings(&diagnostics, "F3037");
    assert_eq!(violations.len(), 1, "integer and floating-point spellings of one are equal: {diagnostics:#?}");
    assert_eq!(violations[0].condition_scenario, None);
}

#[test]
fn unique_items_covering_window_reports_incomplete_analysis() {
    const CONDITION_COUNT: usize = 13;
    let condition_names: Vec<String> = (0..CONDITION_COUNT).map(|index| format!("Toggle{index:02}")).collect();
    let condition_refs: Vec<&str> = condition_names.iter().map(String::as_str).collect();
    let conditional_entries: serde_json::Map<String, Value> = condition_names
        .iter()
        .enumerate()
        .map(|(index, condition)| (format!("Field{index:02}"), if_condition(condition, json!("true"), json!("false"))))
        .collect();
    let target_entries: serde_json::Map<String, Value> = (0..CONDITION_COUNT)
        .map(|index| {
            let value = if index < 7 { "true" } else { "false" };
            (format!("Field{index:02}"), json!(value))
        })
        .collect();
    let semantic_model = model(&list_template(
        toggles(&condition_refs),
        json!([Value::Object(conditional_entries), Value::Object(target_entries)]),
    ));
    let validator = list_validator(json!({"type": "array", "items": {"type": "object"}, "uniqueItems": true}));

    let diagnostics = validate(&validator, &semantic_model);

    assert!(
        findings(&diagnostics, "F3037").is_empty(),
        "the covering set does not prove the mixed world: {diagnostics:#?}"
    );
    assert!(
        semantic_model.exhausted_budget_kinds().contains(&BudgetKind::SchemaScenarioAssignments),
        "8192 exact alternatives must not be treated as complete: {:?}",
        semantic_model.exhausted_budget_kinds()
    );
}

#[test]
fn unique_items_reports_literal_duplicate_beside_curtailed_member() {
    let allowed_values: Vec<String> = (0..258).map(|index| format!("value-{index:03}")).collect();
    let template = list_template(
        json!({"Parameters": {"Choice": {"Type": "String", "AllowedValues": allowed_values}}}),
        json!(["duplicate", "duplicate", {"Ref": "Choice"}]),
    );
    let semantic_model = model(&template);
    let validator = list_validator(string_list_schema("uniqueItems", json!(true)));

    let diagnostics = validate(&validator, &semantic_model);

    assert_eq!(findings(&diagnostics, "F3037").len(), 1, "the literal duplicate remains provable: {diagnostics:#?}");
    assert!(
        semantic_model.exhausted_budget_kinds().contains(&BudgetKind::SchemaScenarioAssignments),
        "the parameter member's omitted alternative must remain visible: {:?}",
        semantic_model.exhausted_budget_kinds()
    );
}

#[test]
fn max_items_reports_unconditional_violation_beside_oversized_complex_member() {
    fn branching_member(depth: usize, index: &mut usize, conditions: &mut Vec<String>) -> Value {
        if depth == 0 {
            let leaf = if (*index).is_multiple_of(2) { json!("optional") } else { no_value() };
            *index += 1;
            return leaf;
        }
        let condition = format!("Branch{depth:02}");
        if !conditions.contains(&condition) {
            conditions.push(condition.clone());
        }
        if_condition(
            &condition,
            branching_member(depth - 1, index, conditions),
            branching_member(depth - 1, index, conditions),
        )
    }

    let mut conditions = Vec::new();
    let mut leaf_index = 0;
    let complex_member = branching_member(9, &mut leaf_index, &mut conditions);
    let condition_refs: Vec<&str> = conditions.iter().map(String::as_str).collect();
    let mut members: Vec<Value> = (0..6).map(|index| json!(format!("fixed-{index}"))).collect();
    members.push(complex_member);
    let semantic_model = model(&list_template(toggles(&condition_refs), Value::Array(members)));
    let validator = list_validator(string_list_schema("maxItems", json!(5)));

    let diagnostics = validate(&validator, &semantic_model);

    let violations = findings(&diagnostics, "F3032");
    assert_eq!(violations.len(), 1, "six unconditional members already violate the maximum: {diagnostics:#?}");
    assert_eq!(violations[0].message, "expected maximum item count: 5, found: 6");
    assert!(semantic_model.exhausted_budget_kinds().contains(&BudgetKind::SchemaScenarioAssignments));
}

#[test]
fn unique_items_does_not_collapse_out_of_range_integral_float() {
    let template = list_template(json!({}), json!([i64::MAX, 9_223_372_036_854_775_808.0_f64]));
    let validator = list_validator(json!({"type": "array", "items": {"type": "number"}, "uniqueItems": true}));

    let diagnostics = validate(&validator, &model(&template));

    assert!(
        findings(&diagnostics, "F3037").is_empty(),
        "2^63 is distinct from the largest signed integer: {diagnostics:#?}"
    );
}

#[test]
fn unique_items_with_shared_conditions_is_complete() {
    let fields: serde_json::Map<String, Value> = (0..9)
        .map(|index| (format!("Field{index}"), if_condition("Shared", json!("enabled"), json!("disabled"))))
        .collect();
    let semantic_model =
        model(&list_template(toggles(&["Shared"]), json!([Value::Object(fields), {"distinct": true}])));
    let validator = list_validator(json!({"type": "array", "items": {"type": "object"}, "uniqueItems": true}));

    let diagnostics = validate(&validator, &semantic_model);

    assert!(findings(&diagnostics, "F3037").is_empty(), "the two members are distinct: {diagnostics:#?}");
    assert!(
        !semantic_model.exhausted_budget_kinds().contains(&BudgetKind::SchemaScenarioAssignments),
        "shared conditions produce only two exact alternatives: {:?}",
        semantic_model.exhausted_budget_kinds()
    );
}

#[test]
fn unique_items_node_heavy_member_reports_incomplete_analysis() {
    let heavy_conditions: Vec<String> = (0..6).map(|index| format!("Heavy{index}")).collect();
    let light_conditions: Vec<String> = (0..6).map(|index| format!("Light{index}")).collect();
    let condition_refs: Vec<&str> = heavy_conditions.iter().chain(&light_conditions).map(String::as_str).collect();
    let unresolved = Value::Array(vec![imported_value(); 50]);
    let mut member = serde_json::Map::new();
    let mut target = serde_json::Map::new();
    for (index, condition) in heavy_conditions.iter().enumerate() {
        member.insert(format!("Heavy{index}"), if_condition(condition, unresolved.clone(), json!("light")));
        target.insert(format!("Heavy{index}"), json!("light"));
    }
    for (index, condition) in light_conditions.iter().enumerate() {
        member.insert(format!("Light{index}"), if_condition(condition, json!("a"), json!("b")));
        target.insert(format!("Light{index}"), json!(if index == 0 { "a" } else { "b" }));
    }
    let semantic_model =
        model(&list_template(toggles(&condition_refs), json!([Value::Object(member), Value::Object(target)])));
    let validator = list_validator(json!({"type": "array", "items": {"type": "object"}, "uniqueItems": true}));

    let diagnostics = validate(&validator, &semantic_model);

    assert!(
        findings(&diagnostics, "F3037").is_empty(),
        "the covering set must not claim an unproven duplicate: {diagnostics:#?}"
    );
    assert!(
        semantic_model.exhausted_budget_kinds().contains(&BudgetKind::SchemaScenarioAssignments),
        "the materialized-node bound forces covering and must be visible: {:?}",
        semantic_model.exhausted_budget_kinds()
    );
}
