//! Focused integration tests for full composition branch enforcement,
//! multipleOf, dependencies array-form, and ref siblings.

use schema_validator::{CompiledSchemaStore, SchemaOverlayError, SchemaValidator};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use template_model::SemanticModel;

fn model(template: &str) -> Arc<SemanticModel> {
    Arc::new(SemanticModel::from_bytes(template.as_bytes()).expect("template must parse"))
}

fn validator(overlays: Vec<(&str, Value)>) -> SchemaValidator {
    SchemaValidator::try_with_additional_schemas(overlays).expect("test overlays must apply")
}

fn validate(sv: &SchemaValidator, template: &str) -> Vec<diagnostics::Diagnostic> {
    sv.validate(&model(template), Some("us-east-1")).diagnostics
}

fn mentions(diags: &[diagnostics::Diagnostic], rule_id: &str, needle: &str) -> bool {
    diags.iter().any(|d| d.rule_id == rule_id && d.message.contains(needle))
}

// ─── multipleOf enforcement ─────────────────────────────────────────────────

#[test]
fn multiple_of_rejects_non_multiple_value() {
    let sv = validator(vec![(
        "AWS::Test::MultipleOf",
        json!({
            "properties": { "Count": { "type": "integer", "multipleOf": 5 } },
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::MultipleOf\n    Properties:\n      Count: 7\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3034", "not a multiple of"),
        "7 is not a multiple of 5, expected F3034: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn multiple_of_accepts_valid_multiple() {
    let sv = validator(vec![(
        "AWS::Test::MultipleOf",
        json!({
            "properties": { "Count": { "type": "integer", "multipleOf": 5 } },
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::MultipleOf\n    Properties:\n      Count: 15\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3034", "not a multiple of"),
        "15 is a multiple of 5, should not fire: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn multiple_of_tolerates_floating_point_imprecision() {
    // 0.3 / 0.1 = 2.9999... in IEEE 754 - the check must tolerate this.
    let sv = validator(vec![(
        "AWS::Test::MultipleOfFloat",
        json!({
            "properties": { "Step": { "type": "number", "multipleOf": 0.1 } },
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::MultipleOfFloat\n    Properties:\n      Step: 0.3\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3034", "not a multiple of"),
        "0.3 is a multiple of 0.1 (within tolerance): {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── dependencies array-form ────────────────────────────────────────────────

#[test]
fn dependencies_array_form_is_compiled_as_dependent_required() {
    let sv = validator(vec![(
        "AWS::Test::Deps",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "C": { "type": "string" }
            },
            "dependencies": { "A": ["B", "C"] },
            "additionalProperties": false
        }),
    )]);
    // Template has A but not B or C
    let template = "Resources:\n  R:\n    Type: AWS::Test::Deps\n    Properties:\n      A: val\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3021", "dependency of"),
        "expected F3021 for missing dependency: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn dependencies_schema_form_is_rejected() {
    let result = SchemaValidator::try_with_additional_schemas(vec![(
        "AWS::Test::SchemaDeps",
        json!({
            "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
            "dependencies": { "A": { "properties": { "B": { "type": "string" } }, "required": ["B"] } }
        }),
    )]);
    match result {
        Err(error) => assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}"),
        Ok(_) => panic!("schema-form dependencies should be rejected"),
    }
}

// ─── anyOf/oneOf with scalar type/enum ──────────────────────────────────────

#[test]
fn any_of_with_required_validates_correctly() {
    let sv = validator(vec![(
        "AWS::Test::AnyOf",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "C": { "type": "string" }
            },
            "anyOf": [{ "required": ["A"] }, { "required": ["B"] }],
            "additionalProperties": false
        }),
    )]);
    // Template has C but neither A nor B - should fail anyOf
    let template = "Resources:\n  R:\n    Type: AWS::Test::AnyOf\n    Properties:\n      C: val\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 when neither branch matches: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn one_of_with_properties_and_additional_properties() {
    let sv = validator(vec![(
        "AWS::Test::OneOf",
        json!({
            "properties": {
                "Mode": { "type": "string" },
                "ConfigA": { "type": "string" },
                "ConfigB": { "type": "string" }
            },
            "oneOf": [
                { "required": ["ConfigA"], "properties": { "ConfigA": { "type": "string" } } },
                { "required": ["ConfigB"], "properties": { "ConfigB": { "type": "string" } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Template has neither ConfigA nor ConfigB - should fail oneOf
    let template = "Resources:\n  R:\n    Type: AWS::Test::OneOf\n    Properties:\n      Mode: test\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3018", "not valid under any"),
        "expected F3018 when no branch matches: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── ref in composition branches ────────────────────────────────────────────

#[test]
fn composition_branch_with_ref_resolves_definition_constraints() {
    let sv = validator(vec![(
        "AWS::Test::BranchRef",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "C": { "type": "string" }
            },
            "definitions": {
                "NeedsA": { "required": ["A"] },
                "NeedsB": { "required": ["B"] }
            },
            "anyOf": [
                { "$ref": "#/definitions/NeedsA" },
                { "$ref": "#/definitions/NeedsB" }
            ],
            "additionalProperties": false
        }),
    )]);
    // Template has C but neither A nor B
    let template = "Resources:\n  R:\n    Type: AWS::Test::BranchRef\n    Properties:\n      C: val\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 when neither referenced branch matches: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── ref siblings ───────────────────────────────────────────────────────────

#[test]
fn ref_siblings_are_enforced_at_validation_time() {
    let sv = validator(vec![(
        "AWS::Test::RefSibling",
        json!({
            "properties": {
                "Name": { "$ref": "#/definitions/NameDef", "maxLength": 5 }
            },
            "definitions": { "NameDef": { "type": "string" } },
            "required": ["Name"],
            "additionalProperties": false
        }),
    )]);
    // Name is 10 chars - exceeds maxLength of 5 stated beside the $ref
    let template = "Resources:\n  R:\n    Type: AWS::Test::RefSibling\n    Properties:\n      Name: TooLongName\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3033", "exceeds maximum"),
        "maxLength beside a $ref should be enforced: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── nested composition ─────────────────────────────────────────────────────

#[test]
fn nested_any_of_inside_one_of_is_compiled() {
    // Verify nested composition is accepted without error
    let sv = validator(vec![(
        "AWS::Test::Nested",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "C": { "type": "string" }
            },
            "oneOf": [
                { "required": ["A"], "anyOf": [{ "required": ["B"] }, { "required": ["C"] }] },
                { "required": ["C"] }
            ],
            "additionalProperties": false
        }),
    )]);
    // Template has B only - does not satisfy either top-level oneOf branch
    let template = "Resources:\n  R:\n    Type: AWS::Test::Nested\n    Properties:\n      B: val\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3018", "not valid under any"),
        "expected F3018 for nested composition: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── anyOf discriminated by type+enum ─────────────────────────────────────

#[test]
fn any_of_discriminated_by_type_and_enum_rejects_wrong_enum() {
    let sv = validator(vec![(
        "AWS::Test::AnyOfTypeEnum",
        json!({
            "properties": {
                "Mode": { "type": "string" },
                "Value": { "type": "string" }
            },
            "anyOf": [
                { "properties": { "Mode": { "type": "string", "enum": ["fast"] } } },
                { "properties": { "Mode": { "type": "string", "enum": ["slow"] } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Mode is "broken" - matches neither branch
    let template =
        "Resources:\n  R:\n    Type: AWS::Test::AnyOfTypeEnum\n    Properties:\n      Mode: broken\n      Value: x\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 when enum value matches no branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn any_of_discriminated_by_type_and_enum_accepts_matching_enum() {
    let sv = validator(vec![(
        "AWS::Test::AnyOfTypeEnum",
        json!({
            "properties": {
                "Mode": { "type": "string" },
                "Value": { "type": "string" }
            },
            "anyOf": [
                { "properties": { "Mode": { "type": "string", "enum": ["fast"] } } },
                { "properties": { "Mode": { "type": "string", "enum": ["slow"] } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Mode is "fast" - matches first branch
    let template =
        "Resources:\n  R:\n    Type: AWS::Test::AnyOfTypeEnum\n    Properties:\n      Mode: fast\n      Value: x\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "expected no F3017 when enum value matches a branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── oneOf exactly-one distinguished only by enum ───────────────────────────

#[test]
fn one_of_enum_discriminator_rejects_ambiguous_value() {
    let sv = validator(vec![(
        "AWS::Test::OneOfEnum",
        json!({
            "properties": {
                "Engine": { "type": "string" }
            },
            "oneOf": [
                { "properties": { "Engine": { "type": "string", "enum": ["mysql"] } } },
                { "properties": { "Engine": { "type": "string", "enum": ["postgres"] } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Engine is "oracle" - matches neither branch
    let template = "Resources:\n  R:\n    Type: AWS::Test::OneOfEnum\n    Properties:\n      Engine: oracle\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3018", "not valid under any"),
        "expected F3018 when value matches no oneOf branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn one_of_enum_discriminator_accepts_exactly_one_match() {
    let sv = validator(vec![(
        "AWS::Test::OneOfEnum",
        json!({
            "properties": {
                "Engine": { "type": "string" }
            },
            "oneOf": [
                { "properties": { "Engine": { "type": "string", "enum": ["mysql"] } } },
                { "properties": { "Engine": { "type": "string", "enum": ["postgres"] } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Engine is "mysql" - matches exactly one branch
    let template = "Resources:\n  R:\n    Type: AWS::Test::OneOfEnum\n    Properties:\n      Engine: mysql\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3018", ""),
        "expected no F3018 when value matches exactly one branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn one_of_enum_discriminator_rejects_multiple_matches() {
    let sv = validator(vec![(
        "AWS::Test::OneOfEnumOverlap",
        json!({
            "properties": {
                "Engine": { "type": "string" }
            },
            "oneOf": [
                { "properties": { "Engine": { "type": "string", "enum": ["mysql", "postgres"] } } },
                { "properties": { "Engine": { "type": "string", "enum": ["postgres", "oracle"] } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Engine is "postgres" - matches BOTH branches
    let template = "Resources:\n  R:\n    Type: AWS::Test::OneOfEnumOverlap\n    Properties:\n      Engine: postgres\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3018", "more than one"),
        "expected F3018 'more than one' when value matches two oneOf branches: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── numeric bounds/multipleOf branch ───────────────────────────────────────

#[test]
fn any_of_numeric_bounds_rejects_out_of_range() {
    let sv = validator(vec![(
        "AWS::Test::AnyOfNumeric",
        json!({
            "properties": {
                "Port": { "type": "integer" }
            },
            "anyOf": [
                { "properties": { "Port": { "type": "integer", "minimum": 1, "maximum": 1024 } } },
                { "properties": { "Port": { "type": "integer", "minimum": 8000, "maximum": 9000 } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Port is 5000 - falls between both ranges
    let template = "Resources:\n  R:\n    Type: AWS::Test::AnyOfNumeric\n    Properties:\n      Port: 5000\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 when numeric value is out of all branch ranges: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn any_of_numeric_bounds_accepts_in_range() {
    let sv = validator(vec![(
        "AWS::Test::AnyOfNumeric",
        json!({
            "properties": {
                "Port": { "type": "integer" }
            },
            "anyOf": [
                { "properties": { "Port": { "type": "integer", "minimum": 1, "maximum": 1024 } } },
                { "properties": { "Port": { "type": "integer", "minimum": 8000, "maximum": 9000 } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Port is 443 - falls in first range
    let template = "Resources:\n  R:\n    Type: AWS::Test::AnyOfNumeric\n    Properties:\n      Port: 443\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "expected no F3017 when numeric value is within a branch range: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn any_of_multiple_of_branch_matching() {
    let sv = validator(vec![(
        "AWS::Test::AnyOfMultipleOf",
        json!({
            "properties": {
                "Size": { "type": "integer" }
            },
            "anyOf": [
                { "properties": { "Size": { "type": "integer", "multipleOf": 64 } } },
                { "properties": { "Size": { "type": "integer", "multipleOf": 100 } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Size is 7 - not a multiple of 64 or 100
    let template = "Resources:\n  R:\n    Type: AWS::Test::AnyOfMultipleOf\n    Properties:\n      Size: 7\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 when not a multiple of any branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );

    // Size is 128 - multiple of 64
    let template2 = "Resources:\n  R:\n    Type: AWS::Test::AnyOfMultipleOf\n    Properties:\n      Size: 128\n";
    let diags2 = validate(&sv, template2);
    assert!(
        !mentions(&diags2, "F3017", ""),
        "expected no F3017 when value is a multiple of 64: {:?}",
        diags2.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── object nested property constraint ──────────────────────────────────────

#[test]
fn any_of_nested_object_property_constraint_rejects_mismatch() {
    let sv = validator(vec![(
        "AWS::Test::AnyOfNested",
        json!({
            "properties": {
                "Config": { "type": "object", "properties": {
                    "Type": { "type": "string" },
                    "Value": { "type": "string" }
                }}
            },
            "anyOf": [
                { "properties": { "Config": {
                    "type": "object",
                    "properties": { "Type": { "type": "string", "enum": ["A"] } }
                }}},
                { "properties": { "Config": {
                    "type": "object",
                    "properties": { "Type": { "type": "string", "enum": ["B"] } }
                }}}
            ],
            "additionalProperties": false
        }),
    )]);
    // Config.Type is "C" - matches neither branch
    let template =
        r#"{"Resources":{"R":{"Type":"AWS::Test::AnyOfNested","Properties":{"Config":{"Type":"C","Value":"x"}}}}}"#;
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 when nested property matches no branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn any_of_nested_object_property_constraint_accepts_match() {
    let sv = validator(vec![(
        "AWS::Test::AnyOfNested",
        json!({
            "properties": {
                "Config": { "type": "object", "properties": {
                    "Type": { "type": "string" },
                    "Value": { "type": "string" }
                }}
            },
            "anyOf": [
                { "properties": { "Config": {
                    "type": "object",
                    "properties": { "Type": { "type": "string", "enum": ["A"] } }
                }}},
                { "properties": { "Config": {
                    "type": "object",
                    "properties": { "Type": { "type": "string", "enum": ["B"] } }
                }}}
            ],
            "additionalProperties": false
        }),
    )]);
    // Config.Type is "A" - matches first branch
    let template =
        r#"{"Resources":{"R":{"Type":"AWS::Test::AnyOfNested","Properties":{"Config":{"Type":"A","Value":"x"}}}}}"#;
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "expected no F3017 when nested property matches a branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── array items constraint in branch ───────────────────────────────────────

#[test]
fn any_of_array_items_constraint_rejects_wrong_item_type() {
    let sv = validator(vec![(
        "AWS::Test::AnyOfItems",
        json!({
            "properties": {
                "Tags": { "type": "array" }
            },
            "anyOf": [
                { "properties": { "Tags": { "type": "array", "items": { "type": "object" } } } },
                { "properties": { "Tags": { "type": "array", "items": { "type": "integer" } } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Tags contains a string - neither object nor integer items (string-to-integer coercion
    // only works for numeric strings; "hello" is not coercible to integer)
    let template = r#"{"Resources":{"R":{"Type":"AWS::Test::AnyOfItems","Properties":{"Tags":["hello"]}}}}"#;
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 when array items don't match any branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn any_of_array_items_constraint_accepts_matching_items() {
    let sv = validator(vec![(
        "AWS::Test::AnyOfItems",
        json!({
            "properties": {
                "Tags": { "type": "array" }
            },
            "anyOf": [
                { "properties": { "Tags": { "type": "array", "items": { "type": "object" } } } },
                { "properties": { "Tags": { "type": "array", "items": { "type": "integer" } } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Tags contains integers - matches second branch
    let template = r#"{"Resources":{"R":{"Type":"AWS::Test::AnyOfItems","Properties":{"Tags":[1,2,3]}}}}"#;
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "expected no F3017 when array items match a branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── conditional (if/then/else) branch ──────────────────────────────────────

#[test]
fn any_of_with_if_then_else_branch_constraint() {
    // A branch that consists of a conditional participates in matching per
    // draft-07: the branch matches when its condition selects a satisfied
    // sub-schema. Engine "mysql" satisfies the conditional branch's then
    // (Port required); engine "sqlite" matches neither branch.
    let sv = validator(vec![(
        "AWS::Test::AnyOfConditional",
        json!({
            "properties": {
                "Engine": { "type": "string" },
                "Port": { "type": "integer" }
            },
            "anyOf": [
                { "properties": { "Engine": { "type": "string", "enum": ["postgres"] } }, "required": ["Engine"] },
                {
                    "if": { "properties": { "Engine": { "enum": ["mysql"] } }, "required": ["Engine"] },
                    "then": { "required": ["Port"] },
                    "else": { "required": ["Engine", "Port"] }
                }
            ],
            "additionalProperties": false
        }),
    )]);
    // Engine mysql with Port - the conditional branch's then is satisfied.
    let satisfied = "Resources:\n  R:\n    Type: AWS::Test::AnyOfConditional\n    Properties:\n      Engine: mysql\n      Port: 3306\n";
    let diags = validate(&sv, satisfied);
    assert!(
        !mentions(&diags, "F3017", ""),
        "expected no F3017 when the conditional branch matches: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );

    // Engine mysql WITHOUT Port - then requires Port, so the conditional branch
    // fails; the enum branch fails too (not postgres) - anyOf reports.
    let violating = "Resources:\n  R:\n    Type: AWS::Test::AnyOfConditional\n    Properties:\n      Engine: mysql\n";
    let diags = validate(&sv, violating);
    assert!(
        mentions(&diags, "F3017", ""),
        "a conditional branch whose then fails must not match vacuously: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn any_of_with_conditional_allof_constraint() {
    // Use allOf with if/then/else (which IS supported by the overlay) to test
    // conditional branch value matching.
    let sv = validator(vec![(
        "AWS::Test::ConditionalAllOf",
        json!({
            "properties": {
                "Engine": { "type": "string", "enum": ["mysql", "postgres"] },
                "Port": { "type": "integer" }
            },
            "allOf": [
                {
                    "if": { "properties": { "Engine": { "enum": ["mysql"] } } },
                    "then": { "dependentRequired": { "Engine": ["Port"] } }
                }
            ],
            "additionalProperties": false
        }),
    )]);
    // Engine is mysql but Port is missing - should flag dependentRequired
    let template = "Resources:\n  R:\n    Type: AWS::Test::ConditionalAllOf\n    Properties:\n      Engine: mysql\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3021", "dependency"),
        "expected F3021 when conditional dependency not met: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── dangling ref non-match ─────────────────────────────────────────────────

#[test]
fn any_of_dangling_ref_marks_branch_non_matching() {
    let sv = validator(vec![(
        "AWS::Test::DanglingRef",
        json!({
            "properties": {
                "Name": { "type": "string" }
            },
            "definitions": {},
            "anyOf": [
                { "$ref": "#/definitions/NonExistent" },
                { "properties": { "Name": { "type": "string", "enum": ["valid"] } } }
            ],
            "additionalProperties": false
        }),
    )]);
    // Name is "valid" - second branch matches despite first being dangling
    let template = "Resources:\n  R:\n    Type: AWS::Test::DanglingRef\n    Properties:\n      Name: valid\n";
    let diags = validate(&sv, template);
    // The dangling-reference branch emits its own finding, so the second branch
    // being valid means anyOf passes overall.
    assert!(
        !mentions(&diags, "F3017", ""),
        "expected no F3017 when at least one non-dangling branch matches: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn any_of_all_branches_dangling_ref_fails() {
    let sv = validator(vec![(
        "AWS::Test::AllDangling",
        json!({
            "properties": {
                "Name": { "type": "string" }
            },
            "definitions": {},
            "anyOf": [
                { "$ref": "#/definitions/NonExistent1" },
                { "$ref": "#/definitions/NonExistent2" }
            ],
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::AllDangling\n    Properties:\n      Name: anything\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 when all branches have dangling refs: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── overlay acceptance gate ────────────────────────────────────────────────

#[test]
fn overlay_acceptance_gate_under_threshold() {
    use std::path::Path;
    // The provider-schema corpus is a maintainer-local input (gitignored under
    // `data-source/upstream/`), so a clean checkout - CI included - has no
    // directory to read. The gate runs only where the corpus exists; when it
    // does, it must be non-empty so the test cannot pass vacuously against an
    // empty directory.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../data-source/upstream/schemas");
    let Ok(entries) = std::fs::read_dir(&root) else {
        eprintln!("skipping overlay_acceptance_gate_under_threshold: no provider-schema corpus at {}", root.display());
        return;
    };
    let mut paths: Vec<_> = entries
        .map(|entry| entry.expect("schema entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "the provider-schema corpus directory exists but contains no schemas: {}",
        root.display()
    );
    let mut store = CompiledSchemaStore::new();
    let mut rejected_count = 0usize;
    for path in &paths {
        let raw: Value = serde_json::from_slice(&std::fs::read(path).expect("schema file")).expect("valid schema json");
        let type_name = raw.get("typeName").and_then(|value| value.as_str()).expect("typeName");
        if store.apply_overlay(type_name, &raw).is_err() {
            rejected_count += 1;
        }
    }
    assert!(
        rejected_count <= 40,
        "overlay rejections ({rejected_count}) exceeds threshold of 40; total schemas: {}",
        paths.len()
    );
}

// ─── Property-level scalar composition ──────────────────────────────────────
// These tests validate anyOf/oneOf/allOf/if_then_else placed DIRECTLY on a
// property schema (not the root resource schema) where the property value is a
// scalar - the case that validate_prop_composition handles.

#[test]
fn prop_any_of_scalar_enum_mismatch_emits_f3017() {
    let sv = validator(vec![(
        "AWS::Test::PropAnyOfEnum",
        json!({
            "properties": {
                "Mode": {
                    "type": "string",
                    "anyOf": [
                        { "enum": ["fast", "turbo"] },
                        { "enum": ["slow", "careful"] }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::PropAnyOfEnum\n    Properties:\n      Mode: broken\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 when scalar value matches no anyOf branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_any_of_scalar_enum_match_no_diagnostic() {
    let sv = validator(vec![(
        "AWS::Test::PropAnyOfEnum",
        json!({
            "properties": {
                "Mode": {
                    "type": "string",
                    "anyOf": [
                        { "enum": ["fast", "turbo"] },
                        { "enum": ["slow", "careful"] }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::PropAnyOfEnum\n    Properties:\n      Mode: fast\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "expected no F3017 when scalar value matches an anyOf branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_any_of_type_mismatch_emits_f3017() {
    let sv = validator(vec![(
        "AWS::Test::PropAnyOfType",
        json!({
            "properties": {
                "Value": {
                    "anyOf": [
                        { "type": "integer" },
                        { "type": "boolean" }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    // "hello" is a string - not coercible to integer or boolean
    let template = r#"{"Resources":{"R":{"Type":"AWS::Test::PropAnyOfType","Properties":{"Value":"hello"}}}}"#;
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 when value type matches no branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_one_of_ambiguity_emits_f3018() {
    let sv = validator(vec![(
        "AWS::Test::PropOneOfAmbig",
        json!({
            "properties": {
                "Port": {
                    "type": "integer",
                    "oneOf": [
                        { "minimum": 1, "maximum": 1024 },
                        { "minimum": 500, "maximum": 2000 }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    // Port 800 falls in both ranges
    let template = "Resources:\n  R:\n    Type: AWS::Test::PropOneOfAmbig\n    Properties:\n      Port: 800\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3018", "more than one"),
        "expected F3018 when value matches more than one oneOf branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_one_of_no_match_emits_f3018() {
    let sv = validator(vec![(
        "AWS::Test::PropOneOfNone",
        json!({
            "properties": {
                "Size": {
                    "type": "integer",
                    "oneOf": [
                        { "minimum": 1, "maximum": 10 },
                        { "minimum": 100, "maximum": 200 }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    // Size 50 falls between both ranges
    let template = "Resources:\n  R:\n    Type: AWS::Test::PropOneOfNone\n    Properties:\n      Size: 50\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3018", "not valid under any"),
        "expected F3018 when value matches no oneOf branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_one_of_exactly_one_match_no_diagnostic() {
    let sv = validator(vec![(
        "AWS::Test::PropOneOfExact",
        json!({
            "properties": {
                "Size": {
                    "type": "integer",
                    "oneOf": [
                        { "minimum": 1, "maximum": 10 },
                        { "minimum": 100, "maximum": 200 }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    // Size 5 matches only the first range
    let template = "Resources:\n  R:\n    Type: AWS::Test::PropOneOfExact\n    Properties:\n      Size: 5\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3018", ""),
        "expected no F3018 when value matches exactly one branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_numeric_bounds_and_multiple_of_in_any_of() {
    let sv = validator(vec![(
        "AWS::Test::PropAnyOfMultipleOf",
        json!({
            "properties": {
                "Capacity": {
                    "type": "integer",
                    "anyOf": [
                        { "multipleOf": 64 },
                        { "multipleOf": 100 }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    // 7 is not a multiple of 64 or 100
    let template = "Resources:\n  R:\n    Type: AWS::Test::PropAnyOfMultipleOf\n    Properties:\n      Capacity: 7\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 when value is not a multiple of any branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );

    // 128 is a multiple of 64
    let template2 =
        "Resources:\n  R:\n    Type: AWS::Test::PropAnyOfMultipleOf\n    Properties:\n      Capacity: 128\n";
    let diags2 = validate(&sv, template2);
    assert!(
        !mentions(&diags2, "F3017", ""),
        "expected no F3017 when value is a multiple of 64: {:?}",
        diags2.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_object_if_then_else_rejects_failing_then_branch() {
    // Property-level if/then/else on an object property: Config.Mode selects
    // which branch applies and the selected branch constrains a nested value.
    let sv = validator(vec![(
        "AWS::Test::PropObjConditional",
        json!({
            "properties": {
                "Config": {
                    "type": "object",
                    "properties": {
                        "Mode": { "type": "string" },
                        "Threshold": { "type": "integer" }
                    },
                    "if": { "properties": { "Mode": { "enum": ["strict"] } } },
                    "then": { "properties": { "Threshold": { "maximum": 10 } } },
                    "else": { "properties": { "Threshold": { "maximum": 1000 } } }
                }
            },
            "additionalProperties": false
        }),
    )]);
    // Mode is "strict" so the then-branch applies; Threshold 50 exceeds maximum 10
    let template = r#"{"Resources":{"R":{"Type":"AWS::Test::PropObjConditional","Properties":{"Config":{"Mode":"strict","Threshold":50}}}}}"#;
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "does not satisfy the composition branch constraint (maximum 10)"),
        "expected conditional constraint violation when then-branch fails: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_object_if_then_else_accepts_passing_then_branch() {
    // Same schema - Mode is "strict" and Threshold is within the then-branch limit.
    let sv = validator(vec![(
        "AWS::Test::PropObjConditional",
        json!({
            "properties": {
                "Config": {
                    "type": "object",
                    "properties": {
                        "Mode": { "type": "string" },
                        "Threshold": { "type": "integer" }
                    },
                    "if": { "properties": { "Mode": { "enum": ["strict"] } } },
                    "then": { "properties": { "Threshold": { "maximum": 10 } } },
                    "else": { "properties": { "Threshold": { "maximum": 1000 } } }
                }
            },
            "additionalProperties": false
        }),
    )]);
    // Mode is "strict" and Threshold 5 is within the then-branch maximum of 10
    let template = r#"{"Resources":{"R":{"Type":"AWS::Test::PropObjConditional","Properties":{"Config":{"Mode":"strict","Threshold":5}}}}}"#;
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "expected no violation when then-branch constraint is satisfied: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_object_if_then_else_uses_else_branch_when_condition_fails() {
    // Mode is "relaxed" so the else-branch applies; Threshold 500 is within
    // the else-branch maximum of 1000.
    let sv = validator(vec![(
        "AWS::Test::PropObjConditional",
        json!({
            "properties": {
                "Config": {
                    "type": "object",
                    "properties": {
                        "Mode": { "type": "string" },
                        "Threshold": { "type": "integer" }
                    },
                    "if": { "properties": { "Mode": { "enum": ["strict"] } } },
                    "then": { "properties": { "Threshold": { "maximum": 10 } } },
                    "else": { "properties": { "Threshold": { "maximum": 1000 } } }
                }
            },
            "additionalProperties": false
        }),
    )]);
    // Mode is "relaxed" (not "strict"), else-branch allows up to 1000
    let template = r#"{"Resources":{"R":{"Type":"AWS::Test::PropObjConditional","Properties":{"Config":{"Mode":"relaxed","Threshold":500}}}}}"#;
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "expected no violation when else-branch allows the value: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_scalar_one_of_enum_rejects_unmatched_value() {
    let sv = validator(vec![(
        "AWS::Test::PropScalarConditional",
        json!({
            "properties": {
                "Format": {
                    "type": "string",
                    "oneOf": [
                        { "enum": ["json"] },
                        { "enum": ["yaml"] },
                        { "enum": ["xml"] }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    // "csv" matches no branch
    let template = "Resources:\n  R:\n    Type: AWS::Test::PropScalarConditional\n    Properties:\n      Format: csv\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3018", "not valid under any"),
        "expected F3018 when scalar value matches no oneOf branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_scalar_one_of_enum_accepts_exactly_one_match() {
    let sv = validator(vec![(
        "AWS::Test::PropScalarConditional",
        json!({
            "properties": {
                "Format": {
                    "type": "string",
                    "oneOf": [
                        { "enum": ["json"] },
                        { "enum": ["yaml"] },
                        { "enum": ["xml"] }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    // "json" matches exactly one branch
    let template =
        "Resources:\n  R:\n    Type: AWS::Test::PropScalarConditional\n    Properties:\n      Format: json\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3018", ""),
        "expected no F3018 when value matches exactly one oneOf branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── KMS format anyOf (exactly the upstream schema pattern) ─────────────────

#[test]
fn kms_format_any_of_accepts_valid_arn() {
    let sv = validator(vec![(
        "AWS::Test::KmsFormat",
        json!({
            "properties": {
                "KmsKeyId": {
                    "type": "string",
                    "anyOf": [
                        { "format": "AWS::KMS::Key.Arn" },
                        { "format": "AWS::KMS::Key.Id" },
                        { "format": "AWS::KMS::Alias.AliasName" }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::KmsFormat\n    Properties:\n      KmsKeyId: arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "valid KMS ARN should not trigger F3017: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn kms_format_any_of_accepts_valid_uuid() {
    let sv = validator(vec![(
        "AWS::Test::KmsFormat",
        json!({
            "properties": {
                "KmsKeyId": {
                    "type": "string",
                    "anyOf": [
                        { "format": "AWS::KMS::Key.Arn" },
                        { "format": "AWS::KMS::Key.Id" },
                        { "format": "AWS::KMS::Alias.AliasName" }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::KmsFormat\n    Properties:\n      KmsKeyId: 12345678-1234-1234-1234-123456789012\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "valid KMS UUID should not trigger F3017: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn kms_format_any_of_accepts_mrk_key_id() {
    let sv = validator(vec![(
        "AWS::Test::KmsFormat",
        json!({
            "properties": {
                "KmsKeyId": {
                    "type": "string",
                    "anyOf": [
                        { "format": "AWS::KMS::Key.Arn" },
                        { "format": "AWS::KMS::Key.Id" },
                        { "format": "AWS::KMS::Alias.AliasName" }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::KmsFormat\n    Properties:\n      KmsKeyId: mrk-1234abcd12ab34cd56ef1234567890ab\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "valid mrk- KMS Key ID should not trigger F3017: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn kms_format_any_of_accepts_alias() {
    let sv = validator(vec![(
        "AWS::Test::KmsFormat",
        json!({
            "properties": {
                "KmsKeyId": {
                    "type": "string",
                    "anyOf": [
                        { "format": "AWS::KMS::Key.Arn" },
                        { "format": "AWS::KMS::Key.Id" },
                        { "format": "AWS::KMS::Alias.AliasName" }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::KmsFormat\n    Properties:\n      KmsKeyId: alias/my-key\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "valid KMS alias should not trigger F3017: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn kms_format_any_of_rejects_invalid_value() {
    let sv = validator(vec![(
        "AWS::Test::KmsFormat",
        json!({
            "properties": {
                "KmsKeyId": {
                    "type": "string",
                    "anyOf": [
                        { "format": "AWS::KMS::Key.Arn" },
                        { "format": "AWS::KMS::Key.Id" },
                        { "format": "AWS::KMS::Alias.AliasName" }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template =
        "Resources:\n  R:\n    Type: AWS::Test::KmsFormat\n    Properties:\n      KmsKeyId: not-a-valid-kms-ref\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "invalid KMS value should trigger F3017: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn kms_format_any_of_rejects_invalid_static_join() {
    let sv = validator(vec![(
        "AWS::Test::KmsFormat",
        json!({
            "properties": {
                "KmsKeyId": {
                    "type": "string",
                    "anyOf": [
                        { "format": "AWS::KMS::Key.Arn" },
                        { "format": "AWS::KMS::Key.Id" },
                        { "format": "AWS::KMS::Alias.AliasName" }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = r#"
Resources:
  R:
    Type: AWS::Test::KmsFormat
    Properties:
      KmsKeyId:
        Fn::Join:
          - ""
          - - "arn:aws:kms:us-east-1:123456789012:key/"
            - "12345"
"#;
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "a fully resolved invalid Fn::Join should trigger F3017: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn kms_format_any_of_skips_dynamic_ref_value() {
    // A dynamic value (!Ref to a parameter) cannot be evaluated at author-time;
    // the validator must conservatively skip composition branch matching rather
    // than reporting a false positive.
    let sv = validator(vec![(
        "AWS::Test::KmsFormat",
        json!({
            "properties": {
                "KmsKeyId": {
                    "type": "string",
                    "anyOf": [
                        { "format": "AWS::KMS::Key.Arn" },
                        { "format": "AWS::KMS::Key.Id" },
                        { "format": "AWS::KMS::Alias.AliasName" }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = r#"
Parameters:
  KeyParam:
    Type: String
Resources:
  R:
    Type: AWS::Test::KmsFormat
    Properties:
      KmsKeyId: !Ref KeyParam
"#;
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "dynamic !Ref value should not trigger composition failure: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
    assert!(
        !mentions(&diags, "F3018", ""),
        "dynamic !Ref value should not trigger oneOf failure: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── Array items with property-level composition ────────────────────────────

#[test]
fn prop_any_of_on_array_items_validates_elements() {
    let sv = validator(vec![(
        "AWS::Test::PropAnyOfItems",
        json!({
            "properties": {
                "Ports": {
                    "type": "array",
                    "items": {
                        "type": "integer",
                        "anyOf": [
                            { "minimum": 1, "maximum": 1024 },
                            { "minimum": 8000, "maximum": 9000 }
                        ]
                    }
                }
            },
            "additionalProperties": false
        }),
    )]);
    // Element 5000 is between both valid ranges
    let template = r#"{"Resources":{"R":{"Type":"AWS::Test::PropAnyOfItems","Properties":{"Ports":[443, 5000]}}}}"#;
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3017", "not valid under any"),
        "expected F3017 for array element outside all anyOf ranges: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn prop_any_of_on_array_items_accepts_valid_elements() {
    let sv = validator(vec![(
        "AWS::Test::PropAnyOfItems",
        json!({
            "properties": {
                "Ports": {
                    "type": "array",
                    "items": {
                        "type": "integer",
                        "anyOf": [
                            { "minimum": 1, "maximum": 1024 },
                            { "minimum": 8000, "maximum": 9000 }
                        ]
                    }
                }
            },
            "additionalProperties": false
        }),
    )]);
    // All elements in valid ranges
    let template = r#"{"Resources":{"R":{"Type":"AWS::Test::PropAnyOfItems","Properties":{"Ports":[443, 8080]}}}}"#;
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3017", ""),
        "expected no F3017 when all array elements are in valid ranges: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── Scenario-aware group decisions ─────────────────────────────────────────
// anyOf/oneOf are decided once per template condition scenario: a property
// valued through Fn::If has a different concrete value in each reachable
// scenario, and each scenario may satisfy a different branch.

#[test]
fn one_of_is_decided_per_condition_scenario() {
    // Mode is A in one scenario and B in the other; each scenario matches
    // exactly one oneOf branch, so the template is valid - deciding the group
    // across scenarios would falsely report "valid under more than one".
    let sv = validator(vec![(
        "AWS::Test::OneOfScenario",
        json!({
            "properties": { "Mode": { "type": "string" } },
            "oneOf": [
                { "properties": { "Mode": { "enum": ["A"] } }, "required": ["Mode"] },
                { "properties": { "Mode": { "enum": ["B"] } }, "required": ["Mode"] }
            ],
            "additionalProperties": false
        }),
    )]);
    let template = r#"{
        "Conditions": { "IsA": { "Fn::Equals": [{ "Ref": "AWS::Region" }, "us-east-1"] } },
        "Resources": {
            "R": {
                "Type": "AWS::Test::OneOfScenario",
                "Properties": { "Mode": { "Fn::If": ["IsA", "A", "B"] } }
            }
        }
    }"#;
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3018", "more than one"),
        "mutually exclusive scenarios each matching one branch must not be reported as ambiguous: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn any_of_reports_the_invalid_condition_scenario() {
    // Mode is A in one scenario (valid) and C in the other (matches no branch):
    // the invalid scenario must be reported even though a sibling scenario is
    // valid, and the finding must carry that scenario's condition assignment.
    let sv = validator(vec![(
        "AWS::Test::AnyOfScenario",
        json!({
            "properties": { "Mode": { "type": "string" } },
            "anyOf": [
                { "properties": { "Mode": { "enum": ["A"] } }, "required": ["Mode"] },
                { "properties": { "Mode": { "enum": ["B"] } }, "required": ["Mode"] }
            ],
            "additionalProperties": false
        }),
    )]);
    let template = r#"{
        "Conditions": { "IsA": { "Fn::Equals": [{ "Ref": "AWS::Region" }, "us-east-1"] } },
        "Resources": {
            "R": {
                "Type": "AWS::Test::AnyOfScenario",
                "Properties": { "Mode": { "Fn::If": ["IsA", "A", "C"] } }
            }
        }
    }"#;
    let diags = validate(&sv, template);
    let finding = diags.iter().find(|d| d.rule_id == "F3017").unwrap_or_else(|| {
        panic!(
            "the scenario with Mode=C matches no anyOf branch and must be reported: {:?}",
            diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
        )
    });
    let conds = finding
        .condition_scenario
        .as_ref()
        .expect("the finding must carry the condition assignment that produces the invalid value");
    assert_eq!(conds.get("IsA"), Some(&false), "the invalid value comes from the IsA=false branch: {conds:?}");
}

#[test]
fn property_level_conditional_then_required_is_enforced() {
    // A conditional stated by an overlay on an object property enforces the
    // selected branch in full - including its `required` list.
    let sv = validator(vec![(
        "AWS::Test::PropCondRequired",
        json!({
            "properties": {
                "Cfg": {
                    "type": "object",
                    "properties": { "Mode": { "type": "string" }, "Extra": { "type": "string" } },
                    "allOf": [{
                        "if": { "properties": { "Mode": { "enum": ["on"] } }, "required": ["Mode"] },
                        "then": { "required": ["Extra"] }
                    }]
                }
            }
        }),
    )]);
    let violating =
        "Resources:\n  R:\n    Type: AWS::Test::PropCondRequired\n    Properties:\n      Cfg:\n        Mode: 'on'\n";
    let diags = validate(&sv, violating);
    assert!(
        mentions(&diags, "F3003", "Extra"),
        "a property-level conditional's required list must be enforced: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
    let ok = "Resources:\n  R:\n    Type: AWS::Test::PropCondRequired\n    Properties:\n      Cfg:\n        Mode: 'on'\n        Extra: x\n";
    let diags = validate(&sv, ok);
    assert!(
        diags.is_empty(),
        "a satisfied conditional must stay clean: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

fn nested_group_schema(keyword: &str) -> Value {
    let mut schema = json!({
        "properties": {
            "Cfg": {
                "type": "object",
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } }
            }
        }
    });
    schema["properties"]["Cfg"][keyword] = json!(["A", "B"]);
    schema
}

fn nested_cfg_template(resource_type: &str, cfg: &str) -> String {
    format!("Resources:\n  R:\n    Type: {resource_type}\n    Properties:\n      Cfg:{cfg}\n")
}

#[test]
fn nested_required_or_counts_only_concrete_members() {
    let resource_type = "AWS::Test::NestedReqOr";
    let sv = validator(vec![(resource_type, nested_group_schema("requiredOr"))]);
    for (cfg, should_fire) in [
        (" {}", true),
        ("\n        A: value", false),
        ("\n        A: !Ref AWS::NoValue\n        B: !Ref AWS::NoValue", true),
        ("\n        A: value\n        B: !Ref AWS::NoValue", false),
    ] {
        let diags = validate(&sv, &nested_cfg_template(resource_type, cfg));
        assert_eq!(
            mentions(&diags, "F3058", "One of"),
            should_fire,
            "unexpected requiredOr result for Cfg:{cfg}: {diags:?}"
        );
    }
}

#[test]
fn nested_required_xor_counts_only_concrete_members() {
    let resource_type = "AWS::Test::NestedReqXor";
    let sv = validator(vec![(resource_type, nested_group_schema("requiredXor"))]);
    for (cfg, should_fire) in [
        (" {}", true),
        ("\n        A: one\n        B: two", true),
        ("\n        A: one", false),
        ("\n        A: one\n        B: !Ref AWS::NoValue", false),
    ] {
        let diags = validate(&sv, &nested_cfg_template(resource_type, cfg));
        assert_eq!(
            mentions(&diags, "F3014", "Exactly one"),
            should_fire,
            "unexpected requiredXor result for Cfg:{cfg}: {diags:?}"
        );
    }
}

#[test]
fn required_xor_participates_in_one_of_branch_matching() {
    let resource_type = "AWS::Test::CompReqXor";
    let sv = validator(vec![(
        resource_type,
        json!({
            "properties": {
                "Cfg": {
                    "type": "object",
                    "properties": {
                        "A": { "type": "string" },
                        "B": { "type": "string" },
                        "C": { "type": "string" }
                    },
                    "oneOf": [{ "requiredXor": ["A", "B"] }, { "required": ["C"] }]
                }
            }
        }),
    )]);
    for (cfg, should_fire) in [("\n        A: value", false), ("\n        C: value", false), (" {}", true)] {
        let diags = validate(&sv, &nested_cfg_template(resource_type, cfg));
        assert_eq!(
            mentions(&diags, "F3018", "schema"),
            should_fire,
            "unexpected oneOf result for Cfg:{cfg}: {diags:?}"
        );
    }
}

#[test]
fn required_or_branch_rejects_an_aws_novalue_member() {
    let resource_type = "AWS::Test::CompReqOr";
    let sv = validator(vec![(
        resource_type,
        json!({
            "properties": {
                "Cfg": {
                    "type": "object",
                    "properties": {
                        "A": { "type": "string" },
                        "B": { "type": "string" },
                        "C": { "type": "string" }
                    },
                    "anyOf": [{ "requiredOr": ["A", "B"] }, { "required": ["C"] }]
                }
            }
        }),
    )]);
    for (cfg, should_fire) in
        [("\n        A: !Ref AWS::NoValue", true), ("\n        A: !Ref AWS::NoValue\n        C: value", false)]
    {
        let diags = validate(&sv, &nested_cfg_template(resource_type, cfg));
        assert_eq!(
            mentions(&diags, "F3017", "not valid under any"),
            should_fire,
            "unexpected anyOf result for Cfg:{cfg}: {diags:?}"
        );
    }
}

#[test]
fn required_or_one_of_is_decided_per_condition_scenario() {
    let resource_type = "AWS::Test::CompReqOrScenarios";
    let sv = validator(vec![(
        resource_type,
        json!({
            "properties": {
                "Cfg": {
                    "type": "object",
                    "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                    "oneOf": [{ "requiredOr": ["A"] }, { "requiredOr": ["B"] }]
                }
            }
        }),
    )]);
    let template = concat!(
        "Conditions:\n",
        "  UseA: !Equals [!Ref AWS::Region, us-east-1]\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::CompReqOrScenarios\n",
        "    Properties:\n",
        "      Cfg:\n",
        "        A: !If [UseA, a, !Ref AWS::NoValue]\n",
        "        B: !If [UseA, !Ref AWS::NoValue, b]\n",
    );
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3018", "schema"),
        "each satisfiable condition scenario must match exactly one requiredOr branch: {diags:?}"
    );
}

// requiredOr reports a defect when every candidate resolves to AWS::NoValue.

#[test]
fn required_or_emits_f3058_when_all_candidates_resolve_to_novalue() {
    // All requiredOr members authored but every one resolves to AWS::NoValue
    // unconditionally - CloudFormation strips them, so none survive deployment.
    let sv = validator(vec![(
        "AWS::Test::ReqOrNoValue",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "C": { "type": "string" }
            },
            "requiredOr": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReqOrNoValue\n",
        "    Properties:\n",
        "      A: !Ref AWS::NoValue\n",
        "      B: !Ref AWS::NoValue\n",
        "      C: hello\n",
    );
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3058", "required property"),
        "expected F3058 when all requiredOr candidates are NoValue: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn required_or_conditional_f3058_only_in_novalue_scenario() {
    // One requiredOr member is conditionally NoValue: the scenario where
    // the condition is false (member A resolves to NoValue) and no other candidate is
    // present must produce a conditional required-property finding. The scenario where the
    // condition is true (member A has a value) must not produce that finding.
    let sv = validator(vec![(
        "AWS::Test::ReqOrCondNoValue",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredOr": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Conditions:\n",
        "  UseA: !Equals [!Ref AWS::Region, us-east-1]\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReqOrCondNoValue\n",
        "    Properties:\n",
        "      A: !If [UseA, real-value, !Ref AWS::NoValue]\n",
    );
    let diags = validate(&sv, template);
    let f3058_diags: Vec<_> = diags.iter().filter(|d| d.rule_id == "F3058").collect();
    assert!(
        !f3058_diags.is_empty(),
        "expected conditional F3058 for the scenario where A is NoValue: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
    // The diagnostic must carry the condition scenario (UseA=false).
    assert!(
        f3058_diags.iter().any(|d| d.condition_scenario.is_some()),
        "F3058 must have condition_scenario set for conditional findings: {:?}",
        f3058_diags.iter().map(|d| (&d.condition_scenario,)).collect::<Vec<_>>()
    );
}

#[test]
fn required_or_no_diagnostic_when_one_candidate_has_value() {
    // At least one requiredOr candidate has a concrete (non-null) value in
    // every scenario, so no required-property finding should fire.
    let sv = validator(vec![(
        "AWS::Test::ReqOrOnePresent",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredOr": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReqOrOnePresent\n",
        "    Properties:\n",
        "      A: hello\n",
        "      B: !Ref AWS::NoValue\n",
    );
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3058", ""),
        "no F3058 when at least one candidate is concrete: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn required_or_nested_in_composition_branch_evaluates_per_scenario() {
    // requiredOr inside a oneOf branch must still evaluate per condition
    // scenario when the member properties are conditional.
    let sv = validator(vec![(
        "AWS::Test::ReqOrNested",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "C": { "type": "string" }
            },
            "oneOf": [
                { "requiredOr": ["A", "B"] },
                { "required": ["C"] }
            ],
            "additionalProperties": false
        }),
    )]);
    // A is conditionally NoValue, B absent, C absent - the first oneOf branch
    // has no surviving member in the UseA=false scenario, triggering a violation in
    // that branch's validate_sub call.
    let template = concat!(
        "Conditions:\n",
        "  UseA: !Equals [!Ref AWS::Region, us-east-1]\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReqOrNested\n",
        "    Properties:\n",
        "      A: !If [UseA, value, !Ref AWS::NoValue]\n",
    );
    let diags = validate(&sv, template);
    // Either the requiredOr violation or a no-branch-matched finding must fire.
    let has_finding = mentions(&diags, "F3058", "") || mentions(&diags, "F3018", "");
    assert!(
        has_finding,
        "expected F3058 or F3018 when nested requiredOr has no surviving candidate: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// requiredXor evaluates each condition scenario independently.

#[test]
fn required_xor_no_false_positive_for_mutually_exclusive_conditions() {
    // Two requiredXor members, each present only in its own condition branch.
    // In every deployable scenario exactly one is present, so no xor finding is expected.
    let sv = validator(vec![(
        "AWS::Test::ReqXorCond",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredXor": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Conditions:\n",
        "  UseA: !Equals [!Ref AWS::Region, us-east-1]\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReqXorCond\n",
        "    Properties:\n",
        "      A: !If [UseA, a-value, !Ref AWS::NoValue]\n",
        "      B: !If [UseA, !Ref AWS::NoValue, b-value]\n",
    );
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3014", ""),
        "no F3014 when each scenario has exactly one member: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn required_xor_emits_f3014_when_zero_members_in_scenario() {
    // Both requiredXor members resolve to NoValue in the same scenario.
    let sv = validator(vec![(
        "AWS::Test::ReqXorZero",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredXor": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReqXorZero\n",
        "    Properties:\n",
        "      A: !Ref AWS::NoValue\n",
        "      B: !Ref AWS::NoValue\n",
    );
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3014", "Exactly one"),
        "expected F3014 when zero members survive deployment: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn required_xor_emits_f3014_when_two_members_in_every_scenario() {
    // Both requiredXor members are unconditionally concrete - always two present.
    let sv = validator(vec![(
        "AWS::Test::ReqXorTwo",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredXor": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReqXorTwo\n",
        "    Properties:\n",
        "      A: hello\n",
        "      B: world\n",
    );
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3014", "Exactly one"),
        "expected F3014 when two members are unconditionally present: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn required_xor_independent_conditions_evaluated_correctly() {
    // Two truly independent conditions (based on different parameters) control
    // two requiredXor members. The satisfiable scenarios include combinations
    // where zero or two are present, which violate the xor constraint.
    let sv = validator(vec![(
        "AWS::Test::ReqXorIndep",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredXor": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Parameters:\n",
        "  ParamA:\n",
        "    Type: String\n",
        "  ParamB:\n",
        "    Type: String\n",
        "Conditions:\n",
        "  CondA: !Equals [!Ref ParamA, yes]\n",
        "  CondB: !Equals [!Ref ParamB, yes]\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReqXorIndep\n",
        "    Properties:\n",
        "      A: !If [CondA, a-value, !Ref AWS::NoValue]\n",
        "      B: !If [CondB, b-value, !Ref AWS::NoValue]\n",
    );
    let diags = validate(&sv, template);
    // With truly independent conditions, CondA=true/CondB=true gives two
    // present (violates xor) and CondA=false/CondB=false gives zero present
    // (also violates xor). The other two worlds are valid.
    let f3014_diags: Vec<_> = diags.iter().filter(|d| d.rule_id == "F3014").collect();
    assert_eq!(
        f3014_diags.len(),
        2,
        "expected exactly 2 F3014 diagnostics (one per violating world), got {}: {:?}",
        f3014_diags.len(),
        f3014_diags.iter().map(|d| (&d.condition_scenario, &d.message)).collect::<Vec<_>>()
    );
    // All xor findings must carry condition_scenario metadata.
    assert!(
        f3014_diags.iter().all(|d| d.condition_scenario.is_some()),
        "F3014 for conditional scenarios must have condition_scenario set: {:?}",
        f3014_diags.iter().map(|d| (&d.condition_scenario,)).collect::<Vec<_>>()
    );
    // Assert the two violating worlds are exactly:
    //   CondA=true, CondB=true (both present)
    //   CondA=false, CondB=false (neither present)
    let scenarios: Vec<&HashMap<String, bool>> =
        f3014_diags.iter().map(|d| d.condition_scenario.as_ref().unwrap()).collect();
    let both_true = scenarios.iter().any(|s| s.get("CondA") == Some(&true) && s.get("CondB") == Some(&true));
    let both_false = scenarios.iter().any(|s| s.get("CondA") == Some(&false) && s.get("CondB") == Some(&false));
    assert!(both_true, "expected a violation for CondA=true, CondB=true (two present): {:?}", scenarios);
    assert!(both_false, "expected a violation for CondA=false, CondB=false (zero present): {:?}", scenarios);
}

#[test]
fn required_xor_nested_in_composition_branch() {
    // requiredXor inside a oneOf branch must still evaluate per scenario.
    let sv = validator(vec![(
        "AWS::Test::ReqXorNested",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "C": { "type": "string" }
            },
            "oneOf": [
                { "requiredXor": ["A", "B"] },
                { "required": ["C"] }
            ],
            "additionalProperties": false
        }),
    )]);
    // In every scenario exactly one of A/B is present (mutually exclusive via
    // condition) - the first oneOf branch should pass.
    let template = concat!(
        "Conditions:\n",
        "  UseA: !Equals [!Ref AWS::Region, us-east-1]\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReqXorNested\n",
        "    Properties:\n",
        "      A: !If [UseA, a-val, !Ref AWS::NoValue]\n",
        "      B: !If [UseA, !Ref AWS::NoValue, b-val]\n",
    );
    let diags = validate(&sv, template);
    // The first oneOf branch should match in both scenarios (xor satisfied),
    // so no no-branch-matched finding should fire.
    assert!(
        !mentions(&diags, "F3018", "not valid under any"),
        "expected no F3018 when requiredXor is satisfied per scenario in nested branch: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn required_xor_dynamic_value_conservatively_present() {
    // When a requiredXor member has a dynamic value (e.g. Ref to a parameter),
    // it must be conservatively treated as present, with no false xor finding.
    let sv = validator(vec![(
        "AWS::Test::ReqXorDynamic",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredXor": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Parameters:\n",
        "  MyParam:\n",
        "    Type: String\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReqXorDynamic\n",
        "    Properties:\n",
        "      A: !Ref MyParam\n",
    );
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3014", ""),
        "no F3014 when a dynamic member is conservatively present: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn required_xor_preserves_conditions_on_dynamic_members() {
    let sv = validator(vec![(
        "AWS::Test::ReqXorDynamicConditional",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredXor": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    let template = r#"
Parameters:
  Target:
    Type: String
  Toggle:
    Type: String
    AllowedValues: ['true', 'false']
Conditions:
  DuplicateTarget: !Equals [!Ref Toggle, 'true']
Resources:
  R:
    Type: AWS::Test::ReqXorDynamicConditional
    Properties:
      A: !Ref Target
      B: !If [DuplicateTarget, !Ref Target, !Ref AWS::NoValue]
"#;

    let diags = validate(&sv, template);
    let findings: Vec<_> = diags.iter().filter(|diagnostic| diagnostic.rule_id == "F3014").collect();
    assert_eq!(findings.len(), 1, "the duplicate-present world must be diagnosed exactly once: {diags:?}");
    assert_eq!(
        findings[0].condition_scenario.as_ref().and_then(|scenario| scenario.get("DuplicateTarget")),
        Some(&true)
    );
}

#[test]
fn required_xor_respects_resource_condition_correlation() {
    let sv = validator(vec![(
        "AWS::Test::ReqXorResourceCondition",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredXor": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    let template = r#"
Parameters:
  Target:
    Type: String
  Toggle:
    Type: String
    AllowedValues: ['true', 'false']
Conditions:
  DuplicateTarget: !Equals [!Ref Toggle, 'true']
  CreateWithoutDuplicate: !Not [!Condition DuplicateTarget]
Resources:
  R:
    Type: AWS::Test::ReqXorResourceCondition
    Condition: CreateWithoutDuplicate
    Properties:
      A: !Ref Target
      B: !If [DuplicateTarget, !Ref Target, !Ref AWS::NoValue]
"#;

    let diags = validate(&sv, template);
    assert!(!mentions(&diags, "F3014", ""), "the resource exists only in the single-present world: {diags:?}");
}

#[test]
fn required_or_dynamic_value_conservatively_present() {
    // When a requiredOr member has a dynamic value, it must be conservatively
    // treated as present, with no false required-property finding.
    let sv = validator(vec![(
        "AWS::Test::ReqOrDynamic",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredOr": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Parameters:\n",
        "  MyParam:\n",
        "    Type: String\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReqOrDynamic\n",
        "    Properties:\n",
        "      A: !Ref MyParam\n",
    );
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3058", ""),
        "no F3058 when a dynamic member is conservatively present: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn outer_key_scenario_constrains_required_xor_evaluation() {
    // When Properties is wrapped in Fn::If, BOTH branches expose the same
    // requiredXor key names but with different values/NoValue. This proves
    // value scenarios are constrained by the outer key condition rather than
    // relying on actual_keys gating.
    let sv = validator(vec![(
        "AWS::Test::OuterKeyXor",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredXor": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    // Both branches expose A and B keys. CondX=true gives A=val, B=NoValue;
    // CondX=false gives A=NoValue, B=val. Each branch has exactly one
    // non-null requiredXor member - no violation in either world.
    let template = r#"{
        "Conditions": { "CondX": { "Fn::Equals": [{ "Ref": "AWS::Region" }, "us-east-1"] } },
        "Resources": {
            "R": {
                "Type": "AWS::Test::OuterKeyXor",
                "Properties": { "Fn::If": ["CondX",
                    { "A": "val", "B": { "Ref": "AWS::NoValue" } },
                    { "A": { "Ref": "AWS::NoValue" }, "B": "val" }
                ] }
            }
        }
    }"#;
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3014", ""),
        "no F3014 when each outer key branch satisfies requiredXor independently: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn outer_key_scenario_constrains_required_or_evaluation() {
    // Both Fn::If branches expose the SAME requiredOr key names but with
    // different values/NoValue, proving value scenarios are constrained by
    // the outer key condition rather than relying on actual_keys gating.
    // Assert exactly one diagnostic tagged with the all-NoValue branch.
    let sv = validator(vec![(
        "AWS::Test::OuterKeyOr",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "requiredOr": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    // Both branches have A and B. CondX=true gives A=val, B=NoValue (at least
    // one present, valid). CondX=false gives A=NoValue, B=NoValue (none present,
    // violation). Exactly one finding should fire, tagged with the CondX=false
    // scenario.
    let template = r#"{
        "Conditions": { "CondX": { "Fn::Equals": [{ "Ref": "AWS::Region" }, "us-east-1"] } },
        "Resources": {
            "R": {
                "Type": "AWS::Test::OuterKeyOr",
                "Properties": { "Fn::If": ["CondX",
                    { "A": "val", "B": { "Ref": "AWS::NoValue" } },
                    { "A": { "Ref": "AWS::NoValue" }, "B": { "Ref": "AWS::NoValue" } }
                ] }
            }
        }
    }"#;
    let diags = validate(&sv, template);
    let f3058_diags: Vec<_> = diags.iter().filter(|d| d.rule_id == "F3058").collect();
    assert_eq!(
        f3058_diags.len(),
        1,
        "expected exactly 1 F3058 (the all-NoValue branch), got {}: {:?}",
        f3058_diags.len(),
        f3058_diags.iter().map(|d| (&d.condition_scenario, &d.message)).collect::<Vec<_>>()
    );
    let conds = f3058_diags[0]
        .condition_scenario
        .as_ref()
        .expect("the F3058 must carry the condition assignment for the all-NoValue branch");
    assert_eq!(conds.get("CondX"), Some(&false), "the all-NoValue branch is CondX=false: {conds:?}");
}

#[test]
fn nested_independent_conditions_inside_one_of_branch() {
    // requiredXor inside a oneOf branch with independent conditions.
    // The nested evaluation under the outer branch assignment must still
    // expand the independent conditions within that branch's world.
    let sv = validator(vec![(
        "AWS::Test::NestedIndep",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "C": { "type": "string" }
            },
            "oneOf": [
                { "requiredXor": ["A", "B"] },
                { "required": ["C"] }
            ],
            "additionalProperties": false
        }),
    )]);
    // A and B are controlled by independent conditions. The satisfiable worlds:
    //   CondA=T, CondB=T: A present, B present (xor violated, 2 present)
    //   CondA=T, CondB=F: A present, B absent (xor satisfied)
    //   CondA=F, CondB=T: A absent, B present (xor satisfied)
    //   CondA=F, CondB=F: A absent, B absent (xor violated, 0 present)
    // In worlds where xor is violated AND C is absent, no oneOf branch is
    // satisfied, producing a no-branch-matched finding. The violating assignments are exactly
    // {CondA=T, CondB=T} and {CondA=F, CondB=F}.
    let template = concat!(
        "Parameters:\n",
        "  ParamA:\n",
        "    Type: String\n",
        "  ParamB:\n",
        "    Type: String\n",
        "Conditions:\n",
        "  CondA: !Equals [!Ref ParamA, yes]\n",
        "  CondB: !Equals [!Ref ParamB, yes]\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::NestedIndep\n",
        "    Properties:\n",
        "      A: !If [CondA, a-val, !Ref AWS::NoValue]\n",
        "      B: !If [CondB, b-val, !Ref AWS::NoValue]\n",
    );
    let diags = validate(&sv, template);
    // Collect all oneOf branch-failure diagnostics.
    let f3018_diags: Vec<_> = diags.iter().filter(|d| d.rule_id == "F3018").collect();
    assert_eq!(
        f3018_diags.len(),
        2,
        "expected exactly 2 F3018 diagnostics (one per violating world), got {}: {:?}",
        f3018_diags.len(),
        f3018_diags.iter().map(|d| (&d.condition_scenario, &d.message)).collect::<Vec<_>>()
    );
    // Assert the two violating worlds are exactly:
    //   CondA=true, CondB=true (both present, xor violated)
    //   CondA=false, CondB=false (neither present, xor violated)
    let scenarios: Vec<&HashMap<String, bool>> =
        f3018_diags.iter().filter_map(|d| d.condition_scenario.as_ref()).collect();
    assert_eq!(scenarios.len(), 2, "both F3018 findings must carry condition_scenario: {:?}", f3018_diags);
    let both_true = scenarios.iter().any(|s| s.get("CondA") == Some(&true) && s.get("CondB") == Some(&true));
    let both_false = scenarios.iter().any(|s| s.get("CondA") == Some(&false) && s.get("CondB") == Some(&false));
    assert!(both_true, "expected a violation for CondA=true, CondB=true: {:?}", scenarios);
    assert!(both_false, "expected a violation for CondA=false, CondB=false: {:?}", scenarios);
}

#[test]
fn conditional_schema_branch_selection_respects_the_active_scenario() {
    let validator = validator(vec![(
        "AWS::Test::ScenarioConditional",
        json!({
            "properties": {
                "Mode": {"type": "string", "enum": ["X", "Y"]},
                "Target": {"type": "string", "enum": ["for-x", "for-y"]}
            },
            "anyOf": [{
                "properties": {
                    "Mode": {"type": "string"},
                    "Target": {"type": "string"}
                },
                "if": {
                    "properties": {"Mode": {"const": "X"}},
                    "required": ["Mode"]
                },
                "then": {"properties": {"Target": {"const": "for-x"}}},
                "else": {"properties": {"Target": {"const": "for-y"}}}
            }],
            "additionalProperties": false
        }),
    )]);
    let template = r#"
Conditions:
  UseX: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  Resource:
    Type: AWS::Test::ScenarioConditional
    Properties:
      Mode: !If [UseX, X, Y]
      Target: !If [UseX, for-x, for-y]
"#;

    let diagnostics = validate(&validator, template);

    assert!(
        !mentions(&diagnostics, "F3017", ""),
        "each condition world satisfies its selected schema branch: {diagnostics:#?}"
    );
}

#[test]
fn independent_optional_conditionals_have_bounded_composition_work() {
    const PROPERTY_COUNT: usize = 14;

    let mut properties = serde_json::Map::new();
    let mut branch_properties = serde_json::Map::new();
    let mut template = String::from("Parameters:\n");
    for index in 0..PROPERTY_COUNT {
        let property_name = format!("Property{index:02}");
        let property_schema = json!({"type": "string", "enum": [format!("value-{index:02}")]});
        properties.insert(property_name.clone(), property_schema.clone());
        branch_properties.insert(property_name, property_schema);
        template.push_str(&format!(
            "  Parameter{index:02}:\n    Type: String\n    AllowedValues: [yes, no]\n    Default: no\n"
        ));
    }
    template.push_str("Conditions:\n");
    for index in 0..PROPERTY_COUNT {
        template.push_str(&format!("  Condition{index:02}: !Equals [!Ref Parameter{index:02}, yes]\n"));
    }
    template.push_str("Resources:\n  Resource:\n    Type: AWS::Test::ScenarioBound\n    Properties:\n");
    for index in 0..PROPERTY_COUNT {
        template.push_str(&format!(
            "      Property{index:02}: !If [Condition{index:02}, value-{index:02}, !Ref AWS::NoValue]\n"
        ));
    }
    let validator = validator(vec![(
        "AWS::Test::ScenarioBound",
        json!({
            "properties": properties,
            "anyOf": [{"properties": branch_properties}],
            "additionalProperties": false
        }),
    )]);

    let diagnostics = validate(&validator, &template);

    assert!(
        diagnostics.iter().all(|diagnostic| !diagnostic.rule_id.starts_with('F')),
        "bounded analysis must not turn uncertainty into a schema violation: {diagnostics:#?}"
    );
    // The budget-exhaustion warning is emitted by the validation engine, not the schema validator.
    // The schema validator records budget exhaustions to the model tracker.
    assert!(
        diagnostics.iter().all(|diagnostic| diagnostic.rule_id != "W9052"),
        "schema validator must not emit per-path budget diagnostics: {diagnostics:#?}"
    );
}

fn conditional_required_or_fixture(property_count: usize) -> (SchemaValidator, String) {
    let mut properties = serde_json::Map::new();
    let mut required_or = Vec::new();
    let mut template = String::from("Parameters:\n");
    for index in 0..property_count {
        let property_name = format!("Property{index:02}");
        properties.insert(property_name.clone(), json!({"type": "string"}));
        required_or.push(property_name);
        template.push_str(&format!(
            "  Parameter{index:02}:\n    Type: String\n    AllowedValues: [yes, no]\n    Default: no\n"
        ));
    }
    template.push_str("Conditions:\n");
    for index in 0..property_count {
        template.push_str(&format!("  Condition{index:02}: !Equals [!Ref Parameter{index:02}, yes]\n"));
    }
    template.push_str("Resources:\n  Resource:\n    Type: AWS::Test::RequiredOrScenarioBound\n    Properties:\n");
    for index in 0..property_count {
        template.push_str(&format!(
            "      Property{index:02}: !If [Condition{index:02}, value-{index:02}, !Ref AWS::NoValue]\n"
        ));
    }
    let validator = validator(vec![(
        "AWS::Test::RequiredOrScenarioBound",
        json!({
            "properties": properties,
            "requiredOr": required_or,
            "additionalProperties": false
        }),
    )]);
    (validator, template)
}

#[test]
fn required_or_scenario_budget_boundary_is_non_silent() {
    let (validator, template) = conditional_required_or_fixture(8);
    let diagnostics = validate(&validator, &template);
    let required_findings: Vec<_> = diagnostics.iter().filter(|diagnostic| diagnostic.rule_id == "F3058").collect();
    assert_eq!(
        required_findings.len(),
        1,
        "all 256 condition worlds must be analyzed, including the all-false world: {diagnostics:#?}"
    );
    assert!(
        diagnostics.iter().all(|diagnostic| diagnostic.rule_id != "W9052"),
        "the exact assignment limit must remain fully analyzable: {diagnostics:#?}"
    );

    let (validator, template) = conditional_required_or_fixture(9);
    let diagnostics = validate(&validator, &template);
    let required_findings: Vec<_> = diagnostics.iter().filter(|diagnostic| diagnostic.rule_id == "F3058").collect();
    assert_eq!(
        required_findings.len(),
        1,
        "targeted witness search must find the reachable all-false world beyond the exact-enumeration limit: {diagnostics:#?}"
    );
    // The budget-exhaustion warning is emitted by the validation engine at report level, not per-path.
    // Schema validator records the exhaustion to the model budget tracker.
    assert!(
        diagnostics.iter().all(|diagnostic| diagnostic.rule_id != "W9052"),
        "schema validator must not emit per-path budget diagnostics: {diagnostics:#?}"
    );
}

fn adversarial_no_value_tree(condition_names: &[String]) -> Value {
    condition_names.iter().rev().fold(
        json!({"Ref": "AWS::NoValue"}),
        |branch, condition| json!({"Fn::If": [condition, branch.clone(), branch]}),
    )
}

fn adversarial_required_xor_fixture(condition_count: usize) -> (SchemaValidator, String) {
    let mut parameters = serde_json::Map::new();
    parameters.insert("Split".to_string(), json!({"Type": "String", "AllowedValues": ["left", "right"]}));
    let mut conditions = serde_json::Map::new();
    conditions.insert("UseLeft".to_string(), json!({"Fn::Equals": [{"Ref": "Split"}, "left"]}));
    let mut flag_names = Vec::new();
    for index in 0..condition_count {
        let parameter_name = format!("FlagParameter{index:02}");
        let condition_name = format!("Flag{index:02}");
        parameters.insert(parameter_name.clone(), json!({"Type": "String", "AllowedValues": ["yes", "no"]}));
        conditions.insert(condition_name.clone(), json!({"Fn::Equals": [{"Ref": parameter_name}, "yes"]}));
        flag_names.push(condition_name);
    }
    let no_value_tree = adversarial_no_value_tree(&flag_names);
    let template = json!({
        "Parameters": parameters,
        "Conditions": conditions,
        "Resources": {
            "Example": {
                "Type": "AWS::Test::RequiredXorBudget",
                "Properties": {
                    "A": {"Fn::If": ["UseLeft", no_value_tree.clone(), "present-a"]},
                    "B": {"Fn::If": ["UseLeft", "present-b", no_value_tree]}
                }
            }
        }
    })
    .to_string();
    let validator = validator(vec![(
        "AWS::Test::RequiredXorBudget",
        json!({
            "properties": {"A": {"type": "string"}, "B": {"type": "string"}},
            "requiredXor": ["A", "B"],
            "additionalProperties": false
        }),
    )]);
    (validator, template)
}

#[test]
fn required_xor_fallback_bounds_adversarial_branch_expansion() {
    const CONDITION_COUNT: usize = 12;
    const MAX_ACCOUNTED_SCENARIOS: u64 = 2_000;

    let (validator, template) = adversarial_required_xor_fixture(CONDITION_COUNT);
    let semantic_model = model(&template);
    let diagnostics = validator.validate(&semantic_model, Some("us-east-1")).diagnostics;

    assert!(
        diagnostics.iter().all(|diagnostic| diagnostic.rule_id != "F3014"),
        "exactly one property is present in every reachable world: {diagnostics:#?}"
    );
    assert!(
        semantic_model.exhausted_budget_kinds().contains(&template_model::BudgetKind::SchemaScenarioAssignments),
        "bounded analysis must record its curtailment on the model: {diagnostics:#?}"
    );
    assert!(
        semantic_model.scenario_combinations_used() <= MAX_ACCOUNTED_SCENARIOS,
        "fallback scenario work must stay locally bounded, used {}",
        semantic_model.scenario_combinations_used()
    );
}

// ─── Budget fallback: targeted proof/witness search ────────────────────────

/// With 9+ conditions where all members resolve to AWS::NoValue in every world
/// (each member is conditional but maps to NoValue regardless), the budget
/// fallback must still emit F3058.
#[test]
fn required_or_budget_fallback_fires_when_all_members_absent() {
    // Use 9 conditions — each requiredOr member is conditional on its own
    // condition but always resolves to AWS::NoValue (both branches produce null).
    let condition_count = 9;
    let mut properties = serde_json::Map::new();
    let mut required_or: Vec<String> = Vec::new();
    let mut template = String::from("Parameters:\n");
    for index in 0..condition_count {
        let property_name = format!("Member{index:02}");
        properties.insert(property_name.clone(), json!({"type": "string"}));
        required_or.push(property_name);
        template.push_str(&format!(
            "  Param{index:02}:\n    Type: String\n    AllowedValues: [yes, no]\n    Default: no\n"
        ));
    }
    template.push_str("Conditions:\n");
    for index in 0..condition_count {
        template.push_str(&format!("  Cond{index:02}: !Equals [!Ref Param{index:02}, yes]\n"));
    }
    // Each member is present as a key but resolves to AWS::NoValue in EVERY
    // scenario — so it's provably absent in all worlds.
    template.push_str("Resources:\n  Res:\n    Type: AWS::Test::BudgetFallbackOr\n    Properties:\n");
    for index in 0..condition_count {
        template
            .push_str(&format!("      Member{index:02}: !If [Cond{index:02}, !Ref AWS::NoValue, !Ref AWS::NoValue]\n"));
    }
    let sv = validator(vec![(
        "AWS::Test::BudgetFallbackOr",
        json!({
            "properties": properties,
            "requiredOr": required_or,
            "additionalProperties": false
        }),
    )]);
    let diagnostics = validate(&sv, &template);
    let findings: Vec<_> = diagnostics.iter().filter(|d| d.rule_id == "F3058").collect();
    assert_eq!(findings.len(), 1, "budget fallback must detect provably absent requiredOr members: {diagnostics:#?}");
}

/// With 9+ conditions but one requiredOr member unconditionally present, the
/// budget fallback must NOT emit F3058.
#[test]
fn required_or_budget_fallback_no_false_positive_when_member_present() {
    // 9 requiredOr members with independent conditions. One member (Member00)
    // is unconditionally present (both branches non-null). The rest resolve to
    // NoValue. Since one member is possibly present, requiredOr is satisfied.
    let condition_count = 9;
    let mut properties = serde_json::Map::new();
    let mut required_or: Vec<String> = Vec::new();
    let mut template = String::from("Parameters:\n");
    for index in 0..condition_count {
        let property_name = format!("Member{index:02}");
        properties.insert(property_name.clone(), json!({"type": "string"}));
        required_or.push(property_name);
        template.push_str(&format!(
            "  Param{index:02}:\n    Type: String\n    AllowedValues: [yes, no]\n    Default: no\n"
        ));
    }
    template.push_str("Conditions:\n");
    for index in 0..condition_count {
        template.push_str(&format!("  Cond{index:02}: !Equals [!Ref Param{index:02}, yes]\n"));
    }
    // Member00 is unconditionally present (both branches produce a real value).
    // All other members always resolve to NoValue.
    template.push_str("Resources:\n  Res:\n    Type: AWS::Test::BudgetFallbackOrValid\n    Properties:\n");
    template.push_str("      Member00: !If [Cond00, val-a, val-b]\n");
    for index in 1..condition_count {
        template
            .push_str(&format!("      Member{index:02}: !If [Cond{index:02}, !Ref AWS::NoValue, !Ref AWS::NoValue]\n"));
    }
    let sv = validator(vec![(
        "AWS::Test::BudgetFallbackOrValid",
        json!({
            "properties": properties,
            "requiredOr": required_or,
            "additionalProperties": false
        }),
    )]);
    let diagnostics = validate(&sv, &template);
    assert!(
        diagnostics.iter().all(|d| d.rule_id != "F3058"),
        "budget fallback must not fire when a member is unconditionally present: {diagnostics:#?}"
    );
}

/// requiredXor budget fallback: all 9 members resolve to AWS::NoValue in every
/// scenario → zero-present is provable → F3014 fires.
#[test]
fn required_xor_budget_fallback_fires_when_all_members_absent() {
    let condition_count = 9;
    let mut properties = serde_json::Map::new();
    let mut required_xor: Vec<String> = Vec::new();
    let mut template = String::from("Parameters:\n");
    for index in 0..condition_count {
        let property_name = format!("Choice{index:02}");
        properties.insert(property_name.clone(), json!({"type": "string"}));
        required_xor.push(property_name);
        template.push_str(&format!(
            "  Param{index:02}:\n    Type: String\n    AllowedValues: [yes, no]\n    Default: no\n"
        ));
    }
    template.push_str("Conditions:\n");
    for index in 0..condition_count {
        template.push_str(&format!("  Cond{index:02}: !Equals [!Ref Param{index:02}, yes]\n"));
    }
    // Each member always resolves to NoValue regardless of condition state.
    template.push_str("Resources:\n  Res:\n    Type: AWS::Test::BudgetXorZero\n    Properties:\n");
    for index in 0..condition_count {
        template
            .push_str(&format!("      Choice{index:02}: !If [Cond{index:02}, !Ref AWS::NoValue, !Ref AWS::NoValue]\n"));
    }
    let sv = validator(vec![(
        "AWS::Test::BudgetXorZero",
        json!({
            "properties": properties,
            "requiredXor": required_xor,
            "additionalProperties": false
        }),
    )]);
    let diagnostics = validate(&sv, &template);
    let findings: Vec<_> = diagnostics.iter().filter(|d| d.rule_id == "F3014").collect();
    assert_eq!(findings.len(), 1, "budget fallback must detect zero-present requiredXor violation: {diagnostics:#?}");
}

/// requiredXor budget fallback: 9 members in the group, all unconditionally
/// present (each has a condition but both branches yield a real value).
/// Two or more are universally present → F3014 fires.
#[test]
fn required_xor_budget_fallback_fires_when_multiple_members_unconditional() {
    let condition_count = 9;
    let mut properties = serde_json::Map::new();
    let mut required_xor: Vec<String> = Vec::new();
    let mut template = String::from("Parameters:\n");
    for index in 0..condition_count {
        let property_name = format!("Choice{index:02}");
        properties.insert(property_name.clone(), json!({"type": "string"}));
        required_xor.push(property_name);
        template.push_str(&format!(
            "  Param{index:02}:\n    Type: String\n    AllowedValues: [yes, no]\n    Default: no\n"
        ));
    }
    template.push_str("Conditions:\n");
    for index in 0..condition_count {
        template.push_str(&format!("  Cond{index:02}: !Equals [!Ref Param{index:02}, yes]\n"));
    }
    // All members are unconditionally present (both branches of Fn::If yield
    // a real value, not NoValue) — at least 2 are universally present.
    template.push_str("Resources:\n  Res:\n    Type: AWS::Test::BudgetXorMultiple\n    Properties:\n");
    for index in 0..condition_count {
        template
            .push_str(&format!("      Choice{index:02}: !If [Cond{index:02}, val-a-{index:02}, val-b-{index:02}]\n"));
    }
    let sv = validator(vec![(
        "AWS::Test::BudgetXorMultiple",
        json!({
            "properties": properties,
            "requiredXor": required_xor,
            "additionalProperties": false
        }),
    )]);
    let diagnostics = validate(&sv, &template);
    let findings: Vec<_> = diagnostics.iter().filter(|d| d.rule_id == "F3014").collect();
    assert_eq!(
        findings.len(),
        1,
        "budget fallback must detect multiple unconditionally-present requiredXor members: {diagnostics:#?}"
    );
}

/// requiredXor budget fallback: 9 members, but only one is unconditionally
/// present (both Fn::If branches yield a real value). All others resolve to
/// NoValue unconditionally. Exactly one universally present → no violation.
#[test]
fn required_xor_budget_fallback_no_false_positive_one_unconditional() {
    let condition_count = 9;
    let mut properties = serde_json::Map::new();
    let mut required_xor: Vec<String> = Vec::new();
    let mut template = String::from("Parameters:\n");
    for index in 0..condition_count {
        let property_name = format!("Choice{index:02}");
        properties.insert(property_name.clone(), json!({"type": "string"}));
        required_xor.push(property_name);
        template.push_str(&format!(
            "  Param{index:02}:\n    Type: String\n    AllowedValues: [yes, no]\n    Default: no\n"
        ));
    }
    template.push_str("Conditions:\n");
    for index in 0..condition_count {
        template.push_str(&format!("  Cond{index:02}: !Equals [!Ref Param{index:02}, yes]\n"));
    }
    // Choice00 is unconditionally present (both branches non-null); all others
    // are unconditionally absent (both branches NoValue). Exactly one member
    // is universally present — no violation.
    template.push_str("Resources:\n  Res:\n    Type: AWS::Test::BudgetXorOk\n    Properties:\n");
    template.push_str("      Choice00: !If [Cond00, val-a, val-b]\n");
    for index in 1..condition_count {
        template
            .push_str(&format!("      Choice{index:02}: !If [Cond{index:02}, !Ref AWS::NoValue, !Ref AWS::NoValue]\n"));
    }
    let sv = validator(vec![(
        "AWS::Test::BudgetXorOk",
        json!({
            "properties": properties,
            "requiredXor": required_xor,
            "additionalProperties": false
        }),
    )]);
    let diagnostics = validate(&sv, &template);
    assert!(
        diagnostics.iter().all(|d| d.rule_id != "F3014"),
        "budget fallback must not fire when exactly one member is unconditionally present: {diagnostics:#?}"
    );
}

/// Nine independently conditional requiredXor members have both an all-false
/// world and worlds where two members are true. Targeted witness search must
/// prove the violation without enumerating all 512 combinations.
#[test]
fn required_xor_budget_fallback_finds_conditional_witnesses() {
    let condition_count = 9;
    let mut properties = serde_json::Map::new();
    let mut required_xor: Vec<String> = Vec::new();
    let mut template = String::from("Parameters:\n");
    for index in 0..condition_count {
        let property_name = format!("Choice{index:02}");
        properties.insert(property_name.clone(), json!({"type": "string"}));
        required_xor.push(property_name);
        template.push_str(&format!(
            "  Param{index:02}:\n    Type: String\n    AllowedValues: [yes, no]\n    Default: no\n"
        ));
    }
    template.push_str("Conditions:\n");
    for index in 0..condition_count {
        template.push_str(&format!("  Cond{index:02}: !Equals [!Ref Param{index:02}, yes]\n"));
    }
    template.push_str("Resources:\n  Res:\n    Type: AWS::Test::BudgetXorConditional\n    Properties:\n");
    for index in 0..condition_count {
        template.push_str(&format!("      Choice{index:02}: !If [Cond{index:02}, present, !Ref AWS::NoValue]\n"));
    }
    let sv = validator(vec![(
        "AWS::Test::BudgetXorConditional",
        json!({
            "properties": properties,
            "requiredXor": required_xor,
            "additionalProperties": false
        }),
    )]);
    let diagnostics = validate(&sv, &template);
    assert!(
        diagnostics.iter().any(|d| d.rule_id == "F3014"),
        "reachable zero- and multiple-present worlds must be diagnosed: {diagnostics:#?}"
    );
}

#[test]
fn required_xor_nine_mutually_exclusive_members_are_valid() {
    const VALUES: [&str; 9] = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
    let mut properties = serde_json::Map::new();
    let mut required_xor = Vec::new();
    let mut template = String::from(
        "Parameters:\n  Selector:\n    Type: String\n    AllowedValues: [a, b, c, d, e, f, g, h, i]\nConditions:\n",
    );
    for (index, value) in VALUES.iter().enumerate() {
        let property = format!("Choice{index:02}");
        properties.insert(property.clone(), json!({"type": "string"}));
        required_xor.push(property);
        template.push_str(&format!("  Is{value}: !Equals [!Ref Selector, {value}]\n"));
    }
    template.push_str("Resources:\n  Res:\n    Type: AWS::Test::BudgetXorExclusive\n    Properties:\n");
    for (index, value) in VALUES.iter().enumerate() {
        template.push_str(&format!("      Choice{index:02}: !If [Is{value}, present, !Ref AWS::NoValue]\n"));
    }
    let sv = validator(vec![(
        "AWS::Test::BudgetXorExclusive",
        json!({
            "properties": properties,
            "requiredXor": required_xor,
            "additionalProperties": false
        }),
    )]);
    let diagnostics = validate(&sv, &template);
    assert!(
        diagnostics.iter().all(|diagnostic| diagnostic.rule_id != "F3014"),
        "exactly one mutually exclusive member is present in every parameter world: {diagnostics:#?}"
    );
}

// ─── Customer-facing composition diagnostics ───────────────────────────────

fn composition_extra<'a>(diagnostic: &'a diagnostics::Diagnostic, key: &str) -> &'a Value {
    &diagnostic
        .context
        .as_ref()
        .expect("composition diagnostic must carry violation context")
        .extra
        .as_ref()
        .expect("composition diagnostic must carry structured extra context")
        .get(key)
        .unwrap_or_else(|| panic!("composition context must contain '{key}'"))
        .0
}

#[test]
fn any_of_zero_match_is_one_actionable_primary_diagnostic() {
    let sv = validator(vec![(
        "AWS::Test::ActionableAnyOf",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "Other": { "type": "string" }
            },
            "anyOf": [{ "required": ["A"] }, { "required": ["B"] }],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ActionableAnyOf\n",
        "    Properties:\n",
        "      Other: value\n",
    );
    let semantic_model = model(template);
    let diags = sv.validate(&semantic_model, Some("us-east-1")).diagnostics;
    let findings: Vec<_> = diags.iter().filter(|d| d.rule_id == "F3017").collect();
    assert_eq!(findings.len(), 1, "anyOf must emit one primary finding: {diags:#?}");
    assert!(
        diags.iter().all(|d| d.rule_id != "F3003"),
        "alternative-only requirements must not escape as standalone F3003 findings: {diags:#?}"
    );

    let finding = findings[0];
    assert!(finding.message.contains("0 branches matched"), "zero-match outcome must be explicit: {}", finding.message);
    assert!(
        finding.message.contains("'A'") && finding.message.contains("'B'"),
        "valid alternatives must be named: {}",
        finding.message
    );
    assert!(
        finding.message.contains("branch 1") && finding.message.contains("branch 2"),
        "each failed branch must be explained: {}",
        finding.message
    );
    assert_eq!(finding.property_path.as_deref(), Some("Properties"));
    assert_eq!(finding.location, Some(semantic_model.resource_span("R", "Properties")));
    assert_eq!(composition_extra(finding, "compositionKind"), &json!("anyOf"));
    assert_eq!(composition_extra(finding, "matchOutcome"), &json!("zeroMatches"));
    assert_eq!(composition_extra(finding, "validPropertyCombinations"), &json!([["A"], ["B"]]));

    let branch_failures =
        composition_extra(finding, "branchFailures").as_array().expect("branchFailures must be an array");
    assert_eq!(branch_failures.len(), 2, "each failed branch needs structured reasons: {branch_failures:#?}");
    assert_eq!(branch_failures[0]["branch"], json!(1));
    assert_eq!(branch_failures[1]["branch"], json!(2));
    assert_eq!(branch_failures[0]["reasons"].as_array().map(Vec::len), Some(1));
    assert_eq!(branch_failures[1]["reasons"].as_array().map(Vec::len), Some(1));
}

#[test]
fn one_of_zero_and_multiple_match_outcomes_are_distinct() {
    let sv = validator(vec![(
        "AWS::Test::ActionableOneOf",
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" },
                "Other": { "type": "string" }
            },
            "oneOf": [{ "required": ["A"] }, { "required": ["B"] }],
            "additionalProperties": false
        }),
    )]);

    let zero =
        validate(&sv, "Resources:\n  R:\n    Type: AWS::Test::ActionableOneOf\n    Properties:\n      Other: value\n");
    let zero_finding = zero.iter().find(|d| d.rule_id == "F3018").expect("zero-match finding");
    assert!(zero_finding.message.contains("0 branches matched"), "got: {}", zero_finding.message);
    assert_eq!(composition_extra(zero_finding, "matchOutcome"), &json!("zeroMatches"));
    assert!(zero.iter().all(|d| d.rule_id != "F3003"), "got: {zero:#?}");
    assert!(composition_extra(zero_finding, "branchFailures").as_array().is_some_and(|v| v.len() == 2));

    let multiple = validate(
        &sv,
        "Resources:\n  R:\n    Type: AWS::Test::ActionableOneOf\n    Properties:\n      A: one\n      B: two\n",
    );
    let multiple_finding = multiple.iter().find(|d| d.rule_id == "F3018").expect("multiple-match finding");
    assert!(multiple_finding.message.contains("2 branches matched"), "got: {}", multiple_finding.message);
    assert!(multiple_finding.message.contains("more than one"), "got: {}", multiple_finding.message);
    assert_eq!(composition_extra(multiple_finding, "matchOutcome"), &json!("multipleMatches"));
    assert_eq!(composition_extra(multiple_finding, "matchingBranches"), &json!([1, 2]));
    assert!(multiple.iter().all(|d| d.rule_id != "F3003"), "got: {multiple:#?}");
}

#[test]
fn scalar_any_of_reports_deduplicated_branch_reasons_at_property_location() {
    let sv = validator(vec![(
        "AWS::Test::ActionableScalarAnyOf",
        json!({
            "properties": {
                "Mode": {
                    "type": "string",
                    "anyOf": [
                        { "allOf": [{ "enum": ["A"] }, { "enum": ["A"] }] },
                        { "enum": ["B"] }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ActionableScalarAnyOf\n",
        "    Properties:\n",
        "      Mode: C\n",
    );
    let semantic_model = model(template);
    let diags = sv.validate(&semantic_model, Some("us-east-1")).diagnostics;
    let findings: Vec<_> = diags.iter().filter(|d| d.rule_id == "F3017").collect();
    assert_eq!(findings.len(), 1, "scalar anyOf must emit one primary finding: {diags:#?}");
    let finding = findings[0];
    assert!(finding.message.contains("branch 1") && finding.message.contains("branch 2"), "got: {}", finding.message);
    assert!(finding.message.contains("'A'") && finding.message.contains("'B'"), "got: {}", finding.message);
    assert_eq!(finding.property_path.as_deref(), Some("Properties.Mode"));
    assert_eq!(finding.location, Some(semantic_model.resource_span("R", "Properties.Mode")));

    let failures = composition_extra(finding, "branchFailures").as_array().expect("branchFailures array");
    assert_eq!(failures.len(), 2);
    assert_eq!(
        failures[0]["reasons"].as_array().map(Vec::len),
        Some(1),
        "identical reasons from nested constraints must be deduplicated: {failures:#?}"
    );
    assert_eq!(failures[0]["reasons"][0]["propertyPath"], json!("Properties.Mode"));
}

#[test]
fn actionable_any_of_preserves_the_invalid_condition_scenario() {
    let sv = validator(vec![(
        "AWS::Test::ActionableScenario",
        json!({
            "properties": { "Mode": { "type": "string" } },
            "anyOf": [
                { "properties": { "Mode": { "enum": ["A"] } }, "required": ["Mode"] },
                { "properties": { "Mode": { "enum": ["B"] } }, "required": ["Mode"] }
            ],
            "additionalProperties": false
        }),
    )]);
    let template = r#"{
        "Conditions": { "IsA": { "Fn::Equals": [{ "Ref": "AWS::Region" }, "us-east-1"] } },
        "Resources": {
            "R": {
                "Type": "AWS::Test::ActionableScenario",
                "Properties": { "Mode": { "Fn::If": ["IsA", "A", "C"] } }
            }
        }
    }"#;
    let diags = validate(&sv, template);
    let findings: Vec<_> = diags.iter().filter(|d| d.rule_id == "F3017").collect();
    assert_eq!(findings.len(), 1, "only the invalid condition world should fail: {findings:#?}");
    assert_eq!(findings[0].condition_scenario.as_ref().and_then(|c| c.get("IsA")), Some(&false));
    assert_eq!(composition_extra(findings[0], "matchOutcome"), &json!("zeroMatches"));
    assert!(composition_extra(findings[0], "branchFailures").as_array().is_some_and(|v| v.len() == 2));
}

// Nested list constraints need complete, condition-compatible worlds even when
// basic type and scalar checks can validate only the outer value.

#[test]
fn conditional_novalue_list_item_still_enforces_min_items() {
    let sv = validator(vec![(
        "AWS::Test::ConstrainedList",
        json!({
            "properties": {
                "Values": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 2
                }
            },
            "required": ["Values"],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Parameters:\n",
        "  Toggle:\n",
        "    Type: String\n",
        "Conditions:\n",
        "  UseBranch: !Equals [!Ref Toggle, 'true']\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ConstrainedList\n",
        "    Properties:\n",
        "      Values:\n",
        "        - fixed\n",
        "        - !If [UseBranch, !Ref AWS::NoValue, other]\n",
    );

    let diags = validate(&sv, template);
    let findings = diags.iter().filter(|d| d.rule_id == "F3032").count();

    assert_eq!(
        findings,
        1,
        "the reachable one-item world must violate minItems: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn conditional_list_item_still_enforces_unique_items() {
    let sv = validator(vec![(
        "AWS::Test::ConstrainedList",
        json!({
            "properties": {
                "Values": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": true
                }
            },
            "required": ["Values"],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Parameters:\n",
        "  Toggle:\n",
        "    Type: String\n",
        "Conditions:\n",
        "  UseBranch: !Equals [!Ref Toggle, 'true']\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ConstrainedList\n",
        "    Properties:\n",
        "      Values:\n",
        "        - fixed\n",
        "        - !If [UseBranch, fixed, other]\n",
    );

    let diags = validate(&sv, template);
    let findings = diags.iter().filter(|d| d.rule_id == "F3037").count();

    assert_eq!(
        findings,
        1,
        "the reachable duplicate world must violate uniqueItems: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── not_enum direct property enforcement ───────────────────────────────────

#[test]
fn not_enum_rejects_excluded_value_on_direct_property() {
    let sv = validator(vec![(
        "AWS::Test::NotEnum",
        json!({
            "properties": {
                "Username": {
                    "type": "string",
                    "not": { "enum": ["admin", "root", "system"] }
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::NotEnum\n    Properties:\n      Username: admin\n";
    let diags = validate(&sv, template);
    assert!(
        mentions(&diags, "F3030", "must not be one of"),
        "excluded value 'admin' should fire F3030: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn not_enum_defers_overridable_parameter_default() {
    let sv = validator(vec![(
        "AWS::Test::NotEnum",
        json!({
            "properties": {
                "Username": {
                    "type": "string",
                    "not": { "enum": ["admin", "root", "system"] }
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = "Parameters:\n  UserName:\n    Type: String\n    Default: admin\nResources:\n  R:\n    Type: AWS::Test::NotEnum\n    Properties:\n      Username: !Ref UserName\n";

    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3030", "must not be one of"),
        "a caller may override the prohibited default before deployment: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn not_enum_rejects_excluded_deterministic_join() {
    let sv = validator(vec![(
        "AWS::Test::NotEnum",
        json!({
            "properties": {
                "Username": {
                    "type": "string",
                    "not": { "enum": ["admin", "root", "system"] }
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template =
        "Resources:\n  R:\n    Type: AWS::Test::NotEnum\n    Properties:\n      Username: !Join ['', [ad, min]]\n";

    let diags = validate(&sv, template);
    let findings: Vec<_> = diags.iter().filter(|diagnostic| diagnostic.rule_id == "F3030").collect();
    assert_eq!(findings.len(), 1, "a literal-only join deterministically produces an excluded value: {diags:?}");
}

#[test]
fn not_enum_checks_only_the_deterministic_conditional_branch() {
    let sv = validator(vec![(
        "AWS::Test::NotEnum",
        json!({
            "properties": {
                "Username": {
                    "type": "string",
                    "not": { "enum": ["admin", "root", "system"] }
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = r#"
Parameters:
  UserName:
    Type: String
    Default: admin
Conditions:
  UseLiteral: !Equals [!Ref AWS::Region, us-east-1]
Resources:
  R:
    Type: AWS::Test::NotEnum
    Properties:
      Username: !If
        - UseLiteral
        - !Join ['', [ad, min]]
        - !Join ['', [!Ref UserName]]
"#;

    let diags = validate(&sv, template);
    let findings: Vec<_> = diags.iter().filter(|diagnostic| diagnostic.rule_id == "F3030").collect();
    assert_eq!(findings.len(), 1, "only the parameter-independent branch proves a violation: {diags:?}");
    assert_eq!(findings[0].condition_scenario.as_ref().and_then(|scenario| scenario.get("UseLiteral")), Some(&true));
}

#[test]
fn not_enum_accepts_non_excluded_value() {
    let sv = validator(vec![(
        "AWS::Test::NotEnum",
        json!({
            "properties": {
                "Username": {
                    "type": "string",
                    "not": { "enum": ["admin", "root", "system"] }
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = "Resources:\n  R:\n    Type: AWS::Test::NotEnum\n    Properties:\n      Username: legitimate_user\n";
    let diags = validate(&sv, template);
    assert!(
        !mentions(&diags, "F3030", "must not be one of"),
        "non-excluded value should not fire F3030: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

// ─── Unicode string length counting ─────────────────────────────────────────

#[test]
fn string_length_counts_unicode_scalar_values_not_bytes() {
    // Each emoji is 4 bytes in UTF-8 but 1 Unicode scalar value.
    // maxLength of 5 should accept 5 emoji characters (5 scalars, 20 bytes).
    let sv = validator(vec![(
        "AWS::Test::UniLength",
        json!({
            "properties": {
                "Label": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 5
                }
            },
            "additionalProperties": false
        }),
    )]);

    // 5 emoji characters = 5 Unicode scalar values = 20 UTF-8 bytes
    let template_ok = "Resources:\n  R:\n    Type: AWS::Test::UniLength\n    Properties:\n      Label: '\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}'\n";
    let diags_ok = validate(&sv, template_ok);
    assert!(
        !diags_ok.iter().any(|d| d.rule_id == "F3033"),
        "5 emoji (5 scalars) within maxLength=5 must not fire F3033: {:?}",
        diags_ok.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );

    // 6 emoji characters = 6 Unicode scalar values > maxLength 5
    let template_bad = "Resources:\n  R:\n    Type: AWS::Test::UniLength\n    Properties:\n      Label: '\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}\u{1F605}'\n";
    let diags_bad = validate(&sv, template_bad);
    assert!(
        diags_bad.iter().any(|d| d.rule_id == "F3033" && d.message.contains("6")),
        "6 emoji (6 scalars) exceeding maxLength=5 must fire F3033 with length 6: {:?}",
        diags_bad.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn string_length_multibyte_characters_below_minimum() {
    // 2-byte characters (e.g. "ñ" is U+00F1, 2 bytes in UTF-8, 1 scalar)
    let sv = validator(vec![(
        "AWS::Test::UniLength",
        json!({
            "properties": {
                "Name": {
                    "type": "string",
                    "minLength": 5
                }
            },
            "additionalProperties": false
        }),
    )]);

    // "a\u{00F1}o" is 3 Unicode scalar values but 4 UTF-8 bytes
    let template = "Resources:\n  R:\n    Type: AWS::Test::UniLength\n    Properties:\n      Name: 'a\u{00F1}o'\n";
    let diags = validate(&sv, template);
    assert!(
        diags.iter().any(|d| d.rule_id == "F3033" && d.message.contains("3")),
        "'a\\u{{00F1}}o' has 3 Unicode scalars, should fire F3033 (below min 5): {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn one_of_required_properties_are_decided_per_condition_scenario() {
    let resource_type = "AWS::Test::ConditionalRequired";
    let validator = validator(vec![(
        resource_type,
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "oneOf": [
                {
                    "type": "object",
                    "properties": { "A": { "type": "string" } },
                    "required": ["A"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": { "B": { "type": "string" } },
                    "required": ["B"],
                    "additionalProperties": false
                }
            ],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Conditions:\n",
        "  UseA: !Equals [!Ref AWS::Region, us-east-1]\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ConditionalRequired\n",
        "    Properties:\n",
        "      A: !If [UseA, a, !Ref AWS::NoValue]\n",
        "      B: !If [UseA, !Ref AWS::NoValue, b]\n",
    );

    let diagnostics = validate(&validator, template);

    assert!(
        !mentions(&diagnostics, "F3018", ""),
        "each condition scenario satisfies exactly one required branch: {diagnostics:?}"
    );
}

#[test]
fn referenced_one_of_required_properties_are_decided_per_condition_scenario() {
    let resource_type = "AWS::Test::ReferencedConditionalRequired";
    let validator = validator(vec![(
        resource_type,
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "definitions": {
                "RequiresA": { "required": ["A"] },
                "RequiresB": { "required": ["B"] }
            },
            "oneOf": [
                { "$ref": "#/definitions/RequiresA" },
                { "$ref": "#/definitions/RequiresB" }
            ],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Conditions:\n",
        "  UseA: !Equals [!Ref AWS::Region, us-east-1]\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ReferencedConditionalRequired\n",
        "    Properties:\n",
        "      A: !If [UseA, a, !Ref AWS::NoValue]\n",
        "      B: !If [UseA, !Ref AWS::NoValue, b]\n",
    );

    let diagnostics = validate(&validator, template);

    assert!(
        !mentions(&diagnostics, "F3018", ""),
        "referenced required branches must preserve condition correlation: {diagnostics:?}"
    );
}

#[test]
fn one_of_required_properties_report_only_the_world_with_no_surviving_property() {
    let resource_type = "AWS::Test::ConditionalRequiredInvalid";
    let validator = validator(vec![(
        resource_type,
        json!({
            "properties": {
                "A": { "type": "string" },
                "B": { "type": "string" }
            },
            "oneOf": [{ "required": ["A"] }, { "required": ["B"] }],
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Conditions:\n",
        "  UseA: !Equals [!Ref AWS::Region, us-east-1]\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ConditionalRequiredInvalid\n",
        "    Properties:\n",
        "      A: !If [UseA, a, !Ref AWS::NoValue]\n",
        "      B: !Ref AWS::NoValue\n",
    );

    let diagnostics = validate(&validator, template);
    let one_of_diagnostics: Vec<_> = diagnostics.iter().filter(|diagnostic| diagnostic.rule_id == "F3018").collect();

    assert_eq!(one_of_diagnostics.len(), 1, "only one condition world violates oneOf: {diagnostics:?}");
    assert_eq!(
        one_of_diagnostics[0].condition_scenario.as_ref().and_then(|scenario| scenario.get("UseA")),
        Some(&false),
        "the finding must identify the world where both properties are removed"
    );
}

#[test]
fn composition_defers_unresolved_substitution_markers() {
    let validator = validator(vec![(
        "AWS::Test::ConditionalPattern",
        json!({
            "properties": {
                "Name": {
                    "type": "string",
                    "anyOf": [
                        { "pattern": "^foo-[a-z]+$" },
                        { "pattern": "^bar-[a-z]+$" }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Parameters:\n",
        "  Name:\n",
        "    Type: String\n",
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::ConditionalPattern\n",
        "    Properties:\n",
        "      Name: !Sub 'foo-${Name}'\n",
    );

    let diagnostics = validate(&validator, template);

    assert!(
        !mentions(&diagnostics, "F3017", ""),
        "an unresolved intrinsic substitution must remain deferred: {diagnostics:?}"
    );
}

#[test]
fn composition_validates_authored_substitution_markers_as_literals() {
    let validator = validator(vec![(
        "AWS::Test::LiteralPattern",
        json!({
            "properties": {
                "Name": {
                    "type": "string",
                    "anyOf": [
                        { "pattern": "^foo-[a-z]+$" },
                        { "pattern": "^bar-[a-z]+$" }
                    ]
                }
            },
            "additionalProperties": false
        }),
    )]);
    let template = concat!(
        "Resources:\n",
        "  R:\n",
        "    Type: AWS::Test::LiteralPattern\n",
        "    Properties:\n",
        "      Name: 'foo-${Name}'\n",
    );

    let diagnostics = validate(&validator, template);

    assert!(
        mentions(&diagnostics, "F3017", "not valid under any"),
        "authored dollar-brace text is a concrete literal and must be validated: {diagnostics:?}"
    );
}
