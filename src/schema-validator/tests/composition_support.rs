//! Focused integration tests for full composition branch enforcement,
//! multipleOf, dependencies array-form, and ref siblings.

use schema_validator::{CompiledSchemaStore, SchemaOverlayError, SchemaValidator};
use serde_json::{Value, json};
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
    // Tags contains a string - neither object nor integer items (string→integer coercion
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
    // The dangling ref branch emits F3003 into the tmp vec, so the second branch
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
    // Plain YAML 1.1 `on` resolves to boolean true. Quote it here so this
    // test isolates conditional enforcement rather than scalar resolution.
    let violating =
        "Resources:\n  R:\n    Type: AWS::Test::PropCondRequired\n    Properties:\n      Cfg:\n        Mode: \"on\"\n";
    let diags = validate(&sv, violating);
    assert!(
        mentions(&diags, "F3003", "Extra"),
        "a property-level conditional's required list must be enforced: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
    let ok = "Resources:\n  R:\n    Type: AWS::Test::PropCondRequired\n    Properties:\n      Cfg:\n        Mode: \"on\"\n        Extra: x\n";
    let diags = validate(&sv, ok);
    assert!(
        diags.is_empty(),
        "a satisfied conditional must stay clean: {:?}",
        diags.iter().map(|d| (&d.rule_id, &d.message)).collect::<Vec<_>>()
    );
}
