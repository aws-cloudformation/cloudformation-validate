//! Gate ↔ evaluator correspondence.
//!
//! The overlay preflight admits a fixed vocabulary for composition branches
//! (`COMPOSITION_ALLOWED_FIELDS`), conditional `if` schemas
//! (`CONDITION_ALLOWED_FIELDS`), condition properties
//! (`CONDITION_PROPERTY_ALLOWED_FIELDS`), and conditional `then`/`else`
//! branches. Every admitted field must actually participate in validation —
//! a field the gate accepts but the evaluator ignores silently weakens the
//! overlay (or over-matches a condition), which is exactly the failure mode
//! the preflight exists to prevent.
//!
//! Each case below states ONE gated field in its gated position, then asserts
//! both directions: a violating template produces a finding and a conforming
//! template stays clean. A field that stops being evaluated fails its
//! violating assertion here rather than shipping as a silent no-op.

use schema_validator::SchemaValidator;
use serde_json::{Value, json};
use std::sync::Arc;
use template_model::SemanticModel;

fn validator(type_name: &str, overlay: Value) -> SchemaValidator {
    SchemaValidator::try_with_additional_schemas(vec![(type_name, overlay)])
        .expect("the gate must accept a field it documents as allowed")
}

fn findings(sv: &SchemaValidator, template: &str) -> Vec<(String, String)> {
    let model = Arc::new(SemanticModel::from_bytes(template.as_bytes()).expect("template parses"));
    sv.validate(&model, None).diagnostics.into_iter().map(|d| (d.rule_id, d.message)).collect()
}

/// One correspondence case: a single gated field, a template that violates it,
/// and a template that satisfies it.
struct Case {
    name: &'static str,
    overlay: Value,
    violating: &'static str,
    conforming: &'static str,
}

fn assert_cases(type_name_prefix: &str, cases: Vec<Case>) {
    let mut failures: Vec<String> = Vec::new();
    for (index, case) in cases.into_iter().enumerate() {
        let type_name = format!("AWS::Gate::{type_name_prefix}{index}");
        let mut overlay = case.overlay;
        // Each case gets its own resource type so cases stay independent.
        let violating = case.violating.replace("TYPE", &type_name);
        let conforming = case.conforming.replace("TYPE", &type_name);
        if let Some(obj) = overlay.as_object_mut() {
            obj.insert("typeName".to_string(), json!(type_name));
        }
        let sv = validator(&type_name, overlay);
        let violating_diags = findings(&sv, &violating);
        if violating_diags.is_empty() {
            failures.push(format!(
                "{}: the violating template produced no finding — the field is not evaluated",
                case.name
            ));
        }
        let conforming_diags = findings(&sv, &conforming);
        if !conforming_diags.is_empty() {
            failures.push(format!("{}: the conforming template produced findings: {conforming_diags:?}", case.name));
        }
    }
    assert!(failures.is_empty(), "gate/evaluator drift:\n{}", failures.join("\n"));
}

/// Every field `COMPOSITION_ALLOWED_FIELDS` admits in a plain `allOf` branch is
/// enforced. `allOf` is used because a violated branch is directly user-visible.
#[test]
fn composition_branch_fields_are_evaluated() {
    let cases = vec![
        Case {
            name: "required",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "required": ["B"] }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n      B: y\n",
        },
        Case {
            name: "properties (enum)",
            overlay: json!({
                "properties": { "P": { "type": "string" } },
                "allOf": [{ "properties": { "P": { "enum": ["a", "b"] } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: zzz\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: a\n",
        },
        Case {
            name: "properties (type)",
            overlay: json!({
                "properties": { "P": {} },
                "allOf": [{ "properties": { "P": { "type": "integer" } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: [1, 2]\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: 5\n",
        },
        Case {
            name: "properties (enumCaseInsensitive)",
            overlay: json!({
                "properties": { "P": { "type": "string" } },
                "allOf": [{ "properties": { "P": { "enumCaseInsensitive": ["Alpha"] } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: beta\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: ALPHA\n",
        },
        Case {
            name: "properties (not.enum)",
            overlay: json!({
                "properties": { "P": { "type": "string" } },
                "allOf": [{ "properties": { "P": { "not": { "enum": ["forbidden"] } } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: forbidden\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: fine\n",
        },
        Case {
            name: "properties (const)",
            overlay: json!({
                "properties": { "P": { "type": "string" } },
                "allOf": [{ "properties": { "P": { "const": "only" } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: other\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: only\n",
        },
        Case {
            name: "properties (pattern)",
            overlay: json!({
                "properties": { "P": { "type": "string" } },
                "allOf": [{ "properties": { "P": { "pattern": "^a" } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: zzz\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: abc\n",
        },
        Case {
            name: "properties (format)",
            overlay: json!({
                "properties": { "P": { "type": "string" } },
                "allOf": [{ "properties": { "P": { "format": "AWS::EC2::VPC.Id" } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: not-a-vpc-id\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: vpc-0123456789abcdef0\n",
        },
        Case {
            name: "properties (minimum/maximum)",
            overlay: json!({
                "properties": { "P": { "type": "integer" } },
                "allOf": [{ "properties": { "P": { "minimum": 5, "maximum": 10 } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: 3\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: 7\n",
        },
        Case {
            name: "properties (exclusiveMinimum/exclusiveMaximum)",
            overlay: json!({
                "properties": { "P": { "type": "integer" } },
                "allOf": [{ "properties": { "P": { "exclusiveMinimum": 5, "exclusiveMaximum": 10 } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: 5\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: 6\n",
        },
        Case {
            name: "properties (multipleOf)",
            overlay: json!({
                "properties": { "P": { "type": "integer" } },
                "allOf": [{ "properties": { "P": { "multipleOf": 10 } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: 15\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: 20\n",
        },
        Case {
            name: "properties (minLength/maxLength)",
            overlay: json!({
                "properties": { "P": { "type": "string" } },
                "allOf": [{ "properties": { "P": { "minLength": 2, "maxLength": 4 } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: toolong\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: ok\n",
        },
        Case {
            name: "properties (minItems/maxItems)",
            overlay: json!({
                "properties": { "P": { "type": "array", "items": { "type": "string" } } },
                "allOf": [{ "properties": { "P": { "minItems": 2 } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P:\n        - one\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P:\n        - one\n        - two\n",
        },
        Case {
            name: "properties (uniqueItems)",
            overlay: json!({
                "properties": { "P": { "type": "array", "items": { "type": "string" } } },
                "allOf": [{ "properties": { "P": { "uniqueItems": true } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P:\n        - dup\n        - dup\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P:\n        - one\n        - two\n",
        },
        Case {
            name: "properties (minProperties/maxProperties)",
            overlay: json!({
                "properties": { "P": { "type": "object" } },
                "allOf": [{ "properties": { "P": { "minProperties": 2 } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P:\n        one: 1\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P:\n        one: 1\n        two: 2\n",
        },
        Case {
            name: "properties (items)",
            overlay: json!({
                "properties": { "P": { "type": "array" } },
                "allOf": [{ "properties": { "P": { "items": { "type": "integer" } } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P:\n        - not-a-number\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P:\n        - 1\n",
        },
        Case {
            name: "$ref branch",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "definitions": { "NeedsB": { "required": ["B"] } },
                "allOf": [{ "$ref": "#/definitions/NeedsB" }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n      B: y\n",
        },
        Case {
            name: "dependentRequired",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "dependentRequired": { "A": ["B"] } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n      B: y\n",
        },
        Case {
            name: "dependentExcluded",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "dependentExcluded": { "A": ["B"] } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n      B: y\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
        },
        Case {
            name: "dependencies (array form)",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "dependencies": { "A": ["B"] } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n      B: y\n",
        },
        Case {
            name: "nested anyOf",
            overlay: json!({
                "properties": { "P": { "type": "string" } },
                "allOf": [{ "properties": { "P": { "anyOf": [ { "enum": ["a"] }, { "enum": ["b"] } ] } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: zzz\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: b\n",
        },
        Case {
            name: "nested oneOf",
            overlay: json!({
                "properties": { "P": { "type": "string" } },
                "allOf": [{ "properties": { "P": { "oneOf": [ { "enum": ["a"] }, { "enum": ["b"] } ] } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: zzz\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: a\n",
        },
        Case {
            name: "nested allOf",
            overlay: json!({
                "properties": { "P": { "type": "string" } },
                "allOf": [{ "properties": { "P": { "allOf": [ { "pattern": "^a" }, { "maxLength": 3 } ] } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: aaaaaa\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      P: ab\n",
        },
        Case {
            name: "branch if/then/else",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" }, "C": { "type": "string" } },
                "allOf": [{
                    "if": { "properties": { "A": { "enum": ["x"] } }, "required": ["A"] },
                    "then": { "required": ["B"] },
                    "else": { "required": ["C"] }
                }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n      B: y\n",
        },
        Case {
            name: "additionalProperties + patternProperties",
            overlay: json!({
                "properties": { "Map": { "type": "object" } },
                "allOf": [{
                    "properties": {
                        "Map": {
                            "patternProperties": { "^allowed": { "type": "string" } },
                            "additionalProperties": false
                        }
                    }
                }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      Map:\n        unexpected: v\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      Map:\n        allowedKey: v\n",
        },
    ];
    assert_cases("Comp", cases);
}

/// Every field `CONDITION_PROPERTY_ALLOWED_FIELDS` admits in an `if` property
/// participates in condition matching. Each case pairs a template where the
/// condition must NOT match (violating the condition constraint — the then
/// branch, whose dependency would fire, must stay silent) with one where it
/// must match (the then branch fires). The `conforming` template here is the
/// non-matching one; the `violating` template is the matching-and-then-violated
/// one.
#[test]
fn condition_property_fields_are_evaluated() {
    let then_dep = json!({ "dependentRequired": { "A": ["B"] } });
    let cases = vec![
        Case {
            name: "if property enum",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "enum": ["x"] } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: other\n",
        },
        Case {
            name: "if property const",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "const": "x" } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: other\n",
        },
        Case {
            name: "if property pattern",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "pattern": "^x" } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: xyz\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: other\n",
        },
        Case {
            name: "if property not.enum",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "not": { "enum": ["skip"] } } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: fire\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: skip\n",
        },
        Case {
            name: "if property type",
            overlay: json!({
                "properties": { "A": {}, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "type": "array" } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A:\n        - item\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: scalar\n",
        },
        Case {
            name: "if property minItems",
            overlay: json!({
                "properties": { "A": { "type": "array", "items": { "type": "string" } }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "minItems": 1 } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A:\n        - one\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: []\n",
        },
        Case {
            name: "if property maxItems",
            overlay: json!({
                "properties": { "A": { "type": "array", "items": { "type": "string" } }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "maxItems": 1 } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A:\n        - one\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A:\n        - one\n        - two\n",
        },
        Case {
            name: "if property minLength",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "minLength": 3 } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: long-enough\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: ab\n",
        },
        Case {
            name: "if property maxLength",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "maxLength": 2 } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: ab\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: too-long\n",
        },
        Case {
            name: "if property minProperties",
            overlay: json!({
                "properties": { "A": { "type": "object" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "minProperties": 2 } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A:\n        k1: v\n        k2: v\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A:\n        k1: v\n",
        },
        Case {
            name: "if property maxProperties",
            overlay: json!({
                "properties": { "A": { "type": "object" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "maxProperties": 1 } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A:\n        k1: v\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A:\n        k1: v\n        k2: v\n",
        },
        Case {
            name: "if property nested required",
            overlay: json!({
                "properties": { "A": { "type": "object", "properties": { "Inner": { "type": "string" } } }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "required": ["Inner"] } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A:\n        Inner: v\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A:\n        Other: v\n",
        },
        Case {
            name: "if property $ref",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "definitions": { "Trigger": { "enum": ["x"] } },
                "allOf": [{ "if": { "properties": { "A": { "$ref": "#/definitions/Trigger" } }, "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: other\n",
        },
        Case {
            name: "if schema type object (matches at the root)",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "type": "object", "required": ["A"] }, "then": then_dep }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      C: x\n",
        },
    ];
    assert_cases("Cond", cases);
}

/// A condition stating a non-object `type` can never match the property object
/// it is evaluated against, so the then branch must never apply.
#[test]
fn condition_root_type_other_than_object_never_matches() {
    let sv = validator(
        "AWS::Gate::RootTypeString",
        json!({
            "typeName": "AWS::Gate::RootTypeString",
            "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
            "allOf": [{ "if": { "type": "string", "required": ["A"] }, "then": { "dependentRequired": { "A": ["B"] } } }]
        }),
    );
    let template = "Resources:\n  R:\n    Type: AWS::Gate::RootTypeString\n    Properties:\n      A: x\n";
    let diags = findings(&sv, template);
    assert!(diags.is_empty(), "a string-typed condition can never match the Properties object: {diags:?}");
}

/// Conditional `then`/`else` branches are enforced in full when selected:
/// required, value constraints, dependency maps, and additionalProperties.
#[test]
fn conditional_then_else_fields_are_enforced() {
    let cases = vec![
        Case {
            name: "then.required",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "enum": ["x"] } }, "required": ["A"] }, "then": { "required": ["B"] } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n      B: y\n",
        },
        Case {
            name: "then.properties value constraint",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "enum": ["x"] } }, "required": ["A"] }, "then": { "properties": { "B": { "enum": ["allowed"] } } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n      B: forbidden\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n      B: allowed\n",
        },
        Case {
            name: "then.dependentExcluded",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "enum": ["x"] } }, "required": ["A"] }, "then": { "dependentExcluded": { "A": ["B"] } } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n      B: y\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: x\n",
        },
        Case {
            name: "else.required",
            overlay: json!({
                "properties": { "A": { "type": "string" }, "C": { "type": "string" } },
                "allOf": [{ "if": { "properties": { "A": { "enum": ["x"] } }, "required": ["A"] }, "then": { "dependentRequired": {} }, "else": { "required": ["C"] } }]
            }),
            violating: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: other\n",
            conforming: "Resources:\n  R:\n    Type: TYPE\n    Properties:\n      A: other\n      C: z\n",
        },
    ];
    assert_cases("ThenElse", cases);
}
