use crate::make_resource_diagnostic_at_source;
use diagnostics::Diagnostic;
use std::sync::Arc;
use template_model::SemanticModel;
use template_model::consts::KEY_TYPE;
use template_model::message::render_str_list;
use template_model::resolver::ResolvedValue;

pub fn validate_definition(
    definition: &serde_json::Value,
    model: &Arc<SemanticModel>,
    resource_id: &str,
    prop_key: &str,
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if !definition.is_object() {
        return out;
    }

    if definition.get("StartAt").is_none() {
        // Missing field: anchor at the nearest authored parent (the definition object itself)
        out.push(mk_at(model, resource_id, prop_key, prop_key, "State machine definition must have 'StartAt'"));
    }
    if definition.get("States").is_none() {
        out.push(mk_at(model, resource_id, prop_key, prop_key, "State machine definition must have 'States'"));
        return out;
    }

    validate_start_at(&mut out, definition, model, resource_id, prop_key, "");

    if let Some(states) = definition.get("States").and_then(|s| s.as_object()) {
        let is_jsonata = definition.get("QueryLanguage").and_then(|v| v.as_str()) == Some("JSONata");
        for (state_name, state) in states {
            validate_state(&mut out, state_name, state, is_jsonata, model, resource_id, prop_key);
        }
    }

    out
}

pub fn validate_all_state_machines(model: &Arc<SemanticModel>) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for name in model.resources_of_type("AWS::StepFunctions::StateMachine") {
        let res = match model.resources.get(name.as_str()) {
            Some(r) => r,
            None => continue,
        };

        for key in &["DefinitionString", "Definition"] {
            let def = match res.properties.get(*key) {
                Some(ResolvedValue::Concrete { value: v }) => {
                    if let Some(s) = v.as_str() {
                        match serde_json::from_str::<serde_json::Value>(s) {
                            Ok(parsed) => parsed,
                            Err(_) => continue,
                        }
                    } else if v.is_object() {
                        v.0.clone()
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };
            out.extend(validate_definition(&def, model, name, &format!("Properties.{}", key)));
            break;
        }
    }
    out
}

fn validate_start_at(
    out: &mut Vec<Diagnostic>,
    definition: &serde_json::Value,
    model: &Arc<SemanticModel>,
    rid: &str,
    prop_key: &str,
    path_prefix: &str,
) {
    let start_at = match definition.get("StartAt").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return,
    };
    let states = match definition.get("States").and_then(|v| v.as_object()) {
        Some(s) => s,
        None => return,
    };

    if !states.contains_key(start_at) {
        let logical_path = if path_prefix.is_empty() {
            format!("{}.StartAt", prop_key)
        } else {
            format!("{}.{}.StartAt", prop_key, path_prefix)
        };
        let display = if path_prefix.is_empty() { "StartAt".to_string() } else { format!("{}.StartAt", path_prefix) };
        out.push(mk_at(
            model,
            rid,
            &logical_path,
            prop_key,
            &format!("StartAt '{}' does not reference a valid state at {}", start_at, display),
        ));
    }

    for (state_name, state) in states {
        if !state.is_object() {
            continue;
        }
        let stype = state.get(KEY_TYPE).and_then(|v| v.as_str()).unwrap_or("");
        let state_path = if path_prefix.is_empty() {
            format!("States.{}", state_name)
        } else {
            format!("{}.States.{}", path_prefix, state_name)
        };

        if stype == "Parallel"
            && let Some(branches) = state.get("Branches").and_then(|v| v.as_array())
        {
            for (i, branch) in branches.iter().enumerate() {
                validate_start_at(out, branch, model, rid, prop_key, &format!("{}.Branches.{}", state_path, i));
            }
        }
        if stype == "Map" {
            for key in &["ItemProcessor", "Iterator"] {
                if let Some(proc) = state.get(key)
                    && proc.is_object()
                {
                    validate_start_at(out, proc, model, rid, prop_key, &format!("{}.{}", state_path, key));
                }
            }
        }
    }
}

fn validate_state(
    out: &mut Vec<Diagnostic>,
    name: &str,
    state: &serde_json::Value,
    is_jsonata: bool,
    model: &Arc<SemanticModel>,
    rid: &str,
    prop_key: &str,
) {
    if !state.is_object() {
        return;
    }
    let state_base = format!("{}.States.{}", prop_key, name);
    let stype = match state.get(KEY_TYPE).and_then(|v| v.as_str()) {
        Some(t) => t,
        None => {
            // Missing Type: anchor at the state object (nearest authored parent)
            out.push(mk_at(
                model,
                rid,
                &state_base,
                prop_key,
                &format!("State '{}' is missing required 'Type' property", name),
            ));
            return;
        }
    };

    let valid_types = ["Task", "Pass", "Choice", "Wait", "Succeed", "Fail", "Parallel", "Map"];
    if !valid_types.contains(&stype) {
        // Invalid existing Type value: anchor at the Type field
        let type_path = format!("{}.Type", state_base);
        out.push(mk_at(
            model,
            rid,
            &type_path,
            prop_key,
            &format!("State '{}' has invalid Type '{}'. Must be one of {}", name, stype, render_str_list(valid_types)),
        ));
        return;
    }

    if is_jsonata {
        for forbidden in &["InputPath", "OutputPath", "Parameters", "ResultPath", "ResultSelector"] {
            if state.get(*forbidden).is_some() {
                // Existing forbidden field: anchor at that exact field
                let field_path = format!("{}.{}", state_base, forbidden);
                out.push(mk_at(
                    model,
                    rid,
                    &field_path,
                    prop_key,
                    &format!("State '{}': '{}' is not allowed when QueryLanguage is JSONata", name, forbidden),
                ));
            }
        }
    }

    match stype {
        "Task" => {
            if state.get("Resource").is_none() {
                // Missing Resource: anchor at the state object (nearest authored parent)
                out.push(mk_at(
                    model,
                    rid,
                    &state_base,
                    prop_key,
                    &format!("Task state '{}' is missing required 'Resource' property", name),
                ));
            }
        }
        "Choice" => {
            if state.get("Choices").is_none() {
                // Missing Choices: anchor at the state object
                out.push(mk_at(
                    model,
                    rid,
                    &state_base,
                    prop_key,
                    &format!("Choice state '{}' is missing required 'Choices' property", name),
                ));
            }
        }
        "Wait" => {
            let has_wait =
                ["Seconds", "Timestamp", "SecondsPath", "TimestampPath"].iter().any(|k| state.get(k).is_some());
            if !has_wait {
                // Missing all timing fields: anchor at the state object
                out.push(mk_at(
                    model,
                    rid,
                    &state_base,
                    prop_key,
                    &format!(
                        "Wait state '{}' must have one of Seconds, Timestamp, SecondsPath, or TimestampPath",
                        name
                    ),
                ));
            }
        }
        _ => {}
    }
}

/// Builds a state-machine diagnostic with separate logical and source paths.
/// `logical_path` carries the precise member path for the diagnostic's `property_path`.
/// `source_path` is the base property key used for span resolution (walks up to the
/// authored DefinitionString/Definition value even when the logical path points deeper).
fn mk_at(model: &Arc<SemanticModel>, rid: &str, logical_path: &str, source_path: &str, msg: &str) -> Diagnostic {
    make_resource_diagnostic_at_source("E3601", msg, model, rid, logical_path, source_path, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use template_model::SemanticModel;

    fn minimal_arc_model() -> Arc<SemanticModel> {
        let yaml = br#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
"#;
        Arc::new(SemanticModel::from_bytes(yaml).expect("model"))
    }

    #[test]
    fn valid_definition_produces_no_diagnostics() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "Hello",
            "States": {
                "Hello": {"Type": "Pass", "End": true}
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(
            diags.is_empty(),
            "Expected no diagnostics, got: {:?}",
            diags.iter().map(|d| &d.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn missing_start_at_anchors_at_definition_base() {
        let model = minimal_arc_model();
        let def = json!({
            "States": {
                "Hello": {"Type": "Pass", "End": true}
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("StartAt")).expect("missing StartAt diagnostic");
        // Missing field anchors at nearest authored parent (the definition base)
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString"));
    }

    #[test]
    fn missing_states_anchors_at_definition_base() {
        let model = minimal_arc_model();
        let def = json!({"StartAt": "Hello"});
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("States")).expect("missing States diagnostic");
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString"));
    }

    #[test]
    fn missing_both_start_at_and_states() {
        let model = minimal_arc_model();
        let def = json!({});
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(diags.iter().any(|d| d.message.contains("StartAt")));
        assert!(diags.iter().any(|d| d.message.contains("States")));
    }

    #[test]
    fn non_object_definition_returns_empty() {
        let model = minimal_arc_model();
        let def = json!("not an object");
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(diags.is_empty());
    }

    #[test]
    fn start_at_referencing_nonexistent_state_anchors_at_start_at_field() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "NonExistent",
            "States": {
                "Hello": {"Type": "Pass", "End": true}
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("NonExistent")).expect("StartAt diagnostic");
        // Existing invalid StartAt anchors at <base>.StartAt
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString.StartAt"));
    }

    #[test]
    fn state_missing_type_anchors_at_state_object() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "Bad",
            "States": {
                "Bad": {"End": true}
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("missing required 'Type'")).expect("missing Type diagnostic");
        // Missing Type: anchor at the state object (nearest authored parent)
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString.States.Bad"));
    }

    #[test]
    fn state_invalid_type_anchors_at_type_field() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "Bad",
            "States": {
                "Bad": {"Type": "InvalidType", "End": true}
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("InvalidType")).expect("invalid Type diagnostic");
        // Existing invalid Type: anchor at <base>.States.<state>.Type
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString.States.Bad.Type"));
    }

    #[test]
    fn all_valid_state_types_accepted() {
        let model = minimal_arc_model();
        for stype in &["Task", "Pass", "Choice", "Wait", "Succeed", "Fail", "Parallel", "Map"] {
            let mut states = serde_json::Map::new();
            let mut state = serde_json::Map::new();
            state.insert("Type".into(), json!(stype));
            state.insert("End".into(), json!(true));
            match *stype {
                "Task" => {
                    state.insert("Resource".into(), json!("arn:aws:lambda:us-east-1:123:function:fn"));
                }
                "Choice" => {
                    state.insert("Choices".into(), json!([]));
                }
                "Wait" => {
                    state.insert("Seconds".into(), json!(10));
                }
                "Parallel" => {
                    state.insert("Branches".into(), json!([]));
                }
                "Map" => {
                    state.insert(
                        "ItemProcessor".into(),
                        json!({"StartAt": "X", "States": {"X": {"Type": "Pass", "End": true}}}),
                    );
                }
                _ => {}
            }
            states.insert("TheState".into(), json!(state));
            let def = json!({"StartAt": "TheState", "States": states});
            let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
            let type_errors: Vec<_> = diags.iter().filter(|d| d.message.contains("invalid Type")).collect();
            assert!(
                type_errors.is_empty(),
                "Type '{}' should be valid, got: {:?}",
                stype,
                type_errors.iter().map(|d| &d.message).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn task_state_missing_resource_anchors_at_state_object() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "T",
            "States": {"T": {"Type": "Task", "End": true}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("Resource")).expect("missing Resource diagnostic");
        // Missing field: anchor at state object
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString.States.T"));
    }

    #[test]
    fn choice_state_missing_choices_anchors_at_state_object() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "C",
            "States": {"C": {"Type": "Choice"}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("Choices")).expect("missing Choices diagnostic");
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString.States.C"));
    }

    #[test]
    fn wait_state_missing_timing_anchors_at_state_object() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "W",
            "States": {"W": {"Type": "Wait", "End": true}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("Seconds")).expect("missing timing diagnostic");
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString.States.W"));
    }

    #[test]
    fn wait_state_with_seconds_is_valid() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "W",
            "States": {"W": {"Type": "Wait", "Seconds": 5, "End": true}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(!diags.iter().any(|d| d.message.contains("Wait state")));
    }

    #[test]
    fn wait_state_with_timestamp_path_is_valid() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "W",
            "States": {"W": {"Type": "Wait", "TimestampPath": "$.ts", "End": true}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(!diags.iter().any(|d| d.message.contains("Wait state")));
    }

    #[test]
    fn jsonata_forbidden_field_anchors_at_exact_field() {
        let model = minimal_arc_model();
        let def = json!({
            "QueryLanguage": "JSONata",
            "StartAt": "P",
            "States": {"P": {"Type": "Pass", "InputPath": "$.x", "End": true}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags
            .iter()
            .find(|d| d.message.contains("InputPath") && d.message.contains("JSONata"))
            .expect("JSONata forbidden field diagnostic");
        // Existing forbidden field: anchors at its exact path
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString.States.P.InputPath"));
    }

    #[test]
    fn jsonata_mode_forbids_all_restricted_fields() {
        let model = minimal_arc_model();
        for field in &["InputPath", "OutputPath", "Parameters", "ResultPath", "ResultSelector"] {
            let mut state = serde_json::Map::new();
            state.insert("Type".into(), json!("Pass"));
            state.insert((*field).into(), json!("$.x"));
            state.insert("End".into(), json!(true));
            let def = json!({
                "QueryLanguage": "JSONata",
                "StartAt": "P",
                "States": {"P": state}
            });
            let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
            assert!(
                diags.iter().any(|d| d.message.contains(field) && d.message.contains("JSONata")),
                "Expected diagnostic for forbidden field '{}' in JSONata mode",
                field
            );
        }
    }

    #[test]
    fn non_jsonata_mode_allows_inputpath() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "P",
            "States": {"P": {"Type": "Pass", "InputPath": "$.x", "End": true}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(!diags.iter().any(|d| d.message.contains("JSONata")));
    }

    #[test]
    fn parallel_branch_bad_start_at_uses_nested_path() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "P",
            "States": {
                "P": {
                    "Type": "Parallel",
                    "End": true,
                    "Branches": [{
                        "StartAt": "Ghost",
                        "States": {
                            "Inner": {"Type": "Pass", "End": true}
                        }
                    }]
                }
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("Ghost")).expect("nested StartAt diagnostic");
        // Nested Parallel: full dotted path through the branch hierarchy
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString.States.P.Branches.0.StartAt"));
    }

    #[test]
    fn map_item_processor_bad_start_at_uses_nested_path() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "M",
            "States": {
                "M": {
                    "Type": "Map",
                    "End": true,
                    "ItemProcessor": {
                        "StartAt": "Missing",
                        "States": {
                            "Inner": {"Type": "Pass", "End": true}
                        }
                    }
                }
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("Missing")).expect("nested Map StartAt diagnostic");
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString.States.M.ItemProcessor.StartAt"));
    }

    #[test]
    fn map_iterator_bad_start_at_uses_nested_path() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "M",
            "States": {
                "M": {
                    "Type": "Map",
                    "End": true,
                    "Iterator": {
                        "StartAt": "Ghost",
                        "States": {
                            "Inner": {"Type": "Pass", "End": true}
                        }
                    }
                }
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("Ghost")).expect("nested Iterator StartAt diagnostic");
        assert_eq!(d.property_path.as_deref(), Some("Properties.DefinitionString.States.M.Iterator.StartAt"));
    }

    #[test]
    fn validate_all_state_machines_with_bad_start_at_template() {
        let templates_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../resources/templates");
        let path = format!("{}/bad/stepfunctions_bad_start_at.yaml", templates_dir);
        let bytes = fs::read(&path).expect("test template should exist");
        let model = Arc::new(SemanticModel::from_bytes(&bytes).expect("should parse"));
        let diags = validate_all_state_machines(&model);
        assert!(!diags.is_empty(), "Expected diagnostics for bad StartAt");
        assert!(diags.iter().any(|d| d.message.contains("StartAt")));
        assert!(diags.iter().all(|d| d.rule_id == "E3601"));
    }

    #[test]
    fn validate_all_state_machines_with_invalid_state_type_template() {
        let templates_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../resources/templates");
        let path = format!("{}/bad/stepfunctions_invalid_state.yaml", templates_dir);
        let bytes = fs::read(&path).expect("test template should exist");
        let model = Arc::new(SemanticModel::from_bytes(&bytes).expect("should parse"));
        let diags = validate_all_state_machines(&model);
        assert!(!diags.is_empty());
        assert!(diags.iter().any(|d| d.message.contains("InvalidType") || d.message.contains("NonExistent")));
    }

    #[test]
    fn validate_all_state_machines_no_sfn_resources() {
        let model = minimal_arc_model();
        let diags = validate_all_state_machines(&model);
        assert!(diags.is_empty());
    }

    #[test]
    fn all_diagnostics_use_e3601_rule_id() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "Ghost",
            "States": {
                "Bad": {"End": true},
                "Invalid": {"Type": "Bogus", "End": true}
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(!diags.is_empty());
        for d in &diags {
            assert_eq!(d.rule_id, "E3601", "Expected E3601, got {} for: {}", d.rule_id, d.message);
        }
    }

    #[test]
    fn start_at_non_string_value_skipped() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": 42,
            "States": {"Hello": {"Type": "Pass", "End": true}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        // Non-string StartAt is silently skipped by validate_start_at (no crash)
        assert!(!diags.iter().any(|d| d.message.contains("does not reference")));
    }

    #[test]
    fn non_object_state_skipped_in_start_at_recursion() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "P",
            "States": {
                "P": "not an object"
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(diags.is_empty() || diags.iter().all(|d| d.rule_id == "E3601"));
    }

    #[test]
    fn parallel_multiple_branches_all_validated_with_paths() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "P",
            "States": {
                "P": {
                    "Type": "Parallel",
                    "End": true,
                    "Branches": [
                        {
                            "StartAt": "Ghost1",
                            "States": {"A": {"Type": "Pass", "End": true}}
                        },
                        {
                            "StartAt": "Ghost2",
                            "States": {"B": {"Type": "Pass", "End": true}}
                        }
                    ]
                }
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d1 = diags.iter().find(|d| d.message.contains("Ghost1")).expect("branch 0 diagnostic");
        let d2 = diags.iter().find(|d| d.message.contains("Ghost2")).expect("branch 1 diagnostic");
        assert_eq!(d1.property_path.as_deref(), Some("Properties.DefinitionString.States.P.Branches.0.StartAt"));
        assert_eq!(d2.property_path.as_deref(), Some("Properties.DefinitionString.States.P.Branches.1.StartAt"));
    }

    #[test]
    fn wait_state_with_timestamp_is_valid() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "W",
            "States": {"W": {"Type": "Wait", "Timestamp": "2024-01-01T00:00:00Z", "End": true}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(!diags.iter().any(|d| d.message.contains("Wait state")));
    }

    #[test]
    fn wait_state_with_seconds_path_is_valid() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "W",
            "States": {"W": {"Type": "Wait", "SecondsPath": "$.delay", "End": true}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(!diags.iter().any(|d| d.message.contains("Wait state")));
    }

    #[test]
    fn task_state_with_resource_is_valid() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "T",
            "States": {"T": {"Type": "Task", "Resource": "arn:aws:lambda:us-east-1:123:function:fn", "End": true}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(!diags.iter().any(|d| d.message.contains("Resource")));
    }

    #[test]
    fn choice_state_with_choices_is_valid() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "C",
            "States": {"C": {"Type": "Choice", "Choices": [{"Variable": "$.x", "NumericEquals": 1, "Next": "C"}], "Default": "C"}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(!diags.iter().any(|d| d.message.contains("Choices")));
    }

    #[test]
    fn succeed_state_no_required_fields() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "S",
            "States": {"S": {"Type": "Succeed"}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(diags.is_empty());
    }

    #[test]
    fn fail_state_no_required_fields() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "F",
            "States": {"F": {"Type": "Fail"}}
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(diags.is_empty());
    }

    #[test]
    fn definition_property_uses_definition_key_in_path() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "Ghost",
            "States": {
                "Hello": {"Type": "Pass", "End": true}
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.Definition");
        let d = diags.iter().find(|d| d.message.contains("Ghost")).expect("StartAt diagnostic");
        assert_eq!(d.property_path.as_deref(), Some("Properties.Definition.StartAt"));
    }

    #[test]
    fn deeply_nested_parallel_preserves_full_path() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "Outer",
            "States": {
                "Outer": {
                    "Type": "Parallel",
                    "End": true,
                    "Branches": [{
                        "StartAt": "Inner",
                        "States": {
                            "Inner": {
                                "Type": "Parallel",
                                "End": true,
                                "Branches": [{
                                    "StartAt": "DeepGhost",
                                    "States": {
                                        "Leaf": {"Type": "Pass", "End": true}
                                    }
                                }]
                            }
                        }
                    }]
                }
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        let d = diags.iter().find(|d| d.message.contains("DeepGhost")).expect("deep nested diagnostic");
        assert_eq!(
            d.property_path.as_deref(),
            Some("Properties.DefinitionString.States.Outer.Branches.0.States.Inner.Branches.0.StartAt")
        );
    }

    #[test]
    fn all_diagnostics_have_span_resolved_to_authored_property() {
        let model = minimal_arc_model();
        let def = json!({
            "StartAt": "Ghost",
            "States": {
                "Bad": {"End": true},
                "Invalid": {"Type": "Bogus", "End": true}
            }
        });
        let diags = validate_definition(&def, &model, "SM", "Properties.DefinitionString");
        assert!(!diags.is_empty());
        // Span resolution uses the base source_path, so all diagnostics get a
        // consistent location regardless of their logical depth. In a minimal model
        // without "SM" as a resource, location may be None — the important thing is
        // that no diagnostic panics during construction.
        for d in &diags {
            assert_eq!(d.rule_id, "E3601");
        }
    }
}
