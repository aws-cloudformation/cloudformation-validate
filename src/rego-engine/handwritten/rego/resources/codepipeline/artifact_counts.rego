package resources

import rego.v1

# E3702: CodePipeline action has too few input artifacts
violation contains make_diag("E3702", "ERROR", name,
    sprintf("Action '%s' (category '%s') has %d input artifacts, expected at least %d",
        [action_name, category, actual_in, expected.min_input])) if {
    some name in resources_of_type("AWS::CodePipeline::Pipeline")
    stages := resolve(name, "Properties.Stages")
    is_array(stages)
    some stage in stages
    is_object(stage)
    actions := object.get(stage, "Actions", [])
    is_array(actions)
    some action in actions
    is_object(action)
    action_name := object.get(action, "Name", "unknown")
    action_type_id := object.get(action, "ActionTypeId", {})
    category := object.get(action_type_id, "Category", "")
    expected := data.codepipeline_action_artifact_counts[category]
    actual_in := count(object.get(action, "InputArtifacts", []))
    actual_in < expected.min_input
}

# E3702: CodePipeline action has too many input artifacts
violation contains make_diag("E3702", "ERROR", name,
    sprintf("Action '%s' (category '%s') has %d input artifacts, expected at most %d",
        [action_name, category, actual_in, expected.max_input])) if {
    some name in resources_of_type("AWS::CodePipeline::Pipeline")
    stages := resolve(name, "Properties.Stages")
    is_array(stages)
    some stage in stages
    is_object(stage)
    actions := object.get(stage, "Actions", [])
    is_array(actions)
    some action in actions
    is_object(action)
    action_name := object.get(action, "Name", "unknown")
    action_type_id := object.get(action, "ActionTypeId", {})
    category := object.get(action_type_id, "Category", "")
    expected := data.codepipeline_action_artifact_counts[category]
    actual_in := count(object.get(action, "InputArtifacts", []))
    actual_in > expected.max_input
}

# E3702: CodePipeline action has too few output artifacts
violation contains make_diag("E3702", "ERROR", name,
    sprintf("Action '%s' (category '%s') has %d output artifacts, expected at least %d",
        [action_name, category, actual_out, expected.min_output])) if {
    some name in resources_of_type("AWS::CodePipeline::Pipeline")
    stages := resolve(name, "Properties.Stages")
    is_array(stages)
    some stage in stages
    is_object(stage)
    actions := object.get(stage, "Actions", [])
    is_array(actions)
    some action in actions
    is_object(action)
    action_name := object.get(action, "Name", "unknown")
    action_type_id := object.get(action, "ActionTypeId", {})
    category := object.get(action_type_id, "Category", "")
    expected := data.codepipeline_action_artifact_counts[category]
    actual_out := count(object.get(action, "OutputArtifacts", []))
    actual_out < expected.min_output
}
