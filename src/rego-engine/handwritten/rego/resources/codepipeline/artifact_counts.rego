package resources

import rego.v1

# Artifact-count constraints are keyed on the full Owner/Category/Provider tuple.
# A category alone is ambiguous (e.g. AWS/Deploy/CloudFormation allows 0 input
# artifacts while AWS/Deploy/CodeDeploy requires 1), so the key joins all three.
_artifact_key(action_type_id) := key if {
    owner := object.get(action_type_id, "Owner", "")
    category := object.get(action_type_id, "Category", "")
    provider := object.get(action_type_id, "Provider", "")
    owner != ""
    category != ""
    provider != ""
    key := sprintf("%s/%s/%s", [owner, category, provider])
}

# E3702: CodePipeline action has too few input artifacts
violation contains make_diag("E3702", "ERROR", name,
    sprintf("Action '%s' (%s) has %d input artifacts, expected at least %d",
        [action_name, key, actual_in, expected.min_input])) if {
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
    key := _artifact_key(action_type_id)
    expected := data.codepipeline_action_artifact_counts[key]
    actual_in := count(object.get(action, "InputArtifacts", []))
    actual_in < expected.min_input
}

# E3702: CodePipeline action has too many input artifacts
violation contains make_diag("E3702", "ERROR", name,
    sprintf("Action '%s' (%s) has %d input artifacts, expected at most %d",
        [action_name, key, actual_in, expected.max_input])) if {
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
    key := _artifact_key(action_type_id)
    expected := data.codepipeline_action_artifact_counts[key]
    actual_in := count(object.get(action, "InputArtifacts", []))
    actual_in > expected.max_input
}

# E3702: CodePipeline action has too few output artifacts
violation contains make_diag("E3702", "ERROR", name,
    sprintf("Action '%s' (%s) has %d output artifacts, expected at least %d",
        [action_name, key, actual_out, expected.min_output])) if {
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
    key := _artifact_key(action_type_id)
    expected := data.codepipeline_action_artifact_counts[key]
    actual_out := count(object.get(action, "OutputArtifacts", []))
    actual_out < expected.min_output
}

# E3702: CodePipeline action has too many output artifacts
violation contains make_diag("E3702", "ERROR", name,
    sprintf("Action '%s' (%s) has %d output artifacts, expected at most %d",
        [action_name, key, actual_out, expected.max_output])) if {
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
    key := _artifact_key(action_type_id)
    expected := data.codepipeline_action_artifact_counts[key]
    actual_out := count(object.get(action, "OutputArtifacts", []))
    actual_out > expected.max_output
}
