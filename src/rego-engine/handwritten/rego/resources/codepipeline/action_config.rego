package resources

import rego.v1

# E3703: CodePipeline action TemplatePath must reference an InputArtifact
violation contains make_diag_full("E3703", "ERROR", name,
    sprintf("Properties.Stages[%d].Actions[%d].Configuration.TemplatePath", [si, ai]),
    sprintf("TemplatePath artifact '%s' is not one of the InputArtifacts", [artifact_name]),
    "Use an artifact name from InputArtifacts as the prefix of TemplatePath",
    "") if {
    some name in resources_of_type("AWS::CodePipeline::Pipeline")
    stages := resolve(name, "Properties.Stages")
    is_array(stages)
    some si, stage in stages
    actions := object.get(stage, "Actions", [])
    is_array(actions)
    some ai, action in actions
    config := object.get(action, "Configuration", {})
    is_object(config)
    tp := object.get(config, "TemplatePath", null)
    is_string(tp)
    contains(tp, "::")
    artifact_name := split(tp, "::")[0]
    input_artifacts := object.get(action, "InputArtifacts", [])
    is_array(input_artifacts)
    input_names := {ia.Name | some ia in input_artifacts; is_object(ia); ia.Name}
    not artifact_name in input_names
}
