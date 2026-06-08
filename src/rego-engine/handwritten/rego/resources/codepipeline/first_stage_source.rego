package resources

import rego.v1

# E3700: First stage of CodePipeline must contain a Source action
violation contains make_diag_full("E3700", "ERROR", name,
    "Properties.Stages[0]",
    "First stage of a pipeline must contain at least one Source action",
    "Add an action with ActionTypeId.Category=Source to the first stage",
    "") if {
    some name in resources_of_type("AWS::CodePipeline::Pipeline")
    stages := resolve(name, "Properties.Stages")
    is_array(stages)
    count(stages) > 0
    first_stage := stages[0]
    is_object(first_stage)
    actions := object.get(first_stage, "Actions", [])
    is_array(actions)
    not any_source_action(actions)
}

any_source_action(actions) if {
    some action in actions
    action.ActionTypeId.Category == "Source"
}
