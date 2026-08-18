package resources

import rego.v1

# E3700: First stage of CodePipeline must contain a Source action.
# When exactly one action exists with a non-Source Category, anchor the
# diagnostic at that Category property for precise attribution. With
# multiple actions, no single action is uniquely at fault, so the
# stage object is the most defensible anchor.
violation contains make_diag_full("E3700", "ERROR", name,
    "Properties.Stages.0.Actions.0.ActionTypeId.Category",
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
    count(actions) == 1
    actions[0].ActionTypeId.Category
}

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
    not _single_action_with_category(actions)
}

_single_action_with_category(actions) if {
    count(actions) == 1
    actions[0].ActionTypeId.Category
}

any_source_action(actions) if {
    some action in actions
    action.ActionTypeId.Category == "Source"
}
