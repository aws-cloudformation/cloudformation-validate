package resources

import rego.v1

_snapstart_apply_on_path := "Properties.SnapStart.ApplyOn"

# SnapStart only takes effect on a published function version. Each reachable
# scenario that enables it is reported at its authored ApplyOn value unless a
# version publishing the function can be created in that same scenario.
violation contains make_diag_at_source_full("W2530", "WARN", name, _snapstart_apply_on_path, source_path,
    "SnapStart is enabled but no AWS::Lambda::Version resource is attached",
    "Add an AWS::Lambda::Version resource that references this function",
) if {
    cfn_rule_active("W2530")
    some name in resources_of_type("AWS::Lambda::Function")
    some scenario in resolve_scenarios(name, _snapstart_apply_on_path)
    scenario.value == "PublishedVersions"
    _resource_scenario_reachable(name, scenario.conditions)
    not _snapstart_version_compatible(name, scenario.conditions)
    source_path := scenario_source_path(name, _snapstart_apply_on_path, scenario.conditions)
}

_snapstart_version_compatible(func_name, conditions) if {
    some version_conditions in _snapstart_published_version_scenarios(func_name)
    _scenario_conditions_compatible(func_name, conditions, version_conditions)
}

# The condition assignments under which an AWS::Lambda::Version publishes a
# version of the function: the version is created and its FunctionName refers
# to the function. A reference from anywhere else in a version, such as
# DependsOn or Description, publishes nothing.
_snapstart_published_version_scenarios(func_name) :=
    _snapstart_reference_version_scenarios(func_name) | _snapstart_named_version_scenarios(func_name)

_snapstart_reference_version_scenarios(func_name) := {conditions |
    some version_name in resources_of_type("AWS::Lambda::Version")
    some edge in input.resources[version_name].outgoingRefs
    edge.target == func_name
    regex.match(`^Properties(\.Fn::If\.[12])*\.FunctionName(\.|$)`, edge.sourcePath)
    conditions := _snapstart_reference_activation_conditions(version_name, edge)
}

_snapstart_named_version_scenarios(func_name) := {conditions |
    function_name_identity := value_identity(func_name, "Properties.FunctionName")
    some version_name in resources_of_type("AWS::Lambda::Version")
    value_identity(version_name, "Properties.FunctionName") == function_name_identity
    conditions := {literal[0]: literal[1] | some literal in _snapstart_creation_literals(version_name)}
}

# The conditions under which a reference is active: the Fn::If branches it is
# authored in and the condition that creates its resource. Undefined when they
# contradict each other, so the reference is never active.
_snapstart_reference_activation_conditions(resource_name, edge) := conditions if {
    literals := _snapstart_branch_literals(edge) | _snapstart_creation_literals(resource_name)
    count({literal[0] | some literal in literals}) == count(literals)
    conditions := {literal[0]: literal[1] | some literal in literals}
}

# A reference's branch context lists the Fn::If conditions enclosing it,
# separated by commas, with a false branch marked by a leading "!".
_snapstart_branch_literals(edge) := {[condition, value] |
    some literal in split(object.get(edge, "conditionContext", ""), ",")
    literal != ""
    condition := trim_prefix(literal, "!")
    value := literal == condition
}

_snapstart_creation_literals(resource_name) := {[condition, true]} if {
    condition := resource_condition(resource_name)
    condition != null
} else := set()
