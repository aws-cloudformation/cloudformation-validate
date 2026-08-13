package resources

import rego.v1

_resource_scenario_reachable(name, conditions) if {
    resource_condition := object.get(input.resources[name], "condition", "")
    resource_condition == ""
    is_satisfiable(conditions)
}

_resource_scenario_reachable(name, conditions) if {
    resource_condition := object.get(input.resources[name], "condition", "")
    resource_condition != ""
    object.get(conditions, resource_condition, true) == true
    is_satisfiable(object.union(conditions, {resource_condition: true}))
}

_scenario_conditions_compatible(name, left, right) if {
    every condition, value in left {
        object.get(right, condition, value) == value
    }
    _resource_scenario_reachable(name, object.union(left, right))
}
