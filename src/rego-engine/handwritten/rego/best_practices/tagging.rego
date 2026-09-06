package best_practices

import rego.v1

# I9040: Resource should have Tags when the resource type supports it
violation contains make_diag_full("I9040", "INFO", name, "Properties.Tags",
    sprintf("Resource '%s' of type '%s' supports Tags but none are configured", [name, res.resourceType]),
    "Add Tags to improve resource organization and cost tracking",
    "") if {
    cfn_rule_active("I9040")
    some name, res in input.resources
    not endswith(res.resourceType, "::MODULE")
    _type_supports_tags(res.resourceType)
    _resource_missing_tags(name)
}

_type_supports_tags(rtype) if {
    "Tags" in schema_properties(rtype)
}

_resource_missing_tags(name) if {
    some scenario in properties_scenarios(name, ["Tags"])
    _tag_scenario_reachable(name, scenario.conditions)
    object.get(scenario.properties, "Tags", null) == null
}

_tag_scenario_reachable(name, conditions) if {
    resource_condition := object.get(input.resources[name], "condition", "")
    resource_condition == ""
    is_satisfiable(conditions)
}

_tag_scenario_reachable(name, conditions) if {
    resource_condition := object.get(input.resources[name], "condition", "")
    resource_condition != ""
    object.get(conditions, resource_condition, true) == true
    is_satisfiable(object.union(conditions, {resource_condition: true}))
}
