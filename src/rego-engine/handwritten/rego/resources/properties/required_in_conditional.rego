package resources

import rego.v1

violation contains make_diag_at_source_conditional("E3024", "ERROR", name,
    property_path,
    source_path,
    "'Key' is a required property",
    "Tag Key cannot be null or AWS::NoValue",
    scenario.conditions,
) if {
    cfn_rule_active("E3024")
    some name, res in input.resources
    "Tags" in schema_properties(res.resourceType)
    some scenario in list_object_missing_required_field_scenarios(name, "Properties.Tags", "Key", "Value")
    property_path := sprintf("Properties.Tags.%d", [scenario.index])
    source_path := scenario_source_path(name, property_path, scenario.conditions)
}

violation contains make_diag_at_source_conditional("E3024", "ERROR", name,
    "Properties.Tags",
    source_path,
    "Tag keys must be unique",
    "Use a different Key for each tag",
    conditions,
) if {
    cfn_rule_active("E3024")
    some name, res in input.resources
    "Tags" in schema_properties(res.resourceType)
    conditions := duplicate_object_field_value_scenario(name, "Properties.Tags", "Key")
    source_path := scenario_source_path(name, "Properties.Tags", conditions)
}
