package resources

import rego.v1

# E3035: Array items with uniqueItems constraint must not have duplicates
# Checks common array properties that should have unique items
violation contains make_diag_at("W9007", "WARN", name,
    sprintf("Properties.%s", [prop_key]),
    sprintf("Array property '%s' contains duplicate values", [prop_key])) if {
    some name, res in input.resources
    some prop_key, prop_val in res.properties
    is_array(prop_val)
    count(prop_val) > 1
    prop_key in unique_array_properties
    count(prop_val) != count({v | some v in prop_val})
}

# Properties known to require unique items
unique_array_properties := {
    "AvailabilityZones",
    "SecurityGroupIds",
    "SecurityGroups",
    "SubnetIds",
    "Subnets",
    "RequiresCompatibilities",
    "PlacementConstraints"
}
