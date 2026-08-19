package resources

import rego.v1

# E3055: CreationPolicy is only valid on specific resource types
valid_creation_policy_types := {
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::CloudFormation::WaitCondition",
    "AWS::EC2::Instance",
    "AWS::AppStream::Fleet",
}

violation contains make_diag_full("E3055", "ERROR", name,
    "CreationPolicy",
    sprintf("CreationPolicy is not supported on resource type '%s'", [rtype]),
    sprintf("Remove CreationPolicy or change resource type to one of: %s", [concat(", ", valid_creation_policy_types)]),
    "") if {
    some name, res in input.resources
    status := lifecycle_attribute_status(name, "CreationPolicy")
    status.mayBePresent
    rtype := res.resourceType
    not rtype in valid_creation_policy_types
}

# E3016: UpdatePolicy is only valid on specific resource types
# Use set for membership testing; preserve the array order for messages.
_update_policy_types := {t | some t in data.rule_tables.update_policy_resource_types}

violation contains make_diag_full("E3016", "ERROR", name,
    "UpdatePolicy",
    sprintf("UpdatePolicy is not supported on resource type '%s'", [rtype]),
    sprintf("Remove UpdatePolicy or change resource type to one of: %s",
        [concat(", ", sort(data.rule_tables.update_policy_resource_types))]),
    "") if {
    some name, res in input.resources
    status := lifecycle_attribute_status(name, "UpdatePolicy")
    status.mayBePresent
    rtype := res.resourceType
    not rtype in _update_policy_types
}

violation contains make_diag_full("E3016", "ERROR", name,
    "UpdatePolicy",
    sprintf("%s is not of type 'object'", [status.invalidValue]),
    "",
    "") if {
    some name, res in input.resources
    rtype := res.resourceType
    rtype in _update_policy_types
    status := lifecycle_attribute_status(name, "UpdatePolicy")
    status.invalidValue != ""
}
