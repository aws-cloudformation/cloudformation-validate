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
    res.creationPolicy != null
    rtype := res.resourceType
    not rtype in valid_creation_policy_types
}

# E3016: UpdatePolicy is only valid on specific resource types
valid_update_policy_types := {
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::ElastiCache::ReplicationGroup",
    "AWS::OpenSearchService::Domain",
    "AWS::Elasticsearch::Domain",
    "AWS::Lambda::Alias",
    "AWS::AppStream::Fleet",
}

violation contains make_diag_full("E3016", "ERROR", name,
    "UpdatePolicy",
    sprintf("UpdatePolicy is not supported on resource type '%s'", [rtype]),
    sprintf("Remove UpdatePolicy or change resource type to one of: %s", [concat(", ", valid_update_policy_types)]),
    "") if {
    some name, res in input.resources
    res.updatePolicy != null
    rtype := res.resourceType
    not rtype in valid_update_policy_types
}
