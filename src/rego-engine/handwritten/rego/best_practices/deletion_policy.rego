package best_practices

import rego.v1

# I3011: Stateful resources should have explicit DeletionPolicy and UpdateReplacePolicy
# Data-driven from stateful_resource_types.json (loaded via data.stateful_resource_types)
# Excludes S3::Bucket which has DeleteRequiresEmptyResource

_i3011_excluded := {"AWS::S3::Bucket"}

# A serverless resource deploys as its transformed CloudFormation type;
# statefulness follows the deployed type, not the shorthand.
_i3011_effective_type(rtype) := "AWS::DynamoDB::Table" if {
    rtype == "AWS::Serverless::SimpleTable"
}

_i3011_effective_type(rtype) := "AWS::CloudFormation::Stack" if {
    rtype == "AWS::Serverless::Application"
}

_i3011_effective_type(rtype) := rtype if {
    not rtype in {"AWS::Serverless::SimpleTable", "AWS::Serverless::Application"}
}

violation contains make_diag("I3011", "INFO", name,
    "'DeletionPolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)") if {
    some name, res in input.resources
    effective := _i3011_effective_type(res.resourceType)
    effective in data.stateful_resource_types
    not effective in _i3011_excluded
    res.deletionPolicy == null
}

violation contains make_diag("I3011", "INFO", name,
    "'UpdateReplacePolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)") if {
    some name, res in input.resources
    effective := _i3011_effective_type(res.resourceType)
    effective in data.stateful_resource_types
    not effective in _i3011_excluded
    res.updateReplacePolicy == null
}
