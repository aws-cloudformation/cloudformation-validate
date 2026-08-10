package best_practices

import rego.v1

# I3011: Stateful resources should have explicit DeletionPolicy and UpdateReplacePolicy
# Data-driven from stateful_resource_types.json (loaded via data.stateful_resource_types)
# Excludes S3::Bucket which has DeleteRequiresEmptyResource

_i3011_excluded := {"AWS::S3::Bucket"}

violation contains make_diag("I3011", "INFO", name,
    "'DeletionPolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)") if {
    some name, res in input.resources
    res.resourceType in data.stateful_resource_types
    not res.resourceType in _i3011_excluded
    res.deletionPolicy == null
}

violation contains make_diag("I3011", "INFO", name,
    "'UpdateReplacePolicy' is a required property (The default action when replacing/removing a resource is to delete it. Set explicit values for stateful resource)") if {
    some name, res in input.resources
    res.resourceType in data.stateful_resource_types
    not res.resourceType in _i3011_excluded
    res.updateReplacePolicy == null
}
