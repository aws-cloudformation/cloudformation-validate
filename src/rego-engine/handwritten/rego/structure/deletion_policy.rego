package structure

import rego.v1

# F0018: UpdateReplacePolicy must be valid
_base_update_policies := {"Delete", "Retain"}
_snapshot_capable_update_types := {
    "AWS::DocDB::DBCluster",
    "AWS::EC2::Volume",
    "AWS::ElastiCache::CacheCluster",
    "AWS::ElastiCache::ReplicationGroup",
    "AWS::Neptune::DBCluster",
    "AWS::RDS::DBCluster",
    "AWS::RDS::DBInstance",
    "AWS::Redshift::Cluster"
}

violation contains make_diag_full("F0018", "FATAL", name, "UpdateReplacePolicy",
    sprintf("UpdateReplacePolicy must be one of Delete, Retain, Snapshot, got '%s'", [policy]),
    "", "") if {
    some name, res in input.resources
    res.resourceType in _snapshot_capable_update_types
    scenarios := lifecycle_policy_scenarios(name, "UpdateReplacePolicy")
    some policy in scenarios
    is_string(policy)
    not policy in (_base_update_policies | {"Snapshot"})
}

violation contains make_diag_full("F0018", "FATAL", name, "UpdateReplacePolicy",
    sprintf("UpdateReplacePolicy must be one of Delete, Retain, got '%s'", [policy]),
    "", "") if {
    some name, res in input.resources
    not res.resourceType in _snapshot_capable_update_types
    scenarios := lifecycle_policy_scenarios(name, "UpdateReplacePolicy")
    some policy in scenarios
    is_string(policy)
    not policy in _base_update_policies
}

# Resolved intrinsic markers remain potentially valid lifecycle policies. Plain
# composite/scalar non-string values can never be accepted policy names.
policy_value_shape(value) := "a list" if {
    is_array(value)
}

policy_value_shape(value) := "an object" if {
    is_object(value)
    not _is_resolved_intrinsic_marker(value)
}

policy_value_shape(value) := "a number" if {
    is_number(value)
}

policy_value_shape(value) := "a boolean" if {
    is_boolean(value)
}

policy_value_shape(value) := "null" if {
    is_null(value)
}

_is_resolved_intrinsic_marker(value) if {
    some key in {"__dynamic", "__ref", "__enum", "__conditional"}
    value[key]
}

violation contains make_diag_full("F0018", "FATAL", name, "UpdateReplacePolicy",
    sprintf("UpdateReplacePolicy must be one of Delete, Retain, Snapshot, got %s", [shape]),
    "", "") if {
    some name, res in input.resources
    res.resourceType in _snapshot_capable_update_types
    scenarios := lifecycle_policy_scenarios(name, "UpdateReplacePolicy")
    some policy in scenarios
    not is_string(policy)
    shape := policy_value_shape(policy)
}

violation contains make_diag_full("F0018", "FATAL", name, "UpdateReplacePolicy",
    sprintf("UpdateReplacePolicy must be one of Delete, Retain, got %s", [shape]),
    "", "") if {
    some name, res in input.resources
    not res.resourceType in _snapshot_capable_update_types
    scenarios := lifecycle_policy_scenarios(name, "UpdateReplacePolicy")
    some policy in scenarios
    not is_string(policy)
    shape := policy_value_shape(policy)
}
