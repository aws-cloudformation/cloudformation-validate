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
    sprintf("UpdateReplacePolicy must be one of Delete, Retain, Snapshot, got '%s'", [val]), "", "") if {
    some name, res in input.resources
    val := res.updateReplacePolicy
    val != null
    is_string(val)
    res.resourceType in _snapshot_capable_update_types
    not val in (_base_update_policies | {"Snapshot"})
}

violation contains make_diag_full("F0018", "FATAL", name, "UpdateReplacePolicy",
    sprintf("UpdateReplacePolicy must be one of Delete, Retain, got '%s'", [val]), "", "") if {
    some name, res in input.resources
    val := res.updateReplacePolicy
    val != null
    is_string(val)
    not res.resourceType in _snapshot_capable_update_types
    not val in _base_update_policies
}

# How a non-string policy value is described, or nothing when it is legal. A
# list or a plain object can never be a policy. A resolved-intrinsic marker is
# never reported: CloudFormation accepts Ref, Fn::If, Fn::FindInMap, Fn::Sub,
# and Fn::Select in these attributes, and the resolved form no longer says
# which function was written.
policy_value_shape(val) := "a list" if {
    is_array(val)
}

policy_value_shape(val) := "an object" if {
    is_object(val)
    not _is_resolved_intrinsic_marker(val)
}

policy_value_shape(val) := "a number" if {
    is_number(val)
}

policy_value_shape(val) := "a boolean" if {
    is_boolean(val)
}

_is_resolved_intrinsic_marker(val) if {
    some key in {"__dynamic", "__ref", "__enum", "__conditional"}
    val[key]
}

violation contains make_diag_full("F0018", "FATAL", name, "UpdateReplacePolicy",
    sprintf("UpdateReplacePolicy must be one of Delete, Retain, Snapshot, got %s", [shape]), "", "") if {
    some name, res in input.resources
    val := res.updateReplacePolicy
    val != null
    not is_string(val)
    res.resourceType in _snapshot_capable_update_types
    shape := policy_value_shape(val)
}

violation contains make_diag_full("F0018", "FATAL", name, "UpdateReplacePolicy",
    sprintf("UpdateReplacePolicy must be one of Delete, Retain, got %s", [shape]), "", "") if {
    some name, res in input.resources
    val := res.updateReplacePolicy
    val != null
    not is_string(val)
    not res.resourceType in _snapshot_capable_update_types
    shape := policy_value_shape(val)
}
