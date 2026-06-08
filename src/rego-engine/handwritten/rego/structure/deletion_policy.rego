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

violation contains make_diag("F0018", "FATAL", name,
    sprintf("UpdateReplacePolicy must be one of Delete, Retain, Snapshot, got '%s'", [val])) if {
    some name, res in input.resources
    val := res.updateReplacePolicy
    val != null
    is_string(val)
    res.resourceType in _snapshot_capable_update_types
    not val in (_base_update_policies | {"Snapshot"})
}

violation contains make_diag("F0018", "FATAL", name,
    sprintf("UpdateReplacePolicy must be one of Delete, Retain, got '%s'", [val])) if {
    some name, res in input.resources
    val := res.updateReplacePolicy
    val != null
    is_string(val)
    not res.resourceType in _snapshot_capable_update_types
    not val in _base_update_policies
}
