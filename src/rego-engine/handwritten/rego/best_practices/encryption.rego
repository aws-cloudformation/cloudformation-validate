package best_practices

import rego.v1

_rds_storage_encryption_fields := [
    "Engine",
    "StorageEncrypted",
    "DBClusterIdentifier",
    "DBSnapshotIdentifier",
    "DBClusterSnapshotIdentifier",
    "SourceDBInstanceIdentifier",
    "SourceDbiResourceId",
    "SourceDBInstanceAutomatedBackupsArn",
    "SourceDBClusterIdentifier",
    "DBSecurityGroups",
]

_rds_inherited_encryption_fields := {
    "DBClusterIdentifier",
    "DBClusterSnapshotIdentifier",
    "SourceDBInstanceIdentifier",
    "SourceDbiResourceId",
    "SourceDBInstanceAutomatedBackupsArn",
    "SourceDBClusterIdentifier",
    "DBSecurityGroups",
}

_rds_encryption_is_inherited_or_ignored(properties) if {
    some field in _rds_inherited_encryption_fields
    object.get(properties, field, null) != null
}

_rds_encryption_is_inherited_or_ignored(properties) if {
    snapshot := object.get(properties, "DBSnapshotIdentifier", null)
    snapshot != null
    snapshot != ""
}

_rds_encryption_disabled(properties) if {
    object.get(properties, "StorageEncrypted", null) == null
}

_rds_encryption_disabled(properties) if {
    value := object.get(properties, "StorageEncrypted", null)
    coerce_to_bool(value) == false
}

_rds_custom_encryption_disabled(properties) if {
    value := object.get(properties, "StorageEncrypted", null)
    value != null
    coerce_to_bool(value) == false
}

_rds_storage_encryption_violation(properties, engine) if {
    not startswith(engine, "custom-")
    _rds_encryption_disabled(properties)
}

_rds_storage_encryption_violation(properties, engine) if {
    startswith(engine, "custom-")
    _rds_custom_encryption_disabled(properties)
}

# RDS instances must use storage encryption whenever the property controls the
# effective encryption mode. Cluster members, restores, replicas, Aurora,
# legacy DB security groups, and unknown values are handled conservatively.
violation contains make_diag_full("W9008", "WARN", name,
    "Properties.StorageEncrypted",
    "RDS instance should have StorageEncrypted set to true",
    "Set StorageEncrypted to true", "") if {
    cfn_rule_active("W9008")
    some name in resources_of_type("AWS::RDS::DBInstance")
    some scenario in properties_scenarios(name, _rds_storage_encryption_fields)
    is_satisfiable(scenario.conditions)
    properties := scenario.properties
    engine_value := object.get(properties, "Engine", null)
    is_string(engine_value)
    engine := lower(engine_value)
    not startswith(engine, "aurora")
    not _rds_encryption_is_inherited_or_ignored(properties)
    _rds_storage_encryption_violation(properties, engine)
}

# RDS instance PubliclyAccessible is true.
violation contains make_diag_full("W9011", "WARN", name, "Properties.PubliclyAccessible",
    "RDS instance has PubliclyAccessible set to true - consider restricting access",
    "Set PubliclyAccessible to false",
    "") if {
    cfn_rule_active("W9011")
    some name in resources_of_type("AWS::RDS::DBInstance")
    coerce_to_bool(resolve(name, "Properties.PubliclyAccessible")) == true
}
