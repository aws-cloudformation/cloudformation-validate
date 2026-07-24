package best_practices

import rego.v1

# W9008: RDS instance should have StorageEncrypted
# Skipped for cluster-member instances (DBClusterIdentifier present): per the
# CloudFormation reference, StorageEncrypted is "Not applicable" there because
# encryption is managed by the DB cluster.
violation contains make_diag_full("W9008", "WARN", name, "",
    "RDS instance should have StorageEncrypted set to true",
    "Set StorageEncrypted to true",
    "") if {
    some name in resources_of_type("AWS::RDS::DBInstance")
    not has_property(name, "StorageEncrypted")
    not has_property(name, "DBClusterIdentifier")
}

# W9011: RDS instance PubliclyAccessible is true
violation contains make_diag_full("W9011", "WARN", name, "Properties.PubliclyAccessible",
    "RDS instance has PubliclyAccessible set to true - consider restricting access",
    "Set PubliclyAccessible to false",
    "") if {
    some name in resources_of_type("AWS::RDS::DBInstance")
    coerce_to_bool(resolve(name, "Properties.PubliclyAccessible")) == true
}
