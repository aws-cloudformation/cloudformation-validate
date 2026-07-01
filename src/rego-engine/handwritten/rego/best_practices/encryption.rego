package best_practices

import rego.v1

# W9008: RDS instance should have StorageEncrypted
violation contains make_diag_full("W9008", "WARN", name, "",
    "RDS instance should have StorageEncrypted set to true",
    "Set StorageEncrypted to true",
    "") if {
    some name in resources_of_type("AWS::RDS::DBInstance")
    not has_property(name, "StorageEncrypted")
}

# W9011: RDS instance PubliclyAccessible is true
violation contains make_diag_full("W9011", "WARN", name, "Properties.PubliclyAccessible",
    "RDS instance has PubliclyAccessible set to true - consider restricting access",
    "Set PubliclyAccessible to false",
    "") if {
    some name in resources_of_type("AWS::RDS::DBInstance")
    val := resolve(name, "Properties.PubliclyAccessible")
    val == true
}
