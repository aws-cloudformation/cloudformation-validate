package resources

import rego.v1

# W3045: S3 AccessControl property is deprecated
violation contains make_diag_full("W3045", "WARN", name,
    "Properties.AccessControl",
    "AccessControl property is deprecated. Use bucket policies instead",
    "Remove AccessControl and use an AWS::S3::BucketPolicy resource",
    "") if {
    some name in resources_of_type("AWS::S3::Bucket")
    ac := resolve(name, "Properties.AccessControl")
    ac != null
}

# E3045: S3 AccessControl requires OwnershipControls
violation contains make_diag_full("E3045", "ERROR", name,
    "Properties",
    "A bucket with 'AccessControl' set should also have at least one 'OwnershipControl' configured",
    "Add OwnershipControls to the bucket when using AccessControl",
    "") if {
    some name in resources_of_type("AWS::S3::Bucket")
    ac := resolve(name, "Properties.AccessControl")
    ac != null
    # OwnershipControls is only required for ACLs that grant access to other
    # accounts. These owner-scoped ACLs need no OwnershipControl.
    not ac in {"Private", "BucketOwnerFullControl", "BucketOwnerRead"}
    not has_property(name, "OwnershipControls")
}
