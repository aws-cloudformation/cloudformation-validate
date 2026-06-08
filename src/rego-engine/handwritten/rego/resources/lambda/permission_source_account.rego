package resources

import rego.v1

# W3663: Lambda Permission with S3 principal should have SourceAccount
violation contains make_diag_full("W3663", "WARN", name,
    "Properties",
    "Lambda Permission with S3 principal should specify SourceAccount to prevent confused deputy",
    "Add SourceAccount property",
    "") if {
    some name in resources_of_type("AWS::Lambda::Permission")
    principal := resolve(name, "Properties.Principal")
    is_string(principal)
    principal == "s3.amazonaws.com"
    sa := resolve(name, "Properties.SourceAccount")
    sa == null
}
