package resources

import rego.v1

# E3636: CodeBuild S3 source location must be in bucket/key format
violation contains make_diag_full("E3636", "ERROR", name,
    "Properties.Source.Location",
    sprintf("CodeBuild S3 source location '%s' must be in 'bucket/key' format", [loc]),
    "Use format: my-bucket/path/to/source.zip",
    "") if {
    cfn_rule_active("E3636")
    some name in resources_of_type("AWS::CodeBuild::Project")
    src_type := resolve(name, "Properties.Source.Type")
    src_type == "S3"
    loc := resolve(name, "Properties.Source.Location")
    is_string(loc)
    not contains(loc, "/")
}
