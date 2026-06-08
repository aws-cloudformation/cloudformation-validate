package resources

import rego.v1

# E9001: Resource Type must be known
violation contains make_diag("E9001", "ERROR", name,
    sprintf("Unknown resource type '%s'", [rtype])) if {
    some name, res in input.resources
    rtype := res.resourceType
    is_string(rtype)
    not rtype in data.known_resource_types
    not startswith(rtype, "Custom::")
    not rtype == "AWS::CloudFormation::CustomResource"
    not startswith(rtype, "AWS::Serverless::")
    not endswith(rtype, "::MODULE")
    not contains(rtype, "::MODULE")
    not rtype == ""
}
