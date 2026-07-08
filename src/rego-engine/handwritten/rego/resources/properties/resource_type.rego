package resources

import rego.v1

# F3006: Resource Type must be known. Only custom resources (`Custom::` prefix)
# and modules (`::MODULE` suffix) are exempt from the known-type set; every other
# type — including all AWS-namespaced types such as `AWS::Serverless::*` and
# `AWS::CloudFormation::*` — must be a recognized type. Valid transform/service
# types already appear in `known_resource_types`, so no namespace is exempted
# wholesale.
violation contains make_diag("F3006", "FATAL", name,
    sprintf("Unknown resource type '%s'", [rtype])) if {
    some name, res in input.resources
    rtype := res.resourceType
    is_string(rtype)
    rtype != ""
    not rtype in data.known_resource_types
    not startswith(rtype, "Custom::")
    not endswith(rtype, "::MODULE")
}
