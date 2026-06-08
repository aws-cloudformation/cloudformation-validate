package best_practices

import rego.v1

# W2010: NoEcho parameter used in resource Metadata
# Metadata is visible in the CloudFormation console, so NoEcho parameters
# should not be referenced there.
violation contains make_diag_full("W2010", "WARN", name, edge.sourcePath,
    sprintf("Don't use 'NoEcho' parameter '%s' in resource metadata", [target]),
    "Move the parameter reference out of Metadata or remove NoEcho",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.parameters)
    input.parameters[target].noEcho == true
    startswith(edge.sourcePath, "Metadata")
}
