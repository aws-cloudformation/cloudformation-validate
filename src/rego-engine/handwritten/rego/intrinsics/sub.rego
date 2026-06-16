package intrinsics

import rego.v1

# `pseudo_parameters` is defined in pseudo_params.rego (shared across this package).

violation contains make_diag("F1018", "FATAL", name,
    sprintf("Fn::Sub variable '${%s}' does not reference a valid resource, parameter, or pseudo-parameter", [target])) if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Sub"
    target := edge.target
    not target in object.keys(input.resources)
    not target in object.keys(input.parameters)
    not target in pseudo_parameters
}
