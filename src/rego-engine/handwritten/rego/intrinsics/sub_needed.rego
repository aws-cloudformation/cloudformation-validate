package intrinsics

import rego.v1

# E1029: Sub needed — ${Variable} in strings outside Fn::Sub
violation contains make_diag_full("F1029", "FATAL", name,
    entry.path,
    sprintf("Found an embedded parameter \"%s\" outside of an \"Fn::Sub\" at %s", [entry.variable, entry.path]),
    "Wrap the string with Fn::Sub",
    "") if {
    some name, res in input.resources
    some entry in res.unsubstitutedVariables
}
