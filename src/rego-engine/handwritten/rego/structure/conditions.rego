package structure

import rego.v1

# E8002: Condition referenced by a resource must be defined in the Conditions section.
violation contains make_diag("E8002", "ERROR", name,
    sprintf("Condition '%s' referenced by resource '%s' is not defined", [cond, name])) if {
    some name, res in input.resources
    cond := res.condition
    cond != null
    is_string(cond)
    not cond in object.keys(input.conditions)
}

# E8002: Condition referenced by an output must be defined in the Conditions section.
violation contains make_diag("E8002", "ERROR", "",
    sprintf("Condition '%s' referenced by output '%s' is not defined", [cond, name])) if {
    some name, out in input.outputs
    cond := out.condition
    cond != null
    is_string(cond)
    not cond in object.keys(input.conditions)
}
