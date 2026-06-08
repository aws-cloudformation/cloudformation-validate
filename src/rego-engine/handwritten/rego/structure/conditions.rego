package structure

import rego.v1

# F8002: Condition referenced by a resource must be defined in the Conditions section.
violation contains make_diag("F8002", "FATAL", name,
    sprintf("Condition '%s' referenced by resource '%s' is not defined", [cond, name])) if {
    some name, res in input.resources
    cond := res.condition
    cond != null
    is_string(cond)
    not cond in object.keys(input.conditions)
}
