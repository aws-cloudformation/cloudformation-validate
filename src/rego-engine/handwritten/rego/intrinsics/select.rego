package intrinsics

import rego.v1

# E1050: Select index must be a non-negative integer
violation contains make_diag("F1050", "FATAL", name,
    "Fn::Select index must be a non-negative integer") if {
    cfn_rule_active("F1050")
    some name, res in input.resources
    some key, val in res.properties
    is_object(val)
    val["Fn::Select"]
    args := val["Fn::Select"]
    is_array(args)
    count(args) >= 1
    idx := args[0]
    is_number(idx)
    idx < 0
}
