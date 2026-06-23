package intrinsics

import rego.v1

# Select index must be a non-negative integer — CloudFormation rejects
# negative indices on deploy.
violation contains make_diag("E1017", "ERROR", name,
    "Fn::Select index must be a non-negative integer") if {
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
