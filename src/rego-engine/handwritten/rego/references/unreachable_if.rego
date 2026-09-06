package references

import rego.v1

# W1028: Fn::If branch cannot be reached (resources)
violation contains make_diag_full("W1028", "WARN", branch.resourceId, branch.path,
    branch.message, "", "") if {
    cfn_rule_active("W1028")
    some name in object.keys(input.resources)
    some branch in unreachable_if_branches(name)
}

# W1028: Fn::If branch cannot be reached (outputs)
violation contains make_diag_full("W1028", "WARN", branch.resourceId, branch.path,
    branch.message, "", "") if {
    cfn_rule_active("W1028")
    some name in object.keys(input.outputs)
    some branch in unreachable_if_branches(sprintf("__output__%s", [name]))
}
