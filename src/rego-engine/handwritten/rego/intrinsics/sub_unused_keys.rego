package intrinsics

import rego.v1

violation contains make_diag_full("W1019", "WARN", name,
    entry.path,
    sprintf("Parameter '%s' not used in Fn::Sub template string", [entry.variable]),
    "Remove the unused key from the Fn::Sub variable map or reference it in the template string",
    "") if {
    cfn_rule_active("W1019")
    some name, res in input.resources
    some entry in res.unusedSubKeys
}
