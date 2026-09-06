package intrinsics

import rego.v1

# I1022: Prefer Fn::Sub over Fn::Join with empty delimiter
violation contains make_diag_full("I1022", "INFO", name,
    path,
    "Prefer using Fn::Sub over Fn::Join with an empty delimiter",
    "", "") if {
    cfn_rule_active("I1022")
    some name, res in input.resources
    some path in res.emptyJoins
}

violation contains make_diag_full("I1022", "INFO", "",
    path,
    "Prefer using Fn::Sub over Fn::Join with an empty delimiter",
    "", "") if {
    cfn_rule_active("I1022")
    some path in input.outputEmptyJoins
}
