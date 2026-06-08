package intrinsics

import rego.v1

# I1022: Prefer Fn::Sub over Fn::Join with empty delimiter
violation contains make_diag_full("I1022", "INFO", name,
    path,
    "Prefer using Fn::Sub over Fn::Join with an empty delimiter",
    "", "") if {
    some name, res in input.resources
    some path in res.emptyJoins
}

violation contains make_diag_full("I1022", "INFO", "",
    path,
    "Prefer using Fn::Sub over Fn::Join with an empty delimiter",
    "", "") if {
    some path in input.outputEmptyJoins
}
