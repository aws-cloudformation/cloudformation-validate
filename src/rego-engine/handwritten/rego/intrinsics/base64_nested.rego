package intrinsics

import rego.v1

# Fn::Base64 only accepts a string or a string-producing intrinsic. The set
# of valid nested intrinsics is captured at parse time in
# `res.base64DisallowedFunctions` — this rule surfaces those parser findings
# as a violation.
violation contains make_diag_at("E1059", "ERROR", name,
    entry.path,
    sprintf("Fn::Base64 does not support nested function '%s'", [entry.variable])) if {
    some name, res in input.resources
    some entry in res.base64DisallowedFunctions
}
