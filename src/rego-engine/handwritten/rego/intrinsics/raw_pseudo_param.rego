package intrinsics

import rego.v1

violation contains make_diag_full("W1054", "WARN", name,
    entry.path,
    sprintf("Found a string '%s' that appears to be a pseudo parameter reference; use 'Ref: %s' instead", [entry.variable, entry.variable]),
    "Use Ref to reference pseudo parameters instead of embedding them as literal strings",
    "") if {
    cfn_rule_active("W1054")
    some name, res in input.resources
    some entry in res.rawPseudoParams
}
