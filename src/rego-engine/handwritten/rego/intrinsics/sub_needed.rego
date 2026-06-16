package intrinsics

import rego.v1

# A `${Variable}` substring appearing in any string outside an Fn::Sub is
# treated as a literal by CloudFormation — the substitution placeholder
# requires Fn::Sub. The parser collects these unsubstituted variables;
# this rule surfaces them as a violation so authors know the value will
# not be interpolated at deploy time.
violation contains make_diag_full("E1029", "ERROR", name,
    entry.path,
    sprintf("Found an embedded parameter \"%s\" outside of an \"Fn::Sub\" at %s", [entry.variable, entry.path]),
    "Wrap the string with Fn::Sub",
    "") if {
    some name, res in input.resources
    some entry in res.unsubstitutedVariables
}
