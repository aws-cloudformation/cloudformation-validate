package intrinsics

import rego.v1

# A property value that is *exactly* a pseudo-parameter name (e.g. the whole
# string is `"AWS::Region"`) is NOT substituted by CloudFormation — only
# `{Ref: AWS::Region}` resolves. This typically indicates a forgotten Fn::Sub
# wrapper or a missing Ref, so we surface it as a warning. Matching cfn-lint's
# RawPseudoParameter (W1054), the comparison is exact equality, not substring.
violation contains make_diag_full("W1054", "WARN", name,
    sprintf("Properties.%s", [prop]),
    sprintf("String value '%s' is the pseudo-parameter '%s' used as a literal — use Ref to resolve it instead", [val, pseudo]),
    sprintf("Use {Ref: %s} instead of the literal string", [pseudo]),
    "") if {
    some name, res in input.resources
    some prop, val in res.properties
    is_string(val)
    some pseudo in pseudo_parameters
    val == pseudo
    # Dynamic-reference substrings are deploy-time-resolved; the pseudo-param
    # name they contain is part of the resolution pattern, not authored text.
    not contains(val, "{{resolve:")
}
