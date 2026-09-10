package resources

import rego.v1

# W1053: Dynamic references should not contain spaces
# Detects strings like '{{ resolve:ssm:...}}' where spaces prevent resolution.
violation contains make_diag_full("W1053", "WARN", name,
    sprintf("Properties.%s", [prop]),
    sprintf("'%s' has spaces and will not be resolved as a dynamic reference. Remove spaces from '{{resolve:...}}'", [val]),
    "Remove spaces from the dynamic reference",
    "") if {
    cfn_rule_active("W1053")
    some name, res in input.resources
    some prop, val in res.properties
    is_string(val)
    contains(val, "resolve:")
    contains(val, "{{")
    contains(val, "}}")
    not contains(val, "{{resolve:")
}
