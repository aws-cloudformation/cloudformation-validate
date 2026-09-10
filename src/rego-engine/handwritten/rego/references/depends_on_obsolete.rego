package references

import rego.v1

# W3005: DependsOn is unnecessary when an intrinsic function already creates a dependency
violation contains make_diag_full("W3005", "WARN", name,
    "DependsOn",
    sprintf("'%s' dependency already enforced by a '%s' at '%s'", [dep, edge.kind, edge.sourcePath]),
    "Remove the DependsOn entry",
    "") if {
    cfn_rule_active("W3005")
    some name, res in input.resources
    deps := res.dependsOn
    is_array(deps)
    some dep in deps
    is_string(dep)
    some edge in res.outgoingRefs
    edge.target == dep
    edge.kind in {"Ref", "GetAtt", "Sub"}
}
