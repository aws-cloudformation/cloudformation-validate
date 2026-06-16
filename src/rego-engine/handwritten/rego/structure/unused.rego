package structure

import rego.v1

# W2001: Unused parameters (not referenced by any Ref/Sub)
violation contains make_diag("W2001", "WARN", "",
    sprintf("Parameter '%s' is not referenced anywhere in the template", [pname])) if {
    some pname in object.keys(input.parameters)
    not _param_referenced(pname)
}

_param_referenced(pname) if {
    some _, res in input.resources
    some edge in res.outgoingRefs
    edge.target == pname
    edge.kind in {"Ref", "Sub"}
}

_param_referenced(pname) if {
    some edge in input.edges
    edge.target == pname
    edge.kind in {"Ref", "Sub"}
}

_param_referenced(pname) if {
    some _, res in input.resources
    some sub in res.simpleSubs
    sub.variable == pname
}

# Parameter used in a condition (Fn::Equals references)
_param_referenced(pname) if {
    some edge in input.edges
    edge.target == pname
    edge.kind == "Condition"
}

_param_referenced(pname) if {
    some p in input.conditionParamRefs
    p == pname
}

# Parameter used in output
_param_referenced(pname) if {
    some _, out in input.outputs
    some edge in out.edges
    edge.target == pname
}

# Parameter used in SAM Globals section
_param_referenced(pname) if {
    some ref in object.get(input, "globalsParamRefs", [])
    ref == pname
}

# W8001: Unused conditions (not referenced by any resource Condition or Fn::If)
violation contains make_diag("W8001", "WARN", "",
    sprintf("Condition '%s' is not used by any resource or Fn::If", [cname])) if {
    some cname in object.keys(input.conditions)
    not _condition_used(cname)
}

_condition_used(cname) if {
    some _, res in input.resources
    res.condition == cname
}

_condition_used(cname) if {
    some _, out in input.outputs
    out.condition == cname
}

_condition_used(cname) if {
    some _, res in input.resources
    some c in res.conditionRefs
    c == cname
}

_condition_used(cname) if {
    some _, out in input.outputs
    some c in object.get(out, "conditionRefs", [])
    c == cname
}

# A condition referenced by ANY other condition's body (via `Condition: <name>`)
# is considered used. This matches cfn-lint's W8001 (conditions/Used.py), which
# collects every such in-Conditions-section reference regardless of whether the
# referencing condition is itself used.
_condition_used(cname) if {
    some other in object.keys(input.conditions)
    other != cname
    some dep in object.get(input.conditions[other], "deps", [])
    dep == cname
}

# W7001: Unused mappings (not referenced by any Fn::FindInMap)
violation contains make_diag("W7001", "WARN", "",
    sprintf("Mapping '%s' is not referenced by any Fn::FindInMap", [mname])) if {
    some mname in object.keys(input.mappings)
    not _mapping_used(mname)
}

_mapping_used(mname) if {
    some _, res in input.resources
    some ref_name in res.findInMapRefs
    ref_name == mname
}
