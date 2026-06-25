package structure

import rego.v1

# W2001: Unused parameters (not referenced by any Ref/Sub). A transform can
# reference parameters opaquely before expansion, so the check is suppressed
# whenever any transform is present.
violation contains make_diag("W2001", "WARN", "",
    sprintf("Parameter '%s' is not referenced anywhere in the template", [pname])) if {
    count(object.get(input.template, "transforms", [])) == 0
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

# Referenced by any Fn::If anywhere in the template (captured pre-resolution so
# deeply nested conditionals are not lost).
_condition_used(cname) if {
    some c in object.get(input, "fnIfConditions", [])
    c == cname
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

# A condition referenced by another condition (via Fn::And/Or/Not Condition
# entries) counts as used, independent of whether that other condition is itself
# used. This mirrors how an unreferenced wrapper condition does not make the
# conditions it nests appear unused.
_condition_used(cname) if {
    some other in object.keys(input.conditions)
    other != cname
    some dep in object.get(input.conditions[other], "deps", [])
    dep == cname
}

# W7001: Unused mappings (not referenced by any Fn::FindInMap).
# A FindInMap with a non-literal map name (e.g. a nested FindInMap) makes it
# impossible to attribute usage to a specific mapping, so the check is disabled
# entirely — matching cfn-lint's W7001. Otherwise a mapping is "used" when its
# name is the literal first argument of any Fn::FindInMap anywhere in the
# template, which findInMapNames collects template-wide.
violation contains make_diag("W7001", "WARN", "",
    sprintf("Mapping '%s' is not referenced by any Fn::FindInMap", [mname])) if {
    not object.get(input, "hasDynamicFindinmapName", false)
    some mname in object.keys(input.mappings)
    not _mapping_used(mname)
}

_mapping_used(mname) if {
    some ref_name in object.get(input, "findInMapNames", [])
    ref_name == mname
}
