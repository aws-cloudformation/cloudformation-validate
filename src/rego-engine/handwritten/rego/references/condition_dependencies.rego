package references

import rego.v1

# W2503: Reference to conditional resource with mutually exclusive condition
# Escalates W1001 to Warning when source and target conditions are mutex
violation contains make_diag_related("W2503", "WARN", source, edge.sourcePath,
    sprintf("Resource '%s' (condition '%s') references '%s' (condition '%s'), but these conditions are mutually exclusive - this reference will always fail",
        [source, source_cond, target, target_cond]),
    [{
        "resource": target,
        "path": "",
        "message": sprintf("Conditional resource '%s' (condition '%s')", [target, target_cond]),
    }]) if {
    some source in object.keys(input.resources)
    some edge in input.resources[source].outgoingRefs
    edge.kind in {"Ref", "GetAtt"}
    target := edge.target
    target in object.keys(input.resources)
    target_cond := resource_condition(target)
    target_cond != null
    source_cond := resource_condition(source)
    source_cond != null
    source_cond != target_cond
    not condition_implies(source_cond, target_cond)
    # conditions_compatible takes resource IDs, not condition names
    not conditions_compatible(source, target)
}

# W2502: DependsOn conditional resource without matching condition
violation contains make_diag_full("W2502", "WARN", source, "DependsOn",
    sprintf("Resource '%s' has DependsOn '%s' which is conditional (condition '%s'), but '%s' does not have a matching condition",
        [source, dep, target_cond, source]),
    sprintf("Add Condition: %s to resource '%s'", [target_cond, source]),
    "") if {
    some source in object.keys(input.resources)
    some dep in input.resources[source].dependsOn
    dep in object.keys(input.resources)
    target_cond := resource_condition(dep)
    target_cond != null
    source_cond := resource_condition(source)
    not condition_implies(source_cond, target_cond)
}
