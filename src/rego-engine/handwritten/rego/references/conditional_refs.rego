package references

import rego.v1

# W1001: Reference to conditional resource that may not exist
violation contains make_diag_full("W1001", "WARN", source, edge.sourcePath,
    sprintf("Reference to '%s' which is conditional on '%s' - target may not exist",
        [target, target_cond]),
    "Add a Condition to the referencing resource that implies the target's condition",
    "") if {
    some source in object.keys(input.resources)
    some edge in input.resources[source].outgoingRefs
    edge.kind in {"Ref", "GetAtt"}
    # A reference that is itself a value inside an Fn::If branch is already
    # guarded by that Fn::If; the explicit branch choice makes it safe, so it is
    # not flagged.
    not _path_inside_fn_if_branch(edge.sourcePath)
    target := edge.target
    target in object.keys(input.resources)
    target_cond := resource_condition(target)
    target_cond != null
    source_cond := resource_condition(source)
    not condition_implies(source_cond, target_cond)
    # Don't flag if the reference is inside an Fn::If guarded by the target's condition
    not _edge_guarded_by(edge, source_cond, target_cond)
}

# True when a path segment "Fn::If" is immediately followed by branch index 1 or 2.
_path_inside_fn_if_branch(path) if {
    segs := split(path, ".")
    some i
    segs[i] == "Fn::If"
    segs[i + 1] in {"1", "2"}
}

# Reference is guarded if the enclosing Fn::If's true-branch condition,
# combined with the source resource's condition, implies the target's condition.
# conjunction_implies(source_cond, fn_if_cond, target_cond) = true when
# `AND(source_cond, fn_if_cond) ⟹ target_cond`.
_edge_guarded_by(edge, source_cond, target_cond) if {
    cc := object.get(edge, "conditionContext", "")
    cc != ""
    some part in split(cc, ",")
    part != ""
    conjunction_implies(source_cond, part, target_cond)
}

# W1001: Output reference to conditional resource that may not exist
violation contains make_diag_full("W1001", "WARN", out_name, edge.sourcePath,
    sprintf("Reference to '%s' which is conditional on '%s' - target may not exist",
        [target, target_cond]),
    "Add a Condition to the output that implies the target's condition",
    "") if {
    some edge in input.edges
    edge.kind in {"Ref", "GetAtt"}
    startswith(edge.source, "__output__")
    out_name := trim_prefix(edge.source, "__output__")
    target := edge.target
    target in object.keys(input.resources)
    target_cond := resource_condition(target)
    target_cond != null
    out_cond := object.get(input.outputs[out_name], "condition", null)
    not _output_condition_implies(out_cond, target_cond)
}

_output_condition_implies(out_cond, target_cond) if {
    out_cond != null
    condition_implies(out_cond, target_cond)
}
