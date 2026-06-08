package resources

import rego.v1

# E3019: Primary identifier uniqueness. Matches cfn-lint's PrimaryIdentifiers rule:
# groups resources by their resolved primary-identifier value tuple and, for each
# group containing more than one resource, emits one diagnostic per resource in the
# group. Diagnostic message mirrors cfn-lint:
#   Primary identifiers {<dict>} should have unique values across the resources {<set>}

violation contains make_diag_at("E3019", "ERROR", rname,
    _e3019_path(id_props),
    sprintf("Primary identifiers %s should have unique values across the resources %s",
        [_fmt_dict(id_props, tuple), _fmt_set(group)])) if {
    some rtype, id_props in data.primary_identifiers
    rids := resources_of_type(rtype)
    count(rids) > 1
    some rname in rids
    tuple := _resource_tuple(rname, id_props)
    group := _group_with_tuple(rids, tuple, id_props)
    count(group) > 1
    not _all_conditions_mutex(group)
}

# Check if all resources in a group are behind mutually exclusive conditions
_all_conditions_mutex(group) if {
    # All resources must have a condition
    cond_set := {c | some r in group; c := object.get(input.resources[r], "condition", ""); c != ""}
    count(cond_set) == count(group)
    # Every pair of distinct conditions must be mutually exclusive
    not _any_compatible_pair(cond_set)
}

# True if any two distinct conditions in the set can coexist (are NOT exclusive)
_any_compatible_pair(cond_set) if {
    some a in cond_set
    some b in cond_set
    a < b
    not _conditions_exclusive(a, b)
}

# Two conditions are exclusive if they appear together in conditionExclusions
_conditions_exclusive(a, b) if {
    some pair in object.get(input, "conditionExclusions", [])
    {a, b} == {pair[0], pair[1]}
}

# Set of resources (from `rids`) whose primary-id tuple matches `target`.
_group_with_tuple(rids, target, id_props) := group if {
    group := {r | some r in rids; _resource_tuple(r, id_props) == target}
}

# Representative tuple for one resource. Per id prop, lexicographically smallest
# concrete non-null scenario; tuple undefined if any prop has no concrete value.
_resource_tuple(rid, id_props) := tuple if {
    tuple := [v |
        some prop in id_props
        vals := {x | some x in resolve_all(rid, sprintf("Properties.%s", [prop])); x != null}
        count(vals) > 0
        sorted := sort([s | some s in vals])
        v := sorted[0]
    ]
    count(tuple) == count(id_props)
}

_e3019_path(id_props) := sprintf("Properties.%s", [id_props[0]]) if count(id_props) == 1
_e3019_path(id_props) := "Properties" if count(id_props) != 1

_fmt_dict(id_props, tuple) := out if {
    pairs := [sprintf("'%s': '%s'", [id_props[i], tuple[i]]) | some i, _ in id_props]
    out := sprintf("{%s}", [concat(", ", pairs)])
}

_fmt_set(names) := out if {
    sorted := sort([n | some n in names])
    quoted := [sprintf("'%s'", [n]) | some n in sorted]
    out := sprintf("{%s}", [concat(", ", quoted)])
}
