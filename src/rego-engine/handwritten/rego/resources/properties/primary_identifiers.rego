package resources

import rego.v1

# E3019: Primary identifier uniqueness. Two resources collide only when a
# satisfiable deploy-time condition assignment gives them the same primary
# identifier simultaneously — comparing per scenario rather than collapsing all
# Fn::If branches to a single representative value (which would invent
# duplicates that can never coexist). Matches cfn-lint.

violation contains make_diag_at("E3019", "ERROR", rname,
    _e3019_path(id_props),
    sprintf("Primary identifiers %s should have unique values across the resources %s",
        [_fmt_dict(id_props, tuple), _fmt_set(group)])) if {
    some rtype, id_props in data.primary_identifiers
    rids := resources_of_type(rtype)
    count(rids) > 1
    some tuple in _conflicting_tuples(rids, id_props)
    group := _group_for_tuple(rids, id_props, tuple)
    count(group) > 1
    some rname in group
}

# All identifier tuples on which at least two resources can collide.
_conflicting_tuples(rids, id_props) := {sa.tuple |
    some a in rids
    some b in rids
    a < b
    some sa in _id_scenarios(a, id_props)
    some sb in _id_scenarios(b, id_props)
    sa.tuple == sb.tuple
    _jointly_satisfiable(sa.assumptions, sb.assumptions)
}

# Resources whose scenarios can produce `tuple` together with at least one other.
_group_for_tuple(rids, id_props, tuple) := {r |
    some r in rids
    some other in rids
    r != other
    some sr in _id_scenarios(r, id_props)
    some so in _id_scenarios(other, id_props)
    sr.tuple == tuple
    so.tuple == tuple
    _jointly_satisfiable(sr.assumptions, so.assumptions)
}

# Enumerate a resource's primary-id scenarios as {tuple, assumptions}, where
# assumptions is the condition map producing the tuple plus the resource's own
# Condition. Only single-property identifiers are expanded across scenarios;
# multi-property identifiers fall back to the first scenario per property.
_id_scenarios(rid, id_props) := scenarios if {
    count(id_props) == 1
    prop := id_props[0]
    base := _resource_condition_map(rid)
    scenarios := {{"tuple": [val], "assumptions": object.union(base, s.conditions)} |
        some s in resolve_scenarios(rid, sprintf("Properties.%s", [prop]))
        s.value != null
        val := _to_str(s.value)
    }
}

_id_scenarios(rid, id_props) := scenarios if {
    count(id_props) != 1
    base := _resource_condition_map(rid)
    tuple := [v |
        some prop in id_props
        vals := {x | some x in resolve_all(rid, sprintf("Properties.%s", [prop])); x != null}
        count(vals) > 0
        sorted := sort([s | some s in vals])
        v := _to_str(sorted[0])
    ]
    count(tuple) == count(id_props)
    scenarios := {{"tuple": tuple, "assumptions": base}}
}

_resource_condition_map(rid) := {cond: true} if {
    cond := object.get(input.resources[rid], "condition", "")
    cond != ""
}

_resource_condition_map(rid) := {} if {
    object.get(input.resources[rid], "condition", "") == ""
}

_to_str(x) := x if is_string(x)
_to_str(x) := json.marshal(x) if not is_string(x)

# Two condition assignments coexist when they agree on shared conditions and the
# merged assignment is satisfiable.
_jointly_satisfiable(a, b) if {
    not _conflicting_maps(a, b)
    is_satisfiable(object.union(a, b))
}

_conflicting_maps(a, b) if {
    some k
    a[k] != b[k]
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
