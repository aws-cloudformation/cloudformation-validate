package resources

import rego.v1

# Primary identifier uniqueness. Two resources collide only when a satisfiable
# deploy-time condition assignment gives them the same identifier simultaneously.

violation contains make_diag_at("E3019", "ERROR", resource_id,
    _e3019_path(identifier_properties),
    sprintf("Primary identifiers %s should have unique values across the resources %s",
        [_fmt_dict(identifier_properties, conflict.tuple), _fmt_set(conflict.resources)])) if {
    cfn_rule_active("E3019")
    resource_types := {resource.resourceType | some _, resource in input.resources}
    some resource_type in resource_types
    identifier_properties := data.primary_identifiers[resource_type]
    some conflict in primary_identifier_conflicts(resource_type, identifier_properties)
    some resource_id in conflict.resources
}

_e3019_path(identifier_properties) := sprintf("Properties.%s", [identifier_properties[0]]) if {
    count(identifier_properties) == 1
}

_e3019_path(identifier_properties) := "Properties" if {
    count(identifier_properties) != 1
}

_fmt_dict(identifier_properties, tuple) := out if {
    pairs := [sprintf("'%s': '%s'", [identifier_properties[i], tuple[i]]) | some i, _ in identifier_properties]
    out := sprintf("{%s}", [concat(", ", pairs)])
}

_fmt_set(names) := out if {
    sorted := sort([name | some name in names])
    quoted := [sprintf("'%s'", [name]) | some name in sorted]
    out := sprintf("{%s}", [concat(", ", quoted)])
}
