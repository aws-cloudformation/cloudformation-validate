package references

import rego.v1

# F3004 (circular dependency) is emitted by template-model's cycle detector;
# keeping it out of rego prevents duplicate findings with divergent messages.

# E3005: DependsOn target must exist. A dynamic reference cannot name a
# resource - DependsOn takes literal logical IDs only - so its message says
# that rather than implying a resource of that name could be added.
violation contains make_diag_full("E3005", "ERROR", name, dep_path,
    sprintf("DependsOn target '%s' does not exist as a resource", [dep]),
    "", "") if {
    some name, res in input.resources
    some dep in res.dependsOn
    not dep in object.keys(input.resources)
    not dep in object.get(input, "samImplicitResources", [])
    not contains(dep, "{{resolve:")
    some dep_path in authored_depends_on_paths(res, dep)
}

violation contains make_diag_full("E3005", "ERROR", name, dep_path,
    sprintf("DependsOn must be a resource logical ID, not a dynamic reference: '%s'", [dep]),
    "", "") if {
    some name, res in input.resources
    some dep in res.dependsOn
    not dep in object.keys(input.resources)
    not dep in object.get(input, "samImplicitResources", [])
    contains(dep, "{{resolve:")
    some dep_path in authored_depends_on_paths(res, dep)
}

# E3005: DependsOn target is conditional and may not exist
# If resource A has DependsOn: B, and B has a condition, then A's condition
# must imply B's condition - otherwise B may not exist when A is created.
violation contains make_diag_full("E3005", "ERROR", name, dep_path,
    sprintf("'%s' will not exist when condition '%s' is False", [dep, dep_cond]),
    sprintf("Add a Condition to '%s' that implies '%s'", [name, dep_cond]),
    "") if {
    some name, res in input.resources
    some dep in res.dependsOn
    dep in object.keys(input.resources)
    dep_cond := resource_condition(dep)
    dep_cond != null
    source_cond := resource_condition(name)
    not condition_implies(source_cond, dep_cond)
    some dep_path in authored_depends_on_paths(res, dep)
}

authored_depends_on_paths(res, dependency) := {edge.sourcePath |
    some edge in res.outgoingRefs
    edge.kind == "DependsOn"
    edge.target == dependency
}
