package references

import rego.v1

# F3004 (circular dependency) is emitted by template-model's cycle detector;
# keeping it out of rego prevents duplicate findings with divergent messages.

# E3005: DependsOn target must exist
violation contains make_diag("E3005", "ERROR", name,
    sprintf("DependsOn target '%s' does not exist as a resource", [dep])) if {
    some name in object.keys(input.resources)
    some dep in input.resources[name].dependsOn
    not dep in object.keys(input.resources)
    not dep in object.get(input, "samImplicitResources", [])
}

# E3005: DependsOn target is conditional and may not exist
# If resource A has DependsOn: B, and B has a condition, then A's condition
# must imply B's condition - otherwise B may not exist when A is created.
violation contains make_diag_full("E3005", "ERROR", name, "DependsOn",
    sprintf("'%s' will not exist when condition '%s' is False", [dep, dep_cond]),
    sprintf("Add a Condition to '%s' that implies '%s'", [name, dep_cond]),
    "") if {
    some name in object.keys(input.resources)
    some dep in input.resources[name].dependsOn
    dep in object.keys(input.resources)
    dep_cond := resource_condition(dep)
    dep_cond != null
    source_cond := resource_condition(name)
    not condition_implies(source_cond, dep_cond)
}
