# E5001: Module resources must not have CreationPolicy, UpdatePolicy, or Tags
package resources

import rego.v1

violation contains make_diag_at("E5001", "ERROR", name,
    "Properties.Tags",
    sprintf("Tags is not permitted within Module resource '%s'", [name])) if {
    some name in object.keys(input.resources)
    endswith(input.resources[name].resourceType, "::MODULE")
    has_property(name, "Tags")
}

violation contains make_diag_at("E5001", "ERROR", name,
    "CreationPolicy",
    sprintf("CreationPolicy is not permitted within Module resource '%s'", [name])) if {
    some name, res in input.resources
    endswith(res.resourceType, "::MODULE")
    res.creationPolicy != null
}

violation contains make_diag_at("E5001", "ERROR", name,
    "UpdatePolicy",
    sprintf("UpdatePolicy is not permitted within Module resource '%s'", [name])) if {
    some name, res in input.resources
    endswith(res.resourceType, "::MODULE")
    res.updatePolicy != null
}
