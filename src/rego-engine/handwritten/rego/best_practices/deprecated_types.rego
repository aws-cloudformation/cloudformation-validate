package best_practices

import rego.v1

# W9009: Resource type is deprecated (sunset or shutdown)
violation contains make_diag_full("W9009", "WARN", name, "",
    sprintf("Resource type '%s' is deprecated - consider using a newer alternative", [rtype]),
    sprintf("Replace %s with a supported alternative", [rtype]),
    "") if {
    some name, res in input.resources
    rtype := res.resourceType
    rtype in data.deprecated_resource_types
}
