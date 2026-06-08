package resources

import rego.v1

# E3001: Resource type not available in configured region
violation contains make_diag("E3001", "ERROR", name,
    sprintf("Resource type '%s' is not available in region '%s'", [rtype, region])) if {
    region := input_region()
    region != null
    available := data.region_resource_types[region]
    available != null
    some name, res in input.resources
    rtype := res.resourceType
    not available[rtype]
    # Only flag if the type is known (exists in at least one region)
    some other_region in object.keys(data.region_resource_types)
    data.region_resource_types[other_region][rtype]
}
