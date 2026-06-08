package best_practices

import rego.v1

# I9040: Resource should have Tags when the resource type supports it
violation contains make_diag_full("I9040", "INFO", name, "Properties.Tags",
    sprintf("Resource '%s' of type '%s' supports Tags but none are configured", [name, res.resourceType]),
    "Add Tags to improve resource organization and cost tracking",
    "") if {
    some name, res in input.resources
    not endswith(res.resourceType, "::MODULE")
    _type_supports_tags(res.resourceType)
    not res.properties.Tags
}

_type_supports_tags(rtype) if {
    "Tags" in schema_properties(rtype)
}
