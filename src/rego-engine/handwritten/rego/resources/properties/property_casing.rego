package resources

import rego.v1

# E3011: Property names must use correct casing
violation contains make_diag_at("E3011", "ERROR", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Property '%s' should be '%s'", [prop, correct])) if {
    some name, res in input.resources
    some prop in object.keys(res.properties)
    schema := data.schema_metadata[res.resourceType]
    schema != null
    expected := schema.properties
    expected != null
    some correct in expected
    lower(prop) == lower(correct)
    prop != correct
}
