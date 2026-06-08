package resources

import rego.v1

# E3033: String length validation through Fn::Sub / intrinsic estimation.
# Only fires when the value is NOT a concrete string (those are already
# covered by the generated F3033 schema rules).
violation contains make_diag_at("W9006", "WARN", name,
    path,
    sprintf("String length %d exceeds maximum %d for property '%s'", [len, max_len, prop])) if {
    some name, res in input.resources
    rtype := res.resourceType
    some prop in schema_properties(rtype)
    constraints := schema_string_length(rtype, prop)
    max_len := constraints.maxLength
    path := sprintf("Properties.%s", [prop])
    val := resolve(name, path)
    not is_string(val)
    len := estimate_string_length(name, path)
    len > max_len
}

violation contains make_diag_at("W9006", "WARN", name,
    path,
    sprintf("String length %d is below minimum %d for property '%s'", [len, min_len, prop])) if {
    some name, res in input.resources
    rtype := res.resourceType
    some prop in schema_properties(rtype)
    constraints := schema_string_length(rtype, prop)
    min_len := constraints.minLength
    min_len > 0
    path := sprintf("Properties.%s", [prop])
    val := resolve(name, path)
    not is_string(val)
    len := estimate_string_length(name, path)
    len < min_len
}
