package structure

import rego.v1

# F0050: Mapping must have valid 3-level structure (map → key1 → key2 → value)
violation contains make_diag_at("F0050", "FATAL", "",
    sprintf("Mappings/%s", [map_name]),
    sprintf("Mapping '%s' must be a map, not %s", [map_name, type_name(input.mappings[map_name])])) if {
    some map_name in object.keys(input.mappings)
    not is_object(input.mappings[map_name])
}

violation contains make_diag_at("F0050", "FATAL", "",
    sprintf("Mappings/%s/%s", [map_name, k1]),
    sprintf("Mapping '%s' has invalid structure - second level key '%s' must be a map", [map_name, k1])) if {
    some map_name in object.keys(input.mappings)
    level1 := input.mappings[map_name]
    is_object(level1)
    some k1 in object.keys(level1)
    not is_object(level1[k1])
}

# F0050: Mapping second-level key count limit (200)
violation contains make_diag_at("F0050", "FATAL", "",
    sprintf("Mappings/%s", [map_name]),
    sprintf("Mapping '%s' has %d top-level keys, maximum is 200", [map_name, cnt])) if {
    some map_name in object.keys(input.mappings)
    level1 := input.mappings[map_name]
    is_object(level1)
    cnt := count(level1)
    cnt > 200
}

# F0050: Mapping third-level attribute count limit (200)
violation contains make_diag_at("F0050", "FATAL", "",
    sprintf("Mappings/%s/%s", [map_name, k1]),
    sprintf("Mapping '%s'.'%s' has %d attributes, maximum is 200", [map_name, k1, cnt])) if {
    some map_name in object.keys(input.mappings)
    level1 := input.mappings[map_name]
    is_object(level1)
    some k1 in object.keys(level1)
    level2 := level1[k1]
    is_object(level2)
    cnt := count(level2)
    cnt > 200
}

# E7001: Mapping second-level keys must match ^[a-zA-Z0-9.-]+$
violation contains make_diag_at("E7001", "ERROR", "",
    sprintf("Mappings/%s/%s", [map_name, k1]),
    sprintf("Mapping '%s' key '%s' does not match format '^[a-zA-Z0-9.-]+$'", [map_name, k1])) if {
    some map_name in object.keys(input.mappings)
    level1 := input.mappings[map_name]
    is_object(level1)
    some k1 in object.keys(level1)
    not regex.match(`^[a-zA-Z0-9.\-]+$`, k1)
}

# E7001: Mapping third-level keys must match ^[a-zA-Z0-9]+$
violation contains make_diag_at("E7001", "ERROR", "",
    sprintf("Mappings/%s/%s/%s", [map_name, k1, k2]),
    sprintf("Mapping '%s'.'%s' key '%s' does not match format '^[a-zA-Z0-9]+$'", [map_name, k1, k2])) if {
    some map_name in object.keys(input.mappings)
    level1 := input.mappings[map_name]
    is_object(level1)
    some k1 in object.keys(level1)
    level2 := level1[k1]
    is_object(level2)
    some k2 in object.keys(level2)
    not regex.match(`^[a-zA-Z0-9]+$`, k2)
}
