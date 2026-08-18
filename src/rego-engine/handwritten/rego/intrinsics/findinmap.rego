package intrinsics

import rego.v1

# A literal mapping name must identify a declared Mappings entry.
violation contains make_diag_full("F1012", "FATAL", name, entry.path,
    sprintf("Fn::FindInMap references non-existent mapping '%s'", [map_name]),
    "", "") if {
    some name, res in input.resources
    some entry in res.findInMapRefPaths
    map_name := entry.target
    not object.get(input, "mappings", {})[map_name]
}
