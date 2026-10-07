package intrinsics

import rego.v1

# F1012: FindInMap map name must exist in Mappings
violation contains make_diag("F1012", "FATAL", name,
    sprintf("Fn::FindInMap references non-existent mapping '%s'", [map_name])) if {
    cfn_rule_active("F1012")
    some name, res in input.resources
    some map_name in res.findInMapRefs
    not object.get(input, "mappings", {})[map_name]
}
