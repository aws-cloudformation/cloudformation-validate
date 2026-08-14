package intrinsics

import rego.v1

# E1015: GetAZs parameter must be a valid region if non-empty string literal.
# The valid-region set comes from the shared `is_valid_region` builtin (backed by
# the template-model region table).
violation contains make_diag("E1015", "ERROR", name,
    sprintf("Fn::GetAZs parameter '%s' is not a valid region", [region])) if {
    some name, res in input.resources
    some _, prop in res.properties
    region := _find_invalid_getazs_region(prop)
}

_find_invalid_getazs_region(val) := region if {
    is_object(val)
    region := val["Fn::GetAZs"]
    is_string(region)
    region != ""
    not is_valid_region(region)
}

_find_invalid_getazs_region(val) := region if {
    is_object(val)
    some _, v in val
    not val["Fn::GetAZs"]
    region := _find_invalid_getazs_region(v)
}

_find_invalid_getazs_region(val) := region if {
    is_array(val)
    some item in val
    region := _find_invalid_getazs_region(item)
}

# E1016: ImportValue cannot use Ref to AWS::StackName
violation contains make_diag_at("E1016", "ERROR", name, edge.sourcePath,
    "Fn::ImportValue cannot use Ref to 'AWS::StackName'") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    edge.target == "AWS::StackName"
    contains(edge.sourcePath, "Fn::ImportValue")
}
