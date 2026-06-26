package structure

import rego.v1

# F0040: Output must have Value property
violation contains make_diag("F0040", "FATAL", "",
    sprintf("Output '%s' is missing required 'Value' property", [name])) if {
    some name in object.keys(input.outputs)
    val := input.outputs[name].value
    is_null(val)
}

# F6101: GetAtt in output returns a non-string type (direct or nested in Sub/Join).
# Uses getattRefs which captures all GetAtt references including those nested
# inside Fn::Sub, Fn::Join, and other intrinsics. An array-returning GetAtt is
# consumed by Fn::Select to extract a string element — the array itself is never
# the output value — so only scalar non-string returns are reported.
violation contains make_diag_at("F6101", "FATAL", name,
    sprintf("Outputs/%s/Value", [name]),
    sprintf("Output '%s': GetAtt '%s.%s' returns type '%s', not 'string'", [name, ref.resource, ref.attribute, ret_type])) if {
    some name in object.keys(input.outputs)
    some ref in input.outputs[name].getattRefs
    ref.resource in object.keys(input.resources)
    target_type := input.resources[ref.resource].resourceType
    ret_type := getatt_return_type(target_type, ref.attribute)
    ret_type != "string"
    ret_type != "array"
}
