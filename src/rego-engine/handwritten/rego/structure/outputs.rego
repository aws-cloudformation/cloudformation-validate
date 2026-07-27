package structure

import rego.v1

# F0040: Output must have Value property
violation contains make_diag_at("F0040", "FATAL", "",
    sprintf("Outputs/%s", [name]),
    sprintf("Output '%s' is missing required 'Value' property", [name])) if {
    some name in object.keys(input.outputs)
    val := input.outputs[name].value
    is_null(val)
}

# F6101: GetAtt in output names an attribute the resource type does not expose.
# The exemptions mirror the resource-side attribute check: custom resources,
# macros, and nested stacks expose caller-defined attributes, and provisioned
# products expose an open-ended Outputs.<key> map.
violation contains make_diag_at("F6101", "FATAL", "",
    sprintf("Outputs/%s/Value", [name]),
    sprintf("'%s' is not one of %s", [ref.attribute, render_list(valid_attrs)])) if {
    some name in object.keys(input.outputs)
    some ref in input.outputs[name].getattRefs
    ref.resource in object.keys(input.resources)
    target_type := input.resources[ref.resource].resourceType
    not target_type in {"AWS::CloudFormation::Stack", "AWS::CloudFormation::CustomResource", "AWS::CloudFormation::Macro"}
    not startswith(target_type, "Custom::")
    not startswith(target_type, "AWS::CloudFormation::CustomResource")
    valid_attrs := data.getatt_attributes[target_type]
    valid_attrs != null
    not ref.attribute in valid_attrs
    not _output_attr_is_map_member(ref.attribute, target_type)
}

_output_attr_is_map_member(attr, target_type) if {
    target_type == "AWS::ServiceCatalog::CloudFormationProvisionedProduct"
    startswith(attr, "Outputs.")
}

# F6101: a Sub variable in the output value that resolves to nothing in the
# template. A recorded entry is itself the finding - the model only records
# variables that failed to resolve.
violation contains make_diag_at("F6101", "FATAL", "",
    sprintf("Outputs/%s/Value", [name]),
    sprintf("Fn::Sub variable '${%s}' does not reference a valid resource, parameter, or pseudo-parameter", [var])) if {
    some name in object.keys(input.outputs)
    some var in object.get(input.outputs[name], "subRefs", [])
}

# F6101: GetAtt in output returns a non-string type (direct or nested in Sub/Join).
# Uses getattRefs which captures all GetAtt references including those nested
# inside Fn::Sub, Fn::Join, and other intrinsics. An array-returning GetAtt is
# consumed by Fn::Select to extract a string element - the array itself is never
# the output value - so only scalar non-string returns are reported.
violation contains make_diag_at("F6101", "FATAL", "",
    sprintf("Outputs/%s/Value", [name]),
    sprintf("Output '%s': GetAtt '%s.%s' returns type '%s', not 'string'", [name, ref.resource, ref.attribute, ret_type])) if {
    some name in object.keys(input.outputs)
    some ref in input.outputs[name].getattRefs
    ref.resource in object.keys(input.resources)
    target_type := input.resources[ref.resource].resourceType
    # An attribute the type does not expose is already reported as an invalid
    # attribute; the return-type check applies only to real attributes.
    valid_attrs := data.getatt_attributes[target_type]
    _attr_is_known(valid_attrs, ref.attribute)
    ret_type := getatt_return_type(target_type, ref.attribute)
    ret_type != "string"
    ret_type != "array"
}

_attr_is_known(valid_attrs, attr) if {
    valid_attrs == null
}

_attr_is_known(valid_attrs, attr) if {
    valid_attrs != null
    attr in valid_attrs
}
