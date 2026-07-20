package intrinsics

import rego.v1

# E9004: GetAtt attribute must exist on target resource type
violation contains make_diag_full("E9004", "ERROR", name, edge.sourcePath,
    sprintf("'%s' is not one of %s", [attr, render_list(valid_attrs)]),
    "Check the resource type documentation for valid GetAtt attributes",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "GetAtt"
    target_name := edge.target
    target_name in object.keys(input.resources)
    target_type := input.resources[target_name].resourceType
    not target_type in _skip_getatt_types
    not startswith(target_type, "Custom::")
    attr := edge.attr
    valid_attrs := data.getatt_attributes[target_type]
    valid_attrs != null
    not attr in valid_attrs
    not _is_map_member_attr(attr, target_type)
}

# A dotted attribute (e.g. Outputs.SomeKey) addresses a member of an open-ended
# map attribute that CloudFormation exposes as <Attr>.<key> for any key. Only two
# resource types have such an attribute: nested stacks and provisioned products
# both expose Outputs.<OutputKey>. Nested stacks (AWS::CloudFormation::Stack) are
# already in _skip_getatt_types, so the only type that reaches here needing the
# exemption is the provisioned product. Every other dotted attribute (e.g. Tags.0
# on a bucket) is a real attribute-validity error — an object/array attribute is
# NOT itself indexable via GetAtt.
_is_map_member_attr(attr, target_type) if {
    target_type == "AWS::ServiceCatalog::CloudFormationProvisionedProduct"
    startswith(attr, "Outputs.")
}

# E9003 is disabled - CloudFormation auto-converts non-string GetAtt return values
# to strings when the destination property is typed as string.

# E1020: GetAtt resource must exist in template
violation contains make_diag_full("F1020", "FATAL", name, "",
    sprintf("Fn::GetAtt references non-existent resource '%s'", [target]),
    "Check that the GetAtt target resource exists in the template",
    "") if {
    not object.get(input, "hasParseErrors", false)
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "GetAtt"
    target := edge.target
    not target in object.keys(input.resources)
    not target in object.get(input, "samImplicitResources", [])
}

# E1040: GetAtt format mismatch
violation contains make_diag_full("E1040", "ERROR", name, edge.sourcePath,
    sprintf("{'Fn::GetAtt': ['%s', '%s']} does not match destination format of '%s'",
        [target_name, attr, dest_fmt]),
    "Use the correct GetAtt attribute",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "GetAtt"
    target_name := edge.target
    target_name in object.keys(input.resources)
    target_type := input.resources[target_name].resourceType
    attr := edge.attr
    src_fmt := _getatt_format(target_type, attr)
    src_fmt != ""
    dest_fmt := _property_format(edge.sourcePath)
    dest_fmt != ""
    src_fmt != dest_fmt
}

_skip_getatt_types := {
    "AWS::CloudFormation::Stack",
    "AWS::CloudFormation::CustomResource",
    "AWS::CloudFormation::Macro",
}

# GetAtt attribute format mapping
default _getatt_format(_, _) := ""
_getatt_format("AWS::EC2::SecurityGroup", "GroupId") := "AWS::EC2::SecurityGroup.Id"
_getatt_format("AWS::EC2::SecurityGroup", "GroupName") := "AWS::EC2::SecurityGroup.Name"
_getatt_format("AWS::EC2::VPC", "DefaultSecurityGroup") := "AWS::EC2::SecurityGroup.Id"
_getatt_format("AWS::Logs::LogGroup", "Arn") := "AWS::Logs::LogGroup.Arn"

# Destination property format from path
default _property_format(_) := ""
_property_format(path) := "AWS::EC2::SecurityGroup.Id" if {
    contains(path, "GroupSet")
}
_property_format(path) := "AWS::Logs::LogGroup.Name" if {
    contains(path, "awslogs-group")
}

# E1028: Fn::If condition name must exist in Conditions section
violation contains make_diag("E1028", "ERROR", name,
    sprintf("Fn::If condition '%s' does not exist in Conditions section", [cond])) if {
    count(object.keys(object.get(input, "conditions", {}))) > 0
    some name, res in input.resources
    some cond in res.conditionRefs
    not cond in object.keys(input.conditions)
}
