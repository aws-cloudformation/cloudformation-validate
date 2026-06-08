package intrinsics

import rego.v1

# E9004: GetAtt attribute must exist on target resource type
violation contains make_diag_full("E9004", "ERROR", name, edge.sourcePath,
    sprintf("'%s' is not one of %v", [attr, valid_attrs]),
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
}

# E9003: GetAtt return type mismatch — non-string where string expected
violation contains make_diag_full("E9003", "ERROR", name, edge.sourcePath,
    sprintf("{'Fn::GetAtt': ['%s', '%s']} is not of type 'string'",
        [target_name, attr]),
    "GetAtt returns a non-string type",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "GetAtt"
    target_name := edge.target
    target_name in object.keys(input.resources)
    target_type := input.resources[target_name].resourceType
    attr := edge.attr
    # Only flag when destination expects string and source returns non-string
    _dest_expects_string(res.resourceType, edge.sourcePath)
    ret_type := getatt_return_type(target_type, attr)
    ret_type in {"integer", "number", "boolean"}
}

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

# Check if destination property expects a string type
_dest_expects_string(rtype, path) if {
    contains(path, "Value")
    rtype == "AWS::SSM::Parameter"
}

# GetAtt attribute format mapping
default _getatt_format(_, _) := ""
_getatt_format("AWS::EC2::SecurityGroup", "GroupId") := "AWS::EC2::SecurityGroup.Id"
_getatt_format("AWS::EC2::SecurityGroup", "GroupName") := "AWS::EC2::SecurityGroup.Name"
_getatt_format("AWS::EC2::VPC", "DefaultSecurityGroup") := "AWS::EC2::VPC.DefaultSecurityGroup"
_getatt_format("AWS::Logs::LogGroup", "Arn") := "AWS::Logs::LogGroup.Arn"

# Destination property format from path
default _property_format(_) := ""
_property_format(path) := "AWS::EC2::SecurityGroup.Id" if {
    contains(path, "GroupSet")
}
_property_format(path) := "AWS::Logs::LogGroup.Name" if {
    contains(path, "awslogs-group")
}

# E1060: If condition name must exist in Conditions section
violation contains make_diag("F1060", "FATAL", name,
    sprintf("Fn::If condition '%s' does not exist in Conditions section", [cond])) if {
    some name, res in input.resources
    some cond in res.conditionRefs
    not cond in object.keys(input.conditions)
}
