package intrinsics

import rego.v1

# W1030: Parameter default fails AMI ID format when used in ImageId property
# Only fires when Default exists AND fails the AMI pattern
violation contains make_diag_full("W1030", "WARN", name, edge.sourcePath,
    sprintf("{'Ref': '%s'} is not a 'AWS::EC2::Image.Id' when 'Ref' is resolved", [target]),
    "Use parameter type AWS::EC2::Image::Id",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.parameters)
    param := input.parameters[target]
    param.type == "String"
    endswith(edge.sourcePath, "ImageId")
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    not regex.match(`^ami-[0-9a-f]{8,17}$`, def)
}

# W1030: Parameter default fails strict CIDR validation when used in CidrBlock property
# Fires when Default exists AND fails strict network validation (host bits set)
violation contains make_diag_full("W1030", "WARN", name, edge.sourcePath,
    sprintf("{'Ref': '%s'} is not a 'ipv4-network' when 'Ref' is resolved", [target]),
    "Validate the parameter value matches CIDR format",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.parameters)
    param := input.parameters[target]
    param.type == "String"
    _is_cidr_prop(edge.sourcePath)
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    not is_valid_cidr_strict(def)
}

_is_cidr_prop(path) if { endswith(path, "CidrBlock") }
_is_cidr_prop(path) if { endswith(path, "DestinationCidrBlock") }

# W1030: VPC::Id parameter default fails VPC ID pattern
violation contains make_diag_full("W1030", "WARN", name, edge.sourcePath,
    sprintf("{'Ref': '%s'} is not a 'AWS::EC2::VPC.Id' with pattern '^vpc-(([0-9A-Fa-f]{8})|([0-9A-Fa-f]{17}))$' when 'Ref' is resolved", [target]),
    "", "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.parameters)
    param := input.parameters[target]
    param.type == "AWS::EC2::VPC::Id"
    endswith(edge.sourcePath, "VpcId")
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    not regex.match(`^vpc-(([0-9A-Fa-f]{8})|([0-9A-Fa-f]{17}))$`, def)
}