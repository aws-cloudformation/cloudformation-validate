package intrinsics

import rego.v1

# W1030: Parameter default is empty string but property has minLength > 0
violation contains make_diag_full("W1030", "WARN", name, edge.sourcePath,
    sprintf("{'Ref': '%s'} is shorter than 1 when 'Ref' is resolved", [target]),
    "Set a non-empty default or add AllowedValues",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.parameters)
    param := input.parameters[target]
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    def == ""
    endswith(edge.sourcePath, "KeyName")
}

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

# W1030: Parameter default doesn't match ARN pattern for SNS topic
violation contains make_diag_full("W1030", "WARN", name, edge.sourcePath,
    sprintf("{'Ref': '%s'} does not match ARN pattern when 'Ref' is resolved", [target]),
    "Ensure the parameter default matches the expected ARN pattern",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.parameters)
    param := input.parameters[target]
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    def != ""
    endswith(edge.sourcePath, "TopicArn")
    not startswith(def, "arn:")
}

# W1030: Parameter default doesn't match ARN pattern when used in ARN context
violation contains make_diag_full("W1030", "WARN", "", sprintf("Parameters.%s.Default", [target]),
    sprintf("{'Ref': '%s'} does not match '^(arn:(aws[A-Za-z\\-]*?|\\*):[^:]+:[^:]*(:(?:\\d{12}|\\*|aws)?:.+|)|\\*)$' when 'Ref' is resolved", [target]),
    "Ensure the parameter default matches the expected ARN pattern",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.parameters)
    param := input.parameters[target]
    param.type == "String"
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    _is_arn_prop(edge.sourcePath)
    not regex.match(`^(arn:(aws[A-Za-z\-]*?|\*):[^:]+:[^:]*(:(\d{12}|\*|aws)?:.+|)|\*)$`, def)
}

_is_cidr_prop(path) if { endswith(path, "CidrBlock") }
_is_cidr_prop(path) if { endswith(path, "DestinationCidrBlock") }

_is_arn_prop(path) if { endswith(path, "TopicArn") }
_is_arn_prop(path) if { endswith(path, "Arn") }
_is_arn_prop(path) if { contains(path, "Resource.") }
_is_arn_prop(path) if { endswith(path, "Resource") }

# W1030: String parameter used where SecurityGroup.Id is expected
violation contains make_diag_full("W1030", "WARN", name, edge.sourcePath,
    sprintf("{'Ref': '%s'} is not a 'AWS::EC2::SecurityGroup.Id' with pattern '^sg-([a-fA-F0-9]{8}|[a-fA-F0-9]{17})$' when 'Ref' is resolved", [target]),
    "", "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.parameters)
    param := input.parameters[target]
    param.type == "String"
    _is_security_group_id_prop(edge.sourcePath)
}

# W1030: String parameter used where Subnet.Id is expected (pattern 1)
violation contains make_diag_full("W1030", "WARN", name, edge.sourcePath,
    sprintf("{'Ref': '%s'} is not a 'AWS::EC2::Subnet.Id' with pattern '^subnet-(([0-9A-Fa-f]{8})|([0-9A-Fa-f]{17}))$' when 'Ref' is resolved", [target]),
    "", "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.parameters)
    param := input.parameters[target]
    param.type == "String"
    endswith(edge.sourcePath, "SubnetId")
}

# W1030: String parameter used where Subnet.Id is expected (pattern 2)
violation contains make_diag_full("W1030", "WARN", name, edge.sourcePath,
    sprintf("{'Ref': '%s'} is not a 'AWS::EC2::Subnet.Id' with pattern '^[\\.\\-_\\/#A-Za-z0-9]{1,512}\\Z' when 'Ref' is resolved", [target]),
    "", "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.parameters)
    param := input.parameters[target]
    param.type == "String"
    endswith(edge.sourcePath, "SubnetId")
}

_is_security_group_id_prop(path) if { contains(path, "GroupSet.") }
_is_security_group_id_prop(path) if { endswith(path, "GroupSet") }
_is_security_group_id_prop(path) if { contains(path, "SecurityGroupIds.") }
_is_security_group_id_prop(path) if { endswith(path, "SecurityGroupIds") }

# W1030: String parameter used where VPC.Id is expected
violation contains make_diag_full("W1030", "WARN", name, edge.sourcePath,
    sprintf("{'Ref': '%s'} is not a 'AWS::EC2::VPC.Id' with pattern '^vpc-([a-fA-F0-9]{8}|[a-fA-F0-9]{17})$' when 'Ref' is resolved", [target]),
    "", "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.parameters)
    param := input.parameters[target]
    param.type == "String"
    endswith(edge.sourcePath, "VpcId")
}

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