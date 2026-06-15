# Format validation rules:
# E1150 (SecurityGroup ID), E1151 (VPC ID), E1152 (AMI ID),
# E1153 (Security Group Name), E1154 (Subnet ID), E1155 (Log Group Name), E1156 (IAM Role ARN)
#
# Each rule fires on any concrete-string scenario that fails the expected pattern.
# `resolve_all` returns ONLY concrete scalar values — unresolved Ref/Dynamic scenarios
# produce no bindings, so these rules never see parameter/resource reference target
# names. Conditional scenarios are validated independently.
package intrinsics

import rego.v1

# E1151: VPC ID format
violation contains make_diag_at("E1151", "ERROR", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Value '%s' does not match VPC ID format (vpc-xxxxxxxxx)", [val])) if {
    some name in object.keys(input.resources)
    some prop in _vpc_id_properties[input.resources[name].resourceType]
    some val in resolve_all(name, sprintf("Properties.%s", [prop]))
    is_string(val)
    not startswith(val, "{{")
    not regex.match(`^vpc-[a-f0-9]{8,17}$`, val)
}

# E1154: Subnet ID format
violation contains make_diag_at("E1154", "ERROR", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Value '%s' does not match Subnet ID format (subnet-xxxxxxxxx)", [val])) if {
    some name in object.keys(input.resources)
    some prop in _subnet_id_properties[input.resources[name].resourceType]
    some val in resolve_all(name, sprintf("Properties.%s", [prop]))
    is_string(val)
    not startswith(val, "{{")
    not regex.match(`^subnet-[a-f0-9]{8,17}$`, val)
}

# E1150: Security Group ID format (list properties — each item validated).
# Retains a `sg-` prefix gate because list items may include arbitrary strings that
# aren't meant to be IDs (e.g. logical IDs in heterogeneous lists). Values starting
# with `sg-` that don't match the pattern are clearly malformed IDs.
violation contains make_diag_at("E1150", "ERROR", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Value '%s' does not match Security Group ID format (sg-xxxxxxxxx)", [val])) if {
    some name in object.keys(input.resources)
    some prop in _sg_id_list_properties[input.resources[name].resourceType]
    arr := resolve(name, sprintf("Properties.%s", [prop]))
    is_array(arr)
    some val in arr
    is_string(val)
    not startswith(val, "{{")
    startswith(val, "sg-")
    not regex.match(`^sg-[a-f0-9]{8,17}$`, val)
}

# E1150: Security Group ID format in NetworkInterfaces GroupSet
violation contains make_diag_at("E1150", "ERROR", name,
    "Properties.NetworkInterfaces.GroupSet",
    sprintf("'%s' is not a 'AWS::EC2::SecurityGroup.Id' with pattern '^sg-([a-fA-F0-9]{8}|[a-fA-F0-9]{17})$'", [val])) if {
    some name in object.keys(input.resources)
    input.resources[name].resourceType in {"AWS::EC2::Instance", "AWS::EC2::LaunchTemplate"}
    some val in resolve_all(name, "Properties.NetworkInterfaces.{}.GroupSet.{}")
    is_string(val)
    startswith(val, "sg-")
    not regex.match(`^sg-[a-fA-F0-9]{8,17}$`, val)
}

# E1152: AMI ID format
violation contains make_diag_at("E1152", "ERROR", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Value '%s' does not match AMI ID format (ami-xxxxxxxxx)", [val])) if {
    some name in object.keys(input.resources)
    some prop in _ami_id_properties[input.resources[name].resourceType]
    some val in resolve_all(name, sprintf("Properties.%s", [prop]))
    is_string(val)
    not startswith(val, "{{")
    not regex.match(`^ami-[a-f0-9]{8,17}$`, val)
}

# E1153: Security Group Name format
violation contains make_diag_at("E1153", "ERROR", name,
    "Properties.GroupName",
    sprintf("Value '%s' does not match Security Group Name format", [val])) if {
    some name in resources_of_type("AWS::EC2::SecurityGroup")
    some val in resolve_all(name, "Properties.GroupName")
    is_string(val)
    not startswith(val, "{{")
    val != ""
    not regex.match(`^[a-zA-Z0-9 \._\-:/()#,@\[\]+=&;\{\}!\$\*]+$`, val)
}

_vpc_id_properties := {
    "AWS::EC2::Subnet": {"VpcId"},
    "AWS::EC2::SecurityGroup": {"VpcId"},
    "AWS::EC2::RouteTable": {"VpcId"},
    "AWS::EC2::InternetGatewayAttachment": {"VpcId"},
    "AWS::EC2::NetworkAcl": {"VpcId"},
}

_subnet_id_properties := {
    "AWS::EC2::Instance": {"SubnetId"},
    "AWS::EC2::NetworkInterface": {"SubnetId"},
}

_sg_id_list_properties := {
    "AWS::EC2::Instance": {"SecurityGroupIds"},
}

_ami_id_properties := {
    "AWS::EC2::Instance": {"ImageId"},
    "AWS::AutoScaling::LaunchConfiguration": {"ImageId"},
    "AWS::EC2::LaunchTemplate": {"LaunchTemplateData.ImageId"},
}

# E1155: CloudWatch Log Group Name format
violation contains make_diag_at("E1155", "ERROR", name,
    "Properties.LogGroupName",
    sprintf("Value '%s' does not match Log Group Name format", [val])) if {
    some name in resources_of_type("AWS::Logs::LogGroup")
    some val in resolve_all(name, "Properties.LogGroupName")
    is_string(val)
    not startswith(val, "{{")
    val != ""
    not regex.match(`^[\.\-_/#A-Za-z0-9]{1,512}$`, val)
}

# E1156: IAM Role ARN format
violation contains make_diag_at("E1156", "ERROR", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Value '%s' does not match IAM Role ARN format", [val])) if {
    some name in object.keys(input.resources)
    some prop in _iam_role_arn_properties[input.resources[name].resourceType]
    some val in resolve_all(name, sprintf("Properties.%s", [prop]))
    is_string(val)
    not startswith(val, "{{")
    startswith(val, "arn:")
    not regex.match(`^arn:(aws|aws-cn|aws-iso|aws-iso-[a-z]{1}|aws-us-gov):iam::[0-9]{12}:role/.*$`, val)
}

_iam_role_arn_properties := {
    "AWS::Lambda::Function": {"Role"},
    "AWS::ECS::TaskDefinition": {"ExecutionRoleArn", "TaskRoleArn"},
    "AWS::StepFunctions::StateMachine": {"RoleArn"},
}
