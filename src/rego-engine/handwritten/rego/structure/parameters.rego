package structure

import rego.v1

# F2002: Parameter Type must be valid
valid_param_types := {
    "String", "Number", "List<Number>", "List<String>", "CommaDelimitedList",
    "AWS::SSM::Parameter::Name",
    "AWS::SSM::Parameter::Value<String>",
    "AWS::SSM::Parameter::Value<List<String>>",
    "AWS::SSM::Parameter::Value<CommaDelimitedList>",
    "AWS::EC2::AvailabilityZone::Name",
    "AWS::EC2::Image::Id",
    "AWS::EC2::Instance::Id",
    "AWS::EC2::KeyPair::KeyName",
    "AWS::EC2::SecurityGroup::GroupName",
    "AWS::EC2::SecurityGroup::Id",
    "AWS::EC2::Subnet::Id",
    "AWS::EC2::Volume::Id",
    "AWS::EC2::VPC::Id",
    "AWS::Route53::HostedZone::Id",
    "List<AWS::EC2::AvailabilityZone::Name>",
    "List<AWS::EC2::Image::Id>",
    "List<AWS::EC2::Instance::Id>",
    "List<AWS::EC2::SecurityGroup::GroupName>",
    "List<AWS::EC2::SecurityGroup::Id>",
    "List<AWS::EC2::Subnet::Id>",
    "List<AWS::EC2::Volume::Id>",
    "List<AWS::EC2::VPC::Id>",
    "List<AWS::Route53::HostedZone::Id>"
}

violation contains make_diag("F2002", "FATAL", "",
    sprintf("Parameter '%s' has invalid Type '%s'", [name, ptype])) if {
    some name, param in input.parameters
    ptype := param.type
    ptype != null
    not ptype in valid_param_types
    not startswith(ptype, "AWS::SSM::Parameter::Value<")
}

# F0015: Default value must be numeric when parameter Type is Number
violation contains make_diag("F0015", "FATAL", "",
    sprintf("Parameter '%s' Default '%s' is not a valid number", [name, def])) if {
    some name, param in input.parameters
    param.type == "Number"
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    not regex.match(`^-?[0-9]+(\.[0-9]+)?$`, def)
}

# F0016: AllowedValues entries must be numeric when parameter Type is Number
violation contains make_diag("F0016", "FATAL", "",
    sprintf("Parameter '%s' AllowedValues entry '%s' is not a valid number", [name, val])) if {
    some name, param in input.parameters
    param.type == "Number"
    avs := param.allowedValues
    avs != null
    some val in avs
    is_string(val)
    not regex.match(`^-?[0-9]+(\.[0-9]+)?$`, val)
}

# F3016: DeletionPolicy must be valid
_base_deletion_policies := {"Delete", "Retain", "RetainExceptOnCreate"}
_snapshot_capable_types := {
    "AWS::DocDB::DBCluster",
    "AWS::EC2::Volume",
    "AWS::ElastiCache::CacheCluster",
    "AWS::ElastiCache::ReplicationGroup",
    "AWS::Neptune::DBCluster",
    "AWS::RDS::DBCluster",
    "AWS::RDS::DBInstance",
    "AWS::Redshift::Cluster"
}

violation contains make_diag("F3016", "FATAL", name,
    sprintf("DeletionPolicy must be one of Delete, Retain, RetainExceptOnCreate, Snapshot, got '%s'", [dp])) if {
    some name, res in input.resources
    dp := res.deletionPolicy
    dp != null
    is_string(dp)
    res.resourceType in _snapshot_capable_types
    not dp in (_base_deletion_policies | {"Snapshot"})
}

violation contains make_diag("F3016", "FATAL", name,
    sprintf("DeletionPolicy must be one of Delete, Retain, RetainExceptOnCreate, got '%s'", [dp])) if {
    some name, res in input.resources
    dp := res.deletionPolicy
    dp != null
    is_string(dp)
    not res.resourceType in _snapshot_capable_types
    not dp in _base_deletion_policies
}

# W2506: ImageId parameters should use AWS::EC2::Image::Id type
_image_id_param_types := {"AWS::EC2::Image::Id", "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>"}

violation contains make_diag("W2506", "WARN", "",
    sprintf("Parameter '%s' is used as an ImageId but has Type '%s' — consider using 'AWS::EC2::Image::Id'", [pname, ptype])) if {
    some name, res in input.resources
    res.resourceType in {"AWS::EC2::Instance", "AWS::AutoScaling::LaunchConfiguration", "AWS::EC2::LaunchTemplate"}
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    endswith(edge.sourcePath, "ImageId")
    pname := edge.target
    pname in object.keys(input.parameters)
    ptype := input.parameters[pname].type
    ptype != null
    not ptype in _image_id_param_types
}
