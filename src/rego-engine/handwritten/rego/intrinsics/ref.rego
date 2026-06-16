package intrinsics

import rego.v1

# `pseudo_parameters` is defined in pseudo_params.rego (shared across this package).

# Ref target must exist
violation contains make_diag_full("F1010", "FATAL", name, "",
    sprintf("Ref '%s' does not reference a valid resource, parameter, or pseudo-parameter", [target]),
    "Check that the Ref target exists as a resource, parameter, or pseudo-parameter",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    not target in object.keys(input.resources)
    not target in object.keys(input.parameters)
    not target in pseudo_parameters
    not target in object.get(input, "samImplicitResources", [])
}

# Invalid Ref targets tracked by the resolver
violation contains make_diag_full("F1020", "FATAL", name, entry.path,
    sprintf("'%s' is not one of %v", [entry.target, _all_valid_targets]),
    "Check that the Ref target exists as a resource, parameter, or pseudo-parameter",
    "") if {
    some name, res in input.resources
    not input.hasParseErrors
    not _has_language_extensions
    some entry in res.invalidRefs
    entry.target != ""
    not entry.target in object.get(input, "samImplicitResources", [])
}

_all_valid_targets := sort(array.concat(
    array.concat(
        sort([k | some k in object.keys(input.resources)]),
        sort([k | some k in object.keys(input.parameters)])
    ),
    sort([k | some k in pseudo_parameters])
))

_valid_ref_targets(name) := targets if {
    res_keys := sort([k | some k in object.keys(input.resources); k != name])
    targets := array.concat(res_keys, sort([p | some p in pseudo_parameters]))
}

# Ref format mismatch — Ref to resource whose type doesn't match destination format
violation contains make_diag_full("E1041", "ERROR", name, edge.sourcePath,
    sprintf("{'Ref': '%s'} does not match destination format of '%s'",
        [target, dest_fmt]),
    "Use a Ref to a resource whose type matches the expected format",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.resources)
    target_type := input.resources[target].resourceType
    dest_fmt := _ref_format_for_prop(edge.sourcePath)
    dest_fmt != ""
    not _ref_type_ok(target_type, dest_fmt)
}

# Non-VPC SecurityGroup Ref used where SecurityGroup.Id expected
# A non-VPC security group (no VpcId property) returns GroupName format, not GroupId
violation contains make_diag_full("E1041", "ERROR", name, edge.sourcePath,
    sprintf("{'Ref': '%s'} with formats ['AWS::EC2::SecurityGroup.Name'] does not match destination format of 'AWS::EC2::SecurityGroup.Id'",
        [target]),
    "Use a Ref to a resource whose type matches the expected format",
    "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Ref"
    target := edge.target
    target in object.keys(input.resources)
    input.resources[target].resourceType == "AWS::EC2::SecurityGroup"
    endswith(edge.sourcePath, "SecurityGroupId")
    not has_property(target, "VpcId")
}

# Simple property-to-format mapping using endswith
default _ref_format_for_prop(_) := ""
_ref_format_for_prop(path) := "AWS::EC2::VPC.Id" if { endswith(path, "VpcId") }
_ref_format_for_prop(path) := "AWS::EC2::Subnet.Id" if { endswith(path, "SubnetId") }
_ref_format_for_prop(path) := "AWS::EC2::NetworkInterface.Id" if { endswith(path, "NetworkInterfaceId") }
_ref_format_for_prop(path) := "AWS::EC2::SecurityGroup.Id" if { endswith(path, "SecurityGroupId") }

default _ref_type_ok(_, _) := false
_ref_type_ok("AWS::EC2::VPC", "AWS::EC2::VPC.Id") := true
_ref_type_ok("AWS::EC2::Subnet", "AWS::EC2::Subnet.Id") := true
_ref_type_ok("AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroup.Id") := true
_ref_type_ok("AWS::EC2::NetworkInterface", "AWS::EC2::NetworkInterface.Id") := true
