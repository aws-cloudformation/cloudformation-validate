package resources

import rego.v1

# Protocols where FromPort/ToPort are meaningful
_sg_port_required_protocols := {"1", "icmp", "6", "tcp", "17", "udp", "TCP", "UDP", "ICMP"}
_sg_port_required_numbers := {1, 6, 17}

_sg_protocol_requires_ports(proto) if {
    is_string(proto)
    proto in _sg_port_required_protocols
}

_sg_protocol_requires_ports(proto) if {
    is_number(proto)
    proto in _sg_port_required_numbers
}

# E3687: FromPort/ToPort are required when IpProtocol is tcp/udp/icmp
violation contains make_diag_full("E3687", "ERROR", name,
    sprintf("Properties.SecurityGroupIngress.%d", [idx]),
    sprintf("['FromPort', 'ToPort'] are required properties when using 'IpProtocol' value %s", [proto]),
    "", "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroup"
    some idx, rule in res.properties.SecurityGroupIngress
    is_object(rule)
    proto := rule.IpProtocol
    _sg_protocol_requires_ports(proto)
    not _sg_has_port(rule)
}

violation contains make_diag_full("E3687", "ERROR", name,
    sprintf("Properties.SecurityGroupEgress.%d", [idx]),
    sprintf("['FromPort', 'ToPort'] are required properties when using 'IpProtocol' value %s", [proto]),
    "", "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroup"
    some idx, rule in res.properties.SecurityGroupEgress
    is_object(rule)
    proto := rule.IpProtocol
    _sg_protocol_requires_ports(proto)
    not _sg_has_port(rule)
}

violation contains make_diag_full("E3687", "ERROR", name,
    "Properties",
    sprintf("['FromPort', 'ToPort'] are required properties when using 'IpProtocol' value %s", [proto]),
    "", "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroupIngress"
    proto := resolve(name, "Properties.IpProtocol")
    _sg_protocol_requires_ports(proto)
    not _sg_has_standalone_port(name)
}

violation contains make_diag_full("E3687", "ERROR", name,
    "Properties",
    sprintf("['FromPort', 'ToPort'] are required properties when using 'IpProtocol' value %s", [proto]),
    "", "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroupEgress"
    proto := resolve(name, "Properties.IpProtocol")
    _sg_protocol_requires_ports(proto)
    not _sg_has_standalone_port(name)
}

# W3687: FromPort/ToPort are ignored when IpProtocol is not tcp/udp/icmp
violation contains make_diag_full("W3687", "WARN", name,
    sprintf("Properties.SecurityGroupIngress.%d.FromPort", [idx]),
    sprintf("['FromPort', 'ToPort'] are ignored when using 'IpProtocol' value '%s'", [proto]),
    "", "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroup"
    some idx, rule in res.properties.SecurityGroupIngress
    is_object(rule)
    proto := rule.IpProtocol
    _sg_protocol_ignores_ports(proto)
    _sg_has_port(rule)
}

violation contains make_diag_full("W3687", "WARN", name,
    sprintf("Properties.SecurityGroupEgress.%d.FromPort", [idx]),
    sprintf("['FromPort', 'ToPort'] are ignored when using 'IpProtocol' value '%s'", [proto]),
    "", "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroup"
    some idx, rule in res.properties.SecurityGroupEgress
    is_object(rule)
    proto := rule.IpProtocol
    _sg_protocol_ignores_ports(proto)
    _sg_has_port(rule)
}

violation contains make_diag_full("W3687", "WARN", name,
    "Properties.FromPort",
    sprintf("['FromPort', 'ToPort'] are ignored when using 'IpProtocol' value '%s'", [proto]),
    "", "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroupIngress"
    proto := resolve(name, "Properties.IpProtocol")
    _sg_protocol_ignores_ports(proto)
    _sg_has_standalone_port(name)
}

violation contains make_diag_full("W3687", "WARN", name,
    "Properties.FromPort",
    sprintf("['FromPort', 'ToPort'] are ignored when using 'IpProtocol' value '%s'", [proto]),
    "", "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroupEgress"
    proto := resolve(name, "Properties.IpProtocol")
    _sg_protocol_ignores_ports(proto)
    _sg_has_standalone_port(name)
}

_sg_protocol_ignores_ports(proto) if {
    is_string(proto)
    not proto in {"1", "icmp", "6", "tcp", "17", "udp", "TCP", "UDP", "ICMP"}
}

_sg_protocol_ignores_ports(proto) if {
    is_number(proto)
    not proto in {1, 6, 17}
}

_sg_has_port(rule) if { object.get(rule, "FromPort", null) != null }
_sg_has_port(rule) if { object.get(rule, "ToPort", null) != null }

_sg_has_standalone_port(name) if { resolve(name, "Properties.FromPort") != null }
_sg_has_standalone_port(name) if { resolve(name, "Properties.ToPort") != null }
