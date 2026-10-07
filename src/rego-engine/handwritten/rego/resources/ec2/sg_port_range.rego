package resources

import rego.v1

# FromPort/ToPort form an ordered port range only for the TCP and UDP
# protocols (named case-insensitively or by IP protocol number 6/17). For
# icmp/icmpv6 the two fields carry the ICMP type and code, where -1 is a
# wildcard, and every other protocol ignores the ports entirely, so no
# ordering constraint applies.
_sg_protocol_has_ordered_port_range(proto) if {
    lower(coerce_to_string(proto)) in {"tcp", "udp", "6", "17"}
}

_sg_inverted_port_range_message(from_port, to_port) := sprintf("FromPort %v is greater than ToPort %v", [from_port, to_port])

_sg_inverted_port_range_fix := "Set FromPort to a value less than or equal to ToPort"

# Inline SecurityGroup rules: FromPort must be <= ToPort for port-range protocols
violation contains make_diag_full("E9002", "ERROR", name,
    sprintf("Properties.%s.%d", [direction, idx]),
    _sg_inverted_port_range_message(from_port, to_port),
    _sg_inverted_port_range_fix,
    "") if {
    cfn_rule_active("E9002")
    some name in resources_of_type("AWS::EC2::SecurityGroup")
    some direction in {"SecurityGroupIngress", "SecurityGroupEgress"}
    some idx, rule in input.resources[name].properties[direction]
    is_object(rule)
    _sg_protocol_has_ordered_port_range(object.get(rule, "IpProtocol", null))
    from_port := coerce_to_integer(object.get(rule, "FromPort", null))
    to_port := coerce_to_integer(object.get(rule, "ToPort", null))
    from_port > to_port
}

# Standalone SecurityGroupIngress/SecurityGroupEgress resources carry one rule
# each at the top level of Properties
violation contains make_diag_full("E9002", "ERROR", name,
    "Properties.FromPort",
    _sg_inverted_port_range_message(from_port, to_port),
    _sg_inverted_port_range_fix,
    "") if {
    cfn_rule_active("E9002")
    some rule_type in {"AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"}
    some name in resources_of_type(rule_type)
    _sg_protocol_has_ordered_port_range(resolve(name, "Properties.IpProtocol"))
    from_port := coerce_to_integer(resolve(name, "Properties.FromPort"))
    to_port := coerce_to_integer(resolve(name, "Properties.ToPort"))
    from_port > to_port
}
