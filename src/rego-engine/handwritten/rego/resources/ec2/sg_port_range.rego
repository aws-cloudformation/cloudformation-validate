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

# SecurityGroup FromPort must be <= ToPort for port-range protocols
violation contains make_diag_full("E9002", "ERROR", name,
    "Properties.SecurityGroupIngress",
    sprintf("FromPort %v is greater than ToPort %v", [from_port, to_port]),
    "Set FromPort to a value less than or equal to ToPort",
    "") if {
    some name in resources_of_type("AWS::EC2::SecurityGroup")
    some key, rule in input.resources[name].properties.SecurityGroupIngress
    is_object(rule)
    _sg_protocol_has_ordered_port_range(object.get(rule, "IpProtocol", null))
    from_port := coerce_to_integer(object.get(rule, "FromPort", null))
    to_port := coerce_to_integer(object.get(rule, "ToPort", null))
    from_port > to_port
}
