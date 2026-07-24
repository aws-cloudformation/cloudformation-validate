package resources

import rego.v1

# Protocols whose FromPort/ToPort carry an ICMP type and code rather than an
# ordered port range, so the "FromPort <= ToPort" check does not apply (e.g.
# type 8 / code -1 is a valid echo-request rule). Covers icmp (protocol 1)
# and icmpv6 (protocol 58) in string and numeric forms.
# https://github.com/aws-cloudformation/cloudformation-validate/issues/226
_sg_icmp_protocol_strings := {"icmp", "icmpv6", "1", "58"}

_sg_icmp_protocol_numbers := {1, 58}

_sg_icmp_protocol(proto) if {
    is_string(proto)
    lower(proto) in _sg_icmp_protocol_strings
}

_sg_icmp_protocol(proto) if {
    is_number(proto)
    proto in _sg_icmp_protocol_numbers
}

# E9002: SecurityGroup FromPort must be <= ToPort
violation contains make_diag_full("E9002", "ERROR", name,
    "Properties.SecurityGroupIngress",
    sprintf("FromPort %v is greater than ToPort %v", [from_port, to_port]),
    "Set FromPort to a value less than or equal to ToPort",
    "") if {
    some name in resources_of_type("AWS::EC2::SecurityGroup")
    some key, rule in input.resources[name].properties.SecurityGroupIngress
    is_object(rule)
    not _sg_icmp_protocol(object.get(rule, "IpProtocol", null))
    from_port := coerce_to_integer(object.get(rule, "FromPort", null))
    to_port := coerce_to_integer(object.get(rule, "ToPort", null))
    from_port > to_port
}
