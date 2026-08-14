package best_practices

import rego.v1

# W2508: Security group allows open access to sensitive port
violation contains make_diag_full("W2508", "WARN", name,
    "Properties.SecurityGroupIngress",
    sprintf("Security group allows %s access to sensitive port %d (range %d-%d)", [cidr, port, from_port, to_port]),
    "Restrict the CIDR range to specific IP addresses",
    "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroup"
    some rule in res.properties.SecurityGroupIngress
    cidr := open_cidr(rule)
    from_port := to_number(rule.FromPort)
    to_port := to_number(rule.ToPort)
    some port in data.sensitive_ports
    port >= from_port
    port <= to_port
}

violation contains make_diag_full("W2508", "WARN", name,
    "Properties.SecurityGroupIngress",
    sprintf("Security group allows all traffic from %s - sensitive port %d is exposed", [cidr, port]),
    "Restrict the CIDR range or limit the protocol",
    "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroup"
    some rule in res.properties.SecurityGroupIngress
    cidr := open_cidr(rule)
    rule.IpProtocol == "-1"
    some port in data.sensitive_ports
}

violation contains make_diag_full("W2508", "WARN", name,
    "Properties",
    sprintf("Security group allows %s access to sensitive port %d (range %d-%d)", [cidr, port, from_port, to_port]),
    "Restrict the CIDR range to specific IP addresses",
    "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroupIngress"
    cidr := open_cidr(res.properties)
    from_port := to_number(res.properties.FromPort)
    to_port := to_number(res.properties.ToPort)
    some port in data.sensitive_ports
    port >= from_port
    port <= to_port
}

violation contains make_diag_full("W2508", "WARN", name,
    "Properties",
    sprintf("Security group allows all traffic from %s - sensitive port %d is exposed", [cidr, port]),
    "Restrict the CIDR range or limit the protocol",
    "") if {
    some name, res in input.resources
    res.resourceType == "AWS::EC2::SecurityGroupIngress"
    cidr := open_cidr(res.properties)
    res.properties.IpProtocol == "-1"
    some port in data.sensitive_ports
}

open_cidr(rule) := "0.0.0.0/0" if {
    rule.CidrIp == "0.0.0.0/0"
}

open_cidr(rule) := "::/0" if {
    rule.CidrIpv6 == "::/0"
}
