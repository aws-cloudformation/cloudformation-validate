# Network exposure: security group rules from every declaration form, subnet CIDR consistency with the owning VPC (pairwise overlap under compatible conditions), network ACL entries, and VPC flow logs.
package custom_network

import rego.v1

_world := {"0.0.0.0/0", "::/0"}

_sensitive_ports := {21, 22, 23, 25, 1433, 1521, 2049, 3306, 3389, 5432, 5601, 6379, 8020, 9200, 9300, 11211, 27017, 50070}

ingress_rules contains {"resource": name, "path": sprintf("Properties.SecurityGroupIngress.%d", [i]), "rule": rule} if {
	some name, res in input.resources
	res.resourceType == "AWS::EC2::SecurityGroup"
	is_array(res.properties.SecurityGroupIngress)
	some i, rule in res.properties.SecurityGroupIngress
	is_object(rule)
}

ingress_rules contains {"resource": name, "path": "Properties", "rule": res.properties} if {
	some name, res in input.resources
	res.resourceType == "AWS::EC2::SecurityGroupIngress"
	is_object(res.properties)
}

_open_to_world(rule) if _world[rule.CidrIp]

_open_to_world(rule) if _world[rule.CidrIpv6]

_all_protocols(rule) if rule.IpProtocol in {"-1", -1}

_port_range(rule) := [0, 65535] if _all_protocols(rule)

_port_range(rule) := [from, to] if {
	not _all_protocols(rule)
	from := coerce_to_integer(rule.FromPort)
	to := coerce_to_integer(rule.ToPort)
}

subnets contains {"resource": name, "cidr": cidr, "vpc": vpc} if {
	some name, res in input.resources
	res.resourceType == "AWS::EC2::Subnet"
	cidr := res.properties.CidrBlock
	is_string(cidr)
	is_valid_cidr_strict(cidr)
	vpc := _vpc_key(res.properties.VpcId)
}

_vpc_key(value) := value.__ref if value.__kind == "resource"

_vpc_key(value) := value if is_string(value)

_egress(entry) if entry.Egress == true

_egress(entry) if entry.Egress == "true"

_entry_open_to_world(entry) if _world[entry.CidrBlock]

_entry_open_to_world(entry) if _world[entry.Ipv6CidrBlock]

_has_flow_log(vpc) if {
	some _, res in input.resources
	res.resourceType == "AWS::EC2::FlowLog"
	res.properties.ResourceId.__ref == vpc
}

violation contains make_diag_at("network.security-group-open-to-world-all-traffic", "ERROR", r.resource, r.path, "ingress rule allows all traffic on every port from any address") if {
	some r in ingress_rules
	_open_to_world(r.rule)
	_all_protocols(r.rule)
}

violation contains make_diag_at("network.security-group-open-to-world-sensitive-port", "ERROR", r.resource, r.path, sprintf("ingress rule exposes port %d to any address", [port])) if {
	some r in ingress_rules
	_open_to_world(r.rule)
	not _all_protocols(r.rule)
	[from, to] := _port_range(r.rule)
	some port in _sensitive_ports
	port >= from
	port <= to
}

violation contains make_diag_at("network.security-group-open-to-world-wide-range", "WARN", r.resource, r.path, sprintf("ingress rule opens %d ports (%d-%d) to any address", [(to - from) + 1, from, to])) if {
	some r in ingress_rules
	_open_to_world(r.rule)
	not _all_protocols(r.rule)
	[from, to] := _port_range(r.rule)
	to - from >= 1000
}

violation contains make_diag_at("network.subnet-outside-vpc-cidr", "ERROR", s.resource, "Properties.CidrBlock", sprintf("subnet CIDR %s is not inside the CIDR %s of VPC %s", [s.cidr, vpc_cidr, s.vpc])) if {
	some s in subnets
	vpc := input.resources[s.vpc]
	vpc.resourceType == "AWS::EC2::VPC"
	vpc_cidr := vpc.properties.CidrBlock
	is_string(vpc_cidr)
	is_valid_cidr_strict(vpc_cidr)
	not ip_subnet_of(s.cidr, vpc_cidr)
}

violation contains make_diag_at("network.subnet-cidr-overlap", "ERROR", a.resource, "Properties.CidrBlock", sprintf("subnet CIDR %s overlaps %s (%s) in VPC %s", [a.cidr, b.resource, b.cidr, a.vpc])) if {
	some a in subnets
	some b in subnets
	a.vpc == b.vpc
	a.resource < b.resource
	ip_overlaps(a.cidr, b.cidr)
	conditions_compatible(a.resource, b.resource)
}

violation contains make_diag("network.network-acl-allows-all-ingress", "WARN", name, "network ACL entry allows all inbound traffic from any address") if {
	some name, res in input.resources
	res.resourceType == "AWS::EC2::NetworkAclEntry"
	entry := res.properties
	lower(entry.RuleAction) == "allow"
	entry.Protocol in {"-1", -1}
	not _egress(entry)
	_entry_open_to_world(entry)
}

violation contains make_diag("network.vpc-flow-logs-missing", "INFO", name, "VPC has no AWS::EC2::FlowLog resource capturing its traffic") if {
	some name, res in input.resources
	res.resourceType == "AWS::EC2::VPC"
	not _has_flow_log(name)
}
