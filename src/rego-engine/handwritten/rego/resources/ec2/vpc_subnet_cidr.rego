package resources

import rego.v1

# E3059: Subnet CIDR must be within one of the VPC's IPv4 networks.
# The shared analysis evaluates every deployment scenario of the subnet's
# CidrBlock against the VPC's own CidrBlock plus its VPCCidrBlock attachments,
# and stays silent when any of those networks is only known at deployment.
violation contains make_diag_at("E3059", "ERROR", finding.subnetId,
    "Properties.CidrBlock", finding.message) if {
    cfn_rule_active("E3059")
    some finding in subnets_outside_vpc_findings()
}
