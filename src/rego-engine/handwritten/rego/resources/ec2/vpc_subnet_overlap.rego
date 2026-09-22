package resources

import rego.v1

# E3060: VPC subnet CIDR overlap.
# The shared analysis compares subnets that provably belong to the same VPC, in
# every pair of deployment scenarios that can coexist, and emits one finding per
# (later_subnet, earlier_subnet) overlapping pair attributed to the later subnet
# with the earlier as related.
violation contains make_diag_related("E3060", "ERROR", finding.subnetId,
    "Properties.CidrBlock", finding.message,
    [{"resource": finding.earlierSubnetId, "message": finding.earlierSubnetMessage}]) if {
    cfn_rule_active("E3060")
    some finding in overlapping_subnet_findings()
}
