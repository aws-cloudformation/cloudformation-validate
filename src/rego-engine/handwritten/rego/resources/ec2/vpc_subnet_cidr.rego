package resources

import rego.v1

# E3059: Subnet CIDR must be within VPC CIDR
violation contains make_diag_at("E3059", "ERROR", subnet_name,
    "Properties.CidrBlock",
    sprintf("Subnet CIDR '%s' is not within VPC CIDR '%s'", [sub_cidr, vpc_cidr])) if {
    cfn_rule_active("E3059")
    some subnet_name in resources_of_type("AWS::EC2::Subnet")
    vpc_name := follow_ref(subnet_name, "Properties.VpcId")
    input.resources[vpc_name].resourceType == "AWS::EC2::VPC"
    vpc_cidr := resolve(vpc_name, "Properties.CidrBlock")
    is_string(vpc_cidr)
    sub_cidr := resolve(subnet_name, "Properties.CidrBlock")
    is_string(sub_cidr)
    not ip_subnet_of(sub_cidr, vpc_cidr)
}
