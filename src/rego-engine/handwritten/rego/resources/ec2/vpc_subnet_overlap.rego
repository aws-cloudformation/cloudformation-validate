package resources

import rego.v1

# E3060: VPC subnet CIDR overlap.
# Emits one diagnostic per (later_subnet, earlier_subnet) overlapping pair. A later
# subnet that overlaps with K earlier subnets produces K findings (each attributed
# to the later subnet, with the earlier as related).
violation contains make_diag_related("E3060", "ERROR", b_name,
    "Properties.CidrBlock",
    sprintf("'%s' overlaps with '%s'", [b_cidr, a_cidr]),
    [{"resource": a_name, "message": sprintf("Overlapping subnet CIDR %s", [a_cidr])}]) if {
    subnets := resources_of_type("AWS::EC2::Subnet")
    some b_idx, b_name in subnets
    b_idx > 0
    not is_from_parameter(b_name, "Properties.CidrBlock")
    b_cidr := resolve(b_name, "Properties.CidrBlock")
    is_string(b_cidr)
    b_vpc := resolve(b_name, "Properties.VpcId")
    some a_idx
    a_idx < b_idx
    a_name := subnets[a_idx]
    conditions_compatible(a_name, b_name)
    not is_from_parameter(a_name, "Properties.CidrBlock")
    resolve(a_name, "Properties.VpcId") == b_vpc
    a_cidr := resolve(a_name, "Properties.CidrBlock")
    is_string(a_cidr)
    ip_overlaps(a_cidr, b_cidr)
}
