package resources

import rego.v1

# E3022: Only one SubnetRouteTableAssociation per subnet
violation contains make_diag_related("E3022", "ERROR", name1,
    "Properties.SubnetId",
    sprintf("Subnet '%s' has multiple SubnetRouteTableAssociations — only one is allowed", [subnet_val]),
    [{"resource": name2, "path": "Properties.SubnetId", "message": "conflicting association"}]) if {
    ids := resources_of_type("AWS::EC2::SubnetRouteTableAssociation")
    some i, name1 in ids
    some j, name2 in ids
    i < j
    subnet_val := resolve(name1, "Properties.SubnetId")
    subnet_val2 := resolve(name2, "Properties.SubnetId")
    subnet_val == subnet_val2
    not is_dynamic(name1, "Properties.SubnetId")
}

# E3041: Route53 RecordSet Name must be subdomain of or equal to HostedZoneName
violation contains make_diag_at("E3041", "ERROR", name,
    "Properties.Name",
    sprintf("RecordSet Name '%s' is not a subdomain of HostedZoneName '%s'", [rec_name, hz_name])) if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    rec_name := resolve(name, "Properties.Name")
    hz_name := resolve(name, "Properties.HostedZoneName")
    is_string(rec_name)
    is_string(hz_name)
    not endswith(rec_name, hz_name)
    # Also check without trailing dot
    trimmed_hz := trim_suffix(hz_name, ".")
    trimmed_rec := trim_suffix(rec_name, ".")
    not endswith(trimmed_rec, trimmed_hz)
    trimmed_rec != trimmed_hz
}
