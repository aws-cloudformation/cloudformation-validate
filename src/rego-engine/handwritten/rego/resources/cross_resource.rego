package resources

import rego.v1

# EC2 allows exactly one route table per subnet. The shared detector preserves
# authored Ref/GetAtt identity and returns one finding per clashing association.
violation contains make_diag_full("E3022", "ERROR", finding.resourceId,
    "Properties.SubnetId", finding.message,
    "Associate each subnet with exactly one route table", "") if {
    some finding in duplicate_subnet_route_table_associations()
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
