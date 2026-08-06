package resources

import rego.v1

# E3023: Route53 RecordSet - A record must have valid IPv4
violation contains make_diag_at("E3023", "ERROR", name,
    sprintf("Properties.ResourceRecords.%d", [i]),
    sprintf("'%s' is not a valid IPv4 address for record type 'A'", [rec])) if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    rtype := resolve(name, "Properties.Type")
    rtype == "A"
    records := resolve_preserving_conditionals(name, "Properties.ResourceRecords")
    is_array(records)
    some i, rec in records
    is_string(rec)
    not regex.match(`^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$`, rec)
}

# E3023: Route53 RecordSet - AAAA record must have valid IPv6
# Use a structural check: must have hex groups separated by colons, 
# with proper :: handling. Reject if it doesn't match basic IPv6 structure.
violation contains make_diag_at("E3023", "ERROR", name,
    sprintf("Properties.ResourceRecords.%d", [i]),
    sprintf("'%s' is not a valid IPv6 address for record type 'AAAA'", [rec])) if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    rtype := resolve(name, "Properties.Type")
    rtype == "AAAA"
    records := resolve_preserving_conditionals(name, "Properties.ResourceRecords")
    is_array(records)
    some i, rec in records
    is_string(rec)
    not is_valid_ipv6(rec)
}

# IPv6 validation: full form has exactly 8 groups of hex separated by colons.
# Compressed form uses :: to replace one or more groups of zeros. A trailing embedded IPv4 (as in
# the IPv4-mapped form `::ffff:1.2.3.4`) is accepted, matching what the service treats as a valid
# IPv6 address.
is_valid_ipv6(addr) if {
    not contains(addr, "::")
    groups := split(addr, ":")
    _ipv6_groups_valid(groups, 8)
}

is_valid_ipv6(addr) if {
    contains(addr, "::")
    not contains(addr, ":::")
    not _starts_with_single_colon(addr)
    not _ends_with_single_colon(addr)
    parts := split(addr, "::")
    count(parts) == 2
    left := [g | some g in split(parts[0], ":"); g != ""]
    right := [g | some g in split(parts[1], ":"); g != ""]
    _ipv6_side_valid(left)
    _ipv6_side_valid(right)
    _ipv6_group_span(left) + _ipv6_group_span(right) < 8
}

# The number of 16-bit groups a side occupies: a trailing embedded IPv4 counts as two groups.
_ipv6_group_span(groups) := count(groups) + 1 if {
    count(groups) > 0
    _is_ipv4(groups[count(groups) - 1])
}

_ipv6_group_span(groups) := count(groups) if {
    count(groups) == 0
}

_ipv6_group_span(groups) := count(groups) if {
    count(groups) > 0
    not _is_ipv4(groups[count(groups) - 1])
}

# Every group is a hex quad, except the last may be an embedded IPv4 address.
_ipv6_side_valid(groups) if {
    every i, g in groups {
        _ipv6_group_ok(g, i, count(groups))
    }
}

# A full (non-compressed) address must fill exactly `expected` 16-bit groups, counting a trailing
# embedded IPv4 as two.
_ipv6_groups_valid(groups, expected) if {
    _ipv6_side_valid(groups)
    _ipv6_group_span(groups) == expected
}

_ipv6_group_ok(g, i, total) if {
    i == total - 1
    _is_ipv4(g)
}

_ipv6_group_ok(g, _, _) if {
    regex.match(`^[0-9a-fA-F]{1,4}$`, g)
}

_is_ipv4(g) if {
    regex.match(`^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$`, g)
}

_starts_with_single_colon(addr) if {
    startswith(addr, ":")
    not startswith(addr, "::")
}

_ends_with_single_colon(addr) if {
    endswith(addr, ":")
    not endswith(addr, "::")
}

# E3023: Route53 RecordSet - CNAME Name must not match HostedZoneName exactly
violation contains make_diag_at("E3023", "ERROR", name,
    "Properties.Name",
    sprintf("CNAME record Name '%s' must not match HostedZoneName '%s' exactly", [rec_name, hz_name])) if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    rtype := resolve(name, "Properties.Type")
    rtype == "CNAME"
    rec_name := resolve(name, "Properties.Name")
    hz_name := resolve(name, "Properties.HostedZoneName")
    is_string(rec_name)
    is_string(hz_name)
    trim_suffix(rec_name, ".") == trim_suffix(hz_name, ".")
}

# E3023: CNAME records must have at most 1 ResourceRecord
violation contains make_diag_at("E3023", "ERROR", name,
    "Properties.ResourceRecords",
    "CNAME records must have at most 1 ResourceRecord") if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    rtype := resolve(name, "Properties.Type")
    rtype == "CNAME"
    all_vals := resolve_all(name, "Properties.ResourceRecords")
    count(all_vals) > 0
    every val in all_vals { is_array(val); count(val) > 1 }
}

# E3023: TXT record values must be double-quoted strings
violation contains make_diag_at("E3023", "ERROR", name,
    sprintf("Properties.ResourceRecords.%d", [i]),
    sprintf("TXT record value '%s' must be enclosed in double quotes", [rec])) if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    rtype := resolve(name, "Properties.Type")
    rtype == "TXT"
    records := resolve_preserving_conditionals(name, "Properties.ResourceRecords")
    is_array(records)
    some i, rec in records
    is_string(rec)
    not regex.match(`^("[^"]{1,255}" *)*"[^"]{1,255}"$`, rec)
}

# E3023: CAA record format (flag tag "value")
violation contains make_diag_at("E3023", "ERROR", name,
    sprintf("Properties.ResourceRecords.%d", [i]),
    sprintf("CAA record value '%s' must match format: flag tag 'value'", [rec])) if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    rtype := resolve(name, "Properties.Type")
    rtype == "CAA"
    records := resolve_preserving_conditionals(name, "Properties.ResourceRecords")
    is_array(records)
    some i, rec in records
    is_string(rec)
    not regex.match(`^(0|128)\s([a-zA-Z0-9]+)\s(".+")$`, rec)
}

# E3023: MX record format (priority domain)
violation contains make_diag_at("E3023", "ERROR", name,
    sprintf("Properties.ResourceRecords.%d", [i]),
    sprintf("MX record value '%s' must match format: priority domain", [rec])) if {
    some name in resources_of_type("AWS::Route53::RecordSet")
    rtype := resolve(name, "Properties.Type")
    rtype == "MX"
    records := resolve_preserving_conditionals(name, "Properties.ResourceRecords")
    is_array(records)
    some i, rec in records
    is_string(rec)
    not regex.match(`^(0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\s\S+$`, rec)
}

# E3023: RecordSetGroup - validate records within RecordSetGroup.RecordSets[]
# A record in RecordSetGroup
violation contains make_diag_at("E3023", "ERROR", name,
    sprintf("Properties.RecordSets.%d.ResourceRecords.%d", [si, ri]),
    sprintf("'%s' is not a valid IPv4 address for record type 'A'", [rec])) if {
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    rsets := resolve_preserving_conditionals(name, "Properties.RecordSets")
    is_array(rsets)
    some si, rset in rsets
    is_object(rset)
    rset.Type == "A"
    is_array(rset.ResourceRecords)
    some ri, rec in rset.ResourceRecords
    is_string(rec)
    not regex.match(`^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$`, rec)
}

# AAAA record in RecordSetGroup
violation contains make_diag_at("E3023", "ERROR", name,
    sprintf("Properties.RecordSets.%d.ResourceRecords.%d", [si, ri]),
    sprintf("'%s' is not a valid IPv6 address for record type 'AAAA'", [rec])) if {
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    rsets := resolve_preserving_conditionals(name, "Properties.RecordSets")
    is_array(rsets)
    some si, rset in rsets
    is_object(rset)
    rset.Type == "AAAA"
    is_array(rset.ResourceRecords)
    some ri, rec in rset.ResourceRecords
    is_string(rec)
    not is_valid_ipv6(rec)
}

# TXT record in RecordSetGroup
violation contains make_diag_at("E3023", "ERROR", name,
    sprintf("Properties.RecordSets.%d.ResourceRecords.%d", [si, ri]),
    sprintf("TXT record value '%s' must be enclosed in double quotes", [rec])) if {
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    rsets := resolve_preserving_conditionals(name, "Properties.RecordSets")
    is_array(rsets)
    some si, rset in rsets
    is_object(rset)
    rset.Type == "TXT"
    is_array(rset.ResourceRecords)
    some ri, rec in rset.ResourceRecords
    is_string(rec)
    not regex.match(`^("[^"]{1,255}" *)*"[^"]{1,255}"$`, rec)
}

# CAA record in RecordSetGroup
violation contains make_diag_at("E3023", "ERROR", name,
    sprintf("Properties.RecordSets.%d.ResourceRecords.%d", [si, ri]),
    sprintf("CAA record value '%s' must match format: flag tag 'value'", [rec])) if {
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    rsets := resolve_preserving_conditionals(name, "Properties.RecordSets")
    is_array(rsets)
    some si, rset in rsets
    is_object(rset)
    rset.Type == "CAA"
    is_array(rset.ResourceRecords)
    some ri, rec in rset.ResourceRecords
    is_string(rec)
    not regex.match(`^(0|128)\s([a-zA-Z0-9]+)\s(".+")$`, rec)
}

# MX record in RecordSetGroup
violation contains make_diag_at("E3023", "ERROR", name,
    sprintf("Properties.RecordSets.%d.ResourceRecords.%d", [si, ri]),
    sprintf("MX record value '%s' must match format: priority domain", [rec])) if {
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    rsets := resolve_preserving_conditionals(name, "Properties.RecordSets")
    is_array(rsets)
    some si, rset in rsets
    is_object(rset)
    rset.Type == "MX"
    is_array(rset.ResourceRecords)
    some ri, rec in rset.ResourceRecords
    is_string(rec)
    not regex.match(`^(0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\s\S+$`, rec)
}

# CNAME maxItems in RecordSetGroup
violation contains make_diag_at("E3023", "ERROR", name,
    sprintf("Properties.RecordSets.%d.ResourceRecords", [si]),
    "CNAME records must have at most 1 ResourceRecord") if {
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    rsets := resolve_preserving_conditionals(name, "Properties.RecordSets")
    is_array(rsets)
    some si, rset in rsets
    is_object(rset)
    rset.Type == "CNAME"
    is_array(rset.ResourceRecords)
    count(rset.ResourceRecords) > 1
}
