package resources

import rego.v1

_route53_scenario_reachable(name, conditions) if {
    resource_condition := object.get(input.resources[name], "condition", "")
    resource_condition == ""
    is_satisfiable(conditions)
}

_route53_scenario_reachable(name, conditions) if {
    resource_condition := object.get(input.resources[name], "condition", "")
    resource_condition != ""
    object.get(conditions, resource_condition, true) == true
    is_satisfiable(object.union(conditions, {resource_condition: true}))
}

_route53_record_identity_scenarios(name) := {scenario |
    some scenario in properties_scenarios(name, ["HostedZoneName", "Name", "Type"])
    _route53_scenario_reachable(name, scenario.conditions)
}

_route53_typed_record_scenarios(name) := {scenario |
    some type_scenario in resolve_scenarios(name, "Properties.Type")
    some record_scenario in list_member_scenarios(name, "Properties.ResourceRecords")
    _scenario_conditions_compatible(name, type_scenario.conditions, record_scenario.conditions)
    conditions := object.union(type_scenario.conditions, record_scenario.conditions)
    scenario := {
        "record_type": type_scenario.value,
        "record": record_scenario.value,
        "record_index": record_scenario.index,
        "conditions": conditions,
    }
}

_route53_cname_multiple_record_source_paths(name) := {source_path |
    some type_scenario in resolve_scenarios(name, "Properties.Type")
    type_scenario.value == "CNAME"
    some source_path in list_member_pair_source_paths(
        name, "Properties.ResourceRecords", type_scenario.conditions)
}

_route53_group_typed_record_scenarios(name) := {scenario |
    some record_set_scenario in list_member_scenarios(name, "Properties.RecordSets")
    is_object(record_set_scenario.value)
    set_index := record_set_scenario.index
    type_path := sprintf("Properties.RecordSets.%d.Type", [set_index])
    records_path := sprintf("Properties.RecordSets.%d.ResourceRecords", [set_index])
    some type_scenario in resolve_scenarios(name, type_path)
    _scenario_conditions_compatible(name, record_set_scenario.conditions, type_scenario.conditions)
    record_set_and_type := object.union(record_set_scenario.conditions, type_scenario.conditions)
    some record_scenario in list_member_scenarios(name, records_path)
    _scenario_conditions_compatible(name, record_set_and_type, record_scenario.conditions)
    conditions := object.union(record_set_and_type, record_scenario.conditions)
    scenario := {
        "record_set_index": set_index,
        "record_type": type_scenario.value,
        "record": record_scenario.value,
        "record_index": record_scenario.index,
        "conditions": conditions,
    }
}

_route53_group_cname_multiple_record_scenarios(name) := {scenario |
    some record_set_scenario in list_member_scenarios(name, "Properties.RecordSets")
    is_object(record_set_scenario.value)
    set_index := record_set_scenario.index
    type_path := sprintf("Properties.RecordSets.%d.Type", [set_index])
    records_path := sprintf("Properties.RecordSets.%d.ResourceRecords", [set_index])
    some type_scenario in resolve_scenarios(name, type_path)
    type_scenario.value == "CNAME"
    _scenario_conditions_compatible(name, record_set_scenario.conditions, type_scenario.conditions)
    record_set_and_type := object.union(record_set_scenario.conditions, type_scenario.conditions)
    some source_path in list_member_pair_source_paths(name, records_path, record_set_and_type)
    scenario := {
        "record_set_index": set_index,
        "source_path": source_path,
    }
}

# E3023: Route53 RecordSet - A record must have valid IPv4
violation contains make_diag_at_source("E3023", "ERROR", name,
    property_path,
    source_path,
    sprintf("'%s' is not a valid IPv4 address for record type 'A'", [rec])) if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSet")
    some scenario in _route53_typed_record_scenarios(name)
    scenario.record_type == "A"
    rec := scenario.record
    i := scenario.record_index
    property_path := sprintf("Properties.ResourceRecords.%d", [i])
    source_path := scenario_source_path(name, property_path, scenario.conditions)
    is_string(rec)
    not regex.match(`^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$`, rec)
}

# E3023: Route53 RecordSet - AAAA record must have valid IPv6
# Use a structural check: must have hex groups separated by colons, 
# with proper :: handling. Reject if it doesn't match basic IPv6 structure.
violation contains make_diag_at_source("E3023", "ERROR", name,
    property_path,
    source_path,
    sprintf("'%s' is not a valid IPv6 address for record type 'AAAA'", [rec])) if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSet")
    some scenario in _route53_typed_record_scenarios(name)
    scenario.record_type == "AAAA"
    rec := scenario.record
    i := scenario.record_index
    property_path := sprintf("Properties.ResourceRecords.%d", [i])
    source_path := scenario_source_path(name, property_path, scenario.conditions)
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
violation contains make_diag_at_source("E3023", "ERROR", name,
    "Properties.Name",
    source_path,
    sprintf("CNAME record Name '%s' must not match HostedZoneName '%s' exactly", [rec_name, hz_name])) if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSet")
    some scenario in _route53_record_identity_scenarios(name)
    properties := scenario.properties
    rtype := object.get(properties, "Type", null)
    rtype == "CNAME"
    rec_name := object.get(properties, "Name", null)
    hz_name := object.get(properties, "HostedZoneName", null)
    is_string(rec_name)
    is_string(hz_name)
    trim_suffix(rec_name, ".") == trim_suffix(hz_name, ".")
    source_path := scenario_source_path(name, "Properties.Name", scenario.conditions)
}

# E3023: CNAME records must have at most 1 ResourceRecord
violation contains make_diag_at_source("E3023", "ERROR", name,
    "Properties.ResourceRecords",
    source_path,
    "CNAME records must have at most 1 ResourceRecord") if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSet")
    some source_path in _route53_cname_multiple_record_source_paths(name)
}

# E3023: TXT record values must be double-quoted strings
violation contains make_diag_at_source("E3023", "ERROR", name,
    property_path,
    source_path,
    sprintf("TXT record value '%s' must be enclosed in double quotes", [rec])) if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSet")
    some scenario in _route53_typed_record_scenarios(name)
    scenario.record_type == "TXT"
    rec := scenario.record
    i := scenario.record_index
    property_path := sprintf("Properties.ResourceRecords.%d", [i])
    source_path := scenario_source_path(name, property_path, scenario.conditions)
    is_string(rec)
    not regex.match(`^("[^"]{1,255}" *)*"[^"]{1,255}"$`, rec)
}

# E3023: CAA record format (flag tag "value")
violation contains make_diag_at_source("E3023", "ERROR", name,
    property_path,
    source_path,
    sprintf("CAA record value '%s' must match format: flag tag 'value'", [rec])) if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSet")
    some scenario in _route53_typed_record_scenarios(name)
    scenario.record_type == "CAA"
    rec := scenario.record
    i := scenario.record_index
    property_path := sprintf("Properties.ResourceRecords.%d", [i])
    source_path := scenario_source_path(name, property_path, scenario.conditions)
    is_string(rec)
    not regex.match(`^(0|128)\s([a-zA-Z0-9]+)\s(".+")$`, rec)
}

# E3023: MX record format (priority domain)
violation contains make_diag_at_source("E3023", "ERROR", name,
    property_path,
    source_path,
    sprintf("MX record value '%s' must match format: priority domain", [rec])) if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSet")
    some scenario in _route53_typed_record_scenarios(name)
    scenario.record_type == "MX"
    rec := scenario.record
    i := scenario.record_index
    property_path := sprintf("Properties.ResourceRecords.%d", [i])
    source_path := scenario_source_path(name, property_path, scenario.conditions)
    is_string(rec)
    not regex.match(`^(0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\s\S+$`, rec)
}

# E3023: RecordSetGroup - validate records within RecordSetGroup.RecordSets[]
# A record in RecordSetGroup
violation contains make_diag_at_source("E3023", "ERROR", name,
    property_path,
    source_path,
    sprintf("'%s' is not a valid IPv4 address for record type 'A'", [rec])) if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    some scenario in _route53_group_typed_record_scenarios(name)
    scenario.record_type == "A"
    si := scenario.record_set_index
    ri := scenario.record_index
    rec := scenario.record
    property_path := sprintf("Properties.RecordSets.%d.ResourceRecords.%d", [si, ri])
    source_path := scenario_source_path(name, property_path, scenario.conditions)
    is_string(rec)
    not regex.match(`^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$`, rec)
}

# AAAA record in RecordSetGroup
violation contains make_diag_at_source("E3023", "ERROR", name,
    property_path,
    source_path,
    sprintf("'%s' is not a valid IPv6 address for record type 'AAAA'", [rec])) if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    some scenario in _route53_group_typed_record_scenarios(name)
    scenario.record_type == "AAAA"
    si := scenario.record_set_index
    ri := scenario.record_index
    rec := scenario.record
    property_path := sprintf("Properties.RecordSets.%d.ResourceRecords.%d", [si, ri])
    source_path := scenario_source_path(name, property_path, scenario.conditions)
    is_string(rec)
    not is_valid_ipv6(rec)
}

# TXT record in RecordSetGroup
violation contains make_diag_at_source("E3023", "ERROR", name,
    property_path,
    source_path,
    sprintf("TXT record value '%s' must be enclosed in double quotes", [rec])) if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    some scenario in _route53_group_typed_record_scenarios(name)
    scenario.record_type == "TXT"
    si := scenario.record_set_index
    ri := scenario.record_index
    rec := scenario.record
    property_path := sprintf("Properties.RecordSets.%d.ResourceRecords.%d", [si, ri])
    source_path := scenario_source_path(name, property_path, scenario.conditions)
    is_string(rec)
    not regex.match(`^("[^"]{1,255}" *)*"[^"]{1,255}"$`, rec)
}

# CAA record in RecordSetGroup
violation contains make_diag_at_source("E3023", "ERROR", name,
    property_path,
    source_path,
    sprintf("CAA record value '%s' must match format: flag tag 'value'", [rec])) if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    some scenario in _route53_group_typed_record_scenarios(name)
    scenario.record_type == "CAA"
    si := scenario.record_set_index
    ri := scenario.record_index
    rec := scenario.record
    property_path := sprintf("Properties.RecordSets.%d.ResourceRecords.%d", [si, ri])
    source_path := scenario_source_path(name, property_path, scenario.conditions)
    is_string(rec)
    not regex.match(`^(0|128)\s([a-zA-Z0-9]+)\s(".+")$`, rec)
}

# MX record in RecordSetGroup
violation contains make_diag_at_source("E3023", "ERROR", name,
    property_path,
    source_path,
    sprintf("MX record value '%s' must match format: priority domain", [rec])) if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    some scenario in _route53_group_typed_record_scenarios(name)
    scenario.record_type == "MX"
    si := scenario.record_set_index
    ri := scenario.record_index
    rec := scenario.record
    property_path := sprintf("Properties.RecordSets.%d.ResourceRecords.%d", [si, ri])
    source_path := scenario_source_path(name, property_path, scenario.conditions)
    is_string(rec)
    not regex.match(`^(0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\s\S+$`, rec)
}

# CNAME maxItems in RecordSetGroup
violation contains make_diag_at_source("E3023", "ERROR", name,
    property_path,
    source_path,
    "CNAME records must have at most 1 ResourceRecord") if {
    cfn_rule_active("E3023")
    some name in resources_of_type("AWS::Route53::RecordSetGroup")
    some scenario in _route53_group_cname_multiple_record_scenarios(name)
    si := scenario.record_set_index
    property_path := sprintf("Properties.RecordSets.%d.ResourceRecords", [si])
    source_path := scenario.source_path
}
