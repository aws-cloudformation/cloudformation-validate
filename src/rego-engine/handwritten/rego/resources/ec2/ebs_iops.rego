package resources

import rego.v1

# E3671: an EBS block device mapping's Iops must satisfy the per-VolumeType
# rules - io1/io2 require Iops and bound it, gp3 bounds it without requiring it.
# This applies to the BlockDeviceMappings[*].Ebs blocks of launch configurations,
# instances, launch templates, spot fleets, and OpsWorks instances - not to a
# standalone AWS::EC2::Volume (whose rules are enforced by the resource schema).

# Build the resource type → base BDM path map from the table.
# Paths are of the form "Resources/<type>/Properties/.../BlockDeviceMappings/*/Ebs"
# We extract the type and the base path up to but NOT including the /*/Ebs suffix.
_ebs_bdm_paths[rtype] := base_path if {
    some raw_path in data.rule_tables.ebs_iops_property_paths
    parts := split(raw_path, "/")
    count(parts) > 2
    parts[0] == "Resources"
    rtype := parts[1]
    _wildcard_count(parts) == 1
    prop_parts := array.slice(parts, 2, count(parts))
    star_idx := _first_star_idx(prop_parts)
    base_parts := array.slice(prop_parts, 0, star_idx)
    base_path := concat(".", base_parts)
}

# Double-wildcard paths (e.g. SpotFleet): outer_prefix/*/middle/*/Ebs
# Yields the path used for nested lookup and its dotted diagnostic form.
_ebs_double_wildcard[rtype] := {"outer_prefix": outer_prefix, "middle_path": middle_parts, "middle_segments": middle_segs} if {
    some raw_path in data.rule_tables.ebs_iops_property_paths
    parts := split(raw_path, "/")
    count(parts) > 2
    parts[0] == "Resources"
    rtype := parts[1]
    _wildcard_count(parts) == 2
    prop_parts := array.slice(parts, 2, count(parts))
    first_star := _first_star_idx(prop_parts)
    outer_parts := array.slice(prop_parts, 0, first_star)
    outer_prefix := concat(".", outer_parts)
    # Segments between the two wildcards: slice from first_star+1, find next star
    after_first := array.slice(prop_parts, first_star + 1, count(prop_parts))
    second_star := _first_star_idx(after_first)
    middle_parts := array.slice(after_first, 0, second_star)
    middle_segs := concat(".", middle_parts)
}

_wildcard_count(parts) := count([p | some p in parts; p == "*"])

# Find the minimum index in arr where arr[idx] == "*"
_first_star_idx(arr) := min_idx if {
    stars := [idx | some idx, v in arr; v == "*"]
    count(stars) > 0
    min_idx := min(stars)
}

# (min, max, required) Iops bounds per volume type.
_ebs_iops_bounds := {
    "io1": {"min": 100, "max": 64000, "required": true},
    "io2": {"min": 100, "max": 256000, "required": true},
    "gp3": {"min": 3000, "max": 16000, "required": false},
}

# --- Single-wildcard BlockDeviceMappings locations ---

# Iops required but absent (io1/io2).
violation contains make_diag_at("E3671", "ERROR", name,
    sprintf("%s.%d.Ebs.Iops", [base_path, i]),
    sprintf("'Iops' is a required property when 'VolumeType' has a value of '%s'", [vtype])) if {
    cfn_rule_active("E3671")
    some rtype, base_path in _ebs_bdm_paths
    some name in resources_of_type(rtype)
    bdms := resolve(name, base_path)
    is_array(bdms)
    some i, bdm in bdms
    ebs := object.get(bdm, "Ebs", null)
    ebs != null
    vtype := object.get(ebs, "VolumeType", null)
    _ebs_iops_bounds[vtype].required == true
    object.get(ebs, "Iops", null) == null
}

# Iops below the minimum for its VolumeType.
violation contains make_diag_at("E3671", "ERROR", name,
    sprintf("%s.%d.Ebs.Iops", [base_path, i]),
    sprintf("%d is less than the minimum of %d", [iops, bounds.min])) if {
    cfn_rule_active("E3671")
    some rtype, base_path in _ebs_bdm_paths
    some name in resources_of_type(rtype)
    bdms := resolve(name, base_path)
    is_array(bdms)
    some i, bdm in bdms
    ebs := object.get(bdm, "Ebs", null)
    ebs != null
    iops_path := sprintf("%s.%d.Ebs.Iops", [base_path, i])
    not is_from_parameter(name, iops_path)
    not is_from_intrinsic(name, iops_path)
    bounds := _ebs_iops_bounds[object.get(ebs, "VolumeType", null)]
    iops := coerce_to_number(object.get(ebs, "Iops", null))
    iops < bounds.min
}

# Iops above the maximum for its VolumeType.
violation contains make_diag_at("E3671", "ERROR", name,
    sprintf("%s.%d.Ebs.Iops", [base_path, i]),
    sprintf("%d is greater than the maximum of %d", [iops, bounds.max])) if {
    cfn_rule_active("E3671")
    some rtype, base_path in _ebs_bdm_paths
    some name in resources_of_type(rtype)
    bdms := resolve(name, base_path)
    is_array(bdms)
    some i, bdm in bdms
    ebs := object.get(bdm, "Ebs", null)
    ebs != null
    iops_path := sprintf("%s.%d.Ebs.Iops", [base_path, i])
    not is_from_parameter(name, iops_path)
    not is_from_intrinsic(name, iops_path)
    bounds := _ebs_iops_bounds[object.get(ebs, "VolumeType", null)]
    iops := coerce_to_number(object.get(ebs, "Iops", null))
    iops > bounds.max
}

# --- Double-wildcard locations (e.g. SpotFleet) ---
# Resolved from ebs_iops_property_paths without hardcoded type/path literals.

violation contains make_diag_at("E3671", "ERROR", name,
    sprintf("%s.%d.%s.%d.Ebs.Iops", [info.outer_prefix, s, info.middle_segments, i]),
    sprintf("'Iops' is a required property when 'VolumeType' has a value of '%s'", [vtype])) if {
    cfn_rule_active("E3671")
    some rtype, info in _ebs_double_wildcard
    some name in resources_of_type(rtype)
    specs := resolve(name, info.outer_prefix)
    is_array(specs)
    some s, spec in specs
    bdms := object.get(spec, info.middle_path, null)
    is_array(bdms)
    some i, bdm in bdms
    ebs := object.get(bdm, "Ebs", null)
    ebs != null
    vtype := object.get(ebs, "VolumeType", null)
    _ebs_iops_bounds[vtype].required == true
    object.get(ebs, "Iops", null) == null
}

violation contains make_diag_at("E3671", "ERROR", name,
    sprintf("%s.%d.%s.%d.Ebs.Iops", [info.outer_prefix, s, info.middle_segments, i]),
    sprintf("%d is less than the minimum of %d", [iops, bounds.min])) if {
    cfn_rule_active("E3671")
    some rtype, info in _ebs_double_wildcard
    some name in resources_of_type(rtype)
    specs := resolve(name, info.outer_prefix)
    is_array(specs)
    some s, spec in specs
    bdms := object.get(spec, info.middle_path, null)
    is_array(bdms)
    some i, bdm in bdms
    ebs := object.get(bdm, "Ebs", null)
    ebs != null
    iops_path := sprintf("%s.%d.%s.%d.Ebs.Iops", [info.outer_prefix, s, info.middle_segments, i])
    not is_from_parameter(name, iops_path)
    not is_from_intrinsic(name, iops_path)
    bounds := _ebs_iops_bounds[object.get(ebs, "VolumeType", null)]
    iops := coerce_to_number(object.get(ebs, "Iops", null))
    iops < bounds.min
}

violation contains make_diag_at("E3671", "ERROR", name,
    sprintf("%s.%d.%s.%d.Ebs.Iops", [info.outer_prefix, s, info.middle_segments, i]),
    sprintf("%d is greater than the maximum of %d", [iops, bounds.max])) if {
    cfn_rule_active("E3671")
    some rtype, info in _ebs_double_wildcard
    some name in resources_of_type(rtype)
    specs := resolve(name, info.outer_prefix)
    is_array(specs)
    some s, spec in specs
    bdms := object.get(spec, info.middle_path, null)
    is_array(bdms)
    some i, bdm in bdms
    ebs := object.get(bdm, "Ebs", null)
    ebs != null
    iops_path := sprintf("%s.%d.%s.%d.Ebs.Iops", [info.outer_prefix, s, info.middle_segments, i])
    not is_from_parameter(name, iops_path)
    not is_from_intrinsic(name, iops_path)
    bounds := _ebs_iops_bounds[object.get(ebs, "VolumeType", null)]
    iops := coerce_to_number(object.get(ebs, "Iops", null))
    iops > bounds.max
}
