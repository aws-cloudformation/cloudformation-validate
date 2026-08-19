package resources

import rego.v1

# W3671: Iops is silently ignored for certain EBS volume types in block device mappings
_bdm_iops_ignored_types := {t | some t in data.rule_tables.ebs_iops_ignored_volume_types}

# Single-wildcard paths
violation contains make_diag_at("W3671", "WARN", name,
    sprintf("%s.%d.Ebs.Iops", [base_path, i]),
    sprintf("Iops is ignored when VolumeType is '%s'", [vtype])) if {
    some rtype, base_path in _ebs_bdm_paths
    some name in resources_of_type(rtype)
    bdms := resolve(name, base_path)
    is_array(bdms)
    some i, bdm in bdms
    ebs := object.get(bdm, "Ebs", null)
    ebs != null
    object.get(ebs, "Iops", null) != null
    vtype := object.get(ebs, "VolumeType", null)
    is_string(vtype)
    vtype in _bdm_iops_ignored_types
}

# Double-wildcard paths (e.g. SpotFleet)
violation contains make_diag_at("W3671", "WARN", name,
    sprintf("%s.%d.%s.%d.Ebs.Iops", [info.outer_prefix, s, info.middle_segments, i]),
    sprintf("Iops is ignored when VolumeType is '%s'", [vtype])) if {
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
    object.get(ebs, "Iops", null) != null
    vtype := object.get(ebs, "VolumeType", null)
    is_string(vtype)
    vtype in _bdm_iops_ignored_types
}
