package resources

import rego.v1

# E3715: VirtualName must match ephemeral[0-23] when Ebs is absent
# Single-wildcard paths
violation contains make_diag_at("E3715", "ERROR", name,
    sprintf("%s.%d.VirtualName", [base_path, i]),
    sprintf("'%s' is not a valid ephemeral device name. Expected format is 'ephemeralN' where N is 0-23", [vname])) if {
    some rtype, base_path in _ebs_bdm_paths
    some name in resources_of_type(rtype)
    bdms := resolve(name, base_path)
    is_array(bdms)
    some i, bdm in bdms
    vname := object.get(bdm, "VirtualName", null)
    vname != null
    is_string(vname)
    object.get(bdm, "Ebs", null) == null
    not regex.match(`^ephemeral([0-9]|1[0-9]|2[0-3])$`, vname)
}

# Double-wildcard ephemeral-device locations (for example, SpotFleet)
violation contains make_diag_at("E3715", "ERROR", name,
    sprintf("%s.%d.%s.%d.VirtualName", [info.outer_prefix, s, info.middle_segments, i]),
    sprintf("'%s' is not a valid ephemeral device name. Expected format is 'ephemeralN' where N is 0-23", [vname])) if {
    some rtype, info in _ebs_double_wildcard
    some name in resources_of_type(rtype)
    specs := resolve(name, info.outer_prefix)
    is_array(specs)
    some s, spec in specs
    bdms := object.get(spec, info.middle_path, null)
    is_array(bdms)
    some i, bdm in bdms
    vname := object.get(bdm, "VirtualName", null)
    vname != null
    is_string(vname)
    object.get(bdm, "Ebs", null) == null
    not regex.match(`^ephemeral([0-9]|1[0-9]|2[0-3])$`, vname)
}

# W3698: VirtualName is silently ignored when Ebs is specified in block device mappings
# Single-wildcard paths
violation contains make_diag_at("W3698", "WARN", name,
    sprintf("%s.%d.VirtualName", [base_path, i]),
    "VirtualName is ignored when Ebs is specified") if {
    some rtype, base_path in _ebs_bdm_paths
    some name in resources_of_type(rtype)
    bdms := resolve(name, base_path)
    is_array(bdms)
    some i, bdm in bdms
    object.get(bdm, "VirtualName", null) != null
    object.get(bdm, "Ebs", null) != null
}

# Double-wildcard ignored-VirtualName locations (for example, SpotFleet)
violation contains make_diag_at("W3698", "WARN", name,
    sprintf("%s.%d.%s.%d.VirtualName", [info.outer_prefix, s, info.middle_segments, i]),
    "VirtualName is ignored when Ebs is specified") if {
    some rtype, info in _ebs_double_wildcard
    some name in resources_of_type(rtype)
    specs := resolve(name, info.outer_prefix)
    is_array(specs)
    some s, spec in specs
    bdms := object.get(spec, info.middle_path, null)
    is_array(bdms)
    some i, bdm in bdms
    object.get(bdm, "VirtualName", null) != null
    object.get(bdm, "Ebs", null) != null
}
