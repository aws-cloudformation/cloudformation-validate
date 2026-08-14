package resources

import rego.v1

# E3671: an EBS block device mapping's Iops must satisfy the per-VolumeType
# rules - io1/io2 require Iops and bound it, gp3 bounds it without requiring it.
# This applies to the BlockDeviceMappings[*].Ebs blocks of launch configurations,
# instances, launch templates, spot fleets, and OpsWorks instances - not to a
# standalone AWS::EC2::Volume (whose rules are enforced by the resource schema).

_ebs_bdm_paths := {
    "AWS::EC2::Instance": "Properties.BlockDeviceMappings",
    "AWS::AutoScaling::LaunchConfiguration": "Properties.BlockDeviceMappings",
    "AWS::OpsWorks::Instance": "Properties.BlockDeviceMappings",
    "AWS::EC2::LaunchTemplate": "Properties.LaunchTemplateData.BlockDeviceMappings",
}

# (min, max, required) Iops bounds per volume type.
_ebs_iops_bounds := {
    "io1": {"min": 100, "max": 64000, "required": true},
    "io2": {"min": 100, "max": 256000, "required": true},
    "gp3": {"min": 3000, "max": 16000, "required": false},
}

# --- Base BlockDeviceMappings locations ---

# Iops required but absent (io1/io2).
violation contains make_diag_at("E3671", "ERROR", name,
    sprintf("%s.%d.Ebs.Iops", [base_path, i]),
    sprintf("'Iops' is a required property when 'VolumeType' has a value of '%s'", [vtype])) if {
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

# Iops below the minimum for its VolumeType. The bound only applies to a literal
# Iops - a value supplied via a parameter Ref/intrinsic has no known value at
# validation time, so it is not folded into the check.
violation contains make_diag_at("E3671", "ERROR", name,
    sprintf("%s.%d.Ebs.Iops", [base_path, i]),
    sprintf("%d is less than the minimum of %d", [iops, bounds.min])) if {
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

# --- SpotFleet nests its mappings under each launch specification ---

violation contains make_diag_at("E3671", "ERROR", name,
    sprintf("Properties.SpotFleetRequestConfigData.LaunchSpecifications.%d.BlockDeviceMappings.%d.Ebs.Iops", [s, i]),
    sprintf("'Iops' is a required property when 'VolumeType' has a value of '%s'", [vtype])) if {
    some name in resources_of_type("AWS::EC2::SpotFleet")
    specs := resolve(name, "Properties.SpotFleetRequestConfigData.LaunchSpecifications")
    is_array(specs)
    some s, spec in specs
    bdms := object.get(spec, "BlockDeviceMappings", null)
    is_array(bdms)
    some i, bdm in bdms
    ebs := object.get(bdm, "Ebs", null)
    ebs != null
    vtype := object.get(ebs, "VolumeType", null)
    _ebs_iops_bounds[vtype].required == true
    object.get(ebs, "Iops", null) == null
}

violation contains make_diag_at("E3671", "ERROR", name,
    sprintf("Properties.SpotFleetRequestConfigData.LaunchSpecifications.%d.BlockDeviceMappings.%d.Ebs.Iops", [s, i]),
    sprintf("%d is less than the minimum of %d", [iops, bounds.min])) if {
    some name in resources_of_type("AWS::EC2::SpotFleet")
    specs := resolve(name, "Properties.SpotFleetRequestConfigData.LaunchSpecifications")
    is_array(specs)
    some s, spec in specs
    bdms := object.get(spec, "BlockDeviceMappings", null)
    is_array(bdms)
    some i, bdm in bdms
    ebs := object.get(bdm, "Ebs", null)
    ebs != null
    iops_path := sprintf("Properties.SpotFleetRequestConfigData.LaunchSpecifications.%d.BlockDeviceMappings.%d.Ebs.Iops", [s, i])
    not is_from_parameter(name, iops_path)
    not is_from_intrinsic(name, iops_path)
    bounds := _ebs_iops_bounds[object.get(ebs, "VolumeType", null)]
    iops := coerce_to_number(object.get(ebs, "Iops", null))
    iops < bounds.min
}

violation contains make_diag_at("E3671", "ERROR", name,
    sprintf("Properties.SpotFleetRequestConfigData.LaunchSpecifications.%d.BlockDeviceMappings.%d.Ebs.Iops", [s, i]),
    sprintf("%d is greater than the maximum of %d", [iops, bounds.max])) if {
    some name in resources_of_type("AWS::EC2::SpotFleet")
    specs := resolve(name, "Properties.SpotFleetRequestConfigData.LaunchSpecifications")
    is_array(specs)
    some s, spec in specs
    bdms := object.get(spec, "BlockDeviceMappings", null)
    is_array(bdms)
    some i, bdm in bdms
    ebs := object.get(bdm, "Ebs", null)
    ebs != null
    iops_path := sprintf("Properties.SpotFleetRequestConfigData.LaunchSpecifications.%d.BlockDeviceMappings.%d.Ebs.Iops", [s, i])
    not is_from_parameter(name, iops_path)
    not is_from_intrinsic(name, iops_path)
    bounds := _ebs_iops_bounds[object.get(ebs, "VolumeType", null)]
    iops := coerce_to_number(object.get(ebs, "Iops", null))
    iops > bounds.max
}
