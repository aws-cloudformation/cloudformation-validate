package resources

import rego.v1

_bdm_resource_paths := {
    "AWS::EC2::Instance": "Properties.BlockDeviceMappings",
    "AWS::AutoScaling::LaunchConfiguration": "Properties.BlockDeviceMappings",
    "AWS::OpsWorks::Instance": "Properties.BlockDeviceMappings",
    "AWS::EC2::LaunchTemplate": "Properties.LaunchTemplateData.BlockDeviceMappings",
}

# E3715: VirtualName must match ephemeral[0-23] when Ebs is absent
violation contains make_diag_at("E3715", "ERROR", name,
    sprintf("%s.%d.VirtualName", [base_path, i]),
    sprintf("'%s' is not a valid ephemeral device name. Expected format is 'ephemeralN' where N is 0-23", [vname])) if {
    some rtype, base_path in _bdm_resource_paths
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

# W3698: VirtualName is silently ignored when Ebs is specified in block device mappings
violation contains make_diag_at("W3698", "WARN", name,
    sprintf("%s.%d.VirtualName", [base_path, i]),
    "VirtualName is ignored when Ebs is specified") if {
    some rtype, base_path in _bdm_resource_paths
    some name in resources_of_type(rtype)
    bdms := resolve(name, base_path)
    is_array(bdms)
    some i, bdm in bdms
    object.get(bdm, "VirtualName", null) != null
    object.get(bdm, "Ebs", null) != null
}
