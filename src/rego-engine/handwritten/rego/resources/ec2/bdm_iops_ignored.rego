package resources

import rego.v1

# W3671: Iops is silently ignored for certain EBS volume types in block device mappings
bdm_iops_ignored_types := {"gp2", "st1", "sc1", "standard"}

violation contains make_diag_at("W3671", "WARN", name,
    sprintf("%s.%d.Ebs.Iops", [base_path, i]),
    sprintf("Iops is ignored when VolumeType is '%s'", [vtype])) if {
    bdm_checks := {
        "AWS::EC2::Instance": "Properties.BlockDeviceMappings",
        "AWS::AutoScaling::LaunchConfiguration": "Properties.BlockDeviceMappings",
        "AWS::OpsWorks::Instance": "Properties.BlockDeviceMappings",
        "AWS::EC2::LaunchTemplate": "Properties.LaunchTemplateData.BlockDeviceMappings",
    }
    some rtype, base_path in bdm_checks
    some name in resources_of_type(rtype)
    bdms := resolve(name, base_path)
    is_array(bdms)
    some i, bdm in bdms
    ebs := object.get(bdm, "Ebs", null)
    ebs != null
    object.get(ebs, "Iops", null) != null
    vtype := object.get(ebs, "VolumeType", null)
    is_string(vtype)
    vtype in bdm_iops_ignored_types
}
