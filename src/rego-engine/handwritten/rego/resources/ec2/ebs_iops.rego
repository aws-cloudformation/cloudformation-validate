package resources

import rego.v1

# E3671: Iops required for io1/io2 VolumeType
violation contains make_diag_at("E3671", "ERROR", name,
    "Properties.Iops",
    sprintf("Iops is required for VolumeType '%s'", [vtype])) if {
    some name in resources_of_type("AWS::EC2::Volume")
    some vtype in resolve_all(name, "Properties.VolumeType")
    vtype in {"io1", "io2"}
    not has_property(name, "Iops")
}

# E3671: Iops not supported for gp2/standard/st1/sc1
violation contains make_diag_at("E3671", "ERROR", name,
    "Properties.Iops",
    sprintf("Iops is not supported for VolumeType '%s'", [vtype])) if {
    some name in resources_of_type("AWS::EC2::Volume")
    some vtype in resolve_all(name, "Properties.VolumeType")
    vtype in {"gp2", "standard", "st1", "sc1"}
    has_property(name, "Iops")
}
