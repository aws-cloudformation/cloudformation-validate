package best_practices

import rego.v1

# W3010: Hardcoded availability zone. Matches cfn-lint's AvailabilityZone rule
# behavior: same resource-type/property allowlist including nested and list-indexed
# paths, and the same message format `Avoid hardcoding availability zones '<zone>'`.
# Values produced by intrinsics (Fn::GetAZs, Ref, etc.) are skipped — cfn-lint does
# the same by ignoring property paths that contain an intrinsic function.

_az_pattern := `^[a-z]{2}(-[a-z]+)+-[0-9][a-z]$`

_az_msg(zone) := sprintf("Avoid hardcoding availability zones '%s'", [zone])

# ── Scalar AvailabilityZone on a single resource type ──────────────────────
_scalar_az_properties := {
    "AWS::DMS::ReplicationInstance": "AvailabilityZone",
    "AWS::EC2::Host": "AvailabilityZone",
    "AWS::EC2::Instance": "AvailabilityZone",
    "AWS::EC2::Subnet": "AvailabilityZone",
    "AWS::EC2::Volume": "AvailabilityZone",
    "AWS::OpsWorks::Instance": "AvailabilityZone",
    "AWS::RDS::DBInstance": "AvailabilityZone",
}

violation contains make_diag_at("W3010", "WARN", name,
    sprintf("Properties.%s", [prop]),
    _az_msg(val)) if {
    some name in object.keys(input.resources)
    rtype := input.resources[name].resourceType
    prop := _scalar_az_properties[rtype]
    path := sprintf("Properties.%s", [prop])
    not is_from_intrinsic(name, path)
    some val in resolve_all(name, path)
    is_string(val)
    regex.match(_az_pattern, val)
}

# ── List of AvailabilityZones (each item is an AZ) ─────────────────────────
_list_az_properties := {
    "AWS::AutoScaling::AutoScalingGroup": "AvailabilityZones",
    "AWS::DAX::Cluster": "AvailabilityZones",
    "AWS::ElasticLoadBalancing::LoadBalancer": "AvailabilityZones",
    "AWS::RDS::DBCluster": "AvailabilityZones",
}

violation contains make_diag_at("W3010", "WARN", name,
    sprintf("Properties.%s.%d", [prop, idx]),
    _az_msg(val)) if {
    some name in object.keys(input.resources)
    rtype := input.resources[name].resourceType
    prop := _list_az_properties[rtype]
    list_path := sprintf("Properties.%s", [prop])
    not is_from_intrinsic(name, list_path)
    arr := resolve(name, list_path)
    is_array(arr)
    some idx, val in arr
    is_string(val)
    regex.match(_az_pattern, val)
    not is_from_intrinsic(name, sprintf("%s.%d", [list_path, idx]))
}

# ── Nested AZ paths ────────────────────────────────────────────────────────
violation contains make_diag_at("W3010", "WARN", name,
    "Properties.LaunchTemplateData.Placement.AvailabilityZone",
    _az_msg(val)) if {
    some name in resources_of_type("AWS::EC2::LaunchTemplate")
    path := "Properties.LaunchTemplateData.Placement.AvailabilityZone"
    not is_from_intrinsic(name, path)
    some val in resolve_all(name, path)
    is_string(val)
    regex.match(_az_pattern, val)
}

violation contains make_diag_at("W3010", "WARN", name,
    "Properties.Instances.Placement.AvailabilityZone",
    _az_msg(val)) if {
    some name in resources_of_type("AWS::EMR::Cluster")
    path := "Properties.Instances.Placement.AvailabilityZone"
    not is_from_intrinsic(name, path)
    some val in resolve_all(name, path)
    is_string(val)
    regex.match(_az_pattern, val)
}

violation contains make_diag_at("W3010", "WARN", name,
    "Properties.ConnectionInput.PhysicalConnectionRequirements.AvailabilityZone",
    _az_msg(val)) if {
    some name in resources_of_type("AWS::Glue::Connection")
    path := "Properties.ConnectionInput.PhysicalConnectionRequirements.AvailabilityZone"
    not is_from_intrinsic(name, path)
    some val in resolve_all(name, path)
    is_string(val)
    regex.match(_az_pattern, val)
}

violation contains make_diag_at("W3010", "WARN", name,
    sprintf("Properties.Targets.%d.AvailabilityZone", [idx]),
    _az_msg(val)) if {
    some name in resources_of_type("AWS::ElasticLoadBalancingV2::TargetGroup")
    targets := resolve(name, "Properties.Targets")
    is_array(targets)
    some idx, target in targets
    is_object(target)
    item_path := sprintf("Properties.Targets.%d.AvailabilityZone", [idx])
    not is_from_intrinsic(name, item_path)
    val := resolve(name, item_path)
    is_string(val)
    regex.match(_az_pattern, val)
}

violation contains make_diag_at("W3010", "WARN", name,
    sprintf("Properties.SpotFleetRequestConfigData.LaunchSpecifications.%d.Placement.AvailabilityZone", [idx]),
    _az_msg(val)) if {
    some name in resources_of_type("AWS::EC2::SpotFleet")
    specs := resolve(name, "Properties.SpotFleetRequestConfigData.LaunchSpecifications")
    is_array(specs)
    some idx, _ in specs
    item_path := sprintf("Properties.SpotFleetRequestConfigData.LaunchSpecifications.%d.Placement.AvailabilityZone", [idx])
    not is_from_intrinsic(name, item_path)
    val := resolve(name, item_path)
    is_string(val)
    regex.match(_az_pattern, val)
}

violation contains make_diag_at("W3010", "WARN", name,
    sprintf("Properties.SpotFleetRequestConfigData.LaunchTemplateConfigs.%d.Overrides.%d.AvailabilityZone", [ci, oi]),
    _az_msg(val)) if {
    some name in resources_of_type("AWS::EC2::SpotFleet")
    cfgs := resolve(name, "Properties.SpotFleetRequestConfigData.LaunchTemplateConfigs")
    is_array(cfgs)
    some ci, _ in cfgs
    overrides := resolve(name, sprintf("Properties.SpotFleetRequestConfigData.LaunchTemplateConfigs.%d.Overrides", [ci]))
    is_array(overrides)
    some oi, _ in overrides
    item_path := sprintf("Properties.SpotFleetRequestConfigData.LaunchTemplateConfigs.%d.Overrides.%d.AvailabilityZone", [ci, oi])
    not is_from_intrinsic(name, item_path)
    val := resolve(name, item_path)
    is_string(val)
    regex.match(_az_pattern, val)
}
