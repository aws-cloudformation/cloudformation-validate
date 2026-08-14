package best_practices

import rego.v1

# I3100: Previous generation instance type
# Matches instance families: c1-c3, m1-m3, r1-r3, cc2, cg1, cr1, g2, hi1, hs1, i2, t1
previous_gen_pattern := `(^|\.)([cmr][1-3]|cc2|cg1|cr1|g2|hi1|hs1|i2|t1)(\.|$)`

# Direct InstanceType properties
instance_type_checks := {
    {"type": "AWS::AutoScaling::LaunchConfiguration", "path": "Properties.InstanceType"},
    {"type": "AWS::EC2::Instance", "path": "Properties.InstanceType"},
    {"type": "AWS::EC2::Host", "path": "Properties.InstanceType"},
    {"type": "AWS::EC2::CapacityReservation", "path": "Properties.InstanceType"},
    {"type": "AWS::RDS::DBInstance", "path": "Properties.DBInstanceClass"},
    {"type": "AWS::ElastiCache::CacheCluster", "path": "Properties.CacheNodeType"},
    {"type": "AWS::ElastiCache::ReplicationGroup", "path": "Properties.CacheNodeType"},
}

violation contains make_diag_full("I3100", "INFO", name,
    check.path,
    sprintf("Previous generation instance type '%s' - consider upgrading", [val]),
    "Upgrade to a current generation instance type",
    "") if {
    some check in instance_type_checks
    some name in resources_of_type(check.type)
    # Only literal string instance types are checked; values from a parameter
    # Ref or other intrinsic are left alone because their deploy-time value is
    # not known here.
    not is_from_parameter(name, check.path)
    not is_from_intrinsic(name, check.path)
    val := resolve(name, check.path)
    is_string(val)
    regex.match(previous_gen_pattern, val)
}

# Nested InstanceType properties
nested_instance_type_checks := {
    {"type": "AWS::EC2::LaunchTemplate", "path": "Properties.LaunchTemplateData.InstanceType"},
    {"type": "AWS::OpenSearchService::Domain", "path": "Properties.ClusterConfig.InstanceType"},
    {"type": "AWS::Elasticsearch::Domain", "path": "Properties.ElasticsearchClusterConfig.InstanceType"},
}

violation contains make_diag_full("I3100", "INFO", name,
    check.path,
    sprintf("Previous generation instance type '%s' - consider upgrading", [val]),
    "Upgrade to a current generation instance type",
    "") if {
    some check in nested_instance_type_checks
    some name in resources_of_type(check.type)
    # Only literal string instance types are checked; values from a parameter
    # Ref or other intrinsic are left alone because their deploy-time value is
    # not known here.
    not is_from_parameter(name, check.path)
    not is_from_intrinsic(name, check.path)
    val := resolve(name, check.path)
    is_string(val)
    regex.match(previous_gen_pattern, val)
}
