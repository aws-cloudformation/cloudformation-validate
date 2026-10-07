package resources

import rego.v1

# Enhanced Monitoring on a DB cluster is configured by two properties that only
# work together: a MonitoringRoleArn is used only when MonitoringInterval is
# greater than 0, and a non-zero interval needs a role to publish with.
_dbcluster_monitoring_message := "MonitoringRoleArn and a MonitoringInterval greater than 0 must be specified together"

violation contains make_diag_at("E3689", "ERROR", name,
    "Properties.MonitoringInterval",
    _dbcluster_monitoring_message) if {
    cfn_rule_active("E3689")
    some name in resources_of_type("AWS::RDS::DBCluster")
    has_property(name, "MonitoringRoleArn")
    interval := coerce_to_integer(resolve(name, "Properties.MonitoringInterval"))
    interval <= 0
}

violation contains make_diag_at("E3689", "ERROR", name,
    "Properties",
    _dbcluster_monitoring_message) if {
    cfn_rule_active("E3689")
    some name in resources_of_type("AWS::RDS::DBCluster")
    has_property(name, "MonitoringRoleArn")
    not has_property(name, "MonitoringInterval")
}

violation contains make_diag_at("E3689", "ERROR", name,
    "Properties",
    _dbcluster_monitoring_message) if {
    cfn_rule_active("E3689")
    some name in resources_of_type("AWS::RDS::DBCluster")
    not has_property(name, "MonitoringRoleArn")
    interval := coerce_to_integer(resolve(name, "Properties.MonitoringInterval"))
    interval > 0
}
