package resources

import rego.v1

# W3688: RDS DBCluster - MasterUsername ignored when SnapshotIdentifier is present
violation contains make_diag_at("W3688", "WARN", name,
    "Properties.MasterUsername",
    "MasterUsername is ignored when SnapshotIdentifier is present") if {
    cfn_rule_active("W3688")
    some name in resources_of_type("AWS::RDS::DBCluster")
    has_property(name, "SnapshotIdentifier")
    has_property(name, "MasterUsername")
}

# W3689: RDS DBCluster - properties ignored when SourceDBClusterIdentifier is present
violation contains make_diag_at("W3689", "WARN", name,
    sprintf("Properties.%s", [prop]),
    sprintf("'%s' is ignored when SourceDBClusterIdentifier is present", [prop])) if {
    cfn_rule_active("W3689")
    some name in resources_of_type("AWS::RDS::DBCluster")
    has_property(name, "SourceDBClusterIdentifier")
    ignored := {"MasterUserPassword", "MasterUsername", "StorageEncrypted"}
    some prop in ignored
    has_property(name, prop)
}

# W3693: RDS DBCluster - Aurora serverless ignores PerformanceInsights properties
violation contains make_diag_at("W3693", "WARN", name,
    sprintf("Properties.%s", [prop]),
    sprintf("'%s' is ignored when EngineMode is 'serverless'", [prop])) if {
    cfn_rule_active("W3693")
    some name in resources_of_type("AWS::RDS::DBCluster")
    engine := resolve(name, "Properties.Engine")
    engine in {"aurora-mysql", "aurora-postgresql"}
    mode := resolve(name, "Properties.EngineMode")
    mode == "serverless"
    ignored := {"PerformanceInsightsEnabled", "PerformanceInsightsKmsKeyId", "PerformanceInsightsRetentionPeriod"}
    some prop in ignored
    has_property(name, prop)
}
