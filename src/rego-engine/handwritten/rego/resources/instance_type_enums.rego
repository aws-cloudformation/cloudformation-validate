package resources

import rego.v1

# E3628: EC2 InstanceType not valid for region
violation contains make_diag_full("E3628", "ERROR", name,
    "Properties.InstanceType",
    sprintf("InstanceType '%s' is not valid for AWS::EC2::Instance in region '%s'", [val, region]),
    "Use a valid instance type for the configured region",
    "") if {
    some name in resources_of_type("AWS::EC2::Instance")
    some val in resolve_all(name, "Properties.InstanceType")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_ec2_instance_instancetype_enum[region]
    valid != null
    not val in valid
}

# E3635: Neptune DBInstanceClass not valid for region
violation contains make_diag_full("E3635", "ERROR", name,
    "Properties.DBInstanceClass",
    sprintf("DBInstanceClass '%s' is not valid for AWS::Neptune::DBInstance in region '%s'", [val, region]),
    "Use a valid instance class for the configured region",
    "") if {
    some name in resources_of_type("AWS::Neptune::DBInstance")
    some val in resolve_all(name, "Properties.DBInstanceClass")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_neptune_dbinstance_dbinstanceclass_enum[region]
    valid != null
    not val in valid
}

# E3641: GameLift EC2InstanceType not valid for region
violation contains make_diag_full("E3641", "ERROR", name,
    "Properties.EC2InstanceType",
    sprintf("EC2InstanceType '%s' is not valid for AWS::GameLift::Fleet in region '%s'", [val, region]),
    "Use a valid instance type for the configured region",
    "") if {
    some name in resources_of_type("AWS::GameLift::Fleet")
    some val in resolve_all(name, "Properties.EC2InstanceType")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_gamelift_fleet_ec2instancetype_enum[region]
    valid != null
    not val in valid
}

# E3667: Redshift NodeType not valid for region
violation contains make_diag_full("E3667", "ERROR", name,
    "Properties.NodeType",
    sprintf("NodeType '%s' is not valid for AWS::Redshift::Cluster in region '%s'", [val, region]),
    "Use a valid node type for the configured region",
    "") if {
    some name in resources_of_type("AWS::Redshift::Cluster")
    some val in resolve_all(name, "Properties.NodeType")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_redshift_cluster_nodetype_enum[region]
    valid != null
    not val in valid
}

# E3670: AmazonMQ HostInstanceType not valid for region
violation contains make_diag_full("E3670", "ERROR", name,
    "Properties.HostInstanceType",
    sprintf("HostInstanceType '%s' is not valid for AWS::AmazonMQ::Broker in region '%s'", [val, region]),
    "Use a valid host instance type for the configured region",
    "") if {
    some name in resources_of_type("AWS::AmazonMQ::Broker")
    some val in resolve_all(name, "Properties.HostInstanceType")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_amazonmq_broker_instancetype_enum[region]
    valid != null
    not val in valid
}

# E3675: EMR InstanceType not valid for region
violation contains make_diag_full("E3675", "ERROR", name,
    "Properties.InstanceType",
    sprintf("InstanceType '%s' is not valid for EMR in region '%s'", [val, region]),
    "Use a valid instance type for the configured region",
    "") if {
    some name in resources_of_type("AWS::EMR::InstanceTypeConfig")
    some val in resolve_all(name, "Properties.InstanceType")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_emr_cluster_instancetypeconfig_instancetype_enum[region]
    valid != null
    not val in valid
}

# E3617: ManagedBlockchain NodeConfiguration InstanceType not valid for region
violation contains make_diag_full("E3617", "ERROR", name,
    "Properties.NodeConfiguration.InstanceType",
    sprintf("InstanceType '%s' is not valid for AWS::ManagedBlockchain::Node in region '%s'", [val, region]),
    "Use a valid instance type for the configured region",
    "") if {
    some name in resources_of_type("AWS::ManagedBlockchain::Node")
    some val in resolve_all(name, "Properties.NodeConfiguration.InstanceType")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_managedblockchain_node_nodeconfiguration_instancetype_enum[region]
    valid != null
    not val in valid
}

# E3620: DocDB DBInstanceClass not valid for region
violation contains make_diag_full("E3620", "ERROR", name,
    "Properties.DBInstanceClass",
    sprintf("DBInstanceClass '%s' is not valid for AWS::DocDB::DBInstance in region '%s'", [val, region]),
    "Use a valid instance class for the configured region",
    "") if {
    some name in resources_of_type("AWS::DocDB::DBInstance")
    some val in resolve_all(name, "Properties.DBInstanceClass")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_docdb_dbinstance_dbinstanceclass_enum[region]
    valid != null
    not val in valid
}

# E3621: AppStream Fleet InstanceType not valid for region
violation contains make_diag_full("E3621", "ERROR", name,
    "Properties.InstanceType",
    sprintf("InstanceType '%s' is not valid for AWS::AppStream::Fleet in region '%s'", [val, region]),
    "Use a valid instance type for the configured region",
    "") if {
    some name in resources_of_type("AWS::AppStream::Fleet")
    some val in resolve_all(name, "Properties.InstanceType")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_appstream_fleet_instancetype_enum[region]
    valid != null
    not val in valid
}

# E3647: ElastiCache CacheNodeType not valid for region
violation contains make_diag_full("E3647", "ERROR", name,
    "Properties.CacheNodeType",
    sprintf("CacheNodeType '%s' is not valid for AWS::ElastiCache::CacheCluster in region '%s'", [val, region]),
    "Use a valid cache node type for the configured region",
    "") if {
    some name in resources_of_type("AWS::ElastiCache::CacheCluster")
    some val in resolve_all(name, "Properties.CacheNodeType")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_elasticache_cachecluster_cachenodetype_enum[region]
    valid != null
    not val in valid
}

# E3672: DAX Cluster NodeType not valid for region
violation contains make_diag_full("E3672", "ERROR", name,
    "Properties.NodeType",
    sprintf("NodeType '%s' is not valid for AWS::DAX::Cluster in region '%s'", [val, region]),
    "Use a valid node type for the configured region",
    "") if {
    some name in resources_of_type("AWS::DAX::Cluster")
    some val in resolve_all(name, "Properties.NodeType")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_dax_cluster_nodetype_enum[region]
    valid != null
    not val in valid
}

# E3694: RDS DBCluster DBClusterInstanceClass not valid for region
violation contains make_diag_full("E3694", "ERROR", name,
    "Properties.DBClusterInstanceClass",
    sprintf("DBClusterInstanceClass '%s' is not valid for AWS::RDS::DBCluster in region '%s'", [val, region]),
    "Use a valid instance class for the configured region",
    "") if {
    some name in resources_of_type("AWS::RDS::DBCluster")
    some val in resolve_all(name, "Properties.DBClusterInstanceClass")
    is_string(val)
    region := input_region()
    region != null
    valid := data.aws_rds_dbcluster_dbclusterinstanceclass_enum[region]
    valid != null
    not val in valid
}
