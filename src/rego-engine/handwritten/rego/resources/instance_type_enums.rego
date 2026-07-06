package resources

import rego.v1

# E3628: EC2 InstanceType not valid for region
violation contains make_diag_full("E3628", "ERROR", name,
    "Properties.InstanceType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::EC2::Instance")
    val := resolve(name, "Properties.InstanceType")
    is_string(val)
    region := effective_region()
    valid := data.aws_ec2_instance_instancetype_enum[region].enum
    valid != null
    not val in valid
}

# E3635: Neptune DBInstanceClass not valid for region
violation contains make_diag_full("E3635", "ERROR", name,
    "Properties.DBInstanceClass",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::Neptune::DBInstance")
    val := resolve(name, "Properties.DBInstanceClass")
    is_string(val)
    region := effective_region()
    valid := data.aws_neptune_dbinstance_dbinstanceclass_enum[region].enum
    valid != null
    not val in valid
}

# E3641: GameLift EC2InstanceType not valid for region
violation contains make_diag_full("E3641", "ERROR", name,
    "Properties.EC2InstanceType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::GameLift::Fleet")
    val := resolve(name, "Properties.EC2InstanceType")
    is_string(val)
    region := effective_region()
    valid := data.aws_gamelift_fleet_ec2instancetype_enum[region].enum
    valid != null
    not val in valid
}

# E3667: Redshift NodeType not valid for region
violation contains make_diag_full("E3667", "ERROR", name,
    "Properties.NodeType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::Redshift::Cluster")
    val := resolve(name, "Properties.NodeType")
    is_string(val)
    region := effective_region()
    valid := data.aws_redshift_cluster_nodetype_enum[region].enum
    valid != null
    not val in valid
}

# E3670: AmazonMQ HostInstanceType not valid for region
violation contains make_diag_full("E3670", "ERROR", name,
    "Properties.HostInstanceType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::AmazonMQ::Broker")
    val := resolve(name, "Properties.HostInstanceType")
    is_string(val)
    region := effective_region()
    valid := data.aws_amazonmq_broker_instancetype_enum[region].enum
    valid != null
    not val in valid
}

# E3675: EMR InstanceType not valid for region
violation contains make_diag_full("E3675", "ERROR", name,
    "Properties.InstanceType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::EMR::InstanceTypeConfig")
    val := resolve(name, "Properties.InstanceType")
    is_string(val)
    region := effective_region()
    valid := data.aws_emr_cluster_instancetypeconfig_instancetype_enum[region].enum
    valid != null
    not val in valid
}

# E3617: ManagedBlockchain NodeConfiguration InstanceType not valid for region
violation contains make_diag_full("E3617", "ERROR", name,
    "Properties.NodeConfiguration.InstanceType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::ManagedBlockchain::Node")
    val := resolve(name, "Properties.NodeConfiguration.InstanceType")
    is_string(val)
    region := effective_region()
    valid := data.aws_managedblockchain_node_nodeconfiguration_instancetype_enum[region].enum
    valid != null
    not val in valid
}

# E3620: DocDB DBInstanceClass not valid for region
violation contains make_diag_full("E3620", "ERROR", name,
    "Properties.DBInstanceClass",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::DocDB::DBInstance")
    val := resolve(name, "Properties.DBInstanceClass")
    is_string(val)
    region := effective_region()
    valid := data.aws_docdb_dbinstance_dbinstanceclass_enum[region].enum
    valid != null
    not val in valid
}

# E3621: AppStream Fleet InstanceType not valid for region
violation contains make_diag_full("E3621", "ERROR", name,
    "Properties.InstanceType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::AppStream::Fleet")
    val := resolve(name, "Properties.InstanceType")
    is_string(val)
    region := effective_region()
    valid := data.aws_appstream_fleet_instancetype_enum[region].enum
    valid != null
    not val in valid
}

# E3647: ElastiCache CacheNodeType not valid for region
violation contains make_diag_full("E3647", "ERROR", name,
    "Properties.CacheNodeType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::ElastiCache::CacheCluster")
    val := resolve(name, "Properties.CacheNodeType")
    is_string(val)
    region := effective_region()
    valid := data.aws_elasticache_cachecluster_cachenodetype_enum[region].enum
    valid != null
    not val in valid
}

# E3672: DAX Cluster NodeType not valid for region
violation contains make_diag_full("E3672", "ERROR", name,
    "Properties.NodeType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::DAX::Cluster")
    val := resolve(name, "Properties.NodeType")
    is_string(val)
    region := effective_region()
    valid := data.aws_dax_cluster_nodetype_enum[region].enum
    valid != null
    not val in valid
}

# E3640: SageMaker processing InstanceType not valid for region
_e3640_paths := {
    "AWS::SageMaker::DataQualityJobDefinition": "Properties.JobResources.ClusterConfig.InstanceType",
    "AWS::SageMaker::ModelBiasJobDefinition": "Properties.JobResources.ClusterConfig.InstanceType",
    "AWS::SageMaker::ModelExplainabilityJobDefinition": "Properties.JobResources.ClusterConfig.InstanceType",
    "AWS::SageMaker::ModelQualityJobDefinition": "Properties.JobResources.ClusterConfig.InstanceType",
    "AWS::SageMaker::MonitoringSchedule": "Properties.MonitoringScheduleConfig.MonitoringJobDefinition.MonitoringResources.ClusterConfig.InstanceType",
}

violation contains make_diag_full("E3640", "ERROR", name, path,
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some rtype, path in _e3640_paths
    some name in resources_of_type(rtype)
    val := resolve(name, path)
    is_string(val)
    region := effective_region()
    valid := data.aws_sagemaker_processing_instancetype_enum[region].enum
    valid != null
    not val in valid
}

# E3642: SageMaker hosting/inference InstanceType not valid for region
violation contains make_diag_full("E3642", "ERROR", name,
    "Properties.ModelVariants.InfrastructureConfig.RealTimeInferenceConfig.InstanceType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::SageMaker::InferenceExperiment")
    some val in resolve_all(name, "Properties.ModelVariants.{}.InfrastructureConfig.RealTimeInferenceConfig.InstanceType")
    is_string(val)
    region := effective_region()
    valid := data.aws_sagemaker_hosting_instancetype_enum[region].enum
    valid != null
    not val in valid
}

# E3643: SageMaker transform InstanceType not valid for region.
violation contains make_diag_full("E3643", "ERROR", name,
    "Properties.ValidationSpecification.ValidationProfiles.TransformJobDefinition.TransformResources.InstanceType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::SageMaker::ModelPackage")
    some val in resolve_all(name, "Properties.ValidationSpecification.ValidationProfiles.{}.TransformJobDefinition.TransformResources.InstanceType")
    is_string(val)
    region := effective_region()
    valid := data.aws_sagemaker_transform_instancetype_enum[region].enum
    valid != null
    not val in valid
}

# E3644: SageMaker cluster InstanceType not valid for region
_e3644_paths := {
    "Properties.InstanceGroups.InstanceType": "Properties.InstanceGroups.{}.InstanceType",
    "Properties.RestrictedInstanceGroups.InstanceType": "Properties.RestrictedInstanceGroups.{}.InstanceType",
}

violation contains make_diag_full("E3644", "ERROR", name, report_path,
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::SageMaker::Cluster")
    some report_path, wildcard_path in _e3644_paths
    some val in resolve_all(name, wildcard_path)
    is_string(val)
    region := effective_region()
    valid := data.aws_sagemaker_cluster_instancetype_enum[region].enum
    valid != null
    not val in valid
}

# E3652: Elasticsearch domain InstanceType not valid for region
violation contains make_diag_full("E3652", "ERROR", name,
    "Properties.ElasticsearchClusterConfig.InstanceType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::Elasticsearch::Domain")
    val := resolve(name, "Properties.ElasticsearchClusterConfig.InstanceType")
    is_string(val)
    region := effective_region()
    valid := data.aws_elasticsearch_domain_elasticsearchclusterconfig_instancetype_enum[region].enum
    valid != null
    not val in valid
}

# E3653: OpenSearch domain InstanceType not valid for region
violation contains make_diag_full("E3653", "ERROR", name,
    "Properties.ClusterConfig.InstanceType",
    sprintf("'%s' is not valid for region '%s'", [val, region]),
    "",
    "") if {
    some name in resources_of_type("AWS::OpenSearchService::Domain")
    val := resolve(name, "Properties.ClusterConfig.InstanceType")
    is_string(val)
    region := effective_region()
    valid := data.aws_opensearchservice_domain_clusterconfig_instancetype_enum[region].enum
    valid != null
    not val in valid
}
