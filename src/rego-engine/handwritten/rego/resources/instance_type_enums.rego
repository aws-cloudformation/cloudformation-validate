package resources

import rego.v1

# Region-scoped instance-type / node-type enum validation. Each rule reads the
# resource's value and asks `region_flat_invalid` whether it is invalid for the
# effective scope: the configured region, or the union of all regions when none
# is configured (a value is flagged only when it is invalid in every region). The
# builtin returns the fully-rendered diagnostic message, or is undefined when the
# value is valid or the document has no entry for the effective scope.

# E3628: EC2 InstanceType not valid for region
violation contains make_diag_full("E3628", "ERROR", name,
    "Properties.InstanceType", msg, "", "") if {
    some name in resources_of_type("AWS::EC2::Instance")
    val := resolve(name, "Properties.InstanceType")
    is_string(val)
    msg := region_flat_invalid(data.aws_ec2_instance_instancetype_enum, val)
}

# E3635: Neptune DBInstanceClass not valid for region
violation contains make_diag_full("E3635", "ERROR", name,
    "Properties.DBInstanceClass", msg, "", "") if {
    some name in resources_of_type("AWS::Neptune::DBInstance")
    val := resolve(name, "Properties.DBInstanceClass")
    is_string(val)
    msg := region_flat_invalid(data.aws_neptune_dbinstance_dbinstanceclass_enum, val)
}

# E3641: GameLift EC2InstanceType not valid for region
violation contains make_diag_full("E3641", "ERROR", name,
    "Properties.EC2InstanceType", msg, "", "") if {
    some name in resources_of_type("AWS::GameLift::Fleet")
    val := resolve(name, "Properties.EC2InstanceType")
    is_string(val)
    msg := region_flat_invalid(data.aws_gamelift_fleet_ec2instancetype_enum, val)
}

# E3667: Redshift NodeType not valid for region
violation contains make_diag_full("E3667", "ERROR", name,
    "Properties.NodeType", msg, "", "") if {
    some name in resources_of_type("AWS::Redshift::Cluster")
    val := resolve(name, "Properties.NodeType")
    is_string(val)
    msg := region_flat_invalid(data.aws_redshift_cluster_nodetype_enum, val)
}

# E3670: AmazonMQ HostInstanceType not valid for region
violation contains make_diag_full("E3670", "ERROR", name,
    "Properties.HostInstanceType", msg, "", "") if {
    some name in resources_of_type("AWS::AmazonMQ::Broker")
    val := resolve(name, "Properties.HostInstanceType")
    is_string(val)
    msg := region_flat_invalid(data.aws_amazonmq_broker_instancetype_enum, val)
}

# E3675: EMR InstanceType not valid for region. Both InstanceTypeConfig and
# InstanceFleetConfig carry an InstanceType validated against the same enum.
violation contains make_diag_full("E3675", "ERROR", name,
    "Properties.InstanceType", msg, "", "") if {
    some rtype in {"AWS::EMR::InstanceTypeConfig", "AWS::EMR::InstanceFleetConfig"}
    some name in resources_of_type(rtype)
    val := resolve(name, "Properties.InstanceType")
    is_string(val)
    msg := region_flat_invalid(data.aws_emr_cluster_instancetypeconfig_instancetype_enum, val)
}

# E3617: ManagedBlockchain NodeConfiguration InstanceType not valid for region
violation contains make_diag_full("E3617", "ERROR", name,
    "Properties.NodeConfiguration.InstanceType", msg, "", "") if {
    some name in resources_of_type("AWS::ManagedBlockchain::Node")
    val := resolve(name, "Properties.NodeConfiguration.InstanceType")
    is_string(val)
    msg := region_flat_invalid(data.aws_managedblockchain_node_nodeconfiguration_instancetype_enum, val)
}

# E3620: DocDB DBInstanceClass not valid for region
violation contains make_diag_full("E3620", "ERROR", name,
    "Properties.DBInstanceClass", msg, "", "") if {
    some name in resources_of_type("AWS::DocDB::DBInstance")
    val := resolve(name, "Properties.DBInstanceClass")
    is_string(val)
    msg := region_flat_invalid(data.aws_docdb_dbinstance_dbinstanceclass_enum, val)
}

# E3621: AppStream Fleet InstanceType not valid for region
violation contains make_diag_full("E3621", "ERROR", name,
    "Properties.InstanceType", msg, "", "") if {
    some name in resources_of_type("AWS::AppStream::Fleet")
    val := resolve(name, "Properties.InstanceType")
    is_string(val)
    msg := region_flat_invalid(data.aws_appstream_fleet_instancetype_enum, val)
}

# E3647: ElastiCache CacheNodeType not valid for region
violation contains make_diag_full("E3647", "ERROR", name,
    "Properties.CacheNodeType", msg, "", "") if {
    some name in resources_of_type("AWS::ElastiCache::CacheCluster")
    val := resolve(name, "Properties.CacheNodeType")
    is_string(val)
    msg := region_flat_invalid(data.aws_elasticache_cachecluster_cachenodetype_enum, val)
}

# E3672: DAX Cluster NodeType not valid for region
violation contains make_diag_full("E3672", "ERROR", name,
    "Properties.NodeType", msg, "", "") if {
    some name in resources_of_type("AWS::DAX::Cluster")
    val := resolve(name, "Properties.NodeType")
    is_string(val)
    msg := region_flat_invalid(data.aws_dax_cluster_nodetype_enum, val)
}

# E3640: SageMaker processing InstanceType not valid for region
_e3640_paths := {
    "AWS::SageMaker::DataQualityJobDefinition": "Properties.JobResources.ClusterConfig.InstanceType",
    "AWS::SageMaker::ModelBiasJobDefinition": "Properties.JobResources.ClusterConfig.InstanceType",
    "AWS::SageMaker::ModelExplainabilityJobDefinition": "Properties.JobResources.ClusterConfig.InstanceType",
    "AWS::SageMaker::ModelQualityJobDefinition": "Properties.JobResources.ClusterConfig.InstanceType",
    "AWS::SageMaker::MonitoringSchedule": "Properties.MonitoringScheduleConfig.MonitoringJobDefinition.MonitoringResources.ClusterConfig.InstanceType",
}

violation contains make_diag_full("E3640", "ERROR", name, path, msg, "", "") if {
    some rtype, path in _e3640_paths
    some name in resources_of_type(rtype)
    val := resolve(name, path)
    is_string(val)
    msg := region_flat_invalid(data.aws_sagemaker_processing_instancetype_enum, val)
}

# Hosting/inference instance types are reported at the exact model-variant entry.
violation contains make_diag_full("E3642", "ERROR", name, report_path, msg, "", "") if {
    some name in resources_of_type("AWS::SageMaker::InferenceExperiment")
    some variants in resolve_all(name, "Properties.ModelVariants")
    is_array(variants)
    some index, variant in variants
    val := variant.InfrastructureConfig.RealTimeInferenceConfig.InstanceType
    is_string(val)
    report_path := sprintf("Properties.ModelVariants.%d.InfrastructureConfig.RealTimeInferenceConfig.InstanceType", [index])
    msg := region_flat_invalid(data.aws_sagemaker_hosting_instancetype_enum, val)
}

# Transform instance types are reported at the exact validation-profile entry.
violation contains make_diag_full("E3643", "ERROR", name, report_path, msg, "", "") if {
    some name in resources_of_type("AWS::SageMaker::ModelPackage")
    some profiles in resolve_all(name, "Properties.ValidationSpecification.ValidationProfiles")
    is_array(profiles)
    some index, profile in profiles
    val := profile.TransformJobDefinition.TransformResources.InstanceType
    is_string(val)
    report_path := sprintf("Properties.ValidationSpecification.ValidationProfiles.%d.TransformJobDefinition.TransformResources.InstanceType", [index])
    msg := region_flat_invalid(data.aws_sagemaker_transform_instancetype_enum, val)
}

_cluster_instance_type_lists := {
    "Properties.InstanceGroups",
    "Properties.RestrictedInstanceGroups",
}

# Cluster instance types are reported at the exact group entry.
violation contains make_diag_full("E3644", "ERROR", name, report_path, msg, "", "") if {
    some name in resources_of_type("AWS::SageMaker::Cluster")
    some list_path in _cluster_instance_type_lists
    some groups in resolve_all(name, list_path)
    is_array(groups)
    some index, group in groups
    val := group.InstanceType
    is_string(val)
    report_path := sprintf("%s.%d.InstanceType", [list_path, index])
    msg := region_flat_invalid(data.aws_sagemaker_cluster_instancetype_enum, val)
}

# E3652: Elasticsearch domain InstanceType not valid for region
violation contains make_diag_full("E3652", "ERROR", name,
    "Properties.ElasticsearchClusterConfig.InstanceType", msg, "", "") if {
    some name in resources_of_type("AWS::Elasticsearch::Domain")
    val := resolve(name, "Properties.ElasticsearchClusterConfig.InstanceType")
    is_string(val)
    msg := region_flat_invalid(data.aws_elasticsearch_domain_elasticsearchclusterconfig_instancetype_enum, val)
}

# E3653: OpenSearch domain InstanceType not valid for region
violation contains make_diag_full("E3653", "ERROR", name,
    "Properties.ClusterConfig.InstanceType", msg, "", "") if {
    some name in resources_of_type("AWS::OpenSearchService::Domain")
    val := resolve(name, "Properties.ClusterConfig.InstanceType")
    is_string(val)
    msg := region_flat_invalid(data.aws_opensearchservice_domain_clusterconfig_instancetype_enum, val)
}
