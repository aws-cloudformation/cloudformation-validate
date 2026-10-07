# Encryption posture: table-driven at-rest and in-transit checks over two dozen resource types, resolved per condition scenario, plus KMS key hygiene and S3 transport policies.
package custom_encryption

import rego.v1

# Resource types whose at-rest encryption is a boolean property that defaults to off.
_at_rest_flags := [
	["AWS::RDS::DBInstance", "Properties.StorageEncrypted"],
	["AWS::RDS::DBCluster", "Properties.StorageEncrypted"],
	["AWS::EC2::Volume", "Properties.Encrypted"],
	["AWS::EFS::FileSystem", "Properties.Encrypted"],
	["AWS::DynamoDB::Table", "Properties.SSESpecification.SSEEnabled"],
	["AWS::Redshift::Cluster", "Properties.Encrypted"],
	["AWS::ElastiCache::ReplicationGroup", "Properties.AtRestEncryptionEnabled"],
	["AWS::OpenSearchService::Domain", "Properties.EncryptionAtRestOptions.Enabled"],
	["AWS::Elasticsearch::Domain", "Properties.EncryptionAtRestOptions.Enabled"],
	["AWS::DocDB::DBCluster", "Properties.StorageEncrypted"],
	["AWS::Neptune::DBCluster", "Properties.StorageEncrypted"],
	["AWS::DAX::Cluster", "Properties.SSESpecification.SSEEnabled"],
	["AWS::WorkSpaces::Workspace", "Properties.RootVolumeEncryptionEnabled"],
	["AWS::WorkSpaces::Workspace", "Properties.UserVolumeEncryptionEnabled"],
	["AWS::EC2::LaunchTemplate", "Properties.LaunchTemplateData.BlockDeviceMappings.{}.Ebs.Encrypted"],
]

# Resource types whose at-rest encryption is an object or key property that is absent by default.
_at_rest_settings := [
	["AWS::Kinesis::Stream", "Properties.StreamEncryption"],
	["AWS::EKS::Cluster", "Properties.EncryptionConfig"],
	["AWS::SNS::Topic", "Properties.KmsMasterKeyId"],
	["AWS::CloudTrail::Trail", "Properties.KMSKeyId"],
	["AWS::Logs::LogGroup", "Properties.KmsKeyId"],
	["AWS::SageMaker::NotebookInstance", "Properties.KmsKeyId"],
	["AWS::Glue::SecurityConfiguration", "Properties.EncryptionConfiguration"],
	["AWS::Athena::WorkGroup", "Properties.WorkGroupConfiguration.ResultConfiguration.EncryptionConfiguration"],
	["AWS::CodeBuild::Project", "Properties.EncryptionKey"],
]

# Absence counts as a finding: every listed setting defaults to the insecure value.
_in_transit_required := [
	["AWS::OpenSearchService::Domain", "Properties.DomainEndpointOptions.EnforceHTTPS", {true, "true"}],
	["AWS::OpenSearchService::Domain", "Properties.NodeToNodeEncryptionOptions.Enabled", {true, "true"}],
	["AWS::Elasticsearch::Domain", "Properties.DomainEndpointOptions.EnforceHTTPS", {true, "true"}],
	["AWS::Elasticsearch::Domain", "Properties.NodeToNodeEncryptionOptions.Enabled", {true, "true"}],
	["AWS::ElastiCache::ReplicationGroup", "Properties.TransitEncryptionEnabled", {true, "true"}],
	["AWS::MSK::Cluster", "Properties.EncryptionInfo.EncryptionInTransit.ClientBroker", {"TLS"}],
	["AWS::ApiGateway::DomainName", "Properties.SecurityPolicy", {"TLS_1_2"}],
	["AWS::ApiGatewayV2::DomainName", "Properties.DomainNameConfigurations.{}.SecurityPolicy", {"TLS_1_2"}],
	["AWS::CloudFront::Distribution", "Properties.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy", {"https-only", "redirect-to-https"}],
	["AWS::CloudFront::Distribution", "Properties.DistributionConfig.CacheBehaviors.{}.ViewerProtocolPolicy", {"https-only", "redirect-to-https"}],
	["AWS::ElasticLoadBalancingV2::Listener", "Properties.Protocol", {"HTTPS", "TLS", "TCP", "UDP", "TCP_UDP", "GENEVE"}],
	["AWS::ElasticLoadBalancing::LoadBalancer", "Properties.Listeners.{}.Protocol", {"HTTPS", "SSL", "TCP"}],
]

_disabled(value) if value == false

_disabled(value) if value == "false"

_true_like(value) if value == true

_true_like(value) if value == "true"

_conditions(scenario) := object.get(scenario, "conditions", {})

_scenario_path(scenario, fallback) := object.get(scenario, "path", fallback)

_false_like_values(value) := [item | some item in ensure_list(value); item in {false, "false"}]

_scenario_diag(rule_id, severity, name, path, message, scenario) := make_diag_conditional(rule_id, severity, name, path, message, _conditions(scenario)) if {
	count(_conditions(scenario)) > 0
}

_scenario_diag(rule_id, severity, name, path, message, scenario) := make_diag_at(rule_id, severity, name, path, message) if {
	count(_conditions(scenario)) == 0
}

_symmetric_key(name) if not has_property(name, "KeySpec")

_symmetric_key(name) if {
	some spec in resolve_all(name, "Properties.KeySpec")
	spec == "SYMMETRIC_DEFAULT"
}

_rotation_enabled(name) if {
	some value in resolve_all(name, "Properties.EnableKeyRotation")
	_true_like(value)
}

_grants_root_admin(document) if {
	some statement in ensure_list(document.Statement)
	statement.Effect == "Allow"
	some action in ensure_list(statement.Action)
	action in {"kms:*", "*"}
	some principal in ensure_list(statement.Principal.AWS)
	is_string(principal)
	arn_matches(principal, "arn:*:iam::*:root")
}

_targets_bucket(value, bucket) if value.__ref == bucket

_targets_bucket(value, bucket) if {
	is_string(value)
	some bucket_name in resolve_all(bucket, "Properties.BucketName")
	value == bucket_name
}

_denies_insecure_transport(bucket) if {
	some _, res in input.resources
	res.resourceType == "AWS::S3::BucketPolicy"
	_targets_bucket(res.properties.Bucket, bucket)
	some statement in ensure_list(res.properties.PolicyDocument.Statement)
	statement.Effect == "Deny"
	some operator, operands in statement.Condition
	lower(operator) == "bool"
	some key, value in operands
	lower(key) == "aws:securetransport"
	count(_false_like_values(value)) > 0
}

violation contains _scenario_diag("encryption.at-rest-disabled", "ERROR", name, _scenario_path(scenario, path), sprintf("%s resolves to %v, so data at rest is stored unencrypted", [_scenario_path(scenario, path), scenario.value]), scenario) if {
	some [type, path] in _at_rest_flags
	some name in resources_of_type(type)
	some scenario in resolve_scenarios(name, path)
	_disabled(scenario.value)
}

violation contains make_diag_at("encryption.at-rest-not-configured", "WARN", name, path, sprintf("%s is not set, so %s is created without encryption at rest", [path, type])) if {
	some [type, path] in array.concat(_at_rest_flags, _at_rest_settings)
	not contains(path, "{}")
	some name in resources_of_type(type)
	property_can_be_absent(name, path)
	not is_dynamic(name, path)
}

violation contains _scenario_diag("encryption.in-transit-not-enforced", "WARN", name, _scenario_path(scenario, path), sprintf("%s resolves to %v; expected one of %v", [_scenario_path(scenario, path), scenario.value, allowed]), scenario) if {
	some [type, path, allowed] in _in_transit_required
	some name in resources_of_type(type)
	some scenario in resolve_scenarios(name, path)
	not allowed[scenario.value]
	is_string(scenario.value)
}

violation contains _scenario_diag("encryption.in-transit-not-enforced", "WARN", name, _scenario_path(scenario, path), sprintf("%s resolves to %v; expected one of %v", [_scenario_path(scenario, path), scenario.value, allowed]), scenario) if {
	some [type, path, allowed] in _in_transit_required
	some name in resources_of_type(type)
	some scenario in resolve_scenarios(name, path)
	not allowed[scenario.value]
	is_boolean(scenario.value)
}

violation contains make_diag_at("encryption.kms-key-rotation-disabled", "WARN", name, "Properties.EnableKeyRotation", "symmetric KMS key does not enable automatic key rotation") if {
	some name in resources_of_type("AWS::KMS::Key")
	_symmetric_key(name)
	not _rotation_enabled(name)
}

violation contains make_diag_at("encryption.kms-key-policy-no-root-admin", "WARN", name, "Properties.KeyPolicy", "key policy grants kms:* to no account root principal, so the key can become unmanageable") if {
	some name in resources_of_type("AWS::KMS::Key")
	document := input.resources[name].properties.KeyPolicy
	is_object(document)
	not _grants_root_admin(document)
}

violation contains make_diag("encryption.s3-secure-transport-policy-missing", "INFO", name, "bucket has no bucket policy denying requests over plain HTTP (aws:SecureTransport)") if {
	some name in resources_of_type("AWS::S3::Bucket")
	not _denies_insecure_transport(name)
}
