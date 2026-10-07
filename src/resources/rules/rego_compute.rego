# Compute hardening: Lambda runtimes, secrets in environment blocks, log groups, service-role trust chains resolved through references, EC2 launch settings and block devices, ECS container definitions, and hardcoded Availability Zones on every resource.
package custom_compute

import rego.v1

_end_of_life_runtimes := {
	"python2.7", "python3.6", "python3.7", "python3.8",
	"nodejs", "nodejs4.3", "nodejs4.3-edge", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
	"ruby2.5", "ruby2.7",
	"go1.x",
	"dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0", "dotnet7",
	"java8",
	"provided",
}

_secret_key_pattern := `(?i)(secret|passw(or)?d|token|api[_-]?key|private[_-]?key|credential)`

# Resources that hand a role to a service principal: the role's trust policy must name that principal.
_service_roles := [
	["AWS::Lambda::Function", "Properties.Role", "lambda.amazonaws.com"],
	["AWS::ECS::TaskDefinition", "Properties.ExecutionRoleArn", "ecs-tasks.amazonaws.com"],
	["AWS::ECS::TaskDefinition", "Properties.TaskRoleArn", "ecs-tasks.amazonaws.com"],
	["AWS::CodeBuild::Project", "Properties.ServiceRole", "codebuild.amazonaws.com"],
	["AWS::StepFunctions::StateMachine", "Properties.RoleArn", "states.amazonaws.com"],
	["AWS::Glue::Job", "Properties.Role", "glue.amazonaws.com"],
	["AWS::Glue::Crawler", "Properties.Role", "glue.amazonaws.com"],
	["AWS::Events::Rule", "Properties.RoleArn", "events.amazonaws.com"],
	["AWS::Scheduler::Schedule", "Properties.Target.RoleArn", "scheduler.amazonaws.com"],
	["AWS::CodePipeline::Pipeline", "Properties.RoleArn", "codepipeline.amazonaws.com"],
	["AWS::CodeDeploy::DeploymentGroup", "Properties.ServiceRoleArn", "codedeploy.amazonaws.com"],
	["AWS::Config::ConfigurationRecorder", "Properties.RoleARN", "config.amazonaws.com"],
	["AWS::EKS::Cluster", "Properties.RoleArn", "eks.amazonaws.com"],
	["AWS::SageMaker::Model", "Properties.ExecutionRoleArn", "sagemaker.amazonaws.com"],
	["AWS::SageMaker::NotebookInstance", "Properties.RoleArn", "sagemaker.amazonaws.com"],
	["AWS::KinesisFirehose::DeliveryStream", "Properties.S3DestinationConfiguration.RoleARN", "firehose.amazonaws.com"],
	["AWS::ApiGateway::Account", "Properties.CloudWatchRoleArn", "apigateway.amazonaws.com"],
	["AWS::AppSync::GraphQLApi", "Properties.LogConfig.CloudWatchLogsRoleArn", "appsync.amazonaws.com"],
	["AWS::Batch::ComputeEnvironment", "Properties.ServiceRole", "batch.amazonaws.com"],
	["AWS::CloudFormation::Stack", "Properties.RoleARN", "cloudformation.amazonaws.com"],
]

_imds_paths := [
	["AWS::EC2::Instance", "Properties.MetadataOptions.HttpTokens"],
	["AWS::EC2::LaunchTemplate", "Properties.LaunchTemplateData.MetadataOptions.HttpTokens"],
	["AWS::AutoScaling::LaunchConfiguration", "Properties.MetadataOptions.HttpTokens"],
]

_network_interface_lists := [
	["AWS::EC2::Instance", "Properties.NetworkInterfaces"],
	["AWS::EC2::LaunchTemplate", "Properties.LaunchTemplateData.NetworkInterfaces"],
]

_block_device_lists := [
	["AWS::EC2::Instance", "Properties.BlockDeviceMappings"],
	["AWS::EC2::LaunchTemplate", "Properties.LaunchTemplateData.BlockDeviceMappings"],
	["AWS::AutoScaling::LaunchConfiguration", "Properties.BlockDeviceMappings"],
]

_true_like(value) if value == true

_true_like(value) if value == "true"

_trusts_service(role, service) if {
	some statement in ensure_list(input.resources[role].properties.AssumeRolePolicyDocument.Statement)
	statement.Effect == "Allow"
	some principal in ensure_list(statement.Principal.Service)
	_matches_service(principal, service)
}

_matches_service(principal, service) if principal == service

# Legacy regional principals such as states.us-east-1.amazonaws.com name the same service.
_matches_service(principal, service) if {
	is_string(principal)
	startswith(principal, sprintf("%s.", [split(service, ".")[0]]))
	endswith(principal, ".amazonaws.com")
}

# A trust policy supplied through a parameter or another opaque value cannot be judged.
_trusts_service(role, _) if is_dynamic(role, "Properties.AssumeRolePolicyDocument")

_has_log_group(function) if {
	some source in ref_sources(function)
	input.resources[source].resourceType == "AWS::Logs::LogGroup"
}

_has_log_group(function) if {
	some _, res in input.resources
	res.resourceType == "AWS::Logs::LogGroup"
	is_string(res.properties.LogGroupName)
	some function_name in resolve_all(function, "Properties.FunctionName")
	res.properties.LogGroupName == sprintf("/aws/lambda/%s", [function_name])
}

_requires_tokens(name, path) if {
	some value in resolve_all(name, path)
	value == "required"
}

_requires_tokens(name, path) if is_dynamic(name, path)

_mutable_tag(image) if endswith(image, ":latest")

_mutable_tag(image) if {
	not contains(image, "@sha256:")
	not regex.match(`:[A-Za-z0-9_][A-Za-z0-9_.-]*$`, image)
}

containers contains {"resource": name, "index": i, "container": container} if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	definitions := input.resources[name].properties.ContainerDefinitions
	is_array(definitions)
	some i, container in definitions
	is_object(container)
}

violation contains make_diag_at("compute.lambda-runtime-end-of-life", "WARN", name, "Properties.Runtime", sprintf("runtime %s no longer receives security updates; migrate to a supported runtime", [runtime])) if {
	some name in resources_of_type("AWS::Lambda::Function")
	some runtime in resolve_all(name, "Properties.Runtime")
	_end_of_life_runtimes[runtime]
}

violation contains make_diag_at("compute.role-not-assumable-by-service", "ERROR", name, path, sprintf("role %s does not trust %s, so %s cannot assume it", [role, service, type])) if {
	some [type, path, service] in _service_roles
	some name in resources_of_type(type)
	role := follow_ref(name, path)
	input.resources[role].resourceType == "AWS::IAM::Role"
	not _trusts_service(role, service)
}

violation contains make_diag_at("compute.lambda-secret-in-environment", "WARN", name, path, sprintf("environment variable %s looks like a secret stored in plain text; read it from Secrets Manager or SSM at runtime", [key])) if {
	some name in resources_of_type("AWS::Lambda::Function")
	variables := input.resources[name].properties.Environment.Variables
	is_object(variables)
	some key, value in variables
	regex.match(_secret_key_pattern, key)
	is_string(value)
	count(value) > 0
	not startswith(value, "{{resolve:")
	path := sprintf("Properties.Environment.Variables.%s", [key])
	not is_from_parameter(name, path)
}

violation contains make_diag("compute.lambda-log-group-missing", "INFO", name, "no AWS::Logs::LogGroup declares this function's log group, so logs are retained forever") if {
	some name in resources_of_type("AWS::Lambda::Function")
	not has_property(name, "LoggingConfig")
	not _has_log_group(name)
}

violation contains make_diag_at("compute.imdsv1-allowed", "WARN", name, path, "instance metadata service allows IMDSv1 because HttpTokens is not 'required'") if {
	some [type, path] in _imds_paths
	some name in resources_of_type(type)
	not _requires_tokens(name, path)
}

violation contains make_diag_at("compute.public-ip-on-launch", "WARN", name, path, "network interface requests a public IP address at launch") if {
	some [type, base] in _network_interface_lists
	some name in resources_of_type(type)
	some item in flatten_list(name, base)
	_true_like(item.value.AssociatePublicIpAddress)
	path := sprintf("%s.%d.AssociatePublicIpAddress", [base, item.index])
}

violation contains make_diag_at("compute.block-device-unencrypted", "ERROR", name, path, "EBS volume created at launch is not encrypted") if {
	some [type, base] in _block_device_lists
	some name in resources_of_type(type)
	some item in flatten_list(name, base)
	is_object(item.value.Ebs)
	not _true_like(item.value.Ebs.Encrypted)
	path := sprintf("%s.%d.Ebs.Encrypted", [base, item.index])
	not is_dynamic(name, path)
}

violation contains make_diag_at("compute.ecs-container-privileged", "ERROR", c.resource, sprintf("Properties.ContainerDefinitions.%d.Privileged", [c.index]), sprintf("container %v runs in privileged mode", [object.get(c.container, "Name", c.index)])) if {
	some c in containers
	_true_like(c.container.Privileged)
}

violation contains make_diag_at("compute.ecs-container-image-tag-mutable", "WARN", c.resource, sprintf("Properties.ContainerDefinitions.%d.Image", [c.index]), sprintf("image %s uses a mutable tag; pin a version tag or digest", [image])) if {
	some c in containers
	image := c.container.Image
	is_string(image)
	_mutable_tag(image)
}

violation contains make_diag_at("compute.ecs-container-secret-in-environment", "WARN", c.resource, sprintf("Properties.ContainerDefinitions.%d.Environment.%d", [c.index, j]), sprintf("environment variable %s looks like a secret stored in plain text; use the Secrets property", [variable.Name])) if {
	some c in containers
	environment := c.container.Environment
	is_array(environment)
	some j, variable in environment
	is_string(variable.Name)
	regex.match(_secret_key_pattern, variable.Name)
	is_string(variable.Value)
	count(variable.Value) > 0
}

violation contains make_diag_at("compute.hardcoded-availability-zone", "INFO", name, hit.path, sprintf("availability zone %s is hardcoded; derive it from Fn::GetAZs or a parameter", [hit.zone])) if {
	some name, res in input.resources
	some hit in hardcoded_azs(name, res.resourceType)
}
