# Reference-graph analysis: unreferenced resources, redundant DependsOn, references whose condition is not implied by the target's condition (SAT-checked per edge), unused parameters, transitive dependency hubs computed pairwise, and pairwise duplicate resource definitions.
package custom_graph

import rego.v1

# Resource types that act on other resources and are legitimately never referenced themselves.
_terminal_types := {
	"AWS::ApiGateway::Account", "AWS::ApiGateway::BasePathMapping", "AWS::ApiGateway::Deployment", "AWS::ApiGateway::Method",
	"AWS::ApiGateway::Stage", "AWS::ApplicationAutoScaling::ScalingPolicy", "AWS::AutoScaling::AutoScalingGroup",
	"AWS::AutoScaling::ScalingPolicy", "AWS::AutoScaling::ScheduledAction", "AWS::Backup::BackupSelection", "AWS::Budgets::Budget",
	"AWS::CloudFormation::CustomResource", "AWS::CloudFormation::Macro", "AWS::CloudFormation::Stack", "AWS::CloudFormation::WaitCondition",
	"AWS::CloudFront::Distribution", "AWS::CloudTrail::Trail", "AWS::CloudWatch::Alarm", "AWS::CloudWatch::Dashboard",
	"AWS::CodeBuild::Project", "AWS::CodeDeploy::DeploymentGroup", "AWS::CodePipeline::Pipeline", "AWS::Config::ConfigRule",
	"AWS::Config::ConfigurationRecorder", "AWS::Config::DeliveryChannel", "AWS::EC2::EIPAssociation", "AWS::EC2::Instance",
	"AWS::EC2::NetworkAclEntry", "AWS::EC2::Route", "AWS::EC2::SecurityGroupEgress", "AWS::EC2::SecurityGroupIngress",
	"AWS::EC2::SubnetNetworkAclAssociation", "AWS::EC2::SubnetRouteTableAssociation", "AWS::EC2::VPCGatewayAttachment",
	"AWS::EC2::VolumeAttachment", "AWS::ECR::ReplicationConfiguration", "AWS::ECS::Service", "AWS::ElasticLoadBalancingV2::Listener",
	"AWS::ElasticLoadBalancingV2::ListenerRule", "AWS::Events::EventBusPolicy", "AWS::Events::Rule", "AWS::Glue::Crawler",
	"AWS::Glue::Trigger", "AWS::GuardDuty::Detector", "AWS::IAM::GroupPolicy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Policy",
	"AWS::IAM::RolePolicy", "AWS::IAM::UserPolicy", "AWS::Lambda::EventSourceMapping", "AWS::Lambda::Permission",
	"AWS::Logs::MetricFilter", "AWS::Logs::ResourcePolicy", "AWS::Logs::SubscriptionFilter", "AWS::Route53::RecordSet",
	"AWS::Route53::RecordSetGroup", "AWS::S3::BucketPolicy", "AWS::SNS::Subscription", "AWS::SNS::TopicPolicy",
	"AWS::SQS::QueuePolicy", "AWS::SSM::Association", "AWS::SSM::Parameter", "AWS::Scheduler::Schedule", "AWS::SecurityHub::Hub",
	"AWS::StepFunctions::StateMachine", "AWS::WAFv2::WebACLAssociation",
}

_hub_minimum_resources := 10

_hub_minimum_direct_dependents := 1

_referenced_targets := {edge.target | some edge in input.edges}

_referenced_by_output(name) if {
	some _, output in input.outputs
	contains(json.marshal(output.value), sprintf("\"__ref\":\"%s\"", [name]))
}

_referenced_by_output(name) if {
	some _, output in input.outputs
	some reference in output.getattRefs
	reference.resource == name
}

_referenced_parameter(name) if _referenced_targets[name]

_referenced_parameter(name) if name in input.conditionParamRefs

_referenced_parameter(name) if name in input.globalsParamRefs

_referenced_parameter(name) if name in input.paramsReferencedInDefinitions

_referenced_parameter(name) if {
	some rule in input.parsedRules
	contains(json.marshal(rule), sprintf("\"%s\"", [name]))
}

_referenced_parameter(name) if {
	some _, output in input.outputs
	contains(json.marshal(output.value), sprintf("\"%s\"", [name]))
}

_transitive_dependents(name) := {other |
	some other, _ in input.resources
	other != name
	depends_on(other, name)
}

violation contains make_diag("graph.unreferenced-resource", "INFO", name, sprintf("%s is neither referenced by another resource nor exposed through an output", [name])) if {
	some name, res in input.resources
	not _terminal_types[res.resourceType]
	not startswith(res.resourceType, "Custom::")
	count(ref_sources(name)) == 0
	not _referenced_by_output(name)
}

violation contains make_diag_at("graph.redundant-depends-on", "INFO", name, "DependsOn", sprintf("DependsOn %s is implied by an existing reference at %s", [target, edge.sourcePath])) if {
	some name, res in input.resources
	some target in res.dependsOn
	some edge in edges_from(name)
	edge.target == target
	edge.kind != "DependsOn"
}

violation contains make_diag_at("graph.reference-to-conditional-resource", "ERROR", edge.source, edge.sourcePath, sprintf("%s references %s, which exists only when %s is true, but %v does not imply that", [edge.source, edge.target, target_condition, source_condition])) if {
	some edge in input.edges
	edge.kind != "DependsOn"
	input.resources[edge.source]
	input.resources[edge.target]
	target_condition := resource_condition(edge.target)
	target_condition != null
	source_condition := resource_condition(edge.source)
	not conjunction_implies(source_condition, object.get(edge, "conditionContext", null), target_condition)
}

violation contains make_diag("graph.parameter-unused", "INFO", "", sprintf("parameter %s is never referenced", [name])) if {
	some name, _ in input.parameters
	not _referenced_parameter(name)
}

violation contains make_diag("graph.dependency-hub", "INFO", name, sprintf("%d of %d resources transitively depend on %s; a change to it ripples through most of the stack", [count(dependents), total, name])) if {
	total := count(input.resources)
	total >= _hub_minimum_resources
	some name, _ in input.resources
	count(ref_sources(name)) >= _hub_minimum_direct_dependents
	dependents := _transitive_dependents(name)
	count(dependents) * 2 > total
}

_duplicates_of(name) := {other |
	some other, candidate in input.resources
	name < other
	candidate.resourceType == input.resources[name].resourceType
	candidate.properties == input.resources[name].properties
}

violation contains make_diag("graph.duplicate-resource-definition", "INFO", name, sprintf("%d later resource(s) such as %s have the same type and identical properties as %s", [count(duplicates), min(duplicates), name])) if {
	some name, res in input.resources
	count(res.properties) > 0
	duplicates := _duplicates_of(name)
	count(duplicates) > 0
}
