# IAM and credentials: every identity, trust, and resource policy document in the template is decomposed into statements and checked for over-broad grants, and every resource's serialized properties are scanned for hardcoded credentials.
package custom_iam

import rego.v1

_identity_types := {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}

_standalone_policy_types := {
	"AWS::IAM::Policy",
	"AWS::IAM::ManagedPolicy",
	"AWS::IAM::RolePolicy",
	"AWS::IAM::UserPolicy",
	"AWS::IAM::GroupPolicy",
}

_resource_policy_properties := {
	"AWS::S3::BucketPolicy": "PolicyDocument",
	"AWS::SQS::QueuePolicy": "PolicyDocument",
	"AWS::SNS::TopicPolicy": "PolicyDocument",
	"AWS::KMS::Key": "KeyPolicy",
	"AWS::SecretsManager::ResourcePolicy": "ResourcePolicy",
	"AWS::ECR::Repository": "RepositoryPolicyText",
	"AWS::EFS::FileSystem": "FileSystemPolicy",
	"AWS::Backup::BackupVault": "AccessPolicy",
	"AWS::OpenSearchService::Domain": "AccessPolicies",
	"AWS::Elasticsearch::Domain": "AccessPolicies",
	"AWS::ApiGateway::RestApi": "Policy",
	"AWS::S3::AccessPoint": "Policy",
	"AWS::CodeArtifact::Domain": "PermissionsPolicyDocument",
	"AWS::CodeArtifact::Repository": "PermissionsPolicyDocument",
	"AWS::IoT::Policy": "PolicyDocument",
	"AWS::EventSchemas::RegistryPolicy": "Policy",
	"AWS::Glacier::VaultLockPolicy": "Policy",
	"AWS::MediaStore::ContainerPolicy": "Policy",
	"AWS::Lambda::LayerVersionPermission": "Policy",
}

_credential_patterns := [
	["AWS access key ID", `(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}`],
	["private key block", `-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----`],
	["password literal", `(?i)"[a-z_-]*(password|passwd|secret)[a-z_-]*":"[^"{}\[\]]{8,}"`],
]

# The size limit CloudFormation and IAM apply to the aggregate inline policies of a principal.
_inline_policy_limits := {"AWS::IAM::Role": 10240, "AWS::IAM::User": 2048, "AWS::IAM::Group": 5120}

policy_documents contains {"resource": name, "path": sprintf("Properties.Policies.%d.PolicyDocument", [i]), "kind": "identity", "document": document} if {
	some name, res in input.resources
	_identity_types[res.resourceType]
	is_array(res.properties.Policies)
	some i, policy in res.properties.Policies
	document := policy.PolicyDocument
	is_object(document)
}

policy_documents contains {"resource": name, "path": "Properties.PolicyDocument", "kind": "identity", "document": document} if {
	some name, res in input.resources
	_standalone_policy_types[res.resourceType]
	document := res.properties.PolicyDocument
	is_object(document)
}

policy_documents contains {"resource": name, "path": sprintf("Properties.%s", [property]), "kind": "resource", "document": document} if {
	some name, res in input.resources
	property := _resource_policy_properties[res.resourceType]
	document := res.properties[property]
	is_object(document)
}

trust_documents contains {"resource": name, "path": "Properties.AssumeRolePolicyDocument", "document": document} if {
	some name, res in input.resources
	res.resourceType == "AWS::IAM::Role"
	document := res.properties.AssumeRolePolicyDocument
	is_object(document)
}

# A lone statement object is valid IAM and is treated as a one-element list.
statements contains {"resource": p.resource, "path": sprintf("%s.Statement.%d", [p.path, i]), "kind": p.kind, "statement": statement} if {
	some p in policy_documents
	some i, statement in ensure_list(p.document.Statement)
	is_object(statement)
}

_strings(value) := [item | some item in ensure_list(value); is_string(item)]

_allows(statement) if statement.Effect == "Allow"

_full_wildcard(action) if action == "*"

_full_wildcard(action) if action == "*:*"

_service_wildcard(action) if {
	not _full_wildcard(action)
	regex.match(`^[A-Za-z0-9-]+:\*$`, action)
}

_all_resources(statement) if {
	some resource in _strings(statement.Resource)
	resource == "*"
}

_has_condition(statement) if {
	is_object(statement.Condition)
	count(statement.Condition) > 0
}

_any_principal(principal) if principal == "*"

_any_principal(principal) if {
	is_object(principal)
	some aws in _strings(principal.AWS)
	aws == "*"
}

_passed_to_service_condition(statement) if {
	some _, operands in statement.Condition
	is_object(operands)
	some key, _ in operands
	lower(key) == "iam:passedtoservice"
}

violation contains make_diag_at("iam.allow-all-actions-all-resources", "ERROR", s.resource, s.path, sprintf("statement allows every action (%s) on every resource without a condition", [action])) if {
	some s in statements
	_allows(s.statement)
	some action in _strings(s.statement.Action)
	_full_wildcard(action)
	_all_resources(s.statement)
	not _has_condition(s.statement)
}

violation contains make_diag_at("iam.service-wildcard-action", "WARN", s.resource, s.path, sprintf("statement allows %s on every resource; list the actions and scope the resources", [action])) if {
	some s in statements
	s.kind == "identity"
	_allows(s.statement)
	some action in _strings(s.statement.Action)
	_service_wildcard(action)
	_all_resources(s.statement)
}

violation contains make_diag_full("iam.passrole-unrestricted", "WARN", s.resource, s.path, "iam:PassRole is allowed on every role without an iam:PassedToService condition", "Restrict Resource to the roles that may be passed or add an iam:PassedToService condition", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html") if {
	some s in statements
	s.kind == "identity"
	_allows(s.statement)
	some action in _strings(s.statement.Action)
	lower(action) in {"iam:passrole", "iam:*", "iam:pass*"}
	_all_resources(s.statement)
	not _passed_to_service_condition(s.statement)
}

violation contains make_diag_at("iam.allow-with-negated-matcher", "WARN", s.resource, s.path, sprintf("Allow statement uses %s, which grants everything that is not listed", [field])) if {
	some s in statements
	_allows(s.statement)
	some field in ["NotAction", "NotResource"]
	object.get(s.statement, field, null) != null
}

violation contains make_diag_at("iam.trust-policy-any-principal", "ERROR", t.resource, sprintf("%s.Statement.%d", [t.path, i]), "role can be assumed by any AWS principal because the trust statement has no condition") if {
	some t in trust_documents
	some i, statement in ensure_list(t.document.Statement)
	is_object(statement)
	_allows(statement)
	_any_principal(statement.Principal)
	not _has_condition(statement)
}

violation contains make_diag_at("iam.inline-policy-size-limit", "WARN", name, "Properties.Policies", sprintf("inline policies total %d characters; %s allows %d", [total, res.resourceType, limit])) if {
	some name, res in input.resources
	limit := _inline_policy_limits[res.resourceType]
	is_array(res.properties.Policies)
	total := sum([count(json.marshal(policy.PolicyDocument)) | some policy in res.properties.Policies; is_object(policy.PolicyDocument)])
	total > limit
}

violation contains make_diag_at("iam.administrator-access-attached", "WARN", name, sprintf("Properties.ManagedPolicyArns.%d", [i]), "the AdministratorAccess managed policy is attached; grant the specific permissions the principal needs") if {
	some name, res in input.resources
	_identity_types[res.resourceType]
	is_array(res.properties.ManagedPolicyArns)
	some i, arn in res.properties.ManagedPolicyArns
	is_string(arn)
	arn_matches(arn, "arn:*:iam::aws:policy/AdministratorAccess")
}

violation contains make_diag_at("iam.resource-policy-public-principal", "ERROR", s.resource, s.path, sprintf("resource policy statement grants %v to any principal without a condition", [_strings(s.statement.Action)])) if {
	some s in statements
	s.kind == "resource"
	_allows(s.statement)
	_any_principal(s.statement.Principal)
	not _has_condition(s.statement)
}

_redact(match) := sprintf("%s...", [substring(match, 0, 24)])

violation contains make_diag("iam.hardcoded-credential", "ERROR", name, sprintf("%s found in the resource properties: %s", [label, _redact(match)])) if {
	some name, res in input.resources
	serialized := json.marshal(res.properties)
	some [label, pattern] in _credential_patterns
	some match in regex.find_n(pattern, serialized, -1)
}
