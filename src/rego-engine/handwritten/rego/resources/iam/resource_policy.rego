package resources

import rego.v1

# E3512: Resource-based IAM policies must have Statement
_resource_policy_checks contains {"type": rtype, "path": prop_path} if {
    some raw_path in data.rule_tables.resource_policy_paths
    parts := split(raw_path, "/")
    count(parts) > 2
    parts[0] == "Resources"
    rtype := parts[1]
    prop_parts := array.slice(parts, 2, count(parts))
    prop_path := concat(".", prop_parts)
}

violation contains make_diag_full("E3512", "ERROR", name,
    prop.path,
    "Resource-based policy must have a Statement property",
    "Add a Statement array to the policy document",
    "") if {
    cfn_rule_active("E3512")
    some prop in _resource_policy_checks
    some name in resources_of_type(prop.type)
    doc := resolve(name, prop.path)
    is_object(doc)
    not doc.Statement
}

# W2511: IAM policy document still pins the older-but-valid '2008-10-17'
# version. Only that specific value warrants the upgrade warning; the current
# version is fine and an invalid value is a schema error, not this warning.
_policy_version_paths := {
    {"type": "AWS::S3::BucketPolicy", "path": "Properties.PolicyDocument.Version"},
    {"type": "AWS::SNS::TopicPolicy", "path": "Properties.PolicyDocument.Version"},
    {"type": "AWS::SQS::QueuePolicy", "path": "Properties.PolicyDocument.Version"},
    {"type": "AWS::KMS::Key", "path": "Properties.KeyPolicy.Version"},
    {"type": "AWS::IAM::Role", "path": "Properties.AssumeRolePolicyDocument.Version"},
    {"type": "AWS::IAM::Policy", "path": "Properties.PolicyDocument.Version"},
    {"type": "AWS::IAM::ManagedPolicy", "path": "Properties.PolicyDocument.Version"},
}

violation contains make_diag_full("W2511", "WARN", name,
    prop.path,
    "IAM Policy Version should be updated to '2012-10-17'",
    "Update the policy document Version to '2012-10-17'",
    "") if {
    cfn_rule_active("W2511")
    some prop in _policy_version_paths
    some name in resources_of_type(prop.type)
    some scenario in resolve_scenarios(name, prop.path)
    scenario.value == "2008-10-17"
}
