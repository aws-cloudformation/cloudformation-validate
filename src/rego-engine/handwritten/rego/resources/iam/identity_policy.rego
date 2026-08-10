package resources

import rego.v1

_single_document_locations := {
    ["AWS::IAM::Policy", "Properties.PolicyDocument"],
    ["AWS::IAM::ManagedPolicy", "Properties.PolicyDocument"],
    ["AWS::IAM::UserPolicy", "Properties.PolicyDocument"],
    ["AWS::IAM::RolePolicy", "Properties.PolicyDocument"],
    ["AWS::IAM::GroupPolicy", "Properties.PolicyDocument"],
    ["AWS::SSO::PermissionSet", "Properties.InlinePolicy"],
}

violation contains make_diag_full("E3510", "ERROR", name, finding.path,
    finding.message, "", "") if {
    some location in _single_document_locations
    some name in resources_of_type(location[0])
    some finding in iam_identity_policy_findings(name, location[1])
}

_policy_list_types := {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}

violation contains make_diag_full("E3510", "ERROR", name, finding.path,
    finding.message, "", "") if {
    some resource_type in _policy_list_types
    some name in resources_of_type(resource_type)
    policies := resolve(name, "Properties.Policies")
    is_array(policies)
    some index, _ in policies
    some finding in iam_identity_policy_findings(name, sprintf("Properties.Policies.%d.PolicyDocument", [index]))
}
