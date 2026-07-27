package resources

import rego.v1

# E3510: IAM identity policy documents must be structurally valid. The shared
# validator produces one finding per defect, anchored inside the document:
# allowed keys, the Version enum, the Statement list, each statement's keys,
# Effect enum, exactly-one-of Action/NotAction and Resource/NotResource pairs,
# value types, and the resource-ARN format.

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
    some loc in _single_document_locations
    some name in resources_of_type(loc[0])
    some finding in iam_identity_policy_findings(name, loc[1])
}

# Inline policies carried in a Policies list (roles, users, groups).
_policy_list_types := {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}

violation contains make_diag_full("E3510", "ERROR", name, finding.path,
    finding.message, "", "") if {
    some rtype in _policy_list_types
    some name in resources_of_type(rtype)
    policies := resolve(name, "Properties.Policies")
    is_array(policies)
    some idx, _ in policies
    some finding in iam_identity_policy_findings(name, sprintf("Properties.Policies.%d.PolicyDocument", [idx]))
}
