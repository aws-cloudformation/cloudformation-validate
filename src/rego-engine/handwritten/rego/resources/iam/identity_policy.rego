package resources

import rego.v1

# IAM identity policy structural validation via the shared builtin.
# Covers IAM::Policy, ManagedPolicy, UserPolicy, RolePolicy, GroupPolicy,
# SSO::PermissionSet, and inline Policies on Role/User/Group.

# --- Single-document policy types ---

violation contains make_diag_at("E3510", "ERROR", name, finding.path, finding.message) if {
    some name in resources_of_type("AWS::IAM::Policy")
    some finding in iam_identity_policy_findings(name, "Properties.PolicyDocument")
}

violation contains make_diag_at("E3510", "ERROR", name, finding.path, finding.message) if {
    some name in resources_of_type("AWS::IAM::ManagedPolicy")
    some finding in iam_identity_policy_findings(name, "Properties.PolicyDocument")
}

violation contains make_diag_at("E3510", "ERROR", name, finding.path, finding.message) if {
    some name in resources_of_type("AWS::IAM::UserPolicy")
    some finding in iam_identity_policy_findings(name, "Properties.PolicyDocument")
}

violation contains make_diag_at("E3510", "ERROR", name, finding.path, finding.message) if {
    some name in resources_of_type("AWS::IAM::RolePolicy")
    some finding in iam_identity_policy_findings(name, "Properties.PolicyDocument")
}

violation contains make_diag_at("E3510", "ERROR", name, finding.path, finding.message) if {
    some name in resources_of_type("AWS::IAM::GroupPolicy")
    some finding in iam_identity_policy_findings(name, "Properties.PolicyDocument")
}

violation contains make_diag_at("E3510", "ERROR", name, finding.path, finding.message) if {
    some name in resources_of_type("AWS::SSO::PermissionSet")
    some finding in iam_identity_policy_findings(name, "Properties.InlinePolicy")
}

# --- Inline policies on Role/User/Group (Properties.Policies[*].PolicyDocument) ---

violation contains make_diag_at("E3510", "ERROR", name, finding.path, finding.message) if {
    some name in resources_of_type("AWS::IAM::Role")
    policies := resolve(name, "Properties.Policies")
    is_array(policies)
    some idx, _ in policies
    doc_path := sprintf("Properties.Policies.%d.PolicyDocument", [idx])
    some finding in iam_identity_policy_findings(name, doc_path)
}

violation contains make_diag_at("E3510", "ERROR", name, finding.path, finding.message) if {
    some name in resources_of_type("AWS::IAM::User")
    policies := resolve(name, "Properties.Policies")
    is_array(policies)
    some idx, _ in policies
    doc_path := sprintf("Properties.Policies.%d.PolicyDocument", [idx])
    some finding in iam_identity_policy_findings(name, doc_path)
}

violation contains make_diag_at("E3510", "ERROR", name, finding.path, finding.message) if {
    some name in resources_of_type("AWS::IAM::Group")
    policies := resolve(name, "Properties.Policies")
    is_array(policies)
    some idx, _ in policies
    doc_path := sprintf("Properties.Policies.%d.PolicyDocument", [idx])
    some finding in iam_identity_policy_findings(name, doc_path)
}
