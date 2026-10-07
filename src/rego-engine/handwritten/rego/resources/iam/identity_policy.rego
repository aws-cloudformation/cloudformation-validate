package resources

import rego.v1

# IAM identity policy structural validation via the shared builtin.
# Covers IAM::Policy, ManagedPolicy, UserPolicy, RolePolicy, GroupPolicy,
# SSO::PermissionSet, and inline Policies on Role/User/Group.

# --- Single-document policy types ---

violation contains make_diag_at_source("E3510", "ERROR", name, finding.effective_path, finding.source_path, finding.message) if {
    cfn_rule_active("E3510")
    some name in resources_of_type("AWS::IAM::Policy")
    some finding in iam_identity_policy_findings(name, "Properties.PolicyDocument")
}

violation contains make_diag_at_source("E3510", "ERROR", name, finding.effective_path, finding.source_path, finding.message) if {
    cfn_rule_active("E3510")
    some name in resources_of_type("AWS::IAM::ManagedPolicy")
    some finding in iam_identity_policy_findings(name, "Properties.PolicyDocument")
}

violation contains make_diag_at_source("E3510", "ERROR", name, finding.effective_path, finding.source_path, finding.message) if {
    cfn_rule_active("E3510")
    some name in resources_of_type("AWS::IAM::UserPolicy")
    some finding in iam_identity_policy_findings(name, "Properties.PolicyDocument")
}

violation contains make_diag_at_source("E3510", "ERROR", name, finding.effective_path, finding.source_path, finding.message) if {
    cfn_rule_active("E3510")
    some name in resources_of_type("AWS::IAM::RolePolicy")
    some finding in iam_identity_policy_findings(name, "Properties.PolicyDocument")
}

violation contains make_diag_at_source("E3510", "ERROR", name, finding.effective_path, finding.source_path, finding.message) if {
    cfn_rule_active("E3510")
    some name in resources_of_type("AWS::IAM::GroupPolicy")
    some finding in iam_identity_policy_findings(name, "Properties.PolicyDocument")
}

violation contains make_diag_at_source("E3510", "ERROR", name, finding.effective_path, finding.source_path, finding.message) if {
    cfn_rule_active("E3510")
    some name in resources_of_type("AWS::SSO::PermissionSet")
    some finding in iam_identity_policy_findings(name, "Properties.InlinePolicy")
}

# --- Inline policies on Role/User/Group (Properties.Policies[*].PolicyDocument) ---

violation contains make_diag_at_source("E3510", "ERROR", name, finding.effective_path, finding.source_path, finding.message) if {
    cfn_rule_active("E3510")
    some name in resources_of_type("AWS::IAM::Role")
    some doc_path in iam_inline_policy_document_paths(name, "Properties.Policies")
    some finding in iam_identity_policy_findings(name, doc_path)
}

violation contains make_diag_at_source("E3510", "ERROR", name, finding.effective_path, finding.source_path, finding.message) if {
    cfn_rule_active("E3510")
    some name in resources_of_type("AWS::IAM::User")
    some doc_path in iam_inline_policy_document_paths(name, "Properties.Policies")
    some finding in iam_identity_policy_findings(name, doc_path)
}

violation contains make_diag_at_source("E3510", "ERROR", name, finding.effective_path, finding.source_path, finding.message) if {
    cfn_rule_active("E3510")
    some name in resources_of_type("AWS::IAM::Group")
    some doc_path in iam_inline_policy_document_paths(name, "Properties.Policies")
    some finding in iam_identity_policy_findings(name, doc_path)
}
