package best_practices

import rego.v1

# Allow statements with NotAction grant every action except those listed.
# Uses the shared scenario-aware builtin which handles single-object Statement,
# conditional document/statement fields, and conditional whole Policies lists.

_iam_policy_not_action_msg := "IAM policy uses NotAction which grants all actions except those listed - consider using Action instead"

violation contains make_diag("W2512", "WARN", name, _iam_policy_not_action_msg) if {
    some rtype in {
        "AWS::IAM::Policy",
        "AWS::IAM::ManagedPolicy",
        "AWS::SQS::QueuePolicy",
        "AWS::SNS::TopicPolicy",
        "AWS::S3::BucketPolicy",
    }
    some name in resources_of_type(rtype)
    iam_policy_has_allow_not_action(name, "Properties.PolicyDocument")
}

violation contains make_diag("W2512", "WARN", name, _iam_policy_not_action_msg) if {
    some rtype in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}
    some name in resources_of_type(rtype)
    some doc_path in iam_inline_policy_document_paths(name, "Properties.Policies")
    iam_policy_has_allow_not_action(name, doc_path)
}

violation contains make_diag("W2512", "WARN", name, _iam_policy_not_action_msg) if {
    some name in resources_of_type("AWS::SSO::PermissionSet")
    iam_policy_has_allow_not_action(name, "Properties.InlinePolicy")
}
