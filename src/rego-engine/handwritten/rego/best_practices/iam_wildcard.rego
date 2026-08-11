package best_practices

import rego.v1

# Allow statements with NotAction grant every action except those listed.
# Statement must be an array before iteration because malformed policy documents
# are diagnosed separately and must not abort evaluation of this package.

_iam_policy_not_action_msg := "IAM policy uses NotAction which grants all actions except those listed - consider using Action instead"

_has_allow_not_action(doc) if {
    is_object(doc)
    stmts := object.get(doc, "Statement", [])
    is_array(stmts)
    some stmt in stmts
    is_object(stmt)
    stmt.Effect == "Allow"
    object.get(stmt, "NotAction", null) != null
}

violation contains make_diag("W2512", "WARN", name, _iam_policy_not_action_msg) if {
    some rtype in {
        "AWS::IAM::Policy",
        "AWS::IAM::ManagedPolicy",
        "AWS::SQS::QueuePolicy",
        "AWS::SNS::TopicPolicy",
        "AWS::S3::BucketPolicy",
    }
    some name in resources_of_type(rtype)
    doc := resolve(name, "Properties.PolicyDocument")
    _has_allow_not_action(doc)
}

violation contains make_diag("W2512", "WARN", name, _iam_policy_not_action_msg) if {
    some rtype in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}
    some name in resources_of_type(rtype)
    policies := resolve(name, "Properties.Policies")
    is_array(policies)
    some policy in policies
    is_object(policy)
    doc := object.get(policy, "PolicyDocument", {})
    _has_allow_not_action(doc)
}

violation contains make_diag("W2512", "WARN", name, _iam_policy_not_action_msg) if {
    some name in resources_of_type("AWS::SSO::PermissionSet")
    doc := resolve(name, "Properties.InlinePolicy")
    _has_allow_not_action(doc)
}
