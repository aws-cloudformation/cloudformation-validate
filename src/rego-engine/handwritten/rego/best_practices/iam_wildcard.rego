package best_practices

import rego.v1

# W2512: IAM policy with NotAction (overly permissive).
# Single canonical message across all IAM policy-carrying resource types.
#
# All call sites guard `Statement` with `is_array` before iterating — rego's `some x in y`
# panics when `y` is not iterable (e.g. a bad `Statement: "Test"` string literal),
# which otherwise aborts evaluation of the whole package for that template.

_iam_policy_not_action_msg := "IAM policy uses NotAction which grants all actions except those listed — consider using Action instead"

violation contains make_diag("W2512", "WARN", name, _iam_policy_not_action_msg) if {
    some name in resources_of_type("AWS::IAM::Policy")
    doc := resolve(name, "Properties.PolicyDocument")
    is_object(doc)
    stmts := object.get(doc, "Statement", [])
    is_array(stmts)
    some stmt in stmts
    is_object(stmt)
    stmt.Effect == "Allow"
    object.get(stmt, "NotAction", null) != null
}

violation contains make_diag("W2512", "WARN", name, _iam_policy_not_action_msg) if {
    some name in resources_of_type("AWS::IAM::ManagedPolicy")
    doc := resolve(name, "Properties.PolicyDocument")
    is_object(doc)
    stmts := object.get(doc, "Statement", [])
    is_array(stmts)
    some stmt in stmts
    is_object(stmt)
    stmt.Effect == "Allow"
    object.get(stmt, "NotAction", null) != null
}

violation contains make_diag("W2512", "WARN", name, _iam_policy_not_action_msg) if {
    some rtype in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}
    some name in resources_of_type(rtype)
    policies := resolve(name, "Properties.Policies")
    is_array(policies)
    some policy in policies
    is_object(policy)
    doc := object.get(policy, "PolicyDocument", {})
    is_object(doc)
    stmts := object.get(doc, "Statement", [])
    is_array(stmts)
    some stmt in stmts
    is_object(stmt)
    stmt.Effect == "Allow"
    object.get(stmt, "NotAction", null) != null
}
