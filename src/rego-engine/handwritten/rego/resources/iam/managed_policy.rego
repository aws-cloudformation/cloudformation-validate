package resources

import rego.v1

# W3037: IAM ManagedPolicy - Statement should have Resource when Action is present
violation contains make_diag_at("W3037", "WARN", name,
    "Properties.PolicyDocument",
    "IAM policy statement has Action but no Resource") if {
    some name in resources_of_type("AWS::IAM::ManagedPolicy")
    doc := resolve(name, "Properties.PolicyDocument")
    is_object(doc)
    stmts := object.get(doc, "Statement", [])
    is_array(stmts)
    some stmt in stmts
    is_object(stmt)
    object.get(stmt, "Action", null) != null
    object.get(stmt, "Resource", null) == null
    object.get(stmt, "NotResource", null) == null
}
