package resources

import rego.v1

# W3515: IAM Statement must have Effect
violation contains make_diag_full("W3515", "WARN", name,
    "Properties.PolicyDocument",
    "IAM policy statement is missing required 'Effect' property",
    "Add Effect: Allow or Effect: Deny to the statement",
    "") if {
    some name in resources_of_type("AWS::IAM::Policy")
    doc := resolve(name, "Properties.PolicyDocument")
    is_object(doc)
    some stmt in doc.Statement
    is_object(stmt)
    not object.get(stmt, "Effect", null) != null
}

# E3514: IAM Statement Effect must be Allow or Deny
violation contains make_diag_full("E3514", "ERROR", name,
    "Properties.PolicyDocument",
    sprintf("IAM policy statement Effect must be 'Allow' or 'Deny', got '%s'", [effect]),
    "Set Effect to 'Allow' or 'Deny'",
    "") if {
    some name in resources_of_type("AWS::IAM::Policy")
    doc := resolve(name, "Properties.PolicyDocument")
    is_object(doc)
    some stmt in doc.Statement
    is_object(stmt)
    effect := stmt.Effect
    not effect in {"Allow", "Deny"}
}

# E9005: IAM Statement must have Action or NotAction (engine-only; E3045 covers S3)
violation contains make_diag_full("E9005", "ERROR", name,
    "Properties.PolicyDocument",
    "IAM policy statement must have 'Action' or 'NotAction'",
    "Add an Action or NotAction to the statement",
    "") if {
    some name in resources_of_type("AWS::IAM::Policy")
    doc := resolve(name, "Properties.PolicyDocument")
    is_object(doc)
    some stmt in doc.Statement
    is_object(stmt)
    not object.get(stmt, "Action", null) != null
    not object.get(stmt, "NotAction", null) != null
}
