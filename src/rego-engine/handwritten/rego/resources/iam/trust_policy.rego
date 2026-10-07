package resources

import rego.v1

# E3530: IAM trust policy (AssumeRolePolicyDocument) must have Statement
violation contains make_diag_full("E3530", "ERROR", name,
    "Properties.AssumeRolePolicyDocument",
    "'Statement' is a required property",
    "Add a Statement array to the AssumeRolePolicyDocument",
    "") if {
    cfn_rule_active("E3530")
    some name in resources_of_type("AWS::IAM::Role")
    doc := resolve(name, "Properties.AssumeRolePolicyDocument")
    is_object(doc)
    not doc.Statement
}

# E3530: Each trust policy statement must have Effect
violation contains make_diag_full("E3530", "ERROR", name,
    sprintf("Properties.AssumeRolePolicyDocument.Statement.%d", [idx]),
    "'Effect' is a required property in trust policy statement",
    "Add Effect (Allow or Deny) to the statement",
    "") if {
    cfn_rule_active("E3530")
    some name in resources_of_type("AWS::IAM::Role")
    doc := resolve(name, "Properties.AssumeRolePolicyDocument")
    is_object(doc)
    is_array(doc.Statement)
    some idx, stmt in doc.Statement
    is_object(stmt)
    not stmt.Effect
}

# E3530: Each trust policy statement must have Principal
violation contains make_diag_full("E3530", "ERROR", name,
    sprintf("Properties.AssumeRolePolicyDocument.Statement.%d", [idx]),
    "'Principal' is a required property in trust policy statement",
    "Add Principal to the statement",
    "") if {
    cfn_rule_active("E3530")
    some name in resources_of_type("AWS::IAM::Role")
    doc := resolve(name, "Properties.AssumeRolePolicyDocument")
    is_object(doc)
    is_array(doc.Statement)
    some idx, stmt in doc.Statement
    is_object(stmt)
    not stmt.Principal
}

# E3530: Each trust policy statement must have Action or NotAction
violation contains make_diag_full("E3530", "ERROR", name,
    sprintf("Properties.AssumeRolePolicyDocument.Statement.%d", [idx]),
    "'Action' or 'NotAction' is a required property in trust policy statement",
    "Add Action or NotAction to the statement",
    "") if {
    cfn_rule_active("E3530")
    some name in resources_of_type("AWS::IAM::Role")
    doc := resolve(name, "Properties.AssumeRolePolicyDocument")
    is_object(doc)
    is_array(doc.Statement)
    some idx, stmt in doc.Statement
    is_object(stmt)
    not stmt.Action
    not stmt.NotAction
}
