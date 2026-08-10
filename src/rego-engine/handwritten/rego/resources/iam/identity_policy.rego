package resources

import rego.v1

# E3510: IAM identity policy must have valid structure
violation contains make_diag_full("E3510", "ERROR", name,
    "Properties.PolicyDocument",
    "IAM identity policy must have a Statement property",
    "Add a Statement array to the PolicyDocument",
    "") if {
    some name in resources_of_type("AWS::IAM::Policy")
    doc := resolve(name, "Properties.PolicyDocument")
    is_object(doc)
    not doc.Statement
}

# Also check inline policies on roles
violation contains make_diag_full("E3510", "ERROR", name,
    sprintf("Properties.Policies[%d].PolicyDocument", [idx]),
    "IAM inline policy must have a Statement property",
    "Add a Statement array to the PolicyDocument",
    "") if {
    some name in resources_of_type("AWS::IAM::Role")
    policies := resolve(name, "Properties.Policies")
    is_array(policies)
    some idx, pol in policies
    doc := pol.PolicyDocument
    is_object(doc)
    not doc.Statement
}
