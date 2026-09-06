package resources

import rego.v1

# E3513: ECR repository policy must have Statement
violation contains make_diag_full("E3513", "ERROR", name,
    "Properties.RepositoryPolicyText",
    "ECR repository policy must have a Statement property",
    "Add a Statement array to the RepositoryPolicyText",
    "") if {
    cfn_rule_active("E3513")
    some name in resources_of_type("AWS::ECR::Repository")
    doc := resolve(name, "Properties.RepositoryPolicyText")
    is_object(doc)
    not doc.Statement
}
