package resources

import rego.v1

# W3694: SNS Subscription - Endpoint should match Protocol
violation contains make_diag_at("W3694", "WARN", name,
    "Properties.Endpoint",
    sprintf("Endpoint references '%s' (type '%s') but Protocol 'sqs' expects an SQS Queue", [target, target_type])) if {
    some name in resources_of_type("AWS::SNS::Subscription")
    protocol := resolve(name, "Properties.Protocol")
    protocol == "sqs"
    target := follow_ref(name, "Properties.Endpoint")
    target != null
    target_res := get_resource(target)
    target_res != null
    target_type := target_res.resourceType
    target_type != "AWS::SQS::Queue"
}

violation contains make_diag_at("W3694", "WARN", name,
    "Properties.Endpoint",
    sprintf("Endpoint references '%s' (type '%s') but Protocol 'lambda' expects a Lambda Function", [target, target_type])) if {
    some name in resources_of_type("AWS::SNS::Subscription")
    protocol := resolve(name, "Properties.Protocol")
    protocol == "lambda"
    target := follow_ref(name, "Properties.Endpoint")
    target != null
    target_res := get_resource(target)
    target_res != null
    target_type := target_res.resourceType
    target_type != "AWS::Lambda::Function"
}
