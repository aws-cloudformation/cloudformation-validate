package resources

import rego.v1

# E3505: SQS VisibilityTimeout must be >= Lambda Function Timeout
# When a Lambda EventSourceMapping connects a function to an SQS queue,
# the queue's VisibilityTimeout must be >= the function's Timeout.
# cfn-lint anchors the finding on the queue's VisibilityTimeout property with
# this exact wording.
violation contains make_diag_full("E3505", "ERROR", queue_name,
    "Properties.VisibilityTimeout",
    sprintf("Queue visibility timeout (%v) is less than Function timeout (%v) seconds", [vis_timeout, func_timeout]),
    "Set the SQS VisibilityTimeout to at least the Lambda function Timeout",
    "") if {
    some esm_name in resources_of_type("AWS::Lambda::EventSourceMapping")
    # Find the function this ESM points to
    func_name := follow_ref(esm_name, "Properties.FunctionName")
    func_name != null
    func_res := get_resource(func_name)
    func_res != null
    func_res.resourceType == "AWS::Lambda::Function"
    func_timeout := object.get(func_res.properties, "Timeout", 3)
    is_number(func_timeout)
    # Find the SQS queue this ESM points to
    queue_name := follow_ref(esm_name, "Properties.EventSourceArn")
    queue_name != null
    queue_res := get_resource(queue_name)
    queue_res != null
    queue_res.resourceType == "AWS::SQS::Queue"
    vis_timeout := object.get(queue_res.properties, "VisibilityTimeout", 30)
    is_number(vis_timeout)
    vis_timeout < func_timeout
}
