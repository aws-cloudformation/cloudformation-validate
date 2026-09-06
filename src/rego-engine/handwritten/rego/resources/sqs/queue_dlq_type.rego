package resources

import rego.v1

# E3502: SQS queue and DLQ must be same type (FIFO/standard).
# Uses outgoingRefs edges to follow both Ref and GetAtt references to the DLQ target.
violation contains make_diag_at("E3502", "ERROR", name,
    "Properties.RedrivePolicy",
    "Source queue type 'FIFO' does not match destination queue type 'standard'") if {
    cfn_rule_active("E3502")
    some name, res in input.resources
    res.resourceType == "AWS::SQS::Queue"
    resolve(name, "Properties.FifoQueue") == true
    some edge in res.outgoingRefs
    contains(edge.sourcePath, "RedrivePolicy.deadLetterTargetArn")
    dlq_name := edge.target
    input.resources[dlq_name].resourceType == "AWS::SQS::Queue"
    not resolve(dlq_name, "Properties.FifoQueue") == true
}

violation contains make_diag_at("E3502", "ERROR", name,
    "Properties.RedrivePolicy",
    "Source queue type 'standard' does not match destination queue type 'FIFO'") if {
    cfn_rule_active("E3502")
    some name, res in input.resources
    res.resourceType == "AWS::SQS::Queue"
    not resolve(name, "Properties.FifoQueue") == true
    some edge in res.outgoingRefs
    contains(edge.sourcePath, "RedrivePolicy.deadLetterTargetArn")
    dlq_name := edge.target
    input.resources[dlq_name].resourceType == "AWS::SQS::Queue"
    resolve(dlq_name, "Properties.FifoQueue") == true
}
