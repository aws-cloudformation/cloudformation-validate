package resources

import rego.v1

# E3501: FIFO SQS queue name must end with .fifo
violation contains make_diag_full("E3501", "ERROR", name,
    "Properties.QueueName",
    sprintf("FIFO queue name '%s' must end with '.fifo'", [qname]),
    "Append .fifo to the queue name",
    "") if {
    cfn_rule_active("E3501")
    some name in resources_of_type("AWS::SQS::Queue")
    fifo := resolve(name, "Properties.FifoQueue")
    fifo == true
    qname := resolve(name, "Properties.QueueName")
    is_string(qname)
    not endswith(qname, ".fifo")
}

# Non-FIFO queue name must not end with .fifo
violation contains make_diag_full("E3501", "ERROR", name,
    "Properties.QueueName",
    sprintf("Non-FIFO queue name '%s' must not end with '.fifo'", [qname]),
    "Remove .fifo suffix or set FifoQueue to true",
    "") if {
    cfn_rule_active("E3501")
    some name in resources_of_type("AWS::SQS::Queue")
    qname := resolve(name, "Properties.QueueName")
    is_string(qname)
    endswith(qname, ".fifo")
    fifo := resolve(name, "Properties.FifoQueue")
    fifo != true
}
