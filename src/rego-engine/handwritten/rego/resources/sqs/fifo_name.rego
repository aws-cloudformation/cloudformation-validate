package resources

import rego.v1

# E2504: FIFO queue name must end with .fifo
violation contains make_diag_at("E2504", "ERROR", name,
    "Properties.QueueName",
    sprintf("FIFO queue name '%s' must end with '.fifo'", [qname])) if {
    some name in resources_of_type("AWS::SQS::Queue")
    some fifo in resolve_all(name, "Properties.FifoQueue")
    fifo == true
    some qname in resolve_all(name, "Properties.QueueName")
    is_string(qname)
    not endswith(qname, ".fifo")
}
