package resources

import rego.v1

violation contains make_diag_full("E3505", "ERROR", timeout.queueId,
    "Properties.VisibilityTimeout",
    timeout.message,
    timeout.suggestedFix,
    "") if {
    cfn_rule_active("E3505")
    some timeout in sqs_event_source_timeout_violations()
}
