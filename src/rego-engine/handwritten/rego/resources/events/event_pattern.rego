package resources

import rego.v1

violation contains make_diag_full("E9014", "ERROR", finding.resourceId,
    finding.propertyPath,
    finding.message,
    finding.suggestedFix,
    "") if {
    cfn_rule_active("E9014")
    some finding in event_pattern_violations()
}
