package resources

import rego.v1

violation contains make_diag_full("E3039", "ERROR", name,
    "Properties",
    msg,
    "",
    "") if {
    cfn_rule_active("E3039")
    some name in resources_of_type("AWS::DynamoDB::Table")
    analysis := dynamodb_scenario_analysis(name)
    some mismatch in analysis.attribute_mismatches
    missing_part := _format_attribute_names("missing definitions", mismatch.missing)
    unused_part := _format_attribute_names("unused definitions", mismatch.unused)
    parts := [part | some part in [missing_part, unused_part]; part != ""]
    msg := sprintf("AttributeDefinitions does not match KeySchema attributes. %s", [concat("; ", parts)])
}

_format_attribute_names(label, names) := result if {
    count(names) > 0
    result := sprintf("%s: [%s]", [label, concat(", ", names)])
}

_format_attribute_names(label, names) := "" if {
    count(names) == 0
}
