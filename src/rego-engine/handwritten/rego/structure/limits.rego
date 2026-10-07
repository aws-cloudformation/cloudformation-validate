package structure

import rego.v1

# F0003: Max 200 parameters
violation contains make_diag("F0003", "FATAL", "", sprintf("Template has %d parameters, maximum is 200", [count(input.parameters)])) if {
    cfn_rule_active("F0003")
    count(input.parameters) > 200
}

# F0004: Max 200 outputs
violation contains make_diag("F0004", "FATAL", "", sprintf("Template has %d outputs, maximum is 200", [count(input.outputs)])) if {
    cfn_rule_active("F0004")
    input.outputs
    count(input.outputs) > 200
}

# F0007: Max 500 resources
violation contains make_diag("F0007", "FATAL", "", sprintf("Template has %d resources, maximum is 500", [count(input.resources)])) if {
    cfn_rule_active("F0007")
    count(input.resources) > 500
}

# F0008: Max 200 mappings
violation contains make_diag("F0008", "FATAL", "", sprintf("Template has %d mappings, maximum is 200", [count(input.mappings)])) if {
    cfn_rule_active("F0008")
    input.mappings
    count(input.mappings) > 200
}

# F0009: Max 200 conditions
violation contains make_diag("F0009", "FATAL", "", sprintf("Template has %d conditions, maximum is 200", [count(input.conditions)])) if {
    cfn_rule_active("F0009")
    input.conditions
    count(input.conditions) > 200
}
