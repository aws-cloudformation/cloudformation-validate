package structure

import rego.v1

# F0003: Max 200 parameters
violation contains make_diag("F0003", "FATAL", "", sprintf("Template has %d parameters, maximum is 200", [count(input.parameters)])) if {
    count(input.parameters) > 200
}

# F0004: Max 200 outputs
violation contains make_diag("F0004", "FATAL", "", sprintf("Template has %d outputs, maximum is 200", [count(input.outputs)])) if {
    input.outputs
    count(input.outputs) > 200
}

# F0007: Max 500 resources
violation contains make_diag("F0007", "FATAL", "", sprintf("Template has %d resources, maximum is 500", [count(input.resources)])) if {
    count(input.resources) > 500
}

# F0008: Max 200 mappings
violation contains make_diag("F0008", "FATAL", "", sprintf("Template has %d mappings, maximum is 200", [count(input.mappings)])) if {
    input.mappings
    count(input.mappings) > 200
}

# F0009: Max 200 conditions
violation contains make_diag("F0009", "FATAL", "", sprintf("Template has %d conditions, maximum is 200", [count(input.conditions)])) if {
    input.conditions
    count(input.conditions) > 200
}
