package structure

import rego.v1

# Approaching-limit warnings (>90% threshold)
# I2010: Parameter count approaching limit
violation contains make_diag("I2010", "INFO", "",
    sprintf("Template has %d parameters, approaching limit of 200", [cnt])) if {
    cnt := count(input.parameters)
    cnt > 180
    cnt <= 200
}

# I6010: Output count approaching limit
violation contains make_diag("I6010", "INFO", "",
    sprintf("Template has %d outputs, approaching limit of 200", [cnt])) if {
    cnt := count(input.outputs)
    cnt > 180
    cnt <= 200
}

# I7010: Mapping count approaching limit
violation contains make_diag("I7010", "INFO", "",
    sprintf("Template has %d mappings, approaching limit of 200", [cnt])) if {
    cnt := count(input.mappings)
    cnt > 180
    cnt <= 200
}

# F2003: Parameter names must be alphanumeric
violation contains make_diag("F2003", "FATAL", "",
    sprintf("Parameter name '%s' must be alphanumeric", [pname])) if {
    some pname in object.keys(input.parameters)
    not regex.match(`^[a-zA-Z0-9]+$`, pname)
}

# F2011/I2011: Parameter name length
violation contains make_diag("F2011", "FATAL", "",
    sprintf("Parameter name '%s' exceeds maximum length of 255", [pname])) if {
    some pname in object.keys(input.parameters)
    count(pname) > 255
}

violation contains make_diag("I2011", "INFO", "",
    sprintf("Parameter name '%s' is approaching maximum length of 255", [pname])) if {
    some pname in object.keys(input.parameters)
    count(pname) > 229
    count(pname) <= 255
}

# F6004: Output names must be alphanumeric
# Fn::ForEach:: prefixed keys are ForEach constructs, not literal output names
violation contains make_diag("F6004", "FATAL", "",
    sprintf("Output name '%s' must be alphanumeric", [oname])) if {
    some oname in object.keys(input.outputs)
    not regex.match(`^[a-zA-Z0-9]+$`, oname)
    not startswith(oname, "Fn::ForEach::")
}

# F6011/I6011: Output name length
violation contains make_diag("F6011", "FATAL", "",
    sprintf("Output name '%s' exceeds maximum length of 255", [oname])) if {
    some oname in object.keys(input.outputs)
    count(oname) > 255
}

violation contains make_diag("I6011", "INFO", "",
    sprintf("Output name '%s' is approaching maximum length of 255", [oname])) if {
    some oname in object.keys(input.outputs)
    count(oname) > 229
    count(oname) <= 255
}

# F7002/I7002: Mapping name length
violation contains make_diag("F7002", "FATAL", "",
    sprintf("Mapping name '%s' exceeds maximum length of 255", [mname])) if {
    some mname in object.keys(input.mappings)
    count(mname) > 255
}

violation contains make_diag("I7002", "INFO", "",
    sprintf("Mapping name '%s' is approaching maximum length of 255", [mname])) if {
    some mname in object.keys(input.mappings)
    count(mname) > 229
    count(mname) <= 255
}

# F1004: Description must be a string
violation contains make_diag("F1004", "FATAL", "",
    "Description must be a string") if {
    desc := input.template.description
    desc != null
    not is_string(desc)
    not is_null(desc)
}

# F3007: Duplicate resource/parameter names
violation contains make_diag("F3007", "FATAL", pname,
    sprintf("'%s' is used as both a parameter and resource logical ID", [pname])) if {
    some pname in object.keys(input.parameters)
    pname in object.keys(input.resources)
}
