package structure

import rego.v1

# Scalar parameter defaults are compared to AllowedValues as a whole.
violation contains make_diag_at("F2012", "FATAL", "",
    sprintf("Parameters/%s/Default", [name]),
    sprintf("Parameter '%s' Default '%s' is not in AllowedValues %s", [name, def, render_list(avs)])) if {
    cfn_rule_active("F2012")
    some name, param in input.parameters
    not _is_cdl_type(param.type)
    def := object.get(param, "default", null)
    def != null
    avs := param.allowedValues
    avs != null
    is_array(avs)
    count(avs) > 0
    not def in {v | some v in avs}
}

# List parameter defaults are split on commas, trimmed, and checked element by element.
violation contains make_diag_at("F2012", "FATAL", "",
    sprintf("Parameters/%s/Default", [name]),
    sprintf("Parameter '%s' Default '%s' is not in AllowedValues %s", [name, element, render_list(avs)])) if {
    cfn_rule_active("F2012")
    some name, param in input.parameters
    _is_cdl_type(param.type)
    def := object.get(param, "default", null)
    def != null
    avs := param.allowedValues
    avs != null
    is_array(avs)
    count(avs) > 0
    some raw_element in split(def, ",")
    element := trim_space(raw_element)
    not element in {v | some v in avs}
}

# F2015: Parameter Default must match AllowedPattern. The match verdict
# (`defaultMatchesAllowedPattern`) is precomputed in the model with a PCRE-aware compiler so that a
# lookaround/`\Z`-style pattern is evaluated correctly. Only report when the pattern is a valid regex
# and the default provably does not match.
violation contains make_diag_at("F2015", "FATAL", "",
    sprintf("Parameters/%s/Default", [name]),
    sprintf("Parameter '%s' Default '%s' does not match AllowedPattern '%s'", [name, def, pat])) if {
    cfn_rule_active("F2015")
    some name, param in input.parameters
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    pat := object.get(param, "allowedPattern", null)
    pat != null
    is_string(pat)
    not _is_cdl_type(param.type)
    param.allowedPatternValid == true
    param.defaultMatchesAllowedPattern == false
}

# F2015: CommaDelimitedList - the precomputed verdict already reflects that every element must match.
violation contains make_diag_at("F2015", "FATAL", "",
    sprintf("Parameters/%s/Default", [name]),
    sprintf("Parameter '%s' Default does not match AllowedPattern '%s'", [name, pat])) if {
    cfn_rule_active("F2015")
    some name, param in input.parameters
    _is_cdl_type(param.type)
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    pat := object.get(param, "allowedPattern", null)
    pat != null
    is_string(pat)
    param.allowedPatternValid == true
    param.defaultMatchesAllowedPattern == false
}

_is_cdl_type(t) if { t == "CommaDelimitedList" }
_is_cdl_type(t) if { startswith(t, "List<") }

# F2015: Parameter Default length below MinLength
violation contains make_diag_at("F2015", "FATAL", "",
    sprintf("Parameters/%s/Default", [name]),
    sprintf("Parameter '%s' Default length %d is less than MinLength %d", [name, count(def), ml])) if {
    cfn_rule_active("F2015")
    some name, param in input.parameters
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    ml := object.get(param, "minLength", null)
    ml != null
    count(def) < ml
}

# F2015: Parameter Default length exceeds MaxLength
violation contains make_diag_at("F2015", "FATAL", "",
    sprintf("Parameters/%s/Default", [name]),
    sprintf("Parameter '%s' Default length %d exceeds MaxLength %d", [name, count(def), ml])) if {
    cfn_rule_active("F2015")
    some name, param in input.parameters
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    ml := object.get(param, "maxLength", null)
    ml != null
    count(def) > ml
}

# F2015: Parameter Default below MinValue
violation contains make_diag_at("F2015", "FATAL", "",
    sprintf("Parameters/%s/Default", [name]),
    sprintf("Parameter '%s' Default %d is less than MinValue %d", [name, num, mv])) if {
    cfn_rule_active("F2015")
    some name, param in input.parameters
    param.type == "Number"
    def := object.get(param, "default", null)
    def != null
    num := to_number(def)
    mv := object.get(param, "minValue", null)
    mv != null
    num < mv
}

# F2015: Parameter Default exceeds MaxValue
violation contains make_diag_at("F2015", "FATAL", "",
    sprintf("Parameters/%s/Default", [name]),
    sprintf("Parameter '%s' Default %d exceeds MaxValue %d", [name, num, mv])) if {
    cfn_rule_active("F2015")
    some name, param in input.parameters
    param.type == "Number"
    def := object.get(param, "default", null)
    def != null
    num := to_number(def)
    mv := object.get(param, "maxValue", null)
    mv != null
    num > mv
}

# E2014: Parameter Default must match Type constraints
# Number type with non-numeric default is already covered by E0015 in parameters.rego

# W2509: Parameter used as password should have NoEcho: true
violation contains make_diag_at("W2509", "WARN", "",
    sprintf("Parameters/%s", [name]),
    sprintf("Parameter '%s' appears to be a password but does not have NoEcho set to true", [name])) if {
    cfn_rule_active("W2509")
    some name, param in input.parameters
    _is_password_param_name(name)
    param.type == "String"
    not _param_has_noecho(name)
}

_is_password_param_name(name) if {
    lower_name := lower(name)
    contains(lower_name, "password")
}

_is_password_param_name(name) if {
    lower_name := lower(name)
    contains(lower_name, "passphrase")
}

_is_password_param_name(name) if {
    lower_name := lower(name)
    contains(lower_name, "secret")
}

_param_has_noecho(name) if {
    input.parameters[name].noEcho == true
}

# F6005: Output Export name validation (must be unique, no Ref to AWS::StackName without Sub)
violation contains make_diag_at("F6005", "FATAL", "",
    sprintf("Outputs/%s/Export/Name", [name]),
    sprintf("Output '%s' Export Name must not be empty", [name])) if {
    cfn_rule_active("F6005")
    some name, out in input.outputs
    export := out.exportName
    export != null
    is_string(export)
    export == ""
}
