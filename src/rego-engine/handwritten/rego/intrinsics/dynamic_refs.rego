package intrinsics

import rego.v1

# E1027: ssm-secure dynamic references not allowed in Conditions, Outputs, or parameter Defaults
violation contains make_diag("E1027", "ERROR", "",
    sprintf("Dynamic reference '{{resolve:ssm-secure:...}}' is not supported in %s", [section])) if {
    some section in {"Conditions", "Outputs"}
    _section_has_pattern(section, "{{resolve:ssm-secure:")
}

violation contains make_diag("E1027", "ERROR", "",
    sprintf("Dynamic reference '{{resolve:ssm-secure:...}}' is not supported in parameter Default for '%s'", [pname])) if {
    some pname, param in input.parameters
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    contains(def, "{{resolve:ssm-secure:")
}

# E1051: secretsmanager dynamic references only in resource Properties
violation contains make_diag("E1051", "ERROR", "",
    sprintf("Dynamic reference '{{resolve:secretsmanager:...}}' is not supported in %s", [section])) if {
    some section in {"Conditions", "Outputs"}
    _section_has_pattern(section, "{{resolve:secretsmanager:")
}

violation contains make_diag("E1051", "ERROR", "",
    sprintf("Dynamic reference '{{resolve:secretsmanager:...}}' is not supported in parameter Default for '%s'", [pname])) if {
    some pname, param in input.parameters
    def := object.get(param, "default", null)
    def != null
    is_string(def)
    contains(def, "{{resolve:secretsmanager:")
}

# E1052: SSM dynamic references only in resource Properties and parameter Defaults
# Must match {{resolve:ssm: but NOT {{resolve:ssm-secure:
violation contains make_diag("E1052", "ERROR", "",
    "Dynamic reference '{{resolve:ssm:...}}' is not supported in Conditions") if {
    some _, cval in input.conditions
    _has_ssm_plain_ref(cval)
}

violation contains make_diag("E1052", "ERROR", "",
    "Dynamic reference '{{resolve:ssm:...}}' is not supported in Outputs") if {
    some _, oval in input.outputs
    _has_ssm_plain_ref(oval)
}

# Check for {{resolve:ssm: that is NOT {{resolve:ssm-secure:
_has_ssm_plain_ref(val) if {
    is_string(val)
    contains(val, "{{resolve:ssm:")
    not contains(val, "{{resolve:ssm-secure:")
}

_has_ssm_plain_ref(val) if {
    is_object(val)
    some _, v in val
    _has_ssm_plain_ref(v)
}

_has_ssm_plain_ref(val) if {
    is_array(val)
    some item in val
    _has_ssm_plain_ref(item)
}

# Helper: check if a section contains a string with a given pattern
_section_has_pattern("Conditions", pattern) if {
    some _, cval in input.conditions
    _value_has_string_containing(cval, pattern)
}

_section_has_pattern("Outputs", pattern) if {
    some _, oval in input.outputs
    _value_has_string_containing(oval, pattern)
}

_value_has_string_containing(val, pattern) if {
    is_string(val)
    contains(val, pattern)
}

_value_has_string_containing(val, pattern) if {
    is_object(val)
    some _, v in val
    _value_has_string_containing(v, pattern)
}

_value_has_string_containing(val, pattern) if {
    is_array(val)
    some item in val
    _value_has_string_containing(item, pattern)
}
