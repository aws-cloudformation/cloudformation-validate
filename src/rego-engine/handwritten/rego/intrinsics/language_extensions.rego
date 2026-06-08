package intrinsics

import rego.v1

# E1030: Fn::Length requires AWS::LanguageExtensions transform
violation contains make_diag("E1030", "ERROR", name,
    "Fn::Length requires the AWS::LanguageExtensions transform") if {
    not _has_language_extensions
    some name, res in input.resources
    _has_intrinsic_in_properties(res, "Fn::Length")
}

# E1031: Fn::ToJsonString requires AWS::LanguageExtensions transform
violation contains make_diag("E1031", "ERROR", name,
    "Fn::ToJsonString requires the AWS::LanguageExtensions transform") if {
    not _has_language_extensions
    some name, res in input.resources
    _has_intrinsic_in_properties(res, "Fn::ToJsonString")
}

# E1032: Fn::ForEach requires AWS::LanguageExtensions transform
violation contains make_diag("E1032", "ERROR", name,
    "Fn::ForEach requires the AWS::LanguageExtensions transform") if {
    not _has_language_extensions
    some name, res in input.resources
    _has_intrinsic_in_properties(res, "Fn::ForEach")
}

_has_language_extensions if {
    some t in input.template.transforms
    t == "AWS::LanguageExtensions"
}

_has_intrinsic_in_properties(res, fn_name) if {
    some _, prop in res.properties
    _value_contains_key(prop, fn_name)
}

_value_contains_key(val, key) if {
    is_object(val)
    val[key]
}

_value_contains_key(val, key) if {
    is_object(val)
    some _, v in val
    _value_contains_key(v, key)
}

_value_contains_key(val, key) if {
    is_array(val)
    some item in val
    _value_contains_key(item, key)
}
