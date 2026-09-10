package structure

import rego.v1

violation contains make_diag("F0001", "FATAL", "", "Resources section must exist and be non-empty") if {
    cfn_rule_active("F0001")
    not input.resources
}

violation contains make_diag("F0001", "FATAL", "", "Resources section must exist and be non-empty") if {
    cfn_rule_active("F0001")
    count(input.resources) == 0
}

violation contains make_diag_full("F0002", "FATAL", "", "AWSTemplateFormatVersion", sprintf("AWSTemplateFormatVersion must be '2010-09-09', got '%s'", [input.template.formatVersion]), "", "") if {
    cfn_rule_active("F0002")
    input.template.formatVersion != null
    input.template.formatVersion != "2010-09-09"
}

# F0005: Top-level keys must be valid section names
valid_sections := {
    "AWSTemplateFormatVersion", "Description", "Metadata", "Parameters",
    "Rules", "Mappings", "Conditions", "Transform", "Resources", "Outputs",
    "Globals",
}

violation contains make_diag_full("F0005", "FATAL", "", key,
    sprintf("'%s' is not a valid top-level template section", [key]), "", "") if {
    cfn_rule_active("F0005")
    some key in input.template.rawTopLevelKeys
    not key in valid_sections
}

# F0011: Description must be string, max 1024 bytes
violation contains make_diag("F0011", "FATAL", "",
    sprintf("Description length %d exceeds maximum 1024", [count(input.template.description)])) if {
    cfn_rule_active("F0011")
    input.template.description != null
    count(input.template.description) > 1024
}

# I1003: Description approaching max length (90% of 1024)
violation contains make_diag("I1003", "INFO", "",
    sprintf("Description length %d is approaching maximum of 1024", [count(input.template.description)])) if {
    cfn_rule_active("I1003")
    input.template.description != null
    count(input.template.description) > 921
    count(input.template.description) <= 1024
}

# F0006: Logical IDs must be alphanumeric
violation contains make_diag("F0006", "FATAL", name,
    sprintf("Logical ID '%s' must be alphanumeric (A-Za-z0-9)", [name])) if {
    cfn_rule_active("F0006")
    some name in object.keys(input.resources)
    is_string(name)
    not regex.match(`^[a-zA-Z0-9]+$`, name)
    name != "Fn::Transform"
    not _is_foreach_with_language_extensions(name)
}

_is_foreach_with_language_extensions(name) if {
    startswith(name, "Fn::ForEach::")
    has_transform("AWS::LanguageExtensions")
}
