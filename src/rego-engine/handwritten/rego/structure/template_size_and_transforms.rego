package structure

import rego.v1

# E1002: Template body size limits
violation contains make_diag("E1002", "ERROR", "",
    sprintf("Template body size %d exceeds maximum of 460,800 bytes", [body_size])) if {
    body_size := input.template.bodySize
    body_size != null
    body_size > 460800
}

violation contains make_diag("E1002", "ERROR", "",
    sprintf("Template body size %d exceeds 51,200 bytes. Use S3 for templates up to 460,800 bytes", [body_size])) if {
    body_size := input.template.bodySize
    body_size != null
    body_size > 51200
    body_size <= 460800
}

# E1005: Transform entries must be strings or objects
violation contains make_diag("E1005", "ERROR", "",
    sprintf("Transform entry must be a string or object, got %v", [entry])) if {
    some entry in input.template.transforms
    not is_string(entry)
    not is_object(entry)
}

# E1005: Transform object must have Name property
violation contains make_diag("E1005", "ERROR", "",
    "Transform object is missing required 'Name' property") if {
    some entry in input.template.transforms
    is_object(entry)
    not entry.Name
}

# I2003: AllowedPattern must be a valid regex.
# CloudFormation validates AllowedPattern with a PCRE-style engine that supports
# lookaround and backreferences; RE2 (regex.is_valid) does not. A pattern that
# fails only because of those constructs is still valid service-side, so only
# report genuinely-malformed regex.
violation contains make_diag("I2003", "INFO", "",
    sprintf("Parameter '%s' AllowedPattern '%s' is not a valid regular expression", [pname, pattern])) if {
    some pname, param in input.parameters
    pattern := param.allowedPattern
    pattern != null
    is_string(pattern)
    not regex.is_valid(pattern)
    not _uses_extended_regex_syntax(pattern)
}

_uses_extended_regex_syntax(pattern) if {
    some prefix in ["(?=", "(?!", "(?<=", "(?<!", "(?>"]
    contains(pattern, prefix)
}

# Backreference: a backslash followed by a digit 1-9.
_uses_extended_regex_syntax(pattern) if {
    regex.match(`\\[1-9]`, pattern)
}
