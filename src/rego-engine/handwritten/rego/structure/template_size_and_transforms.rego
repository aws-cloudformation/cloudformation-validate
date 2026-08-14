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

# I2003: AllowedPattern must be a valid regex. CloudFormation validates AllowedPattern with a
# PCRE-style engine that supports lookaround, backreferences, `\Z` and POSIX classes, so validity is
# precomputed in the model (`allowedPatternValid`) with a PCRE-aware compiler. Report only a pattern
# that is genuinely malformed.
violation contains make_diag_at("I2003", "INFO", "",
    sprintf("Parameters/%s/AllowedPattern", [pname]),
    sprintf("Parameter '%s' AllowedPattern '%s' is not a valid regular expression", [pname, pattern])) if {
    some pname, param in input.parameters
    pattern := param.allowedPattern
    pattern != null
    is_string(pattern)
    param.allowedPatternValid == false
}
