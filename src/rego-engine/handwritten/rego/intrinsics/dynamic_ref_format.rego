package intrinsics

import rego.v1

# Validates that every `{{resolve:...}}` substring matches the official
# per-flavor format. CloudFormation rejects malformed substrings at deploy
# time with a substitution error, so we surface the structural issue at
# author time.
#
# Accepted formats:
#   {{resolve:ssm:<param-name>[:<version>]}}
#   {{resolve:ssm-secure:<param-name>[:<version>]}}
#   {{resolve:secretsmanager:<secret-id>[:SecretString[:json-key[:version-stage[:version-id]]]]}}
#   {{resolve:secretsmanager:arn:<partition>:secretsmanager:<region>:<account>:secret:<name>[:...]}}

violation contains make_diag_full("E1050", "ERROR", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Dynamic reference '%s' does not match the required format for '%s'", [match_str, ref_type]),
    "Check the dynamic reference syntax",
    "") if {
    some name, res in input.resources
    some prop, val in res.properties
    [match_str, ref_type] := _find_malformed_dynref(val)
}

_find_malformed_dynref(val) := [match_str, ref_type] if {
    is_string(val)
    match_str := _extract_dynref(val)
    match_str != ""
    ref_type := _dynref_type(match_str)
    ref_type != ""
    not _valid_dynref_format(match_str, ref_type)
}

_find_malformed_dynref(val) := result if {
    is_object(val)
    some _, v in val
    result := _find_malformed_dynref(v)
}

_find_malformed_dynref(val) := result if {
    is_array(val)
    some item in val
    result := _find_malformed_dynref(item)
}

# Extract the first dynamic reference substring, including the closing braces.
_extract_dynref(s) := match_str if {
    contains(s, "{{resolve:")
    idx := indexof(s, "{{resolve:")
    rest := substring(s, idx, -1)
    end := indexof(rest, "}}")
    end > 0
    match_str := substring(rest, 0, end + 2)
}

_dynref_type(ref_str) := "ssm-secure" if {
    contains(ref_str, "{{resolve:ssm-secure:")
}

_dynref_type(ref_str) := "ssm" if {
    contains(ref_str, "{{resolve:ssm:")
    not contains(ref_str, "{{resolve:ssm-secure:")
}

_dynref_type(ref_str) := "secretsmanager" if {
    contains(ref_str, "{{resolve:secretsmanager:")
}

_valid_dynref_format(ref_str, "ssm") if {
    _valid_ssm_format(ref_str, "ssm")
}

_valid_dynref_format(ref_str, "ssm-secure") if {
    _valid_ssm_format(ref_str, "ssm-secure")
}

# SSM parameter names allow letters, digits, underscore, dot, dash, slash.
# The optional version suffix must be a numeric identifier.
_valid_ssm_format(ref_str, flavor) if {
    prefix := sprintf("{{resolve:%s:", [flavor])
    startswith(ref_str, prefix)
    endswith(ref_str, "}}")
    inner := trim_suffix(trim_prefix(ref_str, prefix), "}}")
    inner != ""
    parts := split(inner, ":")
    count(parts) <= 2
    count(parts) >= 1
    parts[0] != ""
    regex.match(`^[a-zA-Z0-9_.\-/]+$`, parts[0])
    _ssm_version_valid(parts)
}

_ssm_version_valid(parts) if {
    count(parts) == 1
}

_ssm_version_valid(parts) if {
    count(parts) == 2
    regex.match(`^\d+$`, parts[1])
}

_valid_dynref_format(ref_str, "secretsmanager") if {
    prefix := "{{resolve:secretsmanager:"
    startswith(ref_str, prefix)
    endswith(ref_str, "}}")
    inner := trim_suffix(trim_prefix(ref_str, prefix), "}}")
    inner != ""
    _valid_secretsmanager_inner(inner)
}

# ARN form: arn:<partition>:secretsmanager:<region>:<account>:secret:<name>
# followed by the optional :SecretString[:json-key[:version-stage[:version-id]]]
# suffix. The minimum 7 colon-separated pieces correspond to the bare ARN; the
# maximum 11 add the SecretString clause.
_valid_secretsmanager_inner(inner) if {
    startswith(inner, "arn:")
    parts := split(inner, ":")
    count(parts) >= 7
    count(parts) <= 11
}

_valid_secretsmanager_inner(inner) if {
    not startswith(inner, "arn:")
    parts := split(inner, ":")
    count(parts) >= 1
    count(parts) <= 5
    parts[0] != ""
    _sm_secret_string_valid(parts)
}

_sm_secret_string_valid(parts) if {
    count(parts) == 1
}

# When SecretString is specified, the second piece must literally be
# "SecretString". An empty second piece is also valid (omitted).
_sm_secret_string_valid(parts) if {
    count(parts) >= 2
    parts[1] == "SecretString"
}

_sm_secret_string_valid(parts) if {
    count(parts) >= 2
    parts[1] == ""
}
