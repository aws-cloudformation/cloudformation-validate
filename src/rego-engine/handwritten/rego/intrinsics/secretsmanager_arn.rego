package intrinsics

import rego.v1

# A Secrets Manager dynamic reference (`{{resolve:secretsmanager:...}}`)
# expands at deploy time to the secret VALUE, not its ARN. Templates that
# place such a substring on an ARN-typed property therefore deploy a value
# where an ARN is required, breaking the resource at runtime.
#
# The set of property names is loaded from
# `data-source/handwritten/secretsmanager_arn_fields.json` and exposed as
# `data.secretsmanager_arn_fields.secretsmanager_arn_fields` — same source
# the CEL engine consumes, so both engines stay in lockstep.
violation contains make_diag_full("W1051", "WARN", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Dynamic reference to Secrets Manager resolves to the secret value, not the ARN — field '%s' expects an ARN", [prop]),
    "Use the secret ARN directly instead of a dynamic reference",
    "") if {
    some name, res in input.resources
    some prop, val in res.properties
    prop in data.secretsmanager_arn_fields
    _value_contains_sm_dynref(val)
}

_value_contains_sm_dynref(val) if {
    is_string(val)
    contains(val, "{{resolve:secretsmanager:")
}

_value_contains_sm_dynref(val) if {
    is_object(val)
    contains(val.__dynamic, "{{resolve:secretsmanager:")
}
