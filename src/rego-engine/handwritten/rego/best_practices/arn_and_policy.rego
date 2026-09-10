package best_practices

import rego.v1

# W8003 tautological Fn::Equals is detected by template-model and emitted as a
# parser-level diagnostic - no engine rule needed.

# W9002: Hardcoded ARN properties. Any property whose name ends with `Arn` and whose
# resolved value is a literal ARN string is flagged (broader than a
# fixed whitelist; new resource types with new *Arn properties are covered automatically).
violation contains make_diag_at("W9002", "WARN", name,
    sprintf("Properties.%s", [prop]),
    sprintf("Property '%s' has a hardcoded ARN - use Ref, GetAtt, or a parameter instead", [prop])) if {
    cfn_rule_active("W9002")
    some name, res in input.resources
    some prop in object.keys(res.properties)
    endswith(prop, "Arn")
    val := resolve(name, sprintf("Properties.%s", [prop]))
    is_string(val)
    startswith(val, "arn:")
    not is_dynamic(name, sprintf("Properties.%s", [prop]))
}


