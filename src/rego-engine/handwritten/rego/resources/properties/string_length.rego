package resources

import rego.v1

# W9006: a string length constraint broken by a value the template does not state
# literally, such as one built by Fn::Sub or Fn::Join or chosen from a parameter's
# AllowedValues. A literal is checked against the constraint by schema validation
# instead.
#
# Only reported when the constraint is broken whichever value the deployment
# picks: the shortest possibility still too long, or the longest still too short.
# When any possibility has an unknown length there is nothing to report, since the
# deployment may well satisfy the constraint.
violation contains make_diag_at("W9006", "WARN", name,
    path,
    sprintf("String length %d exceeds maximum %d for property '%s'", [bounds.shortest, max_len, prop])) if {
    cfn_rule_active("W9006")
    some name, res in input.resources
    rtype := res.resourceType
    some prop in schema_properties(rtype)
    constraints := schema_string_length(rtype, prop)
    max_len := constraints.maxLength
    path := sprintf("Properties.%s", [prop])
    bounds := estimated_string_length_bounds(name, path)
    bounds.shortest > max_len
}

violation contains make_diag_at("W9006", "WARN", name,
    path,
    sprintf("String length %d is below minimum %d for property '%s'", [bounds.longest, min_len, prop])) if {
    cfn_rule_active("W9006")
    some name, res in input.resources
    rtype := res.resourceType
    some prop in schema_properties(rtype)
    constraints := schema_string_length(rtype, prop)
    min_len := constraints.minLength
    min_len > 0
    path := sprintf("Properties.%s", [prop])
    bounds := estimated_string_length_bounds(name, path)
    bounds.longest < min_len
}
