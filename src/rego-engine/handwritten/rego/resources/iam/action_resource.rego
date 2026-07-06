package resources

import rego.v1

violation contains make_diag_at("I3510", "INFO", name,
    sprintf("Properties.PolicyDocument.Statement.%d.Resource", [stmt_idx]),
    sprintf("action '%s' requires a resource of [%s]",
        [action, _format_list(candidate_formats)])) if {
    some name in resources_of_type("AWS::IAM::Policy")
    doc := resolve(name, "Properties.PolicyDocument")
    is_object(doc)
    stmts := object.get(doc, "Statement", [])
    is_array(stmts)
    some stmt_idx, stmt in stmts
    is_object(stmt)
    not _stmt_has_skip_condition(stmt)
    not _stmt_uses_functions(stmt)
    all_resources := _literal_resources(stmt)
    count(all_resources) > 0
    some action in ensure_list(object.get(stmt, "Action", []))
    _is_specific_action(action)
    candidate_formats := data.iam_action_resource_patterns[lower(action)]
    candidate_formats != null
    is_array(candidate_formats)
    _no_format_matches_any_resource(candidate_formats, all_resources)
}

_is_specific_action(action) if {
    is_string(action)
    not contains(action, "*")
    not contains(action, "?")
    contains(action, ":")
}

_stmt_has_skip_condition(stmt) if {
    some key in {"Resource", "NotResource"}
    vals := ensure_list(object.get(stmt, key, []))
    some val in vals
    is_string(val)
    val == "*"
}

_stmt_has_skip_condition(stmt) if {
    some key in {"Resource", "NotResource"}
    vals := ensure_list(object.get(stmt, key, []))
    some val in vals
    is_string(val)
    contains(val, "{{resolve:")
}

_stmt_has_skip_condition(stmt) if {
    some key in {"Resource", "NotResource"}
    vals := ensure_list(object.get(stmt, key, []))
    some val in vals
    is_object(val)
    ref_target := val["Ref"]
    is_string(ref_target)
    ref_target in input.parameters
}

_stmt_uses_functions(stmt) if {
    some key in {"Resource", "NotResource"}
    vals := ensure_list(object.get(stmt, key, []))
    some val in vals
    not is_string(val)
    not _is_ref_to_parameter(val)
}

_is_ref_to_parameter(val) if {
    is_object(val)
    ref_target := val["Ref"]
    is_string(ref_target)
    ref_target in input.parameters
}

_literal_resources(stmt) := resources if {
    resource_vals := ensure_list(object.get(stmt, "Resource", []))
    not_resource_vals := ensure_list(object.get(stmt, "NotResource", []))
    combined := array.concat(resource_vals, not_resource_vals)
    resources := [r | some r in combined; is_string(r)]
}

_no_format_matches_any_resource(formats, resources) if {
    count([fmt |
        some fmt in formats
        _format_matches_some_resource(fmt, resources)
    ]) == 0
}

# ARN-to-format matching is delegated to the arn_matches_format builtin so the
# implementation is shared (padding short ARNs to six parts, treating
# ${Partition}/${Region}/${Account} as wildcards).
_format_matches_some_resource(fmt, resources) if {
    some r in resources
    arn_matches_format(r, fmt)
}

_format_list(formats) := concat(", ", [sprintf("'%s'", [f]) | some f in formats])
