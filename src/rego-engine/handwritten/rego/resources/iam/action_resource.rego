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

_format_matches_some_resource(fmt, resources) if {
    some r in resources
    _arn_matches_format(r, fmt)
}

_arn_matches_format(resource_arn, format_arn) if {
    r_parts := _split_arn(resource_arn)
    f_parts := _split_arn(format_arn)
    count(r_parts) >= 6
    count(f_parts) >= 6
    _first_five_match(r_parts, f_parts)
    _sixth_part_matches(r_parts[5], f_parts[5])
}

_split_arn(arn) := parts if {
    segments := split(arn, ":")
    count(segments) >= 6
    first_five := array.slice(segments, 0, 5)
    rest := concat(":", array.slice(segments, 5, count(segments)))
    parts := array.concat(first_five, [rest])
}

_split_arn(arn) := parts if {
    segments := split(arn, ":")
    count(segments) < 6
    padding := ["*" | _ := numbers.range(1, 6 - count(segments))]
    parts := array.concat(segments, padding)
}

_first_five_match(r_parts, f_parts) if {
    every i in numbers.range(0, 4) {
        _part_matches(r_parts[i], f_parts[i])
    }
}

_part_matches(r, _) if { r == "*" }
_part_matches(_, f) if { f == "${Partition}" }
_part_matches(_, f) if { f == "${Region}" }
_part_matches(_, f) if { f == "${Account}" }
_part_matches(r, f) if { r == f }

_sixth_part_matches(r, _) if { r == "*" }

_sixth_part_matches(r, f) if {
    r != "*"
    not contains(f, ":")
    not contains(f, "/")
}

_sixth_part_matches(r, f) if {
    r != "*"
    contains(f, ":")
    _segments_match(split(r, ":"), split(f, ":"))
}

_sixth_part_matches(r, f) if {
    r != "*"
    not contains(f, ":")
    contains(f, "/")
    _segments_match(split(r, "/"), split(f, "/"))
}

_segments_match(r_segs, f_segs) if {
    pairs := [[r_segs[i], f_segs[i]] | some i in numbers.range(0, min([count(r_segs), count(f_segs)]) - 1)]
    _pairs_all_pass(pairs)
}

_pairs_all_pass(pairs) if {
    count(pairs) == 0
}

_pairs_all_pass(pairs) if {
    count(pairs) > 0
    every pair in pairs {
        _segment_pair_ok(pair[0], pair[1])
    }
}

_segment_pair_ok(r, f) if { r == f }
_segment_pair_ok(r, _) if { r == "*" }
_segment_pair_ok(r, _) if { startswith(r, "*") }
_segment_pair_ok(_, f) if { f == "" }
_segment_pair_ok(_, f) if { f == ".*" }
_segment_pair_ok(r, f) if { startswith(r, f); contains(r, "*") }

_format_list(formats) := concat(", ", [sprintf("'%s'", [f]) | some f in formats])
