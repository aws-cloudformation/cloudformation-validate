package resources

import rego.v1

violation contains make_diag_at("I3510", "INFO", name,
    sprintf("Properties.PolicyDocument.Statement.%d.Resource", [stmt_idx]),
    sprintf("action '%s' requires a resource of [%s]",
        [action, _format_list(candidate_formats)])) if {
    some name in resources_of_type("AWS::IAM::Policy")
    # Keep Fn::If as `{"Fn::If": [cond, then, else]}` so every branch is visible;
    # a resource is acceptable if any reachable branch matches the action.
    doc := resolve_preserving_conditionals(name, "Properties.PolicyDocument")
    is_object(doc)
    stmts := object.get(doc, "Statement", [])
    is_array(stmts)
    some stmt_idx, stmt in stmts
    is_object(stmt)
    not _stmt_has_skip_condition(name, stmt_idx, stmt)
    not _stmt_uses_functions(name, stmt_idx, stmt)
    all_resources := _reachable_resources(name, stmt_idx, stmt)
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

# Every reachable Resource/NotResource entry as [value, path] pairs. A scalar
# field value is one top-level entry whose Fn::If branches are enumerated (so a
# resource is acceptable if any reachable branch matches); a list element is a
# leaf entry (an Fn::If there is an opaque function). Fn::If nesting is bounded to
# a small depth, which covers realistic templates.
_reachable_entries(name, stmt_idx, stmt) := entries if {
    entries := array.concat(
        _entries_for_key(name, stmt_idx, stmt, "Resource"),
        _entries_for_key(name, stmt_idx, stmt, "NotResource"),
    )
}

_entries_for_key(name, stmt_idx, stmt, key) := entries if {
    field := object.get(stmt, key, null)
    field != null
    base := sprintf("Properties.PolicyDocument.Statement.%d.%s", [stmt_idx, key])
    entries := _expand(field, base, true)
}

_entries_for_key(name, stmt_idx, stmt, key) := [] if {
    object.get(stmt, key, null) == null
}

# Enumerate the entries reachable from a value. A top-level scalar Fn::If descends
# into both branches (still top-level, so nested scalar Fn::If also expands); a
# list expands each element as a non-top-level leaf; anything else is a leaf.
_expand(value, path, top_level) := entries if {
    top_level == true
    is_object(value)
    fnif := value["Fn::If"]
    is_array(fnif)
    count(fnif) == 3
    entries := array.concat(
        _expand(fnif[1], sprintf("%s.Fn::If.1", [path]), true),
        _expand(fnif[2], sprintf("%s.Fn::If.2", [path]), true),
    )
}

_expand(value, path, _) := entries if {
    is_array(value)
    entries := [entry |
        some i, elem in value
        entry := [elem, sprintf("%s.%d", [path, i])]
    ]
}

_expand(value, path, top_level) := [[value, path]] if {
    not is_array(value)
    not _is_top_level_fn_if(value, top_level)
}

_is_top_level_fn_if(value, top_level) if {
    top_level == true
    is_object(value)
    fnif := value["Fn::If"]
    is_array(fnif)
    count(fnif) == 3
}

# A `*`, a dynamic reference, or a Ref-to-parameter in any reachable entry exempts
# the whole statement from the action-format check.
_stmt_has_skip_condition(name, stmt_idx, stmt) if {
    some entry in _reachable_entries(name, stmt_idx, stmt)
    value := entry[0]
    is_string(value)
    value == "*"
}

_stmt_has_skip_condition(name, stmt_idx, stmt) if {
    some entry in _reachable_entries(name, stmt_idx, stmt)
    value := entry[0]
    is_string(value)
    contains(value, "{{resolve:")
}

_stmt_has_skip_condition(name, stmt_idx, stmt) if {
    some entry in _reachable_entries(name, stmt_idx, stmt)
    _is_ref_to_parameter(entry[0])
}

# A function whose ARN is unknowable (any non-string entry that is not a Ref to a
# parameter, e.g. an Fn::If list element or a GetAtt object), or a concrete string
# synthesized by an intrinsic (a fully resolved Fn::Sub/GetAtt/Join, whose real
# ARN is only known at deploy time), makes the action-format check inapplicable.
_stmt_uses_functions(name, stmt_idx, stmt) if {
    some entry in _reachable_entries(name, stmt_idx, stmt)
    not is_string(entry[0])
    not _is_ref_to_parameter(entry[0])
}

_stmt_uses_functions(name, stmt_idx, stmt) if {
    some entry in _reachable_entries(name, stmt_idx, stmt)
    is_string(entry[0])
    is_from_intrinsic(name, entry[1])
}

_is_ref_to_parameter(val) if {
    is_object(val)
    ref_target := val["Ref"]
    is_string(ref_target)
    ref_target in input.parameters
}

# The literal ARNs to match against: every reachable concrete string that was not
# synthesized by an intrinsic.
_reachable_resources(name, stmt_idx, stmt) := resources if {
    resources := {value |
        some entry in _reachable_entries(name, stmt_idx, stmt)
        value := entry[0]
        is_string(value)
        not is_from_intrinsic(name, entry[1])
    }
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
