package resources

import rego.v1

# I3510: IAM action requires a resource ARN matching a known pattern, but none of the
# resources in the statement match. Fires once per (action, expected_pattern) combination
# when no resource in the same statement matches the expected pattern.

# Role inline policies
violation contains make_diag_at("I3510", "INFO", name,
    sprintf("Properties.Policies[%d].PolicyDocument", [policy_idx]),
    sprintf("Action '%s' requires a resource matching '%s' but none of the resources match",
        [action, expected])) if {
    some name in resources_of_type("AWS::IAM::Role")
    policies := resolve(name, "Properties.Policies")
    is_array(policies)
    some policy_idx, policy in policies
    is_object(policy)
    doc := object.get(policy, "PolicyDocument", {})
    stmts := object.get(doc, "Statement", [])
    is_array(stmts)
    some stmt in stmts
    is_object(stmt)
    some action in ensure_list(object.get(stmt, "Action", []))
    _is_specific_action(action)
    expected := data.iam_action_resource_patterns[lower(action)]
    expected != null
    resources := _resource_list(stmt)
    _none_match(resources, expected)
}

# IAM::Policy and IAM::ManagedPolicy
violation contains make_diag_at("I3510", "INFO", name,
    "Properties.PolicyDocument",
    sprintf("Action '%s' requires a resource matching '%s' but none of the resources match",
        [action, expected])) if {
    some rtype in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
    some name in resources_of_type(rtype)
    doc := resolve(name, "Properties.PolicyDocument")
    is_object(doc)
    stmts := object.get(doc, "Statement", [])
    is_array(stmts)
    some stmt in stmts
    is_object(stmt)
    some action in ensure_list(object.get(stmt, "Action", []))
    _is_specific_action(action)
    expected := data.iam_action_resource_patterns[lower(action)]
    expected != null
    resources := _resource_list(stmt)
    _none_match(resources, expected)
}

_is_specific_action(action) if {
    is_string(action)
    not contains(action, "*")
    not contains(action, "?")
    contains(action, ":")
}

# Resource list for a statement. Empty list, contains '*', non-strings, or Sub placeholders => skip.
_resource_list(stmt) := resources if {
    resources := ensure_list(object.get(stmt, "Resource", []))
    count(resources) > 0
    not "*" in resources
    not _has_non_string(resources)
    not _has_placeholder(resources)
}

_has_non_string(resources) if {
    some r in resources
    not is_string(r)
}

_has_placeholder(resources) if {
    some r in resources
    is_string(r)
    contains(r, "${")
}

_has_placeholder(resources) if {
    some r in resources
    is_string(r)
    contains(r, "{{resolve:")
}

_none_match(resources, pattern) if {
    count([r | some r in resources; is_string(r); _arn_matches(r, pattern)]) == 0
}

_arn_matches(arn, pattern) if {
    arn_parts := split(arn, ":")
    pat_parts := split(pattern, ":")
    count(arn_parts) >= 6
    count(pat_parts) >= 6
    _parts_match(arn_parts, pat_parts)
}

_parts_match(arn_parts, pat_parts) if {
    every i, p in pat_parts {
        _segment_matches(arn_parts[i], p)
    }
}

_segment_matches(_, "*") := true
_segment_matches(a, p) if { a == p }

