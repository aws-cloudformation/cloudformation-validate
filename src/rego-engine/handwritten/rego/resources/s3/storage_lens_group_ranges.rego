package resources

import rego.v1

# A Storage Lens group matches objects strictly inside a greater-than/less-than
# pair, and S3 rejects a pair that leaves no object to match. A bound supplied
# by a parameter or another intrinsic is only known at deployment, so its
# default is not folded into the comparison.
_s3_storage_lens_group_ranges := [
    {"filter": "MatchObjectAge", "greater_than": "DaysGreaterThan", "less_than": "DaysLessThan"},
    {"filter": "MatchObjectSize", "greater_than": "BytesGreaterThan", "less_than": "BytesLessThan"},
]

_s3_storage_lens_group_bound_is_literal(name, path) if {
    not is_from_parameter(name, path)
    not is_from_intrinsic(name, path)
}

violation contains make_diag_full("E9018", "ERROR", name,
    less_than_path,
    sprintf("%s %v must be greater than %s %v", [range.less_than, less_than, range.greater_than, greater_than]),
    sprintf("Set %s to a value greater than %s", [range.less_than, range.greater_than]),
    "") if {
    cfn_rule_active("E9018")
    some name in resources_of_type("AWS::S3::StorageLensGroup")
    some range in _s3_storage_lens_group_ranges
    match := input.resources[name].properties.Filter[range.filter]
    is_object(match)
    greater_than_path := sprintf("Properties.Filter.%s.%s", [range.filter, range.greater_than])
    less_than_path := sprintf("Properties.Filter.%s.%s", [range.filter, range.less_than])
    _s3_storage_lens_group_bound_is_literal(name, greater_than_path)
    _s3_storage_lens_group_bound_is_literal(name, less_than_path)
    greater_than := coerce_to_integer(object.get(match, range.greater_than, null))
    less_than := coerce_to_integer(object.get(match, range.less_than, null))
    greater_than >= less_than
}
