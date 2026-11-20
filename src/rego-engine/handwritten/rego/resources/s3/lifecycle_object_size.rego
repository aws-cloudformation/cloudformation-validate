package resources

import rego.v1

# S3 matches objects strictly larger than ObjectSizeGreaterThan and strictly
# smaller than ObjectSizeLessThan, and rejects a lifecycle rule whose range is
# empty. Sizes are usually authored as strings, so compare on the coerced
# integers. A size supplied by a parameter or another intrinsic is only known
# at deployment, so its default is not folded into the comparison.
_s3_lifecycle_object_size_is_literal(name, path) if {
    not is_from_parameter(name, path)
    not is_from_intrinsic(name, path)
}

violation contains make_diag_full("E9015", "ERROR", name,
    less_than_path,
    sprintf("ObjectSizeLessThan %v must be greater than ObjectSizeGreaterThan %v", [less_than, greater_than]),
    "Set ObjectSizeLessThan to a value greater than ObjectSizeGreaterThan",
    "") if {
    cfn_rule_active("E9015")
    some name in resources_of_type("AWS::S3::Bucket")
    rules := input.resources[name].properties.LifecycleConfiguration.Rules
    is_array(rules)
    some idx, rule in rules
    is_object(rule)
    greater_than_path := sprintf("Properties.LifecycleConfiguration.Rules.%d.ObjectSizeGreaterThan", [idx])
    less_than_path := sprintf("Properties.LifecycleConfiguration.Rules.%d.ObjectSizeLessThan", [idx])
    _s3_lifecycle_object_size_is_literal(name, greater_than_path)
    _s3_lifecycle_object_size_is_literal(name, less_than_path)
    greater_than := coerce_to_integer(object.get(rule, "ObjectSizeGreaterThan", null))
    less_than := coerce_to_integer(object.get(rule, "ObjectSizeLessThan", null))
    greater_than >= less_than
}
