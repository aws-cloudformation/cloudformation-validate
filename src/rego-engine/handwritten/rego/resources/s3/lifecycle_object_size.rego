package resources

import rego.v1

_s3_lifecycle_object_size_resource_types := {"AWS::S3::Bucket", "AWS::S3Express::DirectoryBucket"}

# A size sourced from a parameter or intrinsic can vary at deployment, so a
# parameter default or one branch of a condition is not folded into the
# comparison.
_s3_lifecycle_object_size_is_literal(name, path) if {
    not is_from_parameter(name, path)
    not is_from_intrinsic(name, path)
}

# S3 applies a lifecycle rule only to objects strictly larger than
# ObjectSizeGreaterThan and strictly smaller than ObjectSizeLessThan, and
# rejects a rule whose range is empty. Sizes are usually authored as strings,
# so they are compared as coerced integers rather than lexically.
violation contains make_diag_full("E9015", "ERROR", name,
    less_than_path,
    sprintf("ObjectSizeLessThan %v must be greater than ObjectSizeGreaterThan %v", [less_than, greater_than]),
    "Set ObjectSizeLessThan to a value greater than ObjectSizeGreaterThan",
    "") if {
    cfn_rule_active("E9015")
    some resource_type in _s3_lifecycle_object_size_resource_types
    some name in resources_of_type(resource_type)
    lifecycle_rules := input.resources[name].properties.LifecycleConfiguration.Rules
    is_array(lifecycle_rules)
    some idx, lifecycle_rule in lifecycle_rules
    is_object(lifecycle_rule)
    greater_than_path := sprintf("Properties.LifecycleConfiguration.Rules.%d.ObjectSizeGreaterThan", [idx])
    less_than_path := sprintf("Properties.LifecycleConfiguration.Rules.%d.ObjectSizeLessThan", [idx])
    _s3_lifecycle_object_size_is_literal(name, greater_than_path)
    _s3_lifecycle_object_size_is_literal(name, less_than_path)
    greater_than := coerce_to_integer(object.get(lifecycle_rule, "ObjectSizeGreaterThan", null))
    less_than := coerce_to_integer(object.get(lifecycle_rule, "ObjectSizeLessThan", null))
    greater_than >= less_than
}
