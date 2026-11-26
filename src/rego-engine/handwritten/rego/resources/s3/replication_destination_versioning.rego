package resources

import rego.v1

# S3 replicates only into a bucket with versioning enabled. When the destination
# is a bucket in the same template, its authored VersioningConfiguration shows
# whether that holds: an absent configuration or a literal status other than
# Enabled is rejected. A bucket whose Properties are built by an intrinsic is
# skipped because its configuration is only known at deployment.
_s3_bucket_versioning_not_enabled(bucket) := "has no VersioningConfiguration" if {
    properties := input.resources[bucket].properties
    is_object(properties)
    not _s3_properties_are_intrinsic(properties)
    not "VersioningConfiguration" in object.keys(properties)
}

_s3_bucket_versioning_not_enabled(bucket) := sprintf("has versioning status %s", [status]) if {
    status := input.resources[bucket].properties.VersioningConfiguration.Status
    is_string(status)
    status != "Enabled"
}

_s3_properties_are_intrinsic(properties) if {
    some key in object.keys(properties)
    startswith(key, "Fn::")
}

violation contains make_diag_full("E9020", "ERROR", name,
    bucket_path,
    sprintf("Replication destination bucket '%s' %s; S3 replicates only into a bucket with versioning enabled", [destination, reason]),
    sprintf("Set VersioningConfiguration.Status to Enabled on '%s'", [destination]),
    "") if {
    cfn_rule_active("E9020")
    some name in resources_of_type("AWS::S3::Bucket")
    rules := input.resources[name].properties.ReplicationConfiguration.Rules
    is_array(rules)
    some rule_idx, rule in rules
    is_object(rule)
    bucket_path := sprintf("Properties.ReplicationConfiguration.Rules.%d.Destination.Bucket", [rule_idx])
    destination := follow_ref(name, bucket_path)
    destination in resources_of_type("AWS::S3::Bucket")
    reason := _s3_bucket_versioning_not_enabled(destination)
}
