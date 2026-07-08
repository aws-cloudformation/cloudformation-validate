package resources

import rego.v1

# E3504: Backup lifecycle: MoveToColdStorageAfterDays < DeleteAfterDays
violation contains make_diag_at("E3504", "ERROR", name,
    "Properties.BackupPlanRule",
    sprintf("MoveToColdStorageAfterDays (%d) must be less than DeleteAfterDays (%d)", [move_days, delete_days])) if {
    some name in resources_of_type("AWS::Backup::BackupPlan")
    some item in flatten_list(name, "Properties.BackupPlan.BackupPlanRule")
    rule := item.value
    is_object(rule)
    lifecycle := object.get(rule, "Lifecycle", null)
    lifecycle != null
    move_days := object.get(lifecycle, "MoveToColdStorageAfterDays", null)
    delete_days := object.get(lifecycle, "DeleteAfterDays", null)
    move_days != null
    delete_days != null
    is_number(move_days)
    is_number(delete_days)
    move_days >= delete_days
}

# I3013: Retention period on resources with auto-expiring content (data-driven).
# A resource type may list several retention properties (a canary needs both a
# success and a failure retention period). The reference linter collapses the
# required-property check to a single best-match finding anchored on the
# properties object, so report only the first missing property in declaration
# order — emitting one per missing property would over-report a single concern.
violation contains make_diag_at("I3013", "INFO", name,
    "Properties",
    sprintf("'%s' is a required property (The default retention period will delete the data after a pre-defined time. Set an explicit values to avoid data loss on resource)", [props[first_missing]])) if {
    some rtype, props in data.retention_period_requirements
    some name in resources_of_type(rtype)
    _i3013_applies(name, rtype)
    missing_indices := {i | some i, prop in props; property_can_be_absent(name, sprintf("Properties.%s", [prop]))}
    count(missing_indices) > 0
    first_missing := min(missing_indices)
}

# RDS DB instances only need an explicit backup retention period when they are a
# standalone, non-Aurora engine: Aurora manages backups at the cluster level and a
# read replica inherits its source's retention.
_i3013_applies(_, rtype) if rtype != "AWS::RDS::DBInstance"

_i3013_applies(name, "AWS::RDS::DBInstance") if {
    engine := object.get(input.resources[name].properties, "Engine", null)
    is_string(engine)
    not startswith(engine, "aurora")
    not has_property(name, "SourceDBInstanceIdentifier")
}
