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

# I3013: Retention period on resources with auto-expiring content (data-driven)
violation contains make_diag_at("I3013", "INFO", name,
    sprintf("Properties.%s", [prop]),
    sprintf("'%s' is a required property (The default retention period will delete the data after a pre-defined time. Set an explicit values to avoid data loss on resource)", [prop])) if {
    some rtype, props in data.retention_period_requirements
    some name in resources_of_type(rtype)
    some prop in props
    not has_property(name, prop)
}
