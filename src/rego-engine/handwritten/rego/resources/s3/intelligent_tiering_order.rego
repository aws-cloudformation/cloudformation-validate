package resources

import rego.v1

# Intelligent-Tiering moves objects to the Archive Access tier before the Deep
# Archive Access tier, so S3 rejects a configuration whose deep archive day
# count is not greater than its archive day count. A day count supplied by a
# parameter or another intrinsic is only known at deployment, so its default is
# not folded into the comparison.
_s3_intelligent_tiering_tiers contains tier if {
    some name in resources_of_type("AWS::S3::Bucket")
    configs := input.resources[name].properties.IntelligentTieringConfigurations
    is_array(configs)
    some config_idx, config in configs
    is_object(config)
    tierings := object.get(config, "Tierings", null)
    is_array(tierings)
    some tiering_idx, tiering in tierings
    is_object(tiering)
    access_tier := object.get(tiering, "AccessTier", null)
    access_tier in {"ARCHIVE_ACCESS", "DEEP_ARCHIVE_ACCESS"}
    days_path := sprintf("Properties.IntelligentTieringConfigurations.%d.Tierings.%d.Days", [config_idx, tiering_idx])
    not is_from_parameter(name, days_path)
    not is_from_intrinsic(name, days_path)
    days := coerce_to_integer(object.get(tiering, "Days", null))
    tier := {"name": name, "config": config_idx, "access_tier": access_tier, "days": days, "path": days_path}
}

violation contains make_diag_full("E9019", "ERROR", deep_archive.name,
    deep_archive.path,
    sprintf("DEEP_ARCHIVE_ACCESS Days %v must be greater than ARCHIVE_ACCESS Days %v", [deep_archive.days, archive.days]),
    "Set DEEP_ARCHIVE_ACCESS Days to a value greater than ARCHIVE_ACCESS Days",
    "") if {
    cfn_rule_active("E9019")
    some archive in _s3_intelligent_tiering_tiers
    archive.access_tier == "ARCHIVE_ACCESS"
    some deep_archive in _s3_intelligent_tiering_tiers
    deep_archive.access_tier == "DEEP_ARCHIVE_ACCESS"
    deep_archive.name == archive.name
    deep_archive.config == archive.config
    deep_archive.days <= archive.days
}
