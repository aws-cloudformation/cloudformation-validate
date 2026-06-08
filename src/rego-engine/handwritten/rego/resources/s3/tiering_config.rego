package resources

import rego.v1

# E3061: S3 IntelligentTieringConfigurations tiering days must be within range
# ARCHIVE_ACCESS: 90-730 days, DEEP_ARCHIVE_ACCESS: 180-730 days
violation contains make_diag_full("E3061", "ERROR", name,
    sprintf("Properties.IntelligentTieringConfigurations[%d].Tierings[%d].Days", [ci, ti]),
    sprintf("Days %v for %s must be between %d and %d", [days, tier, min_days, 730]),
    sprintf("Set Days between %d and 730", [min_days]),
    "") if {
    some name in resources_of_type("AWS::S3::Bucket")
    configs := resolve(name, "Properties.IntelligentTieringConfigurations")
    is_array(configs)
    some ci, config in configs
    tierings := object.get(config, "Tierings", [])
    is_array(tierings)
    some ti, tiering in tierings
    tier := tiering.AccessTier
    days := tiering.Days
    is_string(tier); is_number(days)
    min_days := _tier_min(tier)
    min_days != null
    _out_of_range(days, min_days, 730)
}

_tier_min(tier) := 90 if { tier == "ARCHIVE_ACCESS" }
_tier_min(tier) := 180 if { tier == "DEEP_ARCHIVE_ACCESS" }

_out_of_range(days, min_val, max_val) if { days < min_val }
_out_of_range(days, min_val, max_val) if { days > max_val }
