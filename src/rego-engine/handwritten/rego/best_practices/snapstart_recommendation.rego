# Lambda functions with supported runtimes should use SnapStart.
package best_practices

import rego.v1

_snapstart_rec_excluded := {r | some r in data.rule_tables.snapstart_recommendation_excluded_runtimes}
_snapstart_supported_regions := {r | some r in data.rule_tables.snapstart_supported_regions}

_is_snapstart_recommended(runtime) if {
    some prefix in data.rule_tables.snapstart_recommendation_runtime_prefixes
    startswith(runtime, prefix)
    not runtime in _snapstart_rec_excluded
}

# When a region is configured, only recommend SnapStart if the region supports it.
# When no region is configured, assume supported (cannot exclude).
_region_supports_snapstart if {
    input_region() == null
}

_region_supports_snapstart if {
    r := input_region()
    r != null
    r in _snapstart_supported_regions
}

violation contains make_diag_full("I2530", "INFO", name,
    "Properties.SnapStart.ApplyOn",
    sprintf("Runtime '%s' should consider using SnapStart for improved performance", [runtime]),
    "Add SnapStart with ApplyOn set to 'PublishedVersions'",
    "https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html") if {
    cfn_rule_active("I2530")
    _region_supports_snapstart
    some name in resources_of_type("AWS::Lambda::Function")
    some runtime in resolve_all(name, "Properties.Runtime")
    is_string(runtime)
    _is_snapstart_recommended(runtime)
    not _has_snapstart_enabled(name)
}

_has_snapstart_enabled(name) if {
    apply_on := resolve(name, "Properties.SnapStart.ApplyOn")
    apply_on == "PublishedVersions"
}
