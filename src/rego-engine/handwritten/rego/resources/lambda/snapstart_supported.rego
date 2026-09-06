package resources

import rego.v1

# E2530: Lambda SnapStart requires a supported runtime: any Python, Java, or
# .NET runtime qualifies except the legacy dotnetcore* family and an explicit
# list of deprecated versions.
_snapstart_unsupported_runtimes := {r | some r in data.rule_tables.snapstart_unsupported_runtimes}

snapstart_runtime_supported(runtime) if {
    some prefix in data.rule_tables.snapstart_runtime_prefixes
    startswith(runtime, prefix)
    not _snapstart_has_unsupported_prefix(runtime)
    not runtime in _snapstart_unsupported_runtimes
}

_snapstart_has_unsupported_prefix(runtime) if {
    some prefix in data.rule_tables.snapstart_unsupported_runtime_prefixes
    startswith(runtime, prefix)
}

violation contains make_diag_full("E2530", "ERROR", name,
    "Properties.SnapStart.ApplyOn",
    sprintf("SnapStart is not supported with runtime '%s'", [runtime]),
    "Use a supported Python, Java, or .NET runtime",
    "") if {
    cfn_rule_active("E2530")
    some name in resources_of_type("AWS::Lambda::Function")
    snap := resolve(name, "Properties.SnapStart")
    is_object(snap)
    apply_on := object.get(snap, "ApplyOn", "None")
    apply_on == "PublishedVersions"
    runtime := resolve(name, "Properties.Runtime")
    is_string(runtime)
    not snapstart_runtime_supported(runtime)
}

# SnapStart enabled in an unsupported region. Only fires when a
# region is explicitly configured and absent from the supported regions list.
_snapstart_supported_regions := {r | some r in data.rule_tables.snapstart_supported_regions}

violation contains make_diag_full("E2530", "ERROR", name,
    "Properties.SnapStart.ApplyOn",
    sprintf("SnapStart is not supported in region '%s'", [region]),
    "Deploy to a region that supports SnapStart or disable SnapStart",
    "") if {
    cfn_rule_active("E2530")
    region := input_region()
    region != null
    not region in _snapstart_supported_regions
    some name in resources_of_type("AWS::Lambda::Function")
    snap := resolve(name, "Properties.SnapStart")
    is_object(snap)
    object.get(snap, "ApplyOn", "None") == "PublishedVersions"
}
