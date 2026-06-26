package resources

import rego.v1

# E2530: Lambda SnapStart requires a supported runtime: any Python, Java, or
# .NET runtime qualifies except the legacy dotnetcore* family and an explicit
# list of deprecated versions.
snapstart_unsupported_runtimes := {
    "dotnet5.0", "dotnet6", "dotnet7",
    "java8.al2", "java8",
    "python3.7", "python3.8", "python3.9", "python3.10", "python3.11",
}

snapstart_runtime_supported(runtime) if {
    some prefix in {"python", "java", "dotnet"}
    startswith(runtime, prefix)
    not startswith(runtime, "dotnetcore")
    not runtime in snapstart_unsupported_runtimes
}

violation contains make_diag_full("E2530", "ERROR", name,
    "Properties.SnapStart",
    sprintf("SnapStart is not supported with runtime '%s'", [runtime]),
    "Use a supported Python, Java, or .NET runtime",
    "") if {
    some name in resources_of_type("AWS::Lambda::Function")
    snap := resolve(name, "Properties.SnapStart")
    is_object(snap)
    apply_on := object.get(snap, "ApplyOn", "None")
    apply_on == "PublishedVersions"
    runtime := resolve(name, "Properties.Runtime")
    is_string(runtime)
    not snapstart_runtime_supported(runtime)
}
