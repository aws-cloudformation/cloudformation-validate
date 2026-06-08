package resources

import rego.v1

# E2530: Lambda SnapStart requires a supported runtime (java11, java17, java21, java25)
snapstart_supported_runtimes := {"java11", "java17", "java21", "java25"}

violation contains make_diag_full("E2530", "ERROR", name,
    "Properties.SnapStart",
    sprintf("SnapStart is not supported with runtime '%s'", [runtime]),
    "Use a supported Java runtime: java11, java17, java21, or java25",
    "") if {
    some name in resources_of_type("AWS::Lambda::Function")
    snap := resolve(name, "Properties.SnapStart")
    is_object(snap)
    apply_on := object.get(snap, "ApplyOn", "None")
    apply_on == "PublishedVersions"
    runtime := resolve(name, "Properties.Runtime")
    is_string(runtime)
    not runtime in snapstart_supported_runtimes
}
