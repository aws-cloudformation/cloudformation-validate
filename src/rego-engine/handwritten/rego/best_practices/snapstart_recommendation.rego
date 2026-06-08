# I2530: Lambda functions with java11+ or dotnet runtimes should use SnapStart
package best_practices

import rego.v1

snapstart_runtimes := {"java11", "java17", "java21", "dotnet6", "dotnet8"}

violation contains make_diag_full("I2530", "INFO", name,
    "Properties.Runtime",
    sprintf("Runtime '%s' should consider using SnapStart for improved performance", [runtime]),
    "Add SnapStart with ApplyOn set to 'PublishedVersions'",
    "https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html") if {
    some name in resources_of_type("AWS::Lambda::Function")
    some runtime in resolve_all(name, "Properties.Runtime")
    is_string(runtime)
    runtime in snapstart_runtimes
    not _has_snapstart_enabled(name)
}

_has_snapstart_enabled(name) if {
    apply_on := resolve(name, "Properties.SnapStart.ApplyOn")
    apply_on == "PublishedVersions"
}
