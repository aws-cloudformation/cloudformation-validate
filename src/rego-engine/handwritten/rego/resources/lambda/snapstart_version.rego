package resources

import rego.v1

# W2530: SnapStart enabled but no Lambda::Version resource attached
violation contains make_diag_full("W2530", "WARN", name,
    "Properties.SnapStart.ApplyOn",
    "SnapStart is enabled but no AWS::Lambda::Version resource is attached",
    "Add an AWS::Lambda::Version resource that references this function",
    "") if {
    some name in resources_of_type("AWS::Lambda::Function")
    snap := resolve(name, "Properties.SnapStart")
    is_object(snap)
    apply_on := object.get(snap, "ApplyOn", "None")
    apply_on == "PublishedVersions"
    # Check if any Lambda::Version references this function
    not _has_version_resource(name)
}

_has_version_resource(func_name) if {
    some ver_name in resources_of_type("AWS::Lambda::Version")
    target := follow_ref(ver_name, "Properties.FunctionName")
    target == func_name
}
