package resources

import rego.v1

# W2533: Zip deployment requires Handler and Runtime
violation contains make_diag_full("W2533", "WARN", name,
    "Properties",
    sprintf("Property '%s' is required for zip file deployment", [missing]),
    sprintf("Add the '%s' property", [missing]),
    "") if {
    some name in resources_of_type("AWS::Lambda::Function")
    _is_zip(name)
    some missing in {"Handler", "Runtime"}
    not has_property(name, missing)
}

_is_zip(name) if {
    pt := resolve(name, "Properties.PackageType")
    pt == "Zip"
}

_is_zip(name) if {
    not has_property(name, "PackageType")
    has_property(name, "Code")
    code := resolve(name, "Properties.Code")
    is_object(code)
    object.get(code, "ZipFile", null) != null
}

_is_zip(name) if {
    not has_property(name, "PackageType")
    has_property(name, "Code")
    code := resolve(name, "Properties.Code")
    is_object(code)
    object.get(code, "S3Key", null) != null
}
