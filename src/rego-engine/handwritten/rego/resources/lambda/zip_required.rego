package resources

import rego.v1

# W2533: Zip deployment requires Handler and Runtime.
# cfn-lint reports a single diagnostic listing every missing property, anchored
# at the Code property, so collect them and emit one finding to match.
violation contains make_diag_full("W2533", "WARN", name,
    "Properties.Code",
    sprintf("Properties [%s] missing for zip file deployment at Resources/%s/Properties", [formatted, name]),
    "Add the missing properties for zip file deployment",
    "") if {
    some name in resources_of_type("AWS::Lambda::Function")
    _is_zip(name)
    missing := [prop | some prop in ["Handler", "Runtime"]; not has_property(name, prop)]
    count(missing) > 0
    formatted := concat(", ", [sprintf("'%s'", [prop]) | some prop in missing])
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
