package resources

import rego.v1

# E3677: When Code.ZipFile is present, Runtime must be nodejs or python
violation contains make_diag("E3677", "ERROR", name,
    sprintf("Runtime '%s' is not supported with Code.ZipFile - use nodejs or python", [runtime])) if {
    some name in resources_of_type("AWS::Lambda::Function")
    zipfile := resolve(name, "Properties.Code.ZipFile")
    zipfile != null
    runtime := resolve(name, "Properties.Runtime")
    is_string(runtime)
    not startswith(runtime, "nodejs")
    not startswith(runtime, "python")
}
