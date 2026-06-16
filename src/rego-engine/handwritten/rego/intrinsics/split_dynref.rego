package intrinsics

import rego.v1

# Fn::Split's first argument is the delimiter — CloudFormation does not
# resolve dynamic references inside it before splitting, so a `{{resolve:...}}`
# substring would be passed through as a literal delimiter and produce wrong
# segments at deploy time.
violation contains make_diag_at("E1058", "ERROR", name,
    path,
    "Fn::Split delimiter must not be a dynamic reference") if {
    some name, res in input.resources
    some path in res.splitDynamicRefDelimiters
}
