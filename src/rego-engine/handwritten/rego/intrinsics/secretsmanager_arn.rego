package intrinsics

import rego.v1

violation contains make_diag_full("W1051", "WARN", name,
    path,
    "Dynamic reference resolves the secret value but this property expects the secret ARN",
    "Use the secret ARN directly or retrieve it from Fn::GetAtt instead of using a resolve reference",
    "") if {
    some name, res in input.resources
    some path in res.secretsmanagerRefPaths
    _path_has_arn_field(path)
}

_path_has_arn_field(path) if {
    some field in data.secretsmanager_arn_fields
    segments := split(path, ".")
    some s in segments
    s == field
}
