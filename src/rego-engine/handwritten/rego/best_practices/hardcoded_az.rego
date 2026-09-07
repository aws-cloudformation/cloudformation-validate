package best_practices

import rego.v1

# W3010: Hardcoded availability zone. The resource-type/property allowlist, the
# availability-zone pattern, and the traversal all come from the shared
# `hardcoded_azs` builtin (backed by template-model). Values produced by
# intrinsics (Fn::GetAZs, Ref, etc.) are skipped by the builtin.

violation contains make_diag_at("W3010", "WARN", name, az.path,
    sprintf("Avoid hardcoding availability zones '%s'", [az.zone])) if {
    cfn_rule_active("W3010")
    some name, res in input.resources
    some az in hardcoded_azs(name, res.resourceType)
}
