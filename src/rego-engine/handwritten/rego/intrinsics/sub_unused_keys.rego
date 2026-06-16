package intrinsics

import rego.v1

# A key in the Fn::Sub variable map that does not appear as `${Key}` in the
# template string is dead code — the value is parsed but never substituted.
# This is a strong signal of an authoring mistake (typo, leftover after a
# rename) so we surface it as a warning.
violation contains make_diag_at("W1019", "WARN", name,
    entry.path,
    sprintf("Parameter '%s' in Fn::Sub variable map is not referenced in the template string", [entry.variable])) if {
    some name, res in input.resources
    some entry in res.unusedSubKeys
}
