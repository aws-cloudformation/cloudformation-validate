package best_practices

import rego.v1

# W1020: Fn::Sub with a single variable and no other text — use Ref instead
# Skip NoEcho parameters — simplifying to !Ref would expose the value.
violation contains make_diag_at("W1020", "WARN", name,
    sub_info.path,
    sprintf("Fn::Sub '${%s}' can be simplified to !Ref %s", [sub_info.variable, sub_info.variable])) if {
    some name, res in input.resources
    some sub_info in res.simpleSubs
    param := object.get(input.parameters, sub_info.variable, null)
    param != null
    not object.get(param, "noEcho", false)
}

# W1020: Fn::Sub with no variables at all — Sub isn't needed
violation contains make_diag_at("W1020", "WARN", name,
    path,
    "Fn::Sub isn't needed because there are no variables") if {
    some name, res in input.resources
    some path in res.redundantSubs
}
