package best_practices

import rego.v1

# W1020: Fn::Sub with no variables at all — Sub isn't needed
violation contains make_diag_at("W1020", "WARN", name,
    path,
    "Fn::Sub isn't needed because there are no variables") if {
    not has_transform("AWS::Serverless-2016-10-31")
    some name, res in input.resources
    some path in res.redundantSubs
}
