package intrinsics

import rego.v1

# E1018: Sub variables must resolve to parameter, resource, or pseudo-parameter
pseudo_params_sub := {
    "AWS::AccountId", "AWS::NotificationARNs", "AWS::NoValue",
    "AWS::Partition", "AWS::Region", "AWS::StackId", "AWS::StackName", "AWS::URLSuffix"
}

violation contains make_diag_full("F1018", "FATAL", name, edge.sourcePath,
    sprintf("Fn::Sub variable '${%s}' does not reference a valid resource, parameter, or pseudo-parameter", [target]),
    "", "") if {
    some name, res in input.resources
    some edge in res.outgoingRefs
    edge.kind == "Sub"
    target := edge.target
    not target in object.keys(input.resources)
    not target in object.keys(input.parameters)
    not target in pseudo_params_sub
    not target in object.get(input, "samImplicitResources", [])
}
