package intrinsics

import rego.v1

# Canonical CloudFormation pseudo-parameter set. Defined once at package
# level so every file in `package intrinsics` (ref.rego, sub.rego,
# raw_pseudo_param.rego) shares one truth. MUST mirror the canonical Rust
# constant `PSEUDO_PARAMETERS` in src/template-model/src/consts.rs — when
# AWS adds a pseudo-parameter, update both.
pseudo_parameters := {
    "AWS::AccountId",
    "AWS::NotificationARNs",
    "AWS::NoValue",
    "AWS::Partition",
    "AWS::Region",
    "AWS::StackId",
    "AWS::StackName",
    "AWS::URLSuffix",
}
