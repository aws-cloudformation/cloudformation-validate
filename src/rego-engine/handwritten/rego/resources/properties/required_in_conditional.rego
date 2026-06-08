package resources

import rego.v1

# E3024/E3003: Tag Key is null (from AWS::NoValue) or missing
violation contains make_diag_full("E3024", "ERROR", name,
    "Properties.Tags",
    "'Key' is a required property",
    "Tag Key cannot be null or AWS::NoValue",
    "") if {
    some name, res in input.resources
    tags := object.get(res.properties, "Tags", null)
    is_array(tags)
    some tag in tags
    is_object(tag)
    # Tag has Value but Key is null or missing
    object.get(tag, "Value", null) != null
    key_val := object.get(tag, "Key", "__missing__")
    key_val in {null, "__missing__"}
}

violation contains make_diag_full("E3003", "ERROR", name,
    "Properties.Tags",
    "'Key' is a required property",
    "Tag Key cannot be null or AWS::NoValue",
    "") if {
    some name, res in input.resources
    tags := object.get(res.properties, "Tags", null)
    is_array(tags)
    some tag in tags
    is_object(tag)
    object.get(tag, "Value", null) != null
    key_val := object.get(tag, "Key", "__missing__")
    key_val in {null, "__missing__"}
}

# E3003: Required properties missing in Fn::If false branch for CloudFront
# When DefaultCacheBehavior is conditional and the false branch is {},
# required sub-properties are missing.
violation contains make_diag_full("E3003", "ERROR", name,
    "Properties.DistributionConfig",
    "'DefaultCacheBehavior' is a required property",
    "Add DefaultCacheBehavior to the Fn::If branch",
    "") if {
    some name in resources_of_type("AWS::CloudFront::Distribution")
    some scenario in resolve_scenarios(name, "Properties.DistributionConfig.DefaultCacheBehavior")
    scenario.value == null
    is_satisfiable(scenario.conditions)
}

violation contains make_diag_full("E3003", "ERROR", name,
    "Properties.DistributionConfig.DefaultCacheBehavior.Fn::If.2",
    "'TargetOriginId' is a required property",
    "Add TargetOriginId to the DefaultCacheBehavior",
    "") if {
    some name in resources_of_type("AWS::CloudFront::Distribution")
    some scenario in resolve_scenarios(name, "Properties.DistributionConfig.DefaultCacheBehavior")
    is_object(scenario.value)
    is_satisfiable(scenario.conditions)
    not object.get(scenario.value, "TargetOriginId", null) != null
}

violation contains make_diag_full("E3003", "ERROR", name,
    "Properties.DistributionConfig.DefaultCacheBehavior.Fn::If.2",
    "'ViewerProtocolPolicy' is a required property",
    "Add ViewerProtocolPolicy to the DefaultCacheBehavior",
    "") if {
    some name in resources_of_type("AWS::CloudFront::Distribution")
    some scenario in resolve_scenarios(name, "Properties.DistributionConfig.DefaultCacheBehavior")
    is_object(scenario.value)
    is_satisfiable(scenario.conditions)
    not object.get(scenario.value, "ViewerProtocolPolicy", null) != null
}
