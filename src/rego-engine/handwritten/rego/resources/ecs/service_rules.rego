package resources

import rego.v1

# E3054: ECS Service FARGATE - TaskDef must have RequiresCompatibilities containing FARGATE
violation contains make_diag_full("E3054", "ERROR", target_name,
    "Properties.RequiresCompatibilities",
    sprintf("[%s] does not contain items matching 'FARGATE'", [rendered]),
    "Add 'FARGATE' to RequiresCompatibilities",
    "") if {
    some svc_name in resources_of_type("AWS::ECS::Service")
    launch := resolve(svc_name, "Properties.LaunchType")
    launch == "FARGATE"
    target_name := follow_ref(svc_name, "Properties.TaskDefinition")
    target_name != null
    taskdef := get_resource(target_name)
    taskdef != null
    # An awsvpc task definition is already Fargate-compatible, so it is exempt.
    # Read the value with a default so an ABSENT NetworkMode (which resolves to
    # undefined) is treated as "not awsvpc" rather than failing the whole rule.
    object.get(taskdef.properties, "NetworkMode", "") != "awsvpc"
    has_property(target_name, "RequiresCompatibilities")
    compat := object.get(taskdef.properties, "RequiresCompatibilities", [])
    not "FARGATE" in compat
    rendered := concat(", ", [sprintf("'%s'", [v]) | some v in compat])
}

# Emit with empty placeholder when RequiresCompatibilities is absent entirely.
violation contains make_diag_full("E3054", "ERROR", target_name,
    "Properties.RequiresCompatibilities",
    "[''] does not contain items matching 'FARGATE'",
    "Add 'FARGATE' to RequiresCompatibilities",
    "") if {
    some svc_name in resources_of_type("AWS::ECS::Service")
    launch := resolve(svc_name, "Properties.LaunchType")
    launch == "FARGATE"
    target_name := follow_ref(svc_name, "Properties.TaskDefinition")
    target_name != null
    taskdef := get_resource(target_name)
    taskdef != null
    # An awsvpc task definition is already Fargate-compatible, so it is exempt.
    # Read the value with a default so an ABSENT NetworkMode (which resolves to
    # undefined) is treated as "not awsvpc" rather than failing the whole rule.
    object.get(taskdef.properties, "NetworkMode", "") != "awsvpc"
    not has_property(target_name, "RequiresCompatibilities")
}

# E3052: ECS Service network config - awsvpc TaskDef requires NetworkConfiguration
violation contains make_diag_full("E3052", "ERROR", svc_name, "Properties",
    "NetworkConfiguration required when TaskDefinition NetworkMode is 'awsvpc'",
    "", "") if {
    some svc_name in resources_of_type("AWS::ECS::Service")
    target_name := follow_ref(svc_name, "Properties.TaskDefinition")
    target_name != null
    taskdef := get_resource(target_name)
    taskdef != null
    taskdef.properties.NetworkMode == "awsvpc"
    not has_property(svc_name, "NetworkConfiguration")
}
