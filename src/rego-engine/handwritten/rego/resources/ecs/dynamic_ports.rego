package resources

import rego.v1

# E3049: ECS dynamic port requires traffic-port health check.
# cfn-lint anchors this on the target group's HealthCheckPort (the property that
# must be 'traffic-port'), with the service as a related location.
violation contains make_diag_related("E3049", "ERROR", tg_name,
    "Properties.HealthCheckPort",
    sprintf("Container '%s' has HostPort 0 but TargetGroup '%s' HealthCheckPort is '%s', must be 'traffic-port'",
        [container_name, tg_name, health_port]),
    [{"resource": svc_name, "path": "Properties.LoadBalancers", "message": "Dynamic host port defined here"}]
) if {
    some svc_name in resources_of_type("AWS::ECS::Service")
    taskdef_id := follow_ref(svc_name, "Properties.TaskDefinition")
    taskdef_id != null
    taskdef := get_resource(taskdef_id)
    taskdef != null
    lbs := resolve(svc_name, "Properties.LoadBalancers")
    is_array(lbs)
    some i, lb in lbs
    is_object(lb)
    container_name := lb.ContainerName
    container_port := lb.ContainerPort
    cdefs := object.get(taskdef.properties, "ContainerDefinitions", [])
    is_array(cdefs)
    some cdef in cdefs
    is_object(cdef)
    cdef.Name == container_name
    some pm in cdef.PortMappings
    is_object(pm)
    pm.ContainerPort == container_port
    object.get(pm, "HostPort", -1) == 0
    tg_name := follow_ref(svc_name, sprintf("Properties.LoadBalancers.%d.TargetGroupArn", [i]))
    tg_name != null
    tg := get_resource(tg_name)
    tg != null
    health_port := object.get(tg.properties, "HealthCheckPort", "")
    health_port != "traffic-port"
}
