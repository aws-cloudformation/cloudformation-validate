package resources

import rego.v1

# ECS dynamic host port (0) registers each task with an ephemeral port, so the
# target group's health check must follow that port. It does so only when
# HealthCheckPort is 'traffic-port' — which is also the default when the
# property is omitted. The finding is anchored on the target group's
# HealthCheckPort (the property that governs the health check), with the
# service as a related location.

# Each ECS-service load balancer that binds a dynamic host port (0) to a
# target group, as {svc, container, tg_name, tg}.
_dynamic_port_bindings contains binding if {
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
    coerce_port_to_string(pm.ContainerPort) == coerce_port_to_string(container_port)
    coerce_port_to_string(object.get(pm, "HostPort", -1)) == "0"
    tg_name := follow_ref(svc_name, sprintf("Properties.LoadBalancers.%d.TargetGroupArn", [i]))
    tg_name != null
    tg := get_resource(tg_name)
    tg != null
    binding := {"svc": svc_name, "container": container_name, "tg_name": tg_name, "tg": tg}
}

_related(svc_name) := [{"resource": svc_name, "path": "Properties.LoadBalancers", "message": "Dynamic host port defined here"}]

# Concrete health-check ports across every conditional branch, as strings so an
# unquoted 8080 and a quoted "8080" compare equal. Opaque values (Ref / dynamic
# reference) resolve to nothing here, so they never look like a fixed port.
_health_check_ports(tg_name) := {port |
    some raw in resolve_all(tg_name, "Properties.HealthCheckPort")
    port := _scalar_port(raw)
}

_scalar_port(x) := x if is_string(x)

_scalar_port(x) := sprintf("%v", [x]) if is_number(x)

# HealthCheckPort pinned to a concrete port other than 'traffic-port' (in any
# branch): health checks target that fixed port instead of the ephemeral traffic
# port. A deploy-time value (Ref/dynamic reference) is not concrete, so it is
# left unflagged — its value is unknowable here.
violation contains make_diag_related("W3049", "WARN", b.tg_name,
    "Properties.HealthCheckPort",
    sprintf("Container '%s' uses dynamic host port 0, so each task registers on an ephemeral port, but TargetGroup '%s' health-checks the fixed port '%s'. The health check will not follow the traffic port unless '%s' is separately served on every target. Use HealthCheckPort 'traffic-port' to health-check the port each target actually receives traffic on",
        [b.container, b.tg_name, wrong_port, wrong_port]),
    _related(b.svc)
) if {
    some b in _dynamic_port_bindings
    some wrong_port in _health_check_ports(b.tg_name)
    wrong_port != "traffic-port"
}

# HealthCheckPort omitted: defaults to 'traffic-port', the correct setting for
# dynamic port mapping. Advisory only — the template deploys and works. An absent
# property has no concrete port, so this never overlaps the wrong-port warning.
violation contains make_diag_related("I3049", "INFO", b.tg_name,
    "Properties.HealthCheckPort",
    sprintf("Container '%s' uses dynamic host port 0; TargetGroup '%s' omits HealthCheckPort, which defaults to 'traffic-port', so the health check follows each task's ephemeral port - the correct behavior for dynamic port mapping",
        [b.container, b.tg_name]),
    _related(b.svc)
) if {
    some b in _dynamic_port_bindings
    not "HealthCheckPort" in object.keys(b.tg.properties)
}
