package resources

import rego.v1

# E3044: Fargate launch type cannot use DAEMON scheduling strategy
violation contains make_diag_full("E3044", "ERROR", name,
    "Properties.SchedulingStrategy",
    "Fargate launch type does not support DAEMON scheduling strategy",
    "Use REPLICA scheduling strategy with Fargate",
    "") if {
    some name in resources_of_type("AWS::ECS::Service")
    launch := resolve(name, "Properties.LaunchType")
    launch == "FARGATE"
    sched := resolve(name, "Properties.SchedulingStrategy")
    sched == "DAEMON"
}
