package resources

import rego.v1

# E3705: Lambda EventSourceMapping with SQS FIFO queue — BatchSize must be ≤ 10
violation contains make_diag_at("E3705", "ERROR", name,
    "Properties.BatchSize",
    sprintf("BatchSize %d exceeds maximum of 10 for SQS FIFO queue event source", [batch_size])) if {
    some name in resources_of_type("AWS::Lambda::EventSourceMapping")
    target := follow_ref(name, "Properties.EventSourceArn")
    get_resource(target).resourceType == "AWS::SQS::Queue"
    resolve(target, "Properties.FifoQueue") == true
    batch_size := resolve(name, "Properties.BatchSize")
    is_number(batch_size)
    batch_size > 10
}

# E3707: RDS DBInstance Engine must match DBCluster Engine
violation contains make_diag_related("E3707", "ERROR", name,
    "Properties.Engine",
    sprintf("DBInstance Engine '%s' does not match DBCluster Engine '%s'", [inst_engine, cluster_engine]),
    [{"resource": cluster_name, "path": "Properties.Engine", "message": "cluster engine"}]) if {
    some name in resources_of_type("AWS::RDS::DBInstance")
    cluster_name := follow_ref(name, "Properties.DBClusterIdentifier")
    inst_engine := resolve(name, "Properties.Engine")
    cluster_engine := resolve(cluster_name, "Properties.Engine")
    is_string(inst_engine)
    is_string(cluster_engine)
    inst_engine != cluster_engine
}

# E3708: API Gateway Method AuthorizationType must match Authorizer Type
violation contains make_diag_at("E3708", "ERROR", auth_id,
    "Properties.Type",
    sprintf("'%s' is not one of %s", [authorizer_type, expected])) if {
    some name in resources_of_type("AWS::ApiGateway::Method")
    auth_id := follow_ref(name, "Properties.AuthorizerId")
    auth_type := resolve(name, "Properties.AuthorizationType")
    authorizer_type := resolve(auth_id, "Properties.Type")
    is_string(auth_type)
    is_string(authorizer_type)
    expected := _auth_type_expected[auth_type]
    not authorizer_type in expected
}

_auth_type_expected := {
    "CUSTOM": ["TOKEN", "REQUEST"],
    "COGNITO_USER_POOLS": ["COGNITO_USER_POOLS"],
}

# E3698: API Gateway Stage/Deployment must reference same RestApi
violation contains make_diag_at("E3698", "ERROR", deployment_name,
    "Properties.RestApiId",
    sprintf("Stage RestApiId references '%s' but Deployment references '%s'", [stage_api, deploy_api])) if {
    some name in resources_of_type("AWS::ApiGateway::Stage")
    stage_api := follow_ref(name, "Properties.RestApiId")
    deployment_name := follow_ref(name, "Properties.DeploymentId")
    deploy_api := follow_ref(deployment_name, "Properties.RestApiId")
    stage_api != deploy_api
}
