package resources

import rego.v1

# E3705: Lambda EventSourceMapping with SQS FIFO queue - BatchSize must be ≤ 10
violation contains make_diag_at("E3705", "ERROR", name,
    "Properties.BatchSize",
    sprintf("BatchSize %d exceeds maximum of 10 for SQS FIFO queue event source", [batch_size])) if {
    cfn_rule_active("E3705")
    some name in resources_of_type("AWS::Lambda::EventSourceMapping")
    target := follow_ref(name, "Properties.EventSourceArn")
    get_resource(target).resourceType == "AWS::SQS::Queue"
    coerce_to_string(resolve(target, "Properties.FifoQueue")) == "true"
    batch_size := coerce_to_integer(resolve(name, "Properties.BatchSize"))
    batch_size > 10
}

# E3707: RDS DBInstance Engine must match DBCluster Engine
violation contains make_diag_related("E3707", "ERROR", name,
    "Properties.Engine",
    sprintf("DBInstance Engine '%s' does not match DBCluster Engine '%s'", [inst_engine, cluster_engine]),
    [{"resource": cluster_name, "path": "Properties.Engine", "message": "cluster engine"}]) if {
    cfn_rule_active("E3707")
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
    sprintf("'%s' is not one of %s", [authorizer_type, render_list(expected)])) if {
    cfn_rule_active("E3708")
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

# E3698: API Gateway Stage/Deployment must reference the same RestApi; a mismatch
# fails deployment. The check applies only when the Stage references a Deployment
# that resolves to a resource. The finding is anchored on the Deployment's
# RestApiId and renders the Stage's own authored RestApiId as
# "<value> was expected".
violation contains make_diag_at("E3698", "ERROR", deployment_name,
    "Properties.RestApiId",
    sprintf("%s was expected", [render_value(authored_form(name, "Properties.RestApiId"))])) if {
    cfn_rule_active("E3698")
    some name in resources_of_type("AWS::ApiGateway::Stage")
    deployment_name := follow_ref(name, "Properties.DeploymentId")
    _rest_api_ids_conflict(name, deployment_name)
}

# E3699: API Gateway Method and the Authorizer it references must reference the
# same RestApi; a mismatch fails deployment. The check applies only when the
# Method references an Authorizer that resolves to a resource. The finding is
# anchored on the Authorizer's RestApiId and renders the Method's own authored
# RestApiId as "<value> was expected".
violation contains make_diag_at("E3699", "ERROR", authorizer_name,
    "Properties.RestApiId",
    sprintf("%s was expected", [render_value(authored_form(name, "Properties.RestApiId"))])) if {
    cfn_rule_active("E3699")
    some name in resources_of_type("AWS::ApiGateway::Method")
    authorizer_name := follow_ref(name, "Properties.AuthorizerId")
    _rest_api_ids_conflict(name, authorizer_name)
}

# Whether two resources' RestApiId properties refer to different REST APIs.
# Identity is compared first: two values that follow to the same resource match
# even when authored differently (e.g. `Ref RestApi` and `Fn::GetAtt
# RestApi.RestApiId` resolve to one API). When either side is not a reference to a
# resource (a literal id or a `Ref` to a parameter), the authored values are
# compared structurally, matching how CloudFormation treats them.
_rest_api_ids_conflict(first_name, second_name) if {
    first_target := follow_ref(first_name, "Properties.RestApiId")
    second_target := follow_ref(second_name, "Properties.RestApiId")
    first_target != second_target
}

_rest_api_ids_conflict(first_name, second_name) if {
    not follow_ref(first_name, "Properties.RestApiId")
    _authored_values_differ(first_name, second_name)
}

_rest_api_ids_conflict(first_name, second_name) if {
    not follow_ref(second_name, "Properties.RestApiId")
    _authored_values_differ(first_name, second_name)
}

_authored_values_differ(first_name, second_name) if {
    first_form := authored_form(first_name, "Properties.RestApiId")
    second_form := authored_form(second_name, "Properties.RestApiId")
    first_form != second_form
}
