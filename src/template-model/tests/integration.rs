use template_model::SemanticModel;
use template_model::SpanProvider;
use template_model::resolver::ResolvedValue;

const TEMPLATES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../resources/templates");

fn model_from_fixture(path: &str) -> SemanticModel {
    let full = format!("{}/{}", TEMPLATES, path);
    let bytes = std::fs::read(&full).unwrap_or_else(|e| panic!("Failed to read {}: {}", full, e));
    SemanticModel::from_bytes(&bytes).unwrap_or_else(|e| panic!("Failed to parse {}: {}", full, e))
}

#[test]
fn model_resources_by_type() {
    let model = model_from_fixture("good/generic.yaml");
    let iam_roles = model.resources_of_type("AWS::IAM::Role");
    assert!(!iam_roles.is_empty(), "Expected IAM roles in generic template");
}

#[test]
fn model_rego_input_valid_json() {
    let model = model_from_fixture("good/generic.yaml");
    let json = serde_json::to_value(model.to_diagnostic_json()).unwrap();
    assert!(json.get("resources").is_some(), "expected 'resources' in diagnostic JSON");
    assert!(json.get("parameters").is_some(), "expected 'parameters' in diagnostic JSON");
    assert!(json.get("edges").is_some(), "expected 'edges' in diagnostic JSON");
}

#[test]
fn fixture_both_intrinsic_forms() {
    let model = model_from_fixture("good/both_forms.yaml");

    assert_eq!(model.resources.len(), 13);

    let bucket_short = model.resource("BucketShort").unwrap();
    match bucket_short.properties.get("BucketName") {
        Some(ResolvedValue::Enum { variants: _ }) => {}
        other => panic!("BucketShort.BucketName: expected Enum from Sub, got {:?}", other),
    }

    let bucket_long = model.resource("BucketLong").unwrap();
    match bucket_long.properties.get("BucketName") {
        Some(ResolvedValue::Enum { variants: _ }) => {}
        other => panic!("BucketLong.BucketName: expected Enum from Sub, got {:?}", other),
    }

    let with_getatt = model.resource("WithGetAtt").unwrap();
    match with_getatt.properties.get("ShortForm") {
        Some(ResolvedValue::Reference { target: t, .. }) => {
            assert_eq!(t, "BucketShort")
        }
        other => panic!("WithGetAtt.ShortForm: expected Reference, got {:?}", other),
    }
    match with_getatt.properties.get("LongFormDotted") {
        Some(ResolvedValue::Reference { target: t, .. }) => {
            assert_eq!(t, "BucketShort")
        }
        other => panic!("WithGetAtt.LongFormDotted: expected Reference, got {:?}", other),
    }
    match with_getatt.properties.get("LongFormArray") {
        Some(ResolvedValue::Reference { target: t, .. }) => {
            assert_eq!(t, "BucketLong")
        }
        other => panic!("WithGetAtt.LongFormArray: expected Reference, got {:?}", other),
    }

    let with_join = model.resource("WithJoin").unwrap();
    match with_join.properties.get("Short") {
        Some(ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "a-b-c");
        }
        other => panic!("WithJoin.Short: expected Concrete 'a-b-c', got {:?}", other),
    }
    match with_join.properties.get("Long") {
        Some(ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "x-y-z");
        }
        other => panic!("WithJoin.Long: expected Concrete 'x-y-z', got {:?}", other),
    }

    let with_select = model.resource("WithSelect").unwrap();
    match with_select.properties.get("Short") {
        Some(ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "a")
        }
        other => panic!("WithSelect.Short: expected Concrete 'a', got {:?}", other),
    }
    match with_select.properties.get("Long") {
        Some(ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "b")
        }
        other => panic!("WithSelect.Long: expected Concrete 'b', got {:?}", other),
    }

    let with_if = model.resource("WithIf").unwrap();
    assert!(
        matches!(with_if.properties.get("Short"), Some(ResolvedValue::Conditional { condition: c, .. }) if c == "IsProd")
    );
    assert!(
        matches!(with_if.properties.get("Long"), Some(ResolvedValue::Conditional { condition: c, .. }) if c == "IsProd")
    );

    let with_b64 = model.resource("WithBase64").unwrap();
    match with_b64.properties.get("Short") {
        Some(ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "aGVsbG8=")
        }
        other => panic!("WithBase64.Short: expected Concrete base64, got {:?}", other),
    }

    let sub_block = model.resource("SubBlock").unwrap();
    match sub_block.properties.get("UserData") {
        Some(ResolvedValue::Enum { variants: _ }) => {}
        other => panic!("SubBlock.UserData: expected Enum from Sub, got {:?}", other),
    }

    assert!(model.conditions.conditions.contains_key("IsProd"));
    assert!(model.conditions.conditions.contains_key("IsDevShort"));
    assert!(model.conditions.conditions.contains_key("Combined"));

    assert!(model.mappings.contains_key("MyMap"));

    assert_eq!(model.outputs.len(), 1);
}

#[test]
fn parser_auto_detects_json() {
    let input = r#"{"Resources":{"R":{"Type":"T"}}}"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert_eq!(model.resources.len(), 1);
}

#[test]
fn parser_auto_detects_yaml() {
    let input = "Resources:\n  R:\n    Type: T\n";
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert_eq!(model.resources.len(), 1);
}

#[test]
fn parser_json_with_leading_whitespace() {
    let input = "  \n  {\"Resources\":{\"R\":{\"Type\":\"T\"}}}";
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert_eq!(model.resources.len(), 1);
}

#[test]
fn parser_yaml_with_comments() {
    let input = "# comment\nResources:\n  R:\n    Type: T\n    # inline comment\n";
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert_eq!(model.resources.len(), 1);
}

#[test]
fn parser_rejects_empty_input() {
    assert!(SemanticModel::from_bytes(b"").is_err(), "empty input should be rejected");
}

#[test]
fn parser_rejects_whitespace_only() {
    assert!(SemanticModel::from_bytes(b"   \n  \n  ").is_err(), "whitespace-only input should be rejected");
}

#[test]
fn parser_rejects_non_object_json() {
    assert!(SemanticModel::from_bytes(b"[1,2,3]").is_err(), "non-object JSON should be rejected");
}

#[test]
fn parser_rejects_scalar_yaml() {
    assert!(SemanticModel::from_bytes(b"just a string").is_err(), "scalar YAML should be rejected");
}

#[test]
fn parser_json_preserves_all_sections() {
    let input = r#"{
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Test template",
        "Parameters": {"P": {"Type": "String", "Default": "val"}},
        "Mappings": {"M": {"k1": {"k2": "v"}}},
        "Conditions": {"C": {"Fn::Equals": ["a", "a"]}},
        "Resources": {"R": {"Type": "T", "Properties": {"V": "x"}}},
        "Outputs": {"O": {"Value": {"Ref": "R"}}}
    }"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert_eq!(model.format_version.as_deref(), Some("2010-09-09"));
    assert_eq!(model.description.as_deref(), Some("Test template"));
    assert_eq!(model.parameters.len(), 1);
    assert_eq!(model.mappings.len(), 1);
    assert_eq!(model.conditions.conditions.len(), 1);
    assert_eq!(model.resources.len(), 1);
    assert_eq!(model.outputs.len(), 1);
}

#[test]
fn parser_yaml_preserves_all_sections() {
    let input = r#"
AWSTemplateFormatVersion: "2010-09-09"
Description: Test template
Parameters:
  P:
    Type: String
    Default: val
Mappings:
  M:
    k1:
      k2: v
Conditions:
  C:
    Fn::Equals: [a, a]
Resources:
  R:
    Type: T
    Properties:
      V: x
Outputs:
  O:
    Value: !Ref R
"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert_eq!(model.format_version.as_deref(), Some("2010-09-09"));
    assert_eq!(model.description.as_deref(), Some("Test template"));
    assert_eq!(model.parameters.len(), 1);
    assert_eq!(model.mappings.len(), 1);
    assert_eq!(model.conditions.conditions.len(), 1);
    assert_eq!(model.resources.len(), 1);
    assert_eq!(model.outputs.len(), 1);
}

#[test]
fn parser_json_yaml_produce_same_resource_types() {
    let json_input = r#"{"Resources":{"Bucket":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"test"}}}}"#;
    let yaml_input = "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: test\n";
    let json_model = SemanticModel::from_bytes(json_input.as_bytes()).unwrap();
    let yaml_model = SemanticModel::from_bytes(yaml_input.as_bytes()).unwrap();
    assert_eq!(
        json_model.resource("Bucket").unwrap().resource_type,
        yaml_model.resource("Bucket").unwrap().resource_type
    );
}

#[test]
fn parser_yaml_intrinsic_short_forms() {
    let input = r#"
Resources:
  R:
    Type: T
    Properties:
      A: !Ref Param
      B: !Sub "hello-${AWS::Region}"
      C: !GetAtt Other.Arn
      D: !Join ["-", ["a", "b"]]
      E: !Select [0, ["x", "y"]]
      F: !Base64 hello
      G: !Split [",", "a,b"]
"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let r = model.resource("R").unwrap();
    assert_eq!(r.properties.len(), 7);
}

#[test]
fn parser_transform_single_string() {
    let input = "Transform: AWS::Serverless-2016-10-31\nResources:\n  R:\n    Type: T\n";
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert_eq!(model.transforms.len(), 1);
    assert_eq!(model.transforms[0], "AWS::Serverless-2016-10-31");
}

#[test]
fn parser_transform_list() {
    let input = r#"{"Transform":["AWS::Serverless-2016-10-31","AWS::Include"],"Resources":{"R":{"Type":"T"}}}"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert_eq!(model.transforms.len(), 2);
}

#[test]
fn parser_minimal_template_no_properties() {
    let input = r#"{"Resources":{"R":{"Type":"T"}}}"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let r = model.resource("R").unwrap();
    assert!(r.properties.is_empty());
    assert_eq!(r.resource_type, "T");
}

#[test]
fn parser_fn_if_undefined_condition_produces_e1028() {
    // An undefined Fn::If condition is reported once, as E1028, even when no
    // Conditions section is present.
    let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::If":["NonExistent",1,2]}}}}}"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let e1028: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E1028").collect();
    assert_eq!(e1028.len(), 1, "exactly one E1028 for an undefined Fn::If condition");
    assert!(e1028[0].message.contains("NonExistent"));
    assert!(!model.diagnostics.iter().any(|d| d.rule_id == "F1104"), "F1104 must no longer fire for this case");
}

#[test]
fn dynamic_reference_e1050_matches_reference_cases() {
    // Each malformed form fires E1050; each valid form does not. These mirror the
    // dynamic-reference schema (ssm numeric version, secretsmanager ARN 'secret'
    // segment, unknown service, and the tolerant ssm parameter-name search).
    let fires = |props: &str| {
        let input = format!(r#"{{"Resources":{{"B":{{"Type":"AWS::S3::Bucket","Properties":{props}}}}}}}"#);
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        model.diagnostics.iter().any(|d| d.rule_id == "E1050")
    };
    // Malformed → E1050
    assert!(fires(r#"{"BucketName":"{{resolve:ssm:/p:notanum}}"}"#), "ssm non-numeric version");
    assert!(fires(r#"{"BucketName":"{{resolve:not-a-service:foo}}"}"#), "unknown service");
    assert!(
        fires(r#"{"BucketName":"{{resolve:secretsmanager:arn:aws:s3:us-east-1:1:notsecret:n}}"}"#),
        "secretsmanager ARN missing 'secret' segment"
    );
    // Valid → no E1050
    assert!(!fires(r#"{"BucketName":"{{resolve:ssm:/my/param}}"}"#), "valid ssm");
    assert!(!fires(r#"{"BucketName":"{{resolve:ssm:my param with spaces}}"}"#), "ssm name with spaces is tolerated");
    assert!(!fires(r#"{"BucketName":"{{resolve:secretsmanager:}}"}"#), "empty secret-id is valid");
    assert!(
        !fires(r#"{"BucketName":"{{resolve:secretsmanager:s:SecretString:k:stage:id}}"}"#),
        "full non-ARN secretsmanager tail is valid"
    );
}

#[test]
fn dynamic_reference_inside_function_is_not_format_checked() {
    // A malformed dynamic reference that is an argument to Fn::Sub is owned by
    // the enclosing function, so E1050 does not fire on it.
    let input = r#"{"Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":{"Fn::Sub":"x-{{resolve:ssm:p:notanum}}"}}}}}"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert!(!model.diagnostics.iter().any(|d| d.rule_id == "E1050"), "dynamic ref inside Fn::Sub must not fire E1050");
}

#[test]
fn bare_ref_condition_body_produces_e8001_not_e8007() {
    // A condition body that is a bare Fn::Ref (to a parameter) is not a boolean
    // and is not a condition reference: report E8001, never E8007.
    let input = r#"{
        "Parameters":{"MyParam":{"Type":"String"}},
        "Conditions":{"MyCond":{"Ref":"MyParam"}},
        "Resources":{"B":{"Type":"AWS::S3::Bucket","Condition":"MyCond"}}
    }"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert!(model.diagnostics.iter().any(|d| d.rule_id == "E8001"), "bare Fn::Ref condition body must be E8001");
    assert!(!model.diagnostics.iter().any(|d| d.rule_id == "E8007"), "must not be reported as an undefined condition");
}

#[test]
fn undefined_output_condition_produces_e6005_with_location() {
    // An output referencing an undefined condition is E6005 (resources use
    // E8002), located at the output.
    let input = r#"{
        "Conditions":{"IsProd":{"Fn::Equals":[{"Ref":"AWS::Region"},"us-east-1"]}},
        "Resources":{"R":{"Type":"AWS::S3::Bucket","Condition":"Missing"}},
        "Outputs":{"Out":{"Condition":"AlsoMissing","Value":"x"}}
    }"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let e6005: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E6005").collect();
    let e8002: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E8002").collect();
    assert_eq!(e6005.len(), 1, "output undefined condition -> E6005");
    assert!(e6005[0].message.contains("AlsoMissing"));
    assert_eq!(e8002.len(), 1, "resource undefined condition -> E8002");
    assert!(e8002[0].message.contains("Missing"));
}

#[test]
fn raw_pseudo_parameter_in_output_and_parameter_default_produce_w1054() {
    // W1054 covers pseudo-parameter strings in Outputs and parameter Defaults,
    // not only resource properties, and includes AWS::NoValue.
    let input = r#"{
        "Parameters":{"P":{"Type":"String","Default":"AWS::Region"}},
        "Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"AWS::NoValue"}}},
        "Outputs":{"Out":{"Value":"AWS::AccountId"}}
    }"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let w1054: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "W1054").collect();
    assert!(w1054.iter().any(|d| d.message.contains("AWS::Region")), "param Default pseudo-param -> W1054");
    assert!(w1054.iter().any(|d| d.message.contains("AWS::AccountId")), "output pseudo-param -> W1054");
    // AWS::NoValue in a resource property is collected for the engine rule; the
    // parse-time set here covers Outputs and parameter Defaults.
}

#[test]
fn yaml_merge_key_produces_w1100() {
    // The `<<` merge key is not supported by CloudFormation; W1100 must fire
    // (regression: the span capture used to read an already-emptied slot).
    let input = "\
.base: &base
  BucketName: my-bucket
Resources:
  B:
    Type: AWS::S3::Bucket
    Properties:
      <<: *base
";
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert!(model.diagnostics.iter().any(|d| d.rule_id == "W1100"), "YAML merge key must produce W1100");
}

#[test]
fn equals_operand_producing_non_scalar_produces_e8003() {
    // A function whose result is not a scalar (Fn::GetAtt, Fn::Base64,
    // Fn::GetAZs, Fn::ImportValue, boolean functions) is not a valid Fn::Equals
    // operand. Each must be rejected with E8003.
    let cases = [
        r#"{"Conditions":{"C":{"Fn::Equals":[{"Fn::GetAtt":["R","Arn"]},"x"]}},"Resources":{"R":{"Type":"AWS::S3::Bucket"}}}"#,
        r#"{"Conditions":{"C":{"Fn::Equals":[{"Fn::Base64":"abc"},"x"]}},"Resources":{"R":{"Type":"AWS::S3::Bucket"}}}"#,
        r#"{"Conditions":{"C":{"Fn::Equals":[{"Fn::ImportValue":"E"},"x"]}},"Resources":{"R":{"Type":"AWS::S3::Bucket"}}}"#,
        r#"{"Conditions":{"C":{"Fn::Equals":[{"Fn::GetAZs":""},"x"]}},"Resources":{"R":{"Type":"AWS::S3::Bucket"}}}"#,
    ];
    for input in cases {
        let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
        assert!(
            model.diagnostics.iter().any(|d| d.rule_id == "E8003"),
            "expected E8003 for a non-scalar Fn::Equals operand in: {input}"
        );
    }
}

#[test]
fn equals_operand_scalar_producing_function_is_accepted() {
    // The value-producing functions permitted by CloudFormation must not trip
    // E8003 when used as an Fn::Equals operand.
    let input = r#"{
        "Parameters":{"X":{"Type":"String"}},
        "Conditions":{
            "C1":{"Fn::Equals":[{"Ref":"X"},"a"]},
            "C2":{"Fn::Equals":[{"Fn::Select":[0,{"Fn::Split":[",","a,b"]}]},"a"]},
            "C3":{"Fn::Equals":[{"Fn::Sub":"${X}"},"a"]}
        },
        "Resources":{"R":{"Type":"AWS::S3::Bucket","Condition":"C1"}}
    }"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert!(
        !model.diagnostics.iter().any(|d| d.rule_id == "E8003"),
        "E8003 must not fire for scalar-producing Fn::Equals operands"
    );
}

#[test]
fn parser_tautological_condition_produces_w8003() {
    let input = r#"
Conditions:
  AlwaysTrue:
    Fn::Equals: ["same", "same"]
Resources:
  R:
    Type: T
"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert!(model.diagnostics.iter().any(|d| d.rule_id == "W8003" && d.message.contains("AlwaysTrue")));
}

#[test]
fn parser_span_index_populated() {
    let input = "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: test\n";
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert!(model.span_index.contains_key("Resources/MyBucket"));
    assert!(model.span_index.contains_key("Resources/MyBucket/Properties/BucketName"));
}

#[test]
fn sam_globals_merged_into_function() {
    let model = model_from_fixture("good/transform_serverless_globals.yaml");
    let func = model.resource("myFunction").unwrap();
    // Globals.Function.Runtime should be merged into the function
    assert!(model.sam_globals.contains_key("Function"));
    assert!(model.sam_globals["Function"].contains_key("Runtime"));
    // The function should have the Runtime property from globals
    assert!(func.properties.contains_key("Runtime"));
    let runtime_span = model
        .source_location("Resources/myFunction/Properties/Runtime")
        .expect("inherited Runtime should retain its Globals source span");
    assert_eq!(runtime_span.start_line, 5, "inherited Runtime should point to Globals.Function.Runtime");
}

#[test]
fn sam_implicit_resources_detected() {
    let model = model_from_fixture("good/transform_serverless_globals.yaml");
    // SAM function generates implicit Role
    assert!(model.sam_implicit_resources.contains("myFunctionRole"));
    // Api event generates implicit ServerlessRestApi
    assert!(model.sam_implicit_resources.contains("ServerlessRestApi"));
}

#[test]
fn sam_globals_param_refs_collected() {
    // The globals template doesn't have param refs, but verify the mechanism works
    let model = model_from_fixture("good/transform_serverless_globals.yaml");
    // globals_param_refs should be populated (may be empty if no Refs in Globals)
    assert_eq!(model.globals_param_refs.len(), 0, "expected no param refs in globals for this template");
}

#[test]
fn dynamic_reference_resolves_to_typed_dynamic() {
    let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":"{{resolve:ssm:my-param}}"}}}}"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    match model.resolve("R", "Properties.V") {
        Some(ResolvedValue::TypedDynamic { reason: msg, param_type: t }) => {
            assert_eq!(t, "String");
            assert!(msg.contains("dynamic reference"));
            assert!(msg.contains("{{resolve:ssm:my-param}}"), "reason should carry the literal, got {msg:?}");
        }
        other => panic!("Expected TypedDynamic, got {:?}", other),
    }
}

#[test]
fn sub_with_implicit_getatt() {
    let input =
        r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Sub":"arn:${Other.Arn}"}}},"Other":{"Type":"T2"}}}"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    // Should produce a Dynamic (can't fully resolve GetAtt) but should record the edge
    assert!(model.graph.depends_on("R", "Other"));
}

#[test]
fn fn_if_edges_have_condition_context() {
    let input = r#"
Conditions:
  C:
    Fn::Equals: ["a", "a"]
Resources:
  R:
    Type: T
    Properties:
      V:
        Fn::If:
          - C
          - !Ref A
          - !Ref B
  A:
    Type: T
  B:
    Type: T
"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let edges = model.graph.outgoing("R");
    let a_edge = edges.iter().find(|e| e.target == "A").unwrap();
    assert!(a_edge.condition_context.as_ref().unwrap().contains("C"));
    let b_edge = edges.iter().find(|e| e.target == "B").unwrap();
    assert!(b_edge.condition_context.as_ref().unwrap().contains("!C"));
}

#[test]
fn resolve_scenarios_nested_conditionals() {
    let input = r#"
Conditions:
  A:
    Fn::Equals: ["x", "x"]
  B:
    Fn::Equals: ["y", "y"]
Resources:
  R:
    Type: T
    Properties:
      V:
        Fn::If:
          - A
          - Fn::If:
              - B
              - 1
              - 2
          - 3
"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let scenarios = model.resolve_scenarios("R", "Properties.V");
    // Should produce 3 scenarios: A=true,B=true→1; A=true,B=false→2; A=false→3
    assert_eq!(scenarios.len(), 3, "expected 3 scenarios, got {:?}", scenarios);
}

#[test]
fn source_location_returns_span() {
    let input = "Resources:\n  R:\n    Type: T\n    Properties:\n      Name: hello\n";
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let span = model.source_location("Resources/R").expect("expected span for Resources/R");
    assert!(span.start_line > 0, "start_line should be > 0, got {}", span.start_line);
}

#[test]
fn source_location_missing_returns_none() {
    let input = "Resources:\n  R:\n    Type: T\n";
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert_eq!(model.source_location("Resources/NonExistent"), None, "nonexistent path should return None");
}

#[test]
fn span_provider_trait_works() {
    let input = "Resources:\n  R:\n    Type: T\n";
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let span = SpanProvider::source_location(&model, "Resources/R");
    assert!(span.is_some(), "SpanProvider should return span for Resources/R");
}

#[test]
fn verify_diagnostic_json_contract() {
    let model = model_from_fixture("good/minimal.yaml");
    let diag = model.to_diagnostic_json();
    let json = serde_json::to_value(&diag).unwrap();

    // Top-level keys must match original contract exactly
    let obj = json.as_object().unwrap();
    let expected_keys: Vec<&str> = vec![
        "template",
        "parameters",
        "conditions",
        "conditionParamRefs",
        "conditionImplications",
        "conditionMutexGroups",
        "conditionExclusions",
        "resourceConditionMap",
        "mappings",
        "resources",
        "outputs",
        "edges",
        "cycles",
        "outputEmptyJoins",
        "samImplicitResources",
        "globalsParamRefs",
        "isCdk",
        "fnIfConditions",
        "findInMapNames",
        "paramsReferencedInDefinitions",
        "hasDynamicFindinmapName",
        "hasParseErrors",
        "parsedRules",
        "resolutionSources",
    ];
    for key in &expected_keys {
        assert!(obj.contains_key(*key), "Missing top-level key: {}", key);
    }
    for key in obj.keys() {
        assert!(expected_keys.contains(&key.as_str()), "Unexpected top-level key: {}", key);
    }

    // Template sub-keys
    let tmpl = obj["template"].as_object().unwrap();
    for key in &["formatVersion", "description", "transforms"] {
        assert!(tmpl.contains_key(*key), "Template missing key: {}", key);
    }

    // Resource sub-keys
    for (_id, res) in obj["resources"].as_object().unwrap() {
        let r = res.as_object().unwrap();
        for key in &[
            "resourceType",
            "condition",
            "dependsOn",
            "deletionPolicy",
            "updateReplacePolicy",
            "properties",
            "outgoingRefs",
            "incomingRefs",
            "findInMapRefs",
            "simpleSubs",
            "redundantSubs",
            "emptyJoins",
            "hardcodedPartitionArns",
            "conditionallyNullProps",
            "conditionRefs",
            "forEachExpansions",
            "unsubstitutedVariables",
            "invalidRefs",
        ] {
            assert!(r.contains_key(*key), "Resource missing key: {}", key);
        }
    }

    // Output sub-keys
    for (_id, out) in obj["outputs"].as_object().unwrap() {
        let o = out.as_object().unwrap();
        for key in &["value", "description", "condition", "exportName", "getattRefs"] {
            assert!(o.contains_key(*key), "Output missing key: {}", key);
        }
    }

    // Edge sub-keys
    for edge in obj["edges"].as_array().unwrap() {
        let e = edge.as_object().unwrap();
        for key in &["source", "sourcePath", "target", "kind"] {
            assert!(e.contains_key(*key), "Edge missing key: {}", key);
        }
    }
}

/// CDK-synthesized bootstrap-version assertion: `Fn::Not` wrapping
/// `Fn::Contains` references the `BootstrapVersion` parameter. The
/// resolver must walk the Rules subtree and emit a Ref edge to that
/// parameter; otherwise downstream "unused parameter" rules misfire.
#[test]
fn rules_section_ref_inside_fn_contains_emits_edge() {
    let input = r#"{
        "Parameters": {
            "BootstrapVersion": {"Type": "String"}
        },
        "Resources": {
            "B": {"Type": "AWS::S3::Bucket"}
        },
        "Rules": {
            "CheckBootstrapVersion": {
                "Assertions": [{
                    "Assert": {
                        "Fn::Not": [{
                            "Fn::Contains": [
                                ["1", "2", "3", "4", "5"],
                                {"Ref": "BootstrapVersion"}
                            ]
                        }]
                    }
                }]
            }
        }
    }"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let edges = model
        .graph
        .outgoing("__rule__CheckBootstrapVersion")
        .into_iter()
        .filter(|e| e.target == "BootstrapVersion")
        .count();
    assert_eq!(edges, 1, "expected a single Ref edge from __rule__CheckBootstrapVersion to BootstrapVersion");
}

#[test]
fn rules_section_ref_in_rule_condition_emits_edge() {
    let input = r#"{
        "Parameters": {
            "Env": {"Type": "String"}
        },
        "Resources": {
            "B": {"Type": "AWS::S3::Bucket"}
        },
        "Rules": {
            "ProdOnly": {
                "RuleCondition": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
                "Assertions": [{
                    "Assert": {"Fn::Equals": ["a", "a"]}
                }]
            }
        }
    }"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let env_edges = model.graph.outgoing("__rule__ProdOnly").into_iter().filter(|e| e.target == "Env").count();
    assert!(env_edges >= 1, "expected Ref edge from __rule__ProdOnly to Env (RuleCondition)");
}

#[test]
fn rules_section_value_of_emits_parameter_ref_edge() {
    let input = r#"{
        "Parameters": {
            "Subnets": {"Type": "List<AWS::EC2::Subnet::Id>"}
        },
        "Resources": {
            "B": {"Type": "AWS::S3::Bucket"}
        },
        "Rules": {
            "VpcCheck": {
                "Assertions": [{
                    "Assert": {
                        "Fn::EachMemberIn": [
                            {"Fn::ValueOfAll": ["Subnets", "VpcId"]},
                            {"Fn::RefAll": "AWS::EC2::VPC::Id"}
                        ]
                    }
                }]
            }
        }
    }"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let subnet_edges = model.graph.outgoing("__rule__VpcCheck").into_iter().filter(|e| e.target == "Subnets").count();
    assert!(subnet_edges >= 1, "expected Ref edge from __rule__VpcCheck to Subnets (Fn::ValueOfAll first arg)");
}

#[test]
fn rules_section_ref_appears_in_diagnostic_edges_array() {
    let input = r#"{
        "Parameters": {
            "BootstrapVersion": {"Type": "String"}
        },
        "Resources": {
            "B": {"Type": "AWS::S3::Bucket"}
        },
        "Rules": {
            "CheckBootstrapVersion": {
                "Assertions": [{
                    "Assert": {
                        "Fn::Not": [{
                            "Fn::Contains": [
                                ["1", "2", "3", "4", "5"],
                                {"Ref": "BootstrapVersion"}
                            ]
                        }]
                    }
                }]
            }
        }
    }"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    let json = serde_json::to_value(model.to_diagnostic_json()).unwrap();
    let edges = json["edges"].as_array().expect("edges array");
    let referenced = edges.iter().any(|e| {
        e.get("target").and_then(|t| t.as_str()) == Some("BootstrapVersion")
            && e.get("source").and_then(|s| s.as_str()).is_some_and(|s| s.starts_with("__rule__"))
    });
    assert!(
        referenced,
        "diagnostic edges array must contain a Ref to BootstrapVersion sourced from a Rules pseudo-resource"
    );
}

#[test]
fn rules_equals_getatt_operand_reports_once() {
    // A GetAtt operand of Fn::Equals in a Rules assertion is the parser's
    // not-a-string finding; the Rules-section allowlist walk must not report
    // the same operand a second time.
    let yaml = b"
Rules:
  R1:
    Assertions:
      - Assert: !Equals [!GetAtt B.Arn, x]
Resources:
  B:
    Type: AWS::S3::Bucket
";
    let model = SemanticModel::from_bytes(yaml).unwrap();
    let e8003 = model.diagnostics.iter().filter(|d| d.rule_id == "E8003").count();
    let f8611 = model.diagnostics.iter().filter(|d| d.rule_id == "F8611").count();
    assert_eq!(e8003, 1, "operand type finding fires once: {:?}", model.diagnostics);
    assert_eq!(f8611, 0, "allowlist walk must not double-report the operand: {:?}", model.diagnostics);
}

#[test]
fn e3001_missing_type_produces_diagnostic() {
    let input = br#"{"Resources":{"R":{"Properties":{"K":"V"}}}}"#;
    let model = SemanticModel::from_bytes(input).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 1, "expected one E3001 for missing Type: {:?}", findings);
    assert!(findings[0].message.contains("missing required property 'Type'"), "message: {}", findings[0].message);
}

#[test]
fn e3001_non_object_resource_body_produces_diagnostic() {
    let yaml = b"
Resources:
  R: a string value
  S:
    Type: AWS::S3::Bucket
";
    let model = SemanticModel::from_bytes(yaml).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 1, "expected one E3001 for non-object body: {:?}", findings);
    assert!(findings[0].message.contains("must be an object"), "message: {}", findings[0].message);
}

#[test]
fn e3001_non_string_type_produces_diagnostic() {
    let input = br#"{"Resources":{"R":{"Type":42,"Properties":{"K":"V"}}}}"#;
    let model = SemanticModel::from_bytes(input).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 1, "expected one E3001 for non-string Type: {:?}", findings);
    assert!(findings[0].message.contains("'Type' must be a string"), "message: {}", findings[0].message);
}

#[test]
fn e3001_unknown_attribute_produces_diagnostic() {
    let input = br#"{"Resources":{"R":{"Type":"AWS::S3::Bucket","Bogus":"x","Properties":{}}}}"#;
    let model = SemanticModel::from_bytes(input).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 1, "expected one E3001 for unknown attribute: {:?}", findings);
    assert!(findings[0].message.contains("invalid property 'Bogus'"), "message: {}", findings[0].message);
}

#[test]
fn e3001_condition_must_be_string() {
    let yaml = b"
Resources:
  R:
    Type: AWS::S3::Bucket
    Condition: true
";
    let model = SemanticModel::from_bytes(yaml).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 1, "expected one E3001 for boolean Condition: {:?}", findings);
    assert!(findings[0].message.contains("'Condition' must be a string"), "message: {}", findings[0].message);
}

#[test]
fn e3001_depends_on_must_be_string_or_list() {
    let input = br#"{"Resources":{"R":{"Type":"AWS::S3::Bucket","DependsOn":123}}}"#;
    let model = SemanticModel::from_bytes(input).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 1, "expected one E3001 for numeric DependsOn: {:?}", findings);
    assert!(findings[0].message.contains("must be a string or list of strings"), "message: {}", findings[0].message);
}

#[test]
fn e3001_depends_on_list_elements_must_be_strings() {
    let input = br#"{"Resources":{"R":{"Type":"AWS::S3::Bucket","DependsOn":["A",123]}}}"#;
    let model = SemanticModel::from_bytes(input).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 1, "expected one E3001 for non-string list element: {:?}", findings);
    assert!(findings[0].message.contains("list elements must be strings"), "message: {}", findings[0].message);
}

#[test]
fn e3001_valid_resource_no_findings() {
    let input = br#"{"Resources":{"R":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"b"},"Condition":"C","DependsOn":["X"],"Metadata":{},"DeletionPolicy":"Retain","UpdateReplacePolicy":"Retain","UpdatePolicy":{},"CreationPolicy":{}}}}"#;
    let model = SemanticModel::from_bytes(input).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert!(findings.is_empty(), "no E3001 for valid resource: {:?}", findings);
}

#[test]
fn e3001_version_attribute_accepted_for_custom_resource() {
    let input = br#"{"Resources":{"R":{"Type":"Custom::Thing","Version":"1.0"}}}"#;
    let model = SemanticModel::from_bytes(input).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert!(findings.is_empty(), "Version is valid for a custom resource: {:?}", findings);
}

#[test]
fn e3001_version_attribute_rejected_for_standard_resource() {
    let input = br#"{"Resources":{"R":{"Type":"AWS::S3::Bucket","Version":"1.0"}}}"#;
    let model = SemanticModel::from_bytes(input).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 1, "Version is not valid for a standard resource: {:?}", findings);
    assert!(findings[0].message.contains("only valid for custom resources"), "message: {}", findings[0].message);
}

#[test]
fn e3001_plain_transform_attribute_is_rejected() {
    let input =
        br#"{"Resources":{"R":{"Type":"AWS::S3::Bucket","Transform":{"Name":"AWS::Include"},"Properties":{}}}}"#;
    let model = SemanticModel::from_bytes(input).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 1, "plain Transform is not a resource attribute: {:?}", findings);
    assert!(findings[0].message.contains("invalid property 'Transform'"), "message: {}", findings[0].message);
}

#[test]
fn e3001_lifecycle_policies_must_be_objects() {
    let yaml = b"
Resources:
  Creation:
    Type: AWS::AutoScaling::AutoScalingGroup
    CreationPolicy: invalid
  Update:
    Type: AWS::AutoScaling::AutoScalingGroup
    UpdatePolicy: 7
";
    let model = SemanticModel::from_bytes(yaml).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 2, "both scalar lifecycle policies must be rejected: {:?}", findings);
    assert!(findings.iter().any(|finding| finding.message.contains("'CreationPolicy' must be an object")));
    assert!(findings.iter().any(|finding| finding.message.contains("'UpdatePolicy' must be an object")));
}

#[test]
fn e3001_custom_resources_reject_lifecycle_policies() {
    let yaml = b"
Resources:
  R:
    Type: AWS::CloudFormation::CustomResource
    CreationPolicy: {}
    UpdatePolicy: {}
";
    let model = SemanticModel::from_bytes(yaml).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 2, "custom resources cannot use lifecycle policies: {:?}", findings);
    assert!(findings.iter().all(|finding| finding.message.contains("not valid for custom resources")));
}

#[test]
fn e3001_intrinsic_lifecycle_policy_shape_is_deferred() {
    let yaml = b"
Parameters:
  Policy:
    Type: String
Resources:
  R:
    Type: AWS::AutoScaling::AutoScalingGroup
    CreationPolicy: !Ref Policy
";
    let model = SemanticModel::from_bytes(yaml).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert!(findings.is_empty(), "an intrinsic policy shape is not statically known: {:?}", findings);
}

#[test]
fn e3001_sam_connectors_accepted_with_transform() {
    let yaml = b"
Transform: AWS::Serverless-2016-10-31
Resources:
  F:
    Type: AWS::Serverless::Function
    Connectors:
      MyConn:
        Properties:
          Destination:
            Id: F
          Permissions:
            - Read
    Properties:
      Runtime: python3.11
      Handler: index.handler
      CodeUri: ./src
";
    let model = SemanticModel::from_bytes(yaml).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert!(findings.is_empty(), "Connectors is valid under SAM transform: {:?}", findings);
}

#[test]
fn e3001_sam_ignore_globals_accepted_with_transform() {
    let yaml = b"
Transform: AWS::Serverless-2016-10-31
Resources:
  F:
    Type: AWS::Serverless::Function
    IgnoreGlobals: true
    Properties:
      Runtime: python3.11
      Handler: index.handler
      CodeUri: ./src
";
    let model = SemanticModel::from_bytes(yaml).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert!(findings.is_empty(), "IgnoreGlobals is valid under SAM transform: {:?}", findings);
}

#[test]
fn e3001_sam_connectors_rejected_without_transform() {
    let yaml = b"
Resources:
  R:
    Type: AWS::S3::Bucket
    Connectors:
      MyConn:
        Properties:
          Destination:
            Id: R
    Properties:
      BucketName: b
";
    let model = SemanticModel::from_bytes(yaml).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert_eq!(findings.len(), 1, "Connectors without SAM transform is invalid: {:?}", findings);
    assert!(findings[0].message.contains("invalid property 'Connectors'"), "message: {}", findings[0].message);
}

#[test]
fn e3001_multiple_violations_per_resource() {
    let input = br#"{"Resources":{"R":{"Properties":{"K":"V"},"Bogus":"x"}}}"#;
    let model = SemanticModel::from_bytes(input).unwrap();
    let findings: Vec<_> = model.diagnostics.iter().filter(|d| d.rule_id == "E3001").collect();
    assert!(findings.len() >= 2, "expected at least 2 E3001 (missing Type + unknown attribute): {:?}", findings);
}
