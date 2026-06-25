use template_model::SemanticModel;

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
        Some(template_model::resolver::ResolvedValue::Enum { variants: _ }) => {}
        other => panic!("BucketShort.BucketName: expected Enum from Sub, got {:?}", other),
    }

    let bucket_long = model.resource("BucketLong").unwrap();
    match bucket_long.properties.get("BucketName") {
        Some(template_model::resolver::ResolvedValue::Enum { variants: _ }) => {}
        other => panic!("BucketLong.BucketName: expected Enum from Sub, got {:?}", other),
    }

    let with_getatt = model.resource("WithGetAtt").unwrap();
    match with_getatt.properties.get("ShortForm") {
        Some(template_model::resolver::ResolvedValue::Reference { target: t, .. }) => {
            assert_eq!(t, "BucketShort")
        }
        other => panic!("WithGetAtt.ShortForm: expected Reference, got {:?}", other),
    }
    match with_getatt.properties.get("LongFormDotted") {
        Some(template_model::resolver::ResolvedValue::Reference { target: t, .. }) => {
            assert_eq!(t, "BucketShort")
        }
        other => panic!("WithGetAtt.LongFormDotted: expected Reference, got {:?}", other),
    }
    match with_getatt.properties.get("LongFormArray") {
        Some(template_model::resolver::ResolvedValue::Reference { target: t, .. }) => {
            assert_eq!(t, "BucketLong")
        }
        other => panic!("WithGetAtt.LongFormArray: expected Reference, got {:?}", other),
    }

    let with_join = model.resource("WithJoin").unwrap();
    match with_join.properties.get("Short") {
        Some(template_model::resolver::ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "a-b-c");
        }
        other => panic!("WithJoin.Short: expected Concrete 'a-b-c', got {:?}", other),
    }
    match with_join.properties.get("Long") {
        Some(template_model::resolver::ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "x-y-z");
        }
        other => panic!("WithJoin.Long: expected Concrete 'x-y-z', got {:?}", other),
    }

    let with_select = model.resource("WithSelect").unwrap();
    match with_select.properties.get("Short") {
        Some(template_model::resolver::ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "a")
        }
        other => panic!("WithSelect.Short: expected Concrete 'a', got {:?}", other),
    }
    match with_select.properties.get("Long") {
        Some(template_model::resolver::ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "b")
        }
        other => panic!("WithSelect.Long: expected Concrete 'b', got {:?}", other),
    }

    let with_if = model.resource("WithIf").unwrap();
    assert!(
        matches!(with_if.properties.get("Short"), Some(template_model::resolver::ResolvedValue::Conditional { condition: c, .. }) if c == "IsProd")
    );
    assert!(
        matches!(with_if.properties.get("Long"), Some(template_model::resolver::ResolvedValue::Conditional { condition: c, .. }) if c == "IsProd")
    );

    let with_b64 = model.resource("WithBase64").unwrap();
    match with_b64.properties.get("Short") {
        Some(template_model::resolver::ResolvedValue::Concrete { value: v }) => {
            assert_eq!(v.as_str().unwrap(), "aGVsbG8=")
        }
        other => panic!("WithBase64.Short: expected Concrete base64, got {:?}", other),
    }

    let sub_block = model.resource("SubBlock").unwrap();
    match sub_block.properties.get("UserData") {
        Some(template_model::resolver::ResolvedValue::Enum { variants: _ }) => {}
        other => panic!("SubBlock.UserData: expected Enum from Sub, got {:?}", other),
    }

    assert!(model.conditions.conditions.contains_key("IsProd"));
    assert!(model.conditions.conditions.contains_key("IsProdShort"));
    assert!(model.conditions.conditions.contains_key("Combined"));

    assert!(model.mappings.contains_key("MyMap"));

    assert_eq!(model.outputs.len(), 1);
}

// ── Parser: JSON/YAML auto-detection and edge cases ─────────────────────

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
fn parser_fn_if_undefined_condition_produces_f1104() {
    let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::If":["NonExistent",1,2]}}}}}"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    assert!(model.diagnostics.iter().any(|d| d.rule_id == "F1104" && d.message.contains("NonExistent")));
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

// ── SAM: globals merging, implicit resources ────────────────────────────

#[test]
fn sam_globals_merged_into_function() {
    let model = model_from_fixture("good/transform_serverless_globals.yaml");
    let func = model.resource("myFunction").unwrap();
    // Globals.Function.Runtime should be merged into the function
    assert!(model.sam_globals.contains_key("Function"));
    assert!(model.sam_globals["Function"].contains_key("Runtime"));
    // The function should have the Runtime property from globals
    assert!(func.properties.contains_key("Runtime"));
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

// ── Dynamic references ({{resolve:...}}) ────────────────────────────────

#[test]
fn dynamic_reference_resolves_to_dynamic() {
    let input = r#"{"Resources":{"R":{"Type":"T","Properties":{"V":"{{resolve:ssm:my-param}}"}}}}"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    match model.resolve("R", "Properties.V") {
        Some(template_model::resolver::ResolvedValue::Dynamic { reason: msg }) => {
            assert!(msg.contains("dynamic reference"));
        }
        other => panic!("Expected Dynamic, got {:?}", other),
    }
}

// ── Sub with GetAtt (implicit in ${Resource.Attr}) ──────────────────────

#[test]
fn sub_with_implicit_getatt() {
    let input =
        r#"{"Resources":{"R":{"Type":"T","Properties":{"V":{"Fn::Sub":"arn:${Other.Arn}"}}},"Other":{"Type":"T2"}}}"#;
    let model = SemanticModel::from_bytes(input.as_bytes()).unwrap();
    // Should produce a Dynamic (can't fully resolve GetAtt) but should record the edge
    assert!(model.graph.depends_on("R", "Other"));
}

// ── Condition stack edges ───────────────────────────────────────────────

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

// ── resolve_scenarios with nested conditionals ──────────────────────────

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

// ── source_location / SpanProvider ──────────────────────────────────────

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
    use diagnostics::SpanProvider;
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

// ── Rules-section ref edges ─────────────────────────────────────────────

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
