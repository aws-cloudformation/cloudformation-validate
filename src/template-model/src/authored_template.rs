//! Renders the parsed template back into the JSON CloudFormation itself accepts,
//! with every intrinsic function in its long form (`{"Ref": ...}`,
//! `{"Fn::GetAtt": [...]}`). Consumers that evaluate the template as the author
//! wrote it - rather than the resolved model - read this view; the CloudFormation
//! Guard evaluator is one such consumer, and it normalizes YAML short tags to the
//! same long form, so both see identical structures.

use crate::consts::{CONDITION_REF_PREFIX, KEY_DEFAULT_VALUE, KEY_NAME, SECTION_PARAMETERS};
use crate::ir::{Arena, IntrinsicFn, NULL_REF, Node, NodeRef, cfn_function_name};
use serde_json::{Map, Value, json};

pub(crate) fn render_authored_json(arena: &Arena, node_ref: NodeRef) -> Value {
    if node_ref == NULL_REF {
        return Value::Null;
    }
    match arena.node(node_ref) {
        Node::Null => Value::Null,
        Node::Bool(flag) => Value::Bool(*flag),
        Node::Int(number) => json!(*number),
        Node::Float(number) => json!(*number),
        Node::String(text) => Value::String(text.clone()),
        Node::List(items) => Value::Array(items.iter().map(|item| render_authored_json(arena, *item)).collect()),
        Node::Map(entries) => Value::Object(render_entries(arena, entries)),
        Node::Intrinsic(intrinsic) => {
            let mut wrapper = Map::with_capacity(1);
            wrapper.insert(cfn_function_name(intrinsic).to_string(), render_intrinsic_argument(arena, intrinsic));
            Value::Object(wrapper)
        }
    }
}

fn render_entries(arena: &Arena, entries: &[(String, NodeRef)]) -> Map<String, Value> {
    entries.iter().map(|(key, value)| (key.clone(), render_authored_json(arena, *value))).collect()
}

fn render_list(arena: &Arena, items: &[NodeRef]) -> Value {
    Value::Array(items.iter().map(|item| render_authored_json(arena, *item)).collect())
}

/// The argument of an intrinsic in the shape CloudFormation documents for it. A
/// `Condition` reference is stored as a prefixed `Ref`, so the prefix is removed to
/// restore the authored condition name.
fn render_intrinsic_argument(arena: &Arena, intrinsic: &IntrinsicFn) -> Value {
    match intrinsic {
        IntrinsicFn::Ref(name) => Value::String(name.strip_prefix(CONDITION_REF_PREFIX).unwrap_or(name).to_string()),
        IntrinsicFn::RefAll(name) => Value::String(name.clone()),
        IntrinsicFn::GetAtt(resource, attribute) => json!([resource, attribute]),
        IntrinsicFn::ValueOf(first, second) | IntrinsicFn::ValueOfAll(first, second) => json!([first, second]),
        IntrinsicFn::Sub(template, None) => Value::String(template.clone()),
        IntrinsicFn::Sub(template, Some(variables)) => {
            json!([template, Value::Object(render_entries(arena, variables))])
        }
        IntrinsicFn::Join(first, second)
        | IntrinsicFn::Select(first, second)
        | IntrinsicFn::Split(first, second)
        | IntrinsicFn::Equals(first, second)
        | IntrinsicFn::Contains(first, second)
        | IntrinsicFn::EachMemberEquals(first, second)
        | IntrinsicFn::EachMemberIn(first, second) => render_list(arena, &[*first, *second]),
        IntrinsicFn::If(condition, if_true, if_false) => {
            json!([condition, render_authored_json(arena, *if_true), render_authored_json(arena, *if_false)])
        }
        IntrinsicFn::IfExpr(condition, if_true, if_false) => render_list(arena, &[*condition, *if_true, *if_false]),
        IntrinsicFn::Cidr(first, second, third) => render_list(arena, &[*first, *second, *third]),
        IntrinsicFn::FindInMap(map_name, top_key, second_key, None) => {
            render_list(arena, &[*map_name, *top_key, *second_key])
        }
        IntrinsicFn::FindInMap(map_name, top_key, second_key, Some(default_value)) => {
            let mut default_wrapper = Map::with_capacity(1);
            default_wrapper.insert(KEY_DEFAULT_VALUE.to_string(), render_authored_json(arena, *default_value));
            json!([
                render_authored_json(arena, *map_name),
                render_authored_json(arena, *top_key),
                render_authored_json(arena, *second_key),
                Value::Object(default_wrapper),
            ])
        }
        IntrinsicFn::Base64(argument)
        | IntrinsicFn::GetAZs(argument)
        | IntrinsicFn::ImportValue(argument)
        | IntrinsicFn::ToJsonString(argument)
        | IntrinsicFn::Length(argument) => render_authored_json(arena, *argument),
        IntrinsicFn::Not(argument) => render_list(arena, &[*argument]),
        IntrinsicFn::And(operands) | IntrinsicFn::Or(operands) => render_list(arena, operands),
        IntrinsicFn::GetStackOutput(arguments) => Value::Object(render_entries(arena, arguments)),
        IntrinsicFn::Transform(name, parameters) => {
            let mut transform = Map::with_capacity(2);
            transform.insert(KEY_NAME.to_string(), Value::String(name.clone()));
            transform.insert(SECTION_PARAMETERS.to_string(), Value::Object(render_entries(arena, parameters)));
            Value::Object(transform)
        }
        IntrinsicFn::ForEach(loop_name, identifier, collection, body) => {
            json!(
                [loop_name, identifier, render_authored_json(arena, *collection), render_authored_json(arena, *body),]
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::model::SemanticModel;
    use serde_json::{Value, json};

    fn authored(yaml: &str) -> Value {
        SemanticModel::from_bytes(yaml.as_bytes()).expect("template must parse").authored_template_json().clone()
    }

    #[test]
    fn plain_values_round_trip_with_sections_and_scalars_intact() {
        let template = authored(
            r#"
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  Env:
    Type: String
    Default: dev
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Properties:
      BucketName: my-bucket
      Tags:
        - Key: Owner
          Value: team
      Versioned: true
      Retention: 30
      Ratio: 0.5
      Nothing: null
"#,
        );
        assert_eq!(template["AWSTemplateFormatVersion"], json!("2010-09-09"));
        assert_eq!(template["Parameters"]["Env"], json!({"Type": "String", "Default": "dev"}));
        let bucket = &template["Resources"]["Bucket"];
        assert_eq!(bucket["Type"], json!("AWS::S3::Bucket"));
        assert_eq!(bucket["DeletionPolicy"], json!("Retain"));
        assert_eq!(bucket["Properties"]["Tags"], json!([{"Key": "Owner", "Value": "team"}]));
        assert_eq!(bucket["Properties"]["Versioned"], json!(true));
        assert_eq!(bucket["Properties"]["Retention"], json!(30));
        assert_eq!(bucket["Properties"]["Ratio"], json!(0.5));
        assert_eq!(bucket["Properties"]["Nothing"], Value::Null);
    }

    #[test]
    fn short_form_intrinsics_render_in_long_form() {
        let template = authored(
            r#"
Parameters:
  Name:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Name, prod]
Resources:
  Role:
    Type: AWS::IAM::Role
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref Name
      RoleArn: !GetAtt Role.Arn
      Joined: !Join ["-", [a, !Ref Name]]
      Subbed: !Sub "${AWS::StackName}-${Name}"
      SubMap: !Sub ["${Prefix}-x", {Prefix: !Ref Name}]
      Picked: !If [IsProd, prod-bucket, !Ref AWS::NoValue]
      Mapped: !FindInMap [Regions, !Ref AWS::Region, Ami]
      Encoded: !Base64 hello
      Imported: !ImportValue shared-vpc
      Selected: !Select [0, !GetAZs ""]
      Pieces: !Split [",", "a,b"]
      Range: !Cidr ["10.0.0.0/16", 6, 8]
"#,
        );
        let properties = &template["Resources"]["Bucket"]["Properties"];
        assert_eq!(properties["BucketName"], json!({"Ref": "Name"}));
        assert_eq!(properties["RoleArn"], json!({"Fn::GetAtt": ["Role", "Arn"]}));
        assert_eq!(properties["Joined"], json!({"Fn::Join": ["-", ["a", {"Ref": "Name"}]]}));
        assert_eq!(properties["Subbed"], json!({"Fn::Sub": "${AWS::StackName}-${Name}"}));
        assert_eq!(properties["SubMap"], json!({"Fn::Sub": ["${Prefix}-x", {"Prefix": {"Ref": "Name"}}]}));
        assert_eq!(properties["Picked"], json!({"Fn::If": ["IsProd", "prod-bucket", {"Ref": "AWS::NoValue"}]}));
        assert_eq!(properties["Mapped"], json!({"Fn::FindInMap": ["Regions", {"Ref": "AWS::Region"}, "Ami"]}));
        assert_eq!(properties["Encoded"], json!({"Fn::Base64": "hello"}));
        assert_eq!(properties["Imported"], json!({"Fn::ImportValue": "shared-vpc"}));
        assert_eq!(properties["Selected"], json!({"Fn::Select": [0, {"Fn::GetAZs": ""}]}));
        assert_eq!(properties["Pieces"], json!({"Fn::Split": [",", "a,b"]}));
        assert_eq!(properties["Range"], json!({"Fn::Cidr": ["10.0.0.0/16", 6, 8]}));
        assert_eq!(template["Conditions"]["IsProd"], json!({"Fn::Equals": [{"Ref": "Name"}, "prod"]}));
    }

    #[test]
    fn condition_functions_and_condition_references_render_with_their_documented_keys() {
        let template = authored(
            r#"
Parameters:
  Env:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Env, prod]
  IsLarge: !Equals [!Ref Env, large]
  Either: !Or [!Condition IsProd, !Condition IsLarge]
  Neither: !Not [!Condition Either]
  Both: !And [!Condition IsProd, !Condition IsLarge]
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Condition: Either
"#,
        );
        let conditions = &template["Conditions"];
        assert_eq!(conditions["Either"], json!({"Fn::Or": [{"Condition": "IsProd"}, {"Condition": "IsLarge"}]}));
        assert_eq!(conditions["Neither"], json!({"Fn::Not": [{"Condition": "Either"}]}));
        assert_eq!(conditions["Both"], json!({"Fn::And": [{"Condition": "IsProd"}, {"Condition": "IsLarge"}]}));
        assert_eq!(template["Resources"]["Bucket"]["Condition"], json!("Either"));
    }

    #[test]
    fn find_in_map_default_and_transform_keep_their_object_arguments() {
        let template = authored(
            r#"
Mappings:
  Regions:
    us-east-1:
      Ami: ami-1
Resources:
  Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: !FindInMap [Regions, us-west-2, Ami, {DefaultValue: ami-default}]
      UserData:
        Fn::Transform:
          Name: AWS::Include
          Parameters:
            Location: s3://bucket/snippet.yaml
"#,
        );
        let properties = &template["Resources"]["Instance"]["Properties"];
        assert_eq!(
            properties["ImageId"],
            json!({"Fn::FindInMap": ["Regions", "us-west-2", "Ami", {"DefaultValue": "ami-default"}]})
        );
        assert_eq!(
            properties["UserData"],
            json!({"Fn::Transform": {"Name": "AWS::Include", "Parameters": {"Location": "s3://bucket/snippet.yaml"}}})
        );
    }

    #[test]
    fn rendering_is_computed_once_and_shared() {
        let model = SemanticModel::from_bytes(b"Resources:\n  B:\n    Type: AWS::S3::Bucket\n").expect("parses");
        let first: *const Value = model.authored_template_json();
        let second: *const Value = model.authored_template_json();
        assert!(std::ptr::eq(first, second), "repeated calls must return the same cached rendering");
    }
}
