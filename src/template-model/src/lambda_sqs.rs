use crate::SemanticModel;
use crate::coercion::coerce_to_integer;
use crate::conditions::Satisfiability;
use crate::consts::{FN_TRANSFORM, KEY_PROPERTIES};
use crate::resolver::ResolvedValue;
use std::collections::{BTreeSet, HashMap};

const SQS_DEFAULT_VISIBILITY_TIMEOUT_SECONDS: i64 = 30;
const LAMBDA_DEFAULT_TIMEOUT_SECONDS: i64 = 3;
const SQS_QUEUE_RESOURCE_TYPE: &str = "AWS::SQS::Queue";
const LAMBDA_FUNCTION_RESOURCE_TYPE: &str = "AWS::Lambda::Function";
const LAMBDA_EVENT_SOURCE_MAPPING_RESOURCE_TYPE: &str = "AWS::Lambda::EventSourceMapping";
const VISIBILITY_TIMEOUT_PROPERTY: &str = "VisibilityTimeout";
const FUNCTION_TIMEOUT_PROPERTY: &str = "Timeout";
const TIMEOUT_SUGGESTED_FIX: &str = "Set the SQS VisibilityTimeout to at least the Lambda function Timeout";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SqsEventSourceTimeoutViolation {
    pub queue_id: String,
    pub visibility_timeout: i64,
    pub function_timeout: i64,
    pub message: String,
    pub suggested_fix: String,
}

struct IntegerPropertyScenario {
    value: i64,
    conditions: HashMap<String, bool>,
}

enum ScenarioPropertyValue<'a> {
    Absent,
    Concrete(&'a serde_json::Value),
    Unknown,
}

#[must_use]
pub fn sqs_event_source_timeout_violations(model: &SemanticModel) -> Vec<SqsEventSourceTimeoutViolation> {
    let mut violations = BTreeSet::new();
    for mapping_id in model.resources_of_type(LAMBDA_EVENT_SOURCE_MAPPING_RESOURCE_TYPE) {
        let Some(mapping) = model.resources.get(mapping_id) else {
            continue;
        };
        if mapping.properties_dynamic || mapping.properties.contains_key(FN_TRANSFORM) {
            continue;
        }
        let (Some(queue_id), Some(function_id)) = (
            model.follow_ref(mapping_id, "Properties.EventSourceArn"),
            model.follow_ref(mapping_id, "Properties.FunctionName"),
        ) else {
            continue;
        };
        let (Some(queue), Some(function)) = (model.resources.get(queue_id), model.resources.get(function_id)) else {
            continue;
        };
        if queue.resource_type != SQS_QUEUE_RESOURCE_TYPE || function.resource_type != LAMBDA_FUNCTION_RESOURCE_TYPE {
            continue;
        }

        let visibility_scenarios = integer_property_scenarios_with_default(
            model,
            queue_id,
            VISIBILITY_TIMEOUT_PROPERTY,
            SQS_DEFAULT_VISIBILITY_TIMEOUT_SECONDS,
        );
        let timeout_scenarios = integer_property_scenarios_with_default(
            model,
            function_id,
            FUNCTION_TIMEOUT_PROPERTY,
            LAMBDA_DEFAULT_TIMEOUT_SECONDS,
        );
        for visibility in &visibility_scenarios {
            for timeout in &timeout_scenarios {
                if visibility.value < timeout.value
                    && scenarios_are_jointly_reachable(
                        model,
                        &[mapping_id, queue_id, function_id],
                        &[&visibility.conditions, &timeout.conditions],
                    )
                {
                    violations.insert(SqsEventSourceTimeoutViolation {
                        queue_id: queue_id.to_string(),
                        visibility_timeout: visibility.value,
                        function_timeout: timeout.value,
                        message: format!(
                            "Queue visibility timeout ({}) is less than Function timeout ({}) seconds",
                            visibility.value, timeout.value
                        ),
                        suggested_fix: TIMEOUT_SUGGESTED_FIX.to_string(),
                    });
                }
            }
        }
    }
    violations.into_iter().collect()
}

fn integer_property_scenarios_with_default(
    model: &SemanticModel,
    resource_id: &str,
    property_name: &str,
    service_default: i64,
) -> Vec<IntegerPropertyScenario> {
    let property_path = format!("{KEY_PROPERTIES}.{property_name}");
    let mut scenarios: Vec<IntegerPropertyScenario> = model
        .resolve_properties_scenarios_projected(resource_id, &[property_name, FN_TRANSFORM])
        .iter()
        .filter_map(|(properties, conditions)| {
            if model.scenario_uses_unresolved_parameter(resource_id, &property_path, conditions) {
                return None;
            }
            let value = match scenario_property_value(properties, property_name) {
                ScenarioPropertyValue::Absent => service_default,
                ScenarioPropertyValue::Concrete(value) => coerce_to_integer(value)?,
                ScenarioPropertyValue::Unknown => return None,
            };
            Some(IntegerPropertyScenario { value, conditions: conditions.clone() })
        })
        .collect();
    scenarios.sort_by_key(|scenario| (scenario.value, canonical_condition_assignment(&scenario.conditions)));
    scenarios.dedup_by(|left, right| left.value == right.value && left.conditions == right.conditions);
    scenarios
}

fn scenario_property_value<'a>(properties: &'a ResolvedValue, property_name: &str) -> ScenarioPropertyValue<'a> {
    match properties {
        ResolvedValue::Map { entries } => {
            if entries.iter().any(|entry| entry.key == FN_TRANSFORM) {
                return ScenarioPropertyValue::Unknown;
            }
            match entries.iter().find(|entry| entry.key == property_name).map(|entry| &entry.value) {
                None => ScenarioPropertyValue::Absent,
                Some(ResolvedValue::Concrete { value }) if value.is_null() => ScenarioPropertyValue::Absent,
                Some(ResolvedValue::Concrete { value }) => ScenarioPropertyValue::Concrete(value),
                Some(_) => ScenarioPropertyValue::Unknown,
            }
        }
        ResolvedValue::Concrete { value } => {
            if value.is_null() {
                return ScenarioPropertyValue::Absent;
            }
            let Some(properties) = value.as_object() else {
                return ScenarioPropertyValue::Unknown;
            };
            if properties.contains_key(FN_TRANSFORM) {
                return ScenarioPropertyValue::Unknown;
            }
            match properties.get(property_name) {
                None | Some(serde_json::Value::Null) => ScenarioPropertyValue::Absent,
                Some(value) => ScenarioPropertyValue::Concrete(value),
            }
        }
        _ => ScenarioPropertyValue::Unknown,
    }
}

fn scenarios_are_jointly_reachable(
    model: &SemanticModel,
    resource_ids: &[&str],
    scenario_conditions: &[&HashMap<String, bool>],
) -> bool {
    let scenario_literals = scenario_conditions
        .iter()
        .flat_map(|conditions| conditions.iter().map(|(condition, value)| (condition.clone(), *value)));
    let resource_literals = resource_ids.iter().filter_map(|resource_id| {
        model
            .resources
            .get(*resource_id)
            .and_then(|resource| resource.condition.clone())
            .map(|condition| (condition, true))
    });
    let mut combined = HashMap::new();
    for (condition, value) in scenario_literals.chain(resource_literals) {
        if combined.insert(condition, value).is_some_and(|previous| previous != value) {
            return false;
        }
    }
    let assumptions: Vec<(String, bool)> = combined.into_iter().collect();
    assumptions.is_empty() || model.conditions.satisfiability(&assumptions) == Satisfiability::Satisfiable
}

fn canonical_condition_assignment(conditions: &HashMap<String, bool>) -> Vec<(String, bool)> {
    let mut assignment: Vec<(String, bool)> =
        conditions.iter().map(|(condition, value)| (condition.clone(), *value)).collect();
    assignment.sort_unstable();
    assignment
}

#[cfg(test)]
mod tests {
    use super::*;

    fn violations(template: &str) -> Vec<SqsEventSourceTimeoutViolation> {
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        sqs_event_source_timeout_violations(&model)
    }

    #[test]
    fn macro_owned_branch_is_skipped_without_hiding_concrete_sibling_branch() {
        let findings = violations(
            r#"
Parameters:
  Stage:
    Type: String
Conditions:
  IsProduction: !Equals [!Ref Stage, production]
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties: !If
      - IsProduction
      - DelaySeconds: 0
        Fn::Transform:
          Name: AWS::Include
          Parameters:
            Location: s3://example-bucket/queue-properties.yaml
      - VisibilityTimeout: 10
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Timeout: 60
  Mapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref Function
      EventSourceArn: !GetAtt Queue.Arn
"#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].queue_id, "Queue");
        assert_eq!(findings[0].visibility_timeout, 10);
        assert_eq!(findings[0].function_timeout, 60);
    }

    #[test]
    fn no_value_branch_uses_service_default() {
        let findings = violations(
            r#"
Parameters:
  Stage:
    Type: String
Conditions:
  IsProduction: !Equals [!Ref Stage, production]
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: 1
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Timeout: !If [IsProduction, 60, !Ref AWS::NoValue]
  Mapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref Function
      EventSourceArn: !GetAtt Queue.Arn
"#,
        );
        assert_eq!(findings.len(), 2, "both the explicit and default function timeouts violate the queue timeout");
        assert!(findings.iter().any(|finding| finding.function_timeout == 3));
        assert!(findings.iter().any(|finding| finding.function_timeout == 60));
    }

    #[test]
    fn unresolved_parameter_default_is_not_a_fixed_deployment_value() {
        let findings = violations(
            r#"
Parameters:
  FunctionTimeout:
    Type: Number
    Default: 60
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: 20
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Timeout: !Ref FunctionTimeout
  Mapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref Function
      EventSourceArn: !GetAtt Queue.Arn
"#,
        );
        assert!(findings.is_empty(), "a caller can override the parameter before deployment");
    }

    #[test]
    fn indeterminate_condition_reachability_does_not_produce_a_violation() {
        let template = r#"
Parameters:
  P1: {Type: String}
  P2: {Type: String}
  P3: {Type: String}
  P4: {Type: String}
  P5: {Type: String}
  P6: {Type: String}
  P7: {Type: String}
  P8: {Type: String}
  P9: {Type: String}
  P10: {Type: String}
  P11: {Type: String}
  P12: {Type: String}
  P13: {Type: String}
  P14: {Type: String}
  P15: {Type: String}
  P16: {Type: String}
  P17: {Type: String}
  P18: {Type: String}
  P19: {Type: String}
  P20: {Type: String}
  P21: {Type: String}
Conditions:
  FirstGroup: !And
    - !Equals [!Ref P2, x]
    - !Equals [!Ref P3, x]
    - !Equals [!Ref P4, x]
    - !Equals [!Ref P5, x]
    - !Equals [!Ref P6, x]
    - !Equals [!Ref P7, x]
    - !Equals [!Ref P8, x]
    - !Equals [!Ref P9, x]
    - !Equals [!Ref P10, x]
    - !Equals [!Ref P11, x]
  SecondGroup: !And
    - !Equals [!Ref P12, x]
    - !Equals [!Ref P13, x]
    - !Equals [!Ref P14, x]
    - !Equals [!Ref P15, x]
    - !Equals [!Ref P16, x]
    - !Equals [!Ref P17, x]
    - !Equals [!Ref P18, x]
    - !Equals [!Ref P19, x]
    - !Equals [!Ref P20, x]
    - !Equals [!Ref P21, x]
  Big: !And
    - !Condition FirstGroup
    - !Condition SecondGroup
    - !Equals [!Ref P1, a]
  NotBig: !Not [!Condition Big]
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: !If [Big, 10, 900]
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Timeout: !If [NotBig, 60, 5]
  Mapping:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      FunctionName: !Ref Function
      EventSourceArn: !GetAtt Queue.Arn
"#;
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        let findings = sqs_event_source_timeout_violations(&model);
        assert!(
            !model.conditions.budget_exhausted_queries().is_empty(),
            "the template must exercise indeterminate satisfiability"
        );
        assert!(findings.is_empty(), "an unproven scenario must not produce an error: {findings:?}");
    }
}
