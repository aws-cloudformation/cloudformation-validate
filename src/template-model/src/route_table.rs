//! Duplicate subnet/route-table association detection.
//!
//! EC2 allows exactly one route table per subnet, so two
//! `AWS::EC2::SubnetRouteTableAssociation` resources naming the same subnet
//! fail at deploy time. A subnet's identity here is the complete authored or
//! resolved value: identical expressions prove one subnet, while expressions
//! that merely share a component reference do not, evaluated through `Fn::If`
//! branches.
//!
//! Two associations clash only when their combined resource-level and
//! property-level condition assumptions are co-satisfiable — if no parameter
//! assignment can make both branches simultaneously true, they are mutually
//! exclusive and cannot conflict at deploy time.

use crate::conditions::Satisfiability;
use crate::model::SemanticModel;
use crate::resolver::ResolvedValue;

/// A clash finding anchored at `Properties.SubnetId`.
#[derive(Debug, Clone)]
pub struct AssociationFinding {
    pub resource_id: String,
    pub message: String,
}

const ASSOCIATION_TYPE: &str = "AWS::EC2::SubnetRouteTableAssociation";

/// Resource condition, property condition, and authored subnet identity.
type ValueKey = (Option<String>, Option<String>, String);

/// Parses a comma-separated condition string (e.g. `"IsProd,!UseVPC"`) into
/// the assumption pairs the satisfiability solver expects.
fn parse_assumptions(conditions: &str) -> Vec<(String, bool)> {
    conditions
        .split(',')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if let Some(negated) = segment.strip_prefix('!') {
                (negated.to_string(), false)
            } else {
                (segment.to_string(), true)
            }
        })
        .collect()
}

/// Builds the full assumption list from a resource condition and a property
/// condition string (both optional).
fn build_assumptions(resource_condition: Option<&str>, property_condition: Option<&str>) -> Vec<(String, bool)> {
    let mut assumptions = Vec::new();
    if let Some(condition) = resource_condition {
        assumptions.push((condition.to_string(), true));
    }
    if let Some(property_cond) = property_condition {
        assumptions.extend(parse_assumptions(property_cond));
    }
    assumptions
}

/// Checks whether the combined assumptions from two value keys can be
/// simultaneously satisfied. Empty assumptions on one side still require the
/// other side to be satisfiable.
fn are_co_satisfiable(model: &SemanticModel, left: &ValueKey, right: &ValueKey) -> bool {
    let mut combined = build_assumptions(left.0.as_deref(), left.1.as_deref());
    combined.extend(build_assumptions(right.0.as_deref(), right.1.as_deref()));
    matches!(model.conditions.satisfiability(&combined), Satisfiability::Satisfiable)
}

pub fn duplicate_subnet_associations(model: &SemanticModel) -> Vec<AssociationFinding> {
    let mut names: Vec<&String> = model
        .resources
        .iter()
        .filter(|(_, resource)| resource.resource_type == ASSOCIATION_TYPE)
        .map(|(name, _)| name)
        .collect();
    names.sort_by_key(|name| {
        model
            .source_location(&format!("Resources/{}", name))
            .map(|span| (span.start_line, span.start_column))
            .unwrap_or((u32::MAX, u32::MAX))
    });

    let mut per_resource: Vec<(&String, Vec<ValueKey>)> = Vec::new();
    for name in &names {
        let resource = &model.resources[*name];
        let mut values = Vec::new();
        if let Some(subnet) = resource.properties.get("SubnetId") {
            collect_subnet_values(
                model,
                name,
                subnet,
                resource.condition.as_deref(),
                None,
                "Properties.SubnetId",
                &mut values,
            );
        }
        per_resource.push((name, values));
    }

    let mut findings = Vec::new();
    for (idx, (name, values)) in per_resource.iter().enumerate() {
        let resource = &model.resources[*name];
        for value in values {
            let mut others: Vec<&String> = Vec::new();
            for (other_idx, (other_name, other_values)) in per_resource.iter().enumerate() {
                if other_idx == idx {
                    continue;
                }
                for other_value in other_values {
                    if value.2 != other_value.2 {
                        continue;
                    }
                    // Preserve one-sided unconditional behavior: when this
                    // resource is unconditional and the other is conditioned,
                    // only the conditioned resource should report the clash
                    // (it is the one that would fail when its condition is
                    // true alongside the always-present unconditional one).
                    let this_is_unconditional = resource.condition.is_none() && value.1.is_none();
                    let other_resource = &model.resources[*other_name];
                    let other_is_conditioned = other_resource.condition.is_some() || other_value.1.is_some();
                    if this_is_unconditional && other_is_conditioned {
                        continue;
                    }
                    if are_co_satisfiable(model, value, other_value) {
                        others.push(other_name);
                        break;
                    }
                }
            }
            others.sort_by_key(|other| names.iter().position(|n| n == other));
            others.dedup();
            if !others.is_empty() {
                findings.push(AssociationFinding {
                    resource_id: (*name).clone(),
                    message: format!(
                        "SubnetId in {} is also associated with {}",
                        name,
                        others.iter().map(|other| other.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                });
            }
        }
    }
    findings
}

fn collect_subnet_values(
    model: &SemanticModel,
    resource_id: &str,
    value: &ResolvedValue,
    resource_condition: Option<&str>,
    property_condition: Option<&str>,
    path: &str,
    out: &mut Vec<ValueKey>,
) {
    match value {
        ResolvedValue::Conditional { condition, if_true, if_false } => {
            let true_condition = append_condition(property_condition, condition, true);
            let false_condition = append_condition(property_condition, condition, false);
            collect_subnet_values(
                model,
                resource_id,
                if_true,
                resource_condition,
                Some(&true_condition),
                &format!("{}.Fn::If.1", path),
                out,
            );
            collect_subnet_values(
                model,
                resource_id,
                if_false,
                resource_condition,
                Some(&false_condition),
                &format!("{}.Fn::If.2", path),
                out,
            );
        }
        ResolvedValue::Concrete { value } if value.as_str().is_none() => {}
        ResolvedValue::List { .. } | ResolvedValue::Map { .. } => {}
        ResolvedValue::Dynamic { .. } if !model.is_from_intrinsic(resource_id, path) => {}
        _ => {
            if let Some(identity) = model.resolved_value_identity(resource_id, path, value) {
                let key = (resource_condition.map(String::from), property_condition.map(String::from), identity);
                if !out.contains(&key) {
                    out.push(key);
                }
            }
        }
    }
}

fn append_condition(parent: Option<&str>, condition: &str, value: bool) -> String {
    let assumption = if value { condition.to_string() } else { format!("!{}", condition) };
    parent.map_or(assumption.clone(), |parent| format!("{},{}", parent, assumption))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(template: &str) -> Vec<(String, String)> {
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        duplicate_subnet_associations(&model)
            .into_iter()
            .map(|finding| (finding.resource_id, finding.message))
            .collect()
    }

    #[test]
    fn distinct_ref_targets_are_clean() {
        let template = "Parameters:\n  A:\n    Type: String\n  B:\n    Type: String\nResources:\n  One:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-1\n      SubnetId: !Ref A\n  Two:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-1\n      SubnetId: !Ref B\n";
        assert!(findings(template).is_empty());
    }

    #[test]
    fn distinct_ref_targets_with_equal_defaults_are_clean() {
        let template = "Parameters:\n  A:\n    Type: String\n    Default: subnet-1\n  B:\n    Type: String\n    Default: subnet-1\nResources:\n  One:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-1\n      SubnetId: !Ref A\n  Two:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-2\n      SubnetId: !Ref B\n";
        assert!(findings(template).is_empty());
    }

    #[test]
    fn distinct_compound_substitutions_sharing_a_component_are_clean() {
        let template = r#"
Parameters:
  Prefix:
    Type: String
    Default: subnet-
    AllowedValues: [subnet-]
  SuffixA:
    Type: String
    Default: aaaaaaaaaaaaaaaaa
    AllowedValues: [aaaaaaaaaaaaaaaaa]
  SuffixB:
    Type: String
    Default: bbbbbbbbbbbbbbbbb
    AllowedValues: [bbbbbbbbbbbbbbbbb]
Resources:
  One:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      RouteTableId: rt-1
      SubnetId: !Sub '${Prefix}${SuffixA}'
  Two:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      RouteTableId: rt-2
      SubnetId: !Sub '${Prefix}${SuffixB}'
"#;
        assert!(findings(template).is_empty());
    }

    #[test]
    fn identical_compound_substitutions_report_both_associations() {
        let template = r#"
Parameters:
  Prefix:
    Type: String
  Suffix:
    Type: String
Resources:
  One:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      RouteTableId: rt-1
      SubnetId: !Sub '${Prefix}${Suffix}'
  Two:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      RouteTableId: rt-2
      SubnetId: !Sub '${Prefix}${Suffix}'
"#;
        assert_eq!(
            findings(template),
            [
                ("One".to_string(), "SubnetId in One is also associated with Two".to_string()),
                ("Two".to_string(), "SubnetId in Two is also associated with One".to_string()),
            ]
        );
    }

    #[test]
    fn same_ref_target_reports_both_associations() {
        let template = "Parameters:\n  A:\n    Type: String\nResources:\n  One:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-1\n      SubnetId: !Ref A\n  Two:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-2\n      SubnetId: !Ref A\n";
        assert_eq!(
            findings(template),
            [
                ("One".to_string(), "SubnetId in One is also associated with Two".to_string()),
                ("Two".to_string(), "SubnetId in Two is also associated with One".to_string()),
            ]
        );
    }

    #[test]
    fn impossible_condition_does_not_clash_with_unconditioned_association() {
        let template = r#"
Parameters:
  Subnet:
    Type: String
Conditions:
  Never: !Equals [always, never]
Resources:
  Plain:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      RouteTableId: rt-1
      SubnetId: !Ref Subnet
  Impossible:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Condition: Never
    Properties:
      RouteTableId: rt-2
      SubnetId: !Ref Subnet
"#;
        assert!(findings(template).is_empty());
    }

    #[test]
    fn opposite_ref_branches_are_clean() {
        let template = "Parameters:\n  A:\n    Type: String\n  B:\n    Type: String\n  Env:\n    Type: String\nConditions:\n  IsProd: !Equals [!Ref Env, prod]\nResources:\n  One:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-1\n      SubnetId: !If [IsProd, !Ref A, !Ref B]\n  Two:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-2\n      SubnetId: !If [IsProd, !Ref B, !Ref A]\n";
        assert!(findings(template).is_empty());
    }

    #[test]
    fn opposite_literal_branches_are_clean() {
        let template = "Parameters:\n  Env:\n    Type: String\nConditions:\n  IsProd: !Equals [!Ref Env, prod]\nResources:\n  One:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-1\n      SubnetId: !If [IsProd, subnet-1, subnet-2]\n  Two:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-2\n      SubnetId: !If [IsProd, subnet-2, subnet-1]\n";
        assert!(findings(template).is_empty());
    }

    #[test]
    fn conditioned_association_clashes_with_unconditioned_association() {
        let template = "Parameters:\n  A:\n    Type: String\n  Env:\n    Type: String\nConditions:\n  IsProd: !Equals [!Ref Env, prod]\nResources:\n  Plain:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-1\n      SubnetId: !Ref A\n  Gated:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Condition: IsProd\n    Properties:\n      RouteTableId: rt-2\n      SubnetId: !Ref A\n";
        assert_eq!(
            findings(template),
            [("Gated".to_string(), "SubnetId in Gated is also associated with Plain".to_string())]
        );
    }

    /// Two resources with mutually exclusive resource-level conditions and
    /// the same subnet identity cannot coexist at deploy time.
    #[test]
    fn mutually_exclusive_resource_conditions_are_clean() {
        let template = r#"
Parameters:
  Env:
    Type: String
  Subnet:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Env, prod]
  IsNotProd: !Not [!Condition IsProd]
Resources:
  ProdAssoc:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Condition: IsProd
    Properties:
      RouteTableId: rt-prod
      SubnetId: !Ref Subnet
  DevAssoc:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Condition: IsNotProd
    Properties:
      RouteTableId: rt-dev
      SubnetId: !Ref Subnet
"#;
        assert!(findings(template).is_empty());
    }

    /// Two resources sharing the same subnet identity and compatible
    /// (co-satisfiable) resource-level conditions report a conflict.
    #[test]
    fn compatible_resource_conditions_report_conflict() {
        let template = r#"
Parameters:
  Env:
    Type: String
  Feature:
    Type: String
  Subnet:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Env, prod]
  UseFeature: !Equals [!Ref Feature, yes]
Resources:
  ProdAssoc:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Condition: IsProd
    Properties:
      RouteTableId: rt-prod
      SubnetId: !Ref Subnet
  FeatureAssoc:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Condition: UseFeature
    Properties:
      RouteTableId: rt-feature
      SubnetId: !Ref Subnet
"#;
        let found = findings(template);
        assert!(
            found.iter().any(|(id, _)| id == "ProdAssoc"),
            "compatible resource conditions must report conflict: {:?}",
            found
        );
        assert!(
            found.iter().any(|(id, _)| id == "FeatureAssoc"),
            "compatible resource conditions must report conflict: {:?}",
            found
        );
    }

    /// Two resources with mutually exclusive property-level conditions
    /// (opposite Fn::If branches) and the same subnet identity are clean.
    #[test]
    fn mutually_exclusive_property_conditions_are_clean() {
        let template = r#"
Parameters:
  Env:
    Type: String
  SubnetA:
    Type: String
  SubnetB:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  One:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      RouteTableId: rt-1
      SubnetId: !If [IsProd, !Ref SubnetA, !Ref SubnetB]
  Two:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      RouteTableId: rt-2
      SubnetId: !If [IsProd, !Ref SubnetB, !Ref SubnetA]
"#;
        assert!(findings(template).is_empty());
    }

    /// When a resource-level condition on one resource is mutually exclusive
    /// with a property-level condition on another, the subnet identities
    /// cannot overlap at deploy time.
    #[test]
    fn mutually_exclusive_resource_and_property_conditions_are_clean() {
        let template = r#"
Parameters:
  Env:
    Type: String
  Subnet:
    Type: String
  OtherSubnet:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Gated:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Condition: IsProd
    Properties:
      RouteTableId: rt-1
      SubnetId: !Ref Subnet
  Branched:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      RouteTableId: rt-2
      SubnetId: !If [IsProd, !Ref OtherSubnet, !Ref Subnet]
"#;
        assert!(findings(template).is_empty());
    }
}
