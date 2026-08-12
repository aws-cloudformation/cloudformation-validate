//! Duplicate subnet/route-table association detection.
//!
//! EC2 allows exactly one route table per subnet, so two
//! `AWS::EC2::SubnetRouteTableAssociation` resources naming the same subnet
//! fail at deploy time. A subnet's identity here is the authored reference: the
//! `Ref` target, the `GetAtt` target and attribute, or the literal string,
//! evaluated through `Fn::If` branches.

use crate::model::SemanticModel;
use crate::resolver::{RefKind, ResolvedValue};

/// A clash finding anchored at `Properties.SubnetId`.
#[derive(Debug, Clone)]
pub struct AssociationFinding {
    pub resource_id: String,
    pub message: String,
}

const ASSOCIATION_TYPE: &str = "AWS::EC2::SubnetRouteTableAssociation";

/// Resource condition, property condition, and authored subnet identity.
type ValueKey = (Option<String>, Option<String>, String);

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
        let mut reference_paths = Vec::new();

        // Resolution can collapse a parameter Ref into its default, so use the
        // graph to retain the target name and branch context the author wrote.
        for edge in model.graph.outgoing(name) {
            if edge.source_path != "Properties.SubnetId" && !edge.source_path.starts_with("Properties.SubnetId.") {
                continue;
            }
            let identity = match &edge.kind {
                RefKind::GetAtt { attr } => format!("{}.{}", edge.target, attr),
                RefKind::Ref => edge.target.clone(),
                _ => continue,
            };
            reference_paths.push(edge.source_path.clone());
            let key = (resource.condition.clone(), edge.condition_context.clone(), identity);
            if !values.contains(&key) {
                values.push(key);
            }
        }

        // Literal subnet IDs do not create graph edges. Exclude any concrete
        // value produced by a reference (for example, a parameter default),
        // because its authored identity is already represented by that edge.
        if let Some(subnet) = resource.properties.get("SubnetId") {
            collect_literal_subnet_values(
                subnet,
                resource.condition.as_deref(),
                None,
                "Properties.SubnetId",
                &reference_paths,
                &mut values,
            );
        }
        per_resource.push((name, values));
    }

    let holders_of = |key: &ValueKey| -> Vec<&String> {
        per_resource.iter().filter(|(_, values)| values.contains(key)).map(|(name, _)| *name).collect()
    };

    let mut findings = Vec::new();
    for (name, values) in &per_resource {
        for value in values {
            let mut others: Vec<&String> = holders_of(value).into_iter().filter(|other| other != name).collect();
            let unconditioned: ValueKey = (None, None, value.2.clone());
            if *value != unconditioned {
                others.extend(holders_of(&unconditioned));
            }
            others.sort_by_key(|other| names.iter().position(|name| name == other));
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

fn collect_literal_subnet_values(
    value: &ResolvedValue,
    resource_condition: Option<&str>,
    property_condition: Option<&str>,
    path: &str,
    reference_paths: &[String],
    out: &mut Vec<ValueKey>,
) {
    match value {
        ResolvedValue::Conditional { condition, if_true, if_false } => {
            let true_condition = append_condition(property_condition, condition, true);
            let false_condition = append_condition(property_condition, condition, false);
            collect_literal_subnet_values(
                if_true,
                resource_condition,
                Some(&true_condition),
                &format!("{}.Fn::If.1", path),
                reference_paths,
                out,
            );
            collect_literal_subnet_values(
                if_false,
                resource_condition,
                Some(&false_condition),
                &format!("{}.Fn::If.2", path),
                reference_paths,
                out,
            );
        }
        ResolvedValue::Concrete { value } => {
            let nested_prefix = format!("{}.", path);
            let comes_from_reference = reference_paths
                .iter()
                .any(|reference_path| reference_path == path || reference_path.starts_with(&nested_prefix));
            if !comes_from_reference && let Some(subnet) = value.as_str() {
                let key =
                    (resource_condition.map(String::from), property_condition.map(String::from), subnet.to_string());
                if !out.contains(&key) {
                    out.push(key);
                }
            }
        }
        _ => {}
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
}
