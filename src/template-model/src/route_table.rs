//! Duplicate subnet/route-table association detection.
//!
//! EC2 allows exactly one route table per subnet, so two
//! `AWS::EC2::SubnetRouteTableAssociation` resources naming the same subnet
//! fail at deploy time. A subnet's identity here is the *authored* reference —
//! the `Ref` target, the `GetAtt` target and attribute, or the literal string —
//! evaluated through `Fn::If` branches. Two associations only clash outright
//! when they are equally conditioned; an association gated by a condition (a
//! resource `Condition` or an `Fn::If` branch) also clashes with any
//! unconditioned association of the same subnet, since the gated one can
//! deploy alongside it.
//!
//! Both rule engines evaluate through this one implementation so their
//! findings are identical.

use crate::model::SemanticModel;
use crate::resolver::{RefKind, ResolvedValue};

/// A clash finding: the association resource and the message naming the other
/// associations sharing its subnet. Anchored at `Properties.SubnetId`.
#[derive(Debug, Clone)]
pub struct AssociationFinding {
    pub resource_id: String,
    pub message: String,
}

const ASSOCIATION_TYPE: &str = "AWS::EC2::SubnetRouteTableAssociation";

/// The identity of one possible subnet value: the resource's `Condition` (if
/// any), the `Fn::If` condition the value sits under (if any), and the
/// subnet's textual identity.
type ValueKey = (Option<String>, Option<String>, String);

pub fn duplicate_subnet_associations(model: &SemanticModel) -> Vec<AssociationFinding> {
    // Template (source) order, so multi-resource messages list the other
    // associations the way the template declares them.
    let mut names: Vec<&String> =
        model.resources.iter().filter(|(_, r)| r.resource_type == ASSOCIATION_TYPE).map(|(n, _)| n).collect();
    names.sort_by_key(|n| {
        model
            .source_location(&format!("Resources/{}", n))
            .map(|s| (s.start_line, s.start_column))
            .unwrap_or((u32::MAX, u32::MAX))
    });

    let mut per_resource: Vec<(&String, Vec<ValueKey>)> = Vec::new();
    for name in &names {
        let res = &model.resources[*name];
        let mut values = Vec::new();
        // References (to parameters as much as resources) are read from the
        // reference graph: resolution may collapse a parameter reference into
        // its default value, but the authored identity is the target name.
        // An edge under an `Fn::If` carries that condition in its context;
        // the polarity is dropped (either branch is the same gating).
        for edge in model.graph.outgoing(name) {
            if edge.source_path != "Properties.SubnetId" && !edge.source_path.starts_with("Properties.SubnetId.") {
                continue;
            }
            let identity = match &edge.kind {
                RefKind::GetAtt { attr } => format!("{}.{}", edge.target, attr),
                RefKind::Ref => edge.target.clone(),
                _ => continue,
            };
            let property_condition = edge
                .condition_context
                .as_ref()
                .map(|ctx| ctx.split(',').map(|c| c.trim_start_matches('!')).collect::<Vec<_>>().join(","));
            let key = (res.condition.clone(), property_condition, identity);
            if !values.contains(&key) {
                values.push(key);
            }
        }
        // Literal subnet ids never form an edge; walk the resolved value for
        // those (through `Fn::If` branches).
        if let Some(subnet) = res.properties.get("SubnetId") {
            collect_literal_subnet_values(subnet, res.condition.as_ref(), None, &mut values);
        }
        per_resource.push((name, values));
    }

    let holders_of = |key: &ValueKey| -> Vec<&String> {
        per_resource.iter().filter(|(_, values)| values.contains(key)).map(|(n, _)| *n).collect()
    };

    let mut out = Vec::new();
    for (name, values) in &per_resource {
        for value in values {
            let mut others: Vec<&String> = holders_of(value).into_iter().filter(|n| n != name).collect();
            let bare: ValueKey = (None, None, value.2.clone());
            if *value != bare {
                others.extend(holders_of(&bare));
            }
            if !others.is_empty() {
                out.push(AssociationFinding {
                    resource_id: (*name).clone(),
                    message: format!(
                        "SubnetId in {} is also associated with {}",
                        name,
                        others.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                });
            }
        }
    }
    out
}

/// Collects the literal subnet identities a value can take. Both `Fn::If`
/// branches carry the branch's condition name (without a polarity — an
/// association selected by either branch of the same condition is the same
/// gating). References are handled from the graph; dynamic values have no
/// stable identity and contribute nothing.
fn collect_literal_subnet_values(
    value: &ResolvedValue,
    resource_condition: Option<&String>,
    property_condition: Option<&String>,
    out: &mut Vec<ValueKey>,
) {
    match value {
        ResolvedValue::Conditional { condition, if_true, if_false } => {
            collect_literal_subnet_values(if_true, resource_condition, Some(condition), out);
            collect_literal_subnet_values(if_false, resource_condition, Some(condition), out);
        }
        ResolvedValue::Concrete { value } => {
            if let Some(s) = value.0.as_str() {
                let key = (resource_condition.cloned(), property_condition.cloned(), s.to_string());
                if !out.contains(&key) {
                    out.push(key);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SemanticModel;

    fn findings(template: &str) -> Vec<(String, String)> {
        let model = SemanticModel::from_bytes(template.as_bytes()).expect("template parses");
        duplicate_subnet_associations(&model).into_iter().map(|f| (f.resource_id, f.message)).collect()
    }

    #[test]
    fn distinct_subnets_are_clean() {
        let template = "Parameters:\n  A:\n    Type: String\n  B:\n    Type: String\nResources:\n  One:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-1\n      SubnetId: !Ref A\n  Two:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-1\n      SubnetId: !Ref B\n";
        assert!(findings(template).is_empty());
    }

    #[test]
    fn same_ref_target_clashes_both_ways() {
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
    fn conditioned_association_clashes_with_unconditioned_same_subnet() {
        let template = "Parameters:\n  A:\n    Type: String\n  Env:\n    Type: String\nConditions:\n  IsProd: !Equals [!Ref Env, prod]\nResources:\n  Plain:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Properties:\n      RouteTableId: rt-1\n      SubnetId: !Ref A\n  Gated:\n    Type: AWS::EC2::SubnetRouteTableAssociation\n    Condition: IsProd\n    Properties:\n      RouteTableId: rt-2\n      SubnetId: !Ref A\n";
        assert_eq!(
            findings(template),
            [("Gated".to_string(), "SubnetId in Gated is also associated with Plain".to_string())]
        );
    }
}
