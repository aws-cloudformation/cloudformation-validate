//! Subnet CIDR placement analysis.
//!
//! EC2 requires every IPv4 subnet CIDR to lie inside one of its VPC's IPv4
//! networks - the VPC's own `CidrBlock` or a secondary block attached through
//! `AWS::EC2::VPCCidrBlock` - and forbids two subnets of one VPC from
//! overlapping. Both checks are evaluated on the concrete deployment scenarios
//! of each `CidrBlock`, so a `Fn::If` or mapping-driven value is judged in every
//! branch it can take and two subnets are compared only in scenarios that can
//! occur together.
//!
//! A network that is only known at deployment - an IPAM allocation, a CIDR
//! taken from a parameter, or an unresolved reference - makes the containing
//! question unanswerable, and no finding is emitted for it. Two subnets are
//! compared only when they provably belong to the same VPC.

use std::collections::HashMap;

use ipnetwork::Ipv4Network;

use crate::consts::KEY_PROPERTIES;
use crate::model::SemanticModel;

const VPC_TYPE: &str = "AWS::EC2::VPC";
const SUBNET_TYPE: &str = "AWS::EC2::Subnet";
const VPC_CIDR_BLOCK_TYPE: &str = "AWS::EC2::VPCCidrBlock";
const CIDR_BLOCK_PROPERTY: &str = "CidrBlock";
const VPC_ID_PROPERTY: &str = "VpcId";
const IPV4_IPAM_POOL_PROPERTY: &str = "Ipv4IpamPoolId";

/// A subnet whose IPv4 CIDR lies outside every IPv4 network of its VPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetOutsideVpcFinding {
    pub subnet_id: String,
    pub message: String,
}

/// A subnet whose IPv4 CIDR overlaps an earlier subnet of the same VPC in a
/// deployment scenario where both exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetOverlapFinding {
    pub subnet_id: String,
    pub message: String,
    pub earlier_subnet_id: String,
    pub earlier_subnet_message: String,
}

/// One concrete IPv4 network a `CidrBlock` can take, with the condition
/// assumptions under which it takes it.
struct CidrScenario {
    network: Ipv4Network,
    conditions: HashMap<String, bool>,
}

/// The IPv4 networks of a VPC, or `None` when at least one of them is unknown
/// before deployment and containment therefore cannot be decided.
fn vpc_ipv4_networks(model: &SemanticModel, vpc_id: &str) -> Option<Vec<Ipv4Network>> {
    let mut networks = static_ipv4_networks(model, vpc_id)?;
    for attachment in model.resources_of_type(VPC_CIDR_BLOCK_TYPE) {
        if model.follow_ref(attachment, &property_path(VPC_ID_PROPERTY)) != Some(vpc_id) {
            continue;
        }
        if model.has_property(attachment, &property_path(IPV4_IPAM_POOL_PROPERTY)) {
            return None;
        }
        if model.has_property(attachment, &property_path(CIDR_BLOCK_PROPERTY)) {
            networks.extend(static_ipv4_networks(model, attachment)?);
        }
    }
    Some(networks)
}

/// The IPv4 networks a resource's own `CidrBlock` can take across its
/// scenarios, or `None` when the block is absent, IPAM-allocated, taken from a
/// parameter, or unresolved in any scenario.
fn static_ipv4_networks(model: &SemanticModel, resource_id: &str) -> Option<Vec<Ipv4Network>> {
    let cidr_path = property_path(CIDR_BLOCK_PROPERTY);
    if model.has_property(resource_id, &property_path(IPV4_IPAM_POOL_PROPERTY))
        || !model.has_property(resource_id, &cidr_path)
        || model.is_from_parameter(resource_id, &cidr_path)
        || model.has_unresolved_scenario(resource_id, &cidr_path)
    {
        return None;
    }
    let networks: Vec<Ipv4Network> = cidr_scenarios(model, resource_id).into_iter().map(|s| s.network).collect();
    (!networks.is_empty()).then_some(networks)
}

/// Every reachable scenario in which the resource's `CidrBlock` is a literal
/// IPv4 network. Values that are not IPv4 CIDRs belong to other rules.
fn cidr_scenarios(model: &SemanticModel, resource_id: &str) -> Vec<CidrScenario> {
    model
        .resolve_scenarios_json(resource_id, &property_path(CIDR_BLOCK_PROPERTY))
        .into_iter()
        .filter_map(|(value, conditions)| {
            let network: Ipv4Network = value.as_str()?.parse().ok()?;
            scenario_is_reachable(model, resource_id, &conditions).then_some(CidrScenario { network, conditions })
        })
        .collect()
}

fn property_path(property_name: &str) -> String {
    format!("{KEY_PROPERTIES}.{property_name}")
}

/// Whether a scenario can occur at all once the resource's own condition is
/// added to its assumptions.
fn scenario_is_reachable(model: &SemanticModel, resource_id: &str, conditions: &HashMap<String, bool>) -> bool {
    assumptions_are_satisfiable(model, conditions, [resource_id])
}

/// Whether two subnets' scenarios can be deployed together: their condition
/// assumptions must agree wherever they overlap and be jointly satisfiable
/// alongside both resources' own conditions.
fn scenarios_coexist(
    model: &SemanticModel,
    left: (&str, &HashMap<String, bool>),
    right: (&str, &HashMap<String, bool>),
) -> bool {
    let mut combined = left.1.clone();
    for (condition, value) in right.1 {
        if combined.get(condition).is_some_and(|existing| existing != value) {
            return false;
        }
        combined.insert(condition.clone(), *value);
    }
    assumptions_are_satisfiable(model, &combined, [left.0, right.0])
}

/// Whether the scenario assumptions, extended with every listed resource's own
/// condition being true, can all hold at once.
fn assumptions_are_satisfiable<'a>(
    model: &SemanticModel,
    conditions: &HashMap<String, bool>,
    resource_ids: impl IntoIterator<Item = &'a str>,
) -> bool {
    let mut assumptions: Vec<(String, bool)> = conditions.iter().map(|(name, value)| (name.clone(), *value)).collect();
    for resource_id in resource_ids {
        let Some(resource_condition) =
            model.resources.get(resource_id).and_then(|resource| resource.condition.as_ref())
        else {
            continue;
        };
        match conditions.get(resource_condition) {
            Some(false) => return false,
            Some(true) => {}
            None => assumptions.push((resource_condition.clone(), true)),
        }
    }
    assumptions.is_empty() || model.conditions.is_satisfiable(&assumptions)
}

fn subnet_cidr_is_static(model: &SemanticModel, subnet_id: &str) -> bool {
    !model.is_from_parameter(subnet_id, &property_path(CIDR_BLOCK_PROPERTY))
}

/// Subnets whose IPv4 CIDR falls outside every IPv4 network of the VPC they
/// reference, one finding per distinct offending CIDR.
pub fn subnets_outside_vpc(model: &SemanticModel) -> Vec<SubnetOutsideVpcFinding> {
    let mut findings = Vec::new();
    for subnet_id in model.resources_of_type(SUBNET_TYPE) {
        if !subnet_cidr_is_static(model, subnet_id) {
            continue;
        }
        let Some(vpc_id) = model.follow_ref(subnet_id, &property_path(VPC_ID_PROPERTY)) else {
            continue;
        };
        if model.resources.get(vpc_id).is_none_or(|vpc| vpc.resource_type != VPC_TYPE) {
            continue;
        }
        let Some(vpc_networks) = vpc_ipv4_networks(model, vpc_id) else {
            continue;
        };
        for scenario in cidr_scenarios(model, subnet_id) {
            if vpc_networks.iter().any(|vpc_network| scenario.network.is_subnet_of(*vpc_network)) {
                continue;
            }
            let finding = SubnetOutsideVpcFinding {
                subnet_id: subnet_id.clone(),
                message: outside_vpc_message(&scenario.network, &vpc_networks),
            };
            if !findings.contains(&finding) {
                findings.push(finding);
            }
        }
    }
    findings
}

fn outside_vpc_message(subnet_network: &Ipv4Network, vpc_networks: &[Ipv4Network]) -> String {
    match vpc_networks {
        [only] => format!("Subnet CIDR '{subnet_network}' is not within VPC CIDR '{only}'"),
        several => {
            let rendered: Vec<String> = several.iter().map(|network| format!("'{network}'")).collect();
            format!("Subnet CIDR '{subnet_network}' is not within any VPC CIDR [{}]", rendered.join(", "))
        }
    }
}

/// Pairs of same-VPC subnets whose IPv4 CIDRs overlap in a scenario where both
/// are deployed. Each finding is attributed to the later subnet in template
/// order, with the earlier one as its related resource.
pub fn overlapping_subnets(model: &SemanticModel) -> Vec<SubnetOverlapFinding> {
    let subnets = model.resources_of_type(SUBNET_TYPE);
    let vpc_id_path = property_path(VPC_ID_PROPERTY);
    let mut findings = Vec::new();
    for (later_index, later_id) in subnets.iter().enumerate() {
        if !subnet_cidr_is_static(model, later_id) {
            continue;
        }
        let Some(later_vpc) = model.referenced_resource_or_value_identity(later_id, &vpc_id_path) else {
            continue;
        };
        let later_scenarios = cidr_scenarios(model, later_id);
        if later_scenarios.is_empty() {
            continue;
        }
        for earlier_id in &subnets[..later_index] {
            if !subnet_cidr_is_static(model, earlier_id)
                || model.referenced_resource_or_value_identity(earlier_id, &vpc_id_path).as_deref()
                    != Some(later_vpc.as_str())
            {
                continue;
            }
            for later in &later_scenarios {
                for earlier in cidr_scenarios(model, earlier_id) {
                    if !later.network.overlaps(earlier.network)
                        || !scenarios_coexist(model, (earlier_id, &earlier.conditions), (later_id, &later.conditions))
                    {
                        continue;
                    }
                    let finding = SubnetOverlapFinding {
                        subnet_id: later_id.clone(),
                        message: format!("'{}' overlaps with '{}'", later.network, earlier.network),
                        earlier_subnet_id: earlier_id.clone(),
                        earlier_subnet_message: format!("Overlapping subnet CIDR {}", earlier.network),
                    };
                    if !findings.contains(&finding) {
                        findings.push(finding);
                    }
                }
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(template: &str) -> SemanticModel {
        SemanticModel::from_bytes(template.as_bytes()).expect("template parses")
    }

    fn outside(template: &str) -> Vec<(String, String)> {
        subnets_outside_vpc(&model(template)).into_iter().map(|f| (f.subnet_id, f.message)).collect()
    }

    fn overlaps(template: &str) -> Vec<(String, String, String)> {
        overlapping_subnets(&model(template))
            .into_iter()
            .map(|f| (f.subnet_id, f.earlier_subnet_id, f.message))
            .collect()
    }

    const TWO_VPCS_SAME_LAYOUT: &str = r#"
Resources:
  VpcA:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  VpcB:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VpcA
      CidrBlock: 10.0.0.0/24
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VpcB
      CidrBlock: 10.0.0.0/24
  SubnetC:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !GetAtt VpcA.VpcId
      CidrBlock: 10.0.1.0/24
  SubnetD:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VpcA
      CidrBlock: 10.0.1.0/24
"#;

    #[test]
    fn subnets_in_different_vpcs_never_overlap() {
        let found = overlaps(TWO_VPCS_SAME_LAYOUT);
        assert_eq!(
            found,
            [("SubnetD".to_string(), "SubnetC".to_string(), "'10.0.1.0/24' overlaps with '10.0.1.0/24'".to_string())]
        );
    }

    #[test]
    fn ref_and_getatt_to_the_same_vpc_are_one_vpc() {
        let found = overlaps(TWO_VPCS_SAME_LAYOUT);
        assert!(found.iter().any(|(later, earlier, _)| later == "SubnetD" && earlier == "SubnetC"));
    }

    #[test]
    fn same_parameter_vpc_groups_subnets() {
        let template = r#"
Parameters:
  Vpc:
    Type: AWS::EC2::VPC::Id
Resources:
  A:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.0.0.0/24
  B:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.0.0.0/25
"#;
        assert_eq!(overlaps(template).len(), 1);
    }

    #[test]
    fn unresolved_cidr_is_not_compared() {
        let template = r#"
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  A:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: !GetAtt Vpc.CidrBlock
  B:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: !ImportValue Shared
  C:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: !Select [0, !Cidr [!GetAtt Vpc.CidrBlock, 4, 8]]
"#;
        assert!(overlaps(template).is_empty());
        assert!(outside(template).is_empty());
    }

    #[test]
    fn opposite_conditional_branches_do_not_overlap() {
        let template = r#"
Parameters:
  Env:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  A:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: !If [IsProd, 10.0.0.0/24, 10.0.1.0/24]
  B:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: !If [IsProd, 10.0.1.0/24, 10.0.0.0/24]
"#;
        assert!(overlaps(template).is_empty());
    }

    #[test]
    fn overlap_in_either_branch_is_reported() {
        let template = r#"
Parameters:
  Env:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  A:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.0.1.0/24
  B:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: !If [IsProd, 10.0.0.0/24, 10.0.1.0/24]
"#;
        assert_eq!(
            overlaps(template),
            [("B".to_string(), "A".to_string(), "'10.0.1.0/24' overlaps with '10.0.1.0/24'".to_string())]
        );
    }

    #[test]
    fn mutually_exclusive_subnets_do_not_overlap() {
        let template = r#"
Parameters:
  Env:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Env, prod]
  IsNotProd: !Not [!Condition IsProd]
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  A:
    Type: AWS::EC2::Subnet
    Condition: IsProd
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.0.0.0/24
  B:
    Type: AWS::EC2::Subnet
    Condition: IsNotProd
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.0.0.0/24
"#;
        assert!(overlaps(template).is_empty());
    }

    #[test]
    fn secondary_vpc_cidr_blocks_contain_subnets() {
        let template = r#"
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  Secondary:
    Type: AWS::EC2::VPCCidrBlock
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.1.0.0/16
  Inside:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.1.0.0/24
  Outside:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.2.0.0/24
"#;
        assert_eq!(
            outside(template),
            [(
                "Outside".to_string(),
                "Subnet CIDR '10.2.0.0/24' is not within any VPC CIDR ['10.0.0.0/16', '10.1.0.0/16']".to_string()
            )]
        );
    }

    #[test]
    fn dynamic_vpc_network_suppresses_containment() {
        let template = r#"
Parameters:
  VpcCidr:
    Type: String
    Default: 10.0.0.0/16
Resources:
  IpamVpc:
    Type: AWS::EC2::VPC
    Properties:
      Ipv4IpamPoolId: ipam-pool-0123456789abcdef0
      Ipv4NetmaskLength: 16
  A:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref IpamVpc
      CidrBlock: 10.9.0.0/24
  ParamVpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: !Ref VpcCidr
  B:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref ParamVpc
      CidrBlock: 10.9.0.0/24
  ExtendedVpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  IpamSecondary:
    Type: AWS::EC2::VPCCidrBlock
    Properties:
      VpcId: !Ref ExtendedVpc
      Ipv4IpamPoolId: ipam-pool-0123456789abcdef0
      Ipv4NetmaskLength: 16
  C:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref ExtendedVpc
      CidrBlock: 10.9.0.0/24
"#;
        assert!(outside(template).is_empty());
    }

    #[test]
    fn conditional_subnet_cidr_is_checked_in_every_branch() {
        let template = r#"
Parameters:
  Env:
    Type: String
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  A:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: !If [IsProd, 10.0.0.0/24, 10.5.0.0/24]
"#;
        assert_eq!(
            outside(template),
            [("A".to_string(), "Subnet CIDR '10.5.0.0/24' is not within VPC CIDR '10.0.0.0/16'".to_string())]
        );
    }

    #[test]
    fn literal_subnet_outside_literal_vpc_is_reported() {
        let template = r#"
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  A:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 192.168.0.0/24
"#;
        assert_eq!(
            outside(template),
            [("A".to_string(), "Subnet CIDR '192.168.0.0/24' is not within VPC CIDR '10.0.0.0/16'".to_string())]
        );
    }
}
