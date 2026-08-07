//! Shared detection of hardcoded availability zones, so both rule engines emit
//! identical findings from one implementation instead of two that can drift.

use crate::consts::KEY_PROPERTIES;
use crate::model::SemanticModel;
use crate::resolver::ResolvedValue;
use crate::value_patterns::AVAILABILITY_ZONE_PATTERN;
use regex::Regex;
use std::sync::LazyLock;

/// Resource types mapped to the property descriptor whose value is a hardcoded
/// availability-zone name to flag. A descriptor is a `.`-separated path under
/// `Properties` with two wildcard segments:
/// - `*` - the value at this path is a list whose every element is itself an AZ.
/// - `{}` - the value at this path is a list; descend into every element and
///   continue matching the remaining segments.
pub const AZ_PATHS: &[(&str, &str)] = &[
    ("AWS::AutoScaling::AutoScalingGroup", "AvailabilityZones.*"),
    ("AWS::DAX::Cluster", "AvailabilityZones.*"),
    ("AWS::DMS::ReplicationInstance", "AvailabilityZone"),
    ("AWS::EC2::Host", "AvailabilityZone"),
    ("AWS::EC2::Instance", "AvailabilityZone"),
    ("AWS::EC2::LaunchTemplate", "LaunchTemplateData.Placement.AvailabilityZone"),
    ("AWS::EC2::SpotFleet", "SpotFleetRequestConfigData.LaunchSpecifications.{}.Placement.AvailabilityZone"),
    ("AWS::EC2::SpotFleet", "SpotFleetRequestConfigData.LaunchTemplateConfigs.{}.Overrides.{}.AvailabilityZone"),
    ("AWS::EC2::Subnet", "AvailabilityZone"),
    ("AWS::EC2::Volume", "AvailabilityZone"),
    ("AWS::ElasticLoadBalancing::LoadBalancer", "AvailabilityZones.*"),
    ("AWS::ElasticLoadBalancingV2::TargetGroup", "Targets.{}.AvailabilityZone"),
    ("AWS::EMR::Cluster", "Instances.Placement.AvailabilityZone"),
    ("AWS::Glue::Connection", "ConnectionInput.PhysicalConnectionRequirements.AvailabilityZone"),
    ("AWS::OpsWorks::Instance", "AvailabilityZone"),
    ("AWS::RDS::DBCluster", "AvailabilityZones.*"),
    ("AWS::RDS::DBInstance", "AvailabilityZone"),
];

static AZ_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(AVAILABILITY_ZONE_PATTERN).expect("AVAILABILITY_ZONE_PATTERN is a valid regex"));

pub struct HardcodedAz {
    pub path: String,
    pub zone: String,
}

pub fn message(zone: &str) -> String {
    format!("Avoid hardcoding availability zones '{zone}'")
}

/// Values produced by intrinsics (`Fn::GetAZs`, `Ref`, …) are skipped: those are
/// not hardcoded even when they resolve to a concrete zone.
pub fn find(model: &SemanticModel, resource_id: &str, resource_type: &str) -> Vec<HardcodedAz> {
    let mut found = Vec::new();
    for (rtype, descriptor) in AZ_PATHS {
        if *rtype != resource_type {
            continue;
        }
        let segments: Vec<&str> = descriptor.split('.').collect();
        walk(model, resource_id, &segments, 0, KEY_PROPERTIES.to_string(), &mut found);
    }
    found
}

fn walk(model: &SemanticModel, name: &str, segments: &[&str], idx: usize, path: String, found: &mut Vec<HardcodedAz>) {
    if idx == segments.len() {
        push_if_hardcoded_az(model, name, path, found);
        return;
    }
    match segments[idx] {
        // Each list element is itself an availability zone.
        "*" => {
            if model.is_from_intrinsic(name, &path) {
                return;
            }
            let Some(len) = resolve_array_len(model, name, &path) else {
                return;
            };
            for i in 0..len {
                push_if_hardcoded_az(model, name, format!("{path}.{i}"), found);
            }
        }
        // Descend into every list element, then continue matching.
        "{}" => {
            let Some(len) = resolve_array_len(model, name, &path) else {
                return;
            };
            for i in 0..len {
                walk(model, name, segments, idx + 1, format!("{path}.{i}"), found);
            }
        }
        seg => walk(model, name, segments, idx + 1, format!("{path}.{seg}"), found),
    }
}

fn push_if_hardcoded_az(model: &SemanticModel, name: &str, path: String, found: &mut Vec<HardcodedAz>) {
    if model.is_from_intrinsic(name, &path) {
        return;
    }
    if let Some(zone) = resolve_concrete_string(model, name, &path)
        && AZ_RE.is_match(&zone)
    {
        found.push(HardcodedAz { path, zone });
    }
}

fn resolve_concrete_string(model: &SemanticModel, name: &str, path: &str) -> Option<String> {
    match model.resolve_deep(name, path).or_else(|| model.resolve(name, path).cloned())? {
        ResolvedValue::Concrete { value } => value.as_str().map(str::to_string),
        _ => None,
    }
}

fn resolve_array_len(model: &SemanticModel, name: &str, path: &str) -> Option<usize> {
    match model.resolve_deep(name, path).or_else(|| model.resolve(name, path).cloned())? {
        ResolvedValue::Concrete { value } => value.as_array().map(Vec::len),
        ResolvedValue::List { items } => Some(items.len()),
        _ => None,
    }
}
