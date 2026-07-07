//! Shared logic for validating region-scoped instance-type / node-type enum
//! values, used identically by the schema validator and both rule engines so
//! they cannot diverge.
//!
//! Each embedded enum document is a `{ "<region>": ... }` map. When a region is
//! configured, a value is checked against that one region's allowed set. When no
//! region is configured, it is checked against the **union of every region** —
//! flagged only when it is invalid in every region — so a value valid in the
//! caller's actual target region is not reported just because it is unavailable
//! in the platform-default region. The synthetic non-region keys some documents
//! carry (`all`, `description`) are excluded by intersecting the document's keys
//! with [`AWS_REGIONS`].
//!
//! Two document shapes exist:
//! - **Flat**: `{ "<region>": { "enum": [...] } }` (EC2, DocDB, AmazonMQ, …).
//! - **Conditional** (RDS `DBInstanceClass` / `DBClusterInstanceClass`): each
//!   region maps to an `allOf` of if/then branches keyed on Engine/LicenseModel;
//!   a value is valid in a region only when it is in the intersection of every
//!   matching branch's enum.

use crate::consts::AWS_REGIONS;
use crate::model::SemanticModel;
use crate::resolved_value::resolved_value_at_path;
use crate::resolver::ResolvedValue;
use diagnostics::message::render_str_list;
use std::collections::{BTreeSet, HashSet};

/// Resource types and property paths whose instance-type / node-type value is
/// validated against a region-scoped enum. This is the single list of what
/// "region-scoped validation" covers, used to decide whether the no-region
/// best-effort advisory applies to a template. A `{}` segment matches every
/// element of a list. Both rule engines validate exactly these paths; keeping the
/// set here documents the advisory's trigger in one place.
pub const REGION_SCOPED_TYPE_PATHS: &[(&str, &str)] = &[
    ("AWS::EC2::Instance", "Properties.InstanceType"),
    ("AWS::GameLift::Fleet", "Properties.EC2InstanceType"),
    ("AWS::EMR::InstanceTypeConfig", "Properties.InstanceType"),
    ("AWS::EMR::InstanceFleetConfig", "Properties.InstanceType"),
    ("AWS::ManagedBlockchain::Node", "Properties.NodeConfiguration.InstanceType"),
    ("AWS::DocDB::DBInstance", "Properties.DBInstanceClass"),
    ("AWS::AppStream::Fleet", "Properties.InstanceType"),
    ("AWS::ElastiCache::CacheCluster", "Properties.CacheNodeType"),
    ("AWS::DAX::Cluster", "Properties.NodeType"),
    ("AWS::Neptune::DBInstance", "Properties.DBInstanceClass"),
    ("AWS::Redshift::Cluster", "Properties.NodeType"),
    ("AWS::AmazonMQ::Broker", "Properties.HostInstanceType"),
    ("AWS::RDS::DBInstance", "Properties.DBInstanceClass"),
    ("AWS::RDS::DBCluster", "Properties.DBClusterInstanceClass"),
    ("AWS::SageMaker::DataQualityJobDefinition", "Properties.JobResources.ClusterConfig.InstanceType"),
    ("AWS::SageMaker::ModelBiasJobDefinition", "Properties.JobResources.ClusterConfig.InstanceType"),
    ("AWS::SageMaker::ModelExplainabilityJobDefinition", "Properties.JobResources.ClusterConfig.InstanceType"),
    ("AWS::SageMaker::ModelQualityJobDefinition", "Properties.JobResources.ClusterConfig.InstanceType"),
    (
        "AWS::SageMaker::MonitoringSchedule",
        "Properties.MonitoringScheduleConfig.MonitoringJobDefinition.MonitoringResources.ClusterConfig.InstanceType",
    ),
    ("AWS::Elasticsearch::Domain", "Properties.ElasticsearchClusterConfig.InstanceType"),
    ("AWS::OpenSearchService::Domain", "Properties.ClusterConfig.InstanceType"),
    (
        "AWS::SageMaker::InferenceExperiment",
        "Properties.ModelVariants.{}.InfrastructureConfig.RealTimeInferenceConfig.InstanceType",
    ),
    (
        "AWS::SageMaker::ModelPackage",
        "Properties.ValidationSpecification.ValidationProfiles.{}.TransformJobDefinition.TransformResources.InstanceType",
    ),
    ("AWS::SageMaker::Cluster", "Properties.InstanceGroups.{}.InstanceType"),
    ("AWS::SageMaker::Cluster", "Properties.RestrictedInstanceGroups.{}.InstanceType"),
];

/// Whether the template contains at least one region-scoped instance-type /
/// node-type value that resolves to a concrete string — i.e. a value that the
/// region-scoped enum rules actually validate. Used to decide whether the
/// no-region best-effort advisory is worth emitting: a template with no such
/// value had nothing validated best-effort, so the advisory would be noise. The
/// result depends only on the model, so it is identical across engines.
pub fn template_has_region_scoped_value(model: &SemanticModel) -> bool {
    REGION_SCOPED_TYPE_PATHS.iter().any(|(rtype, path)| {
        model.resources_of_type(rtype).iter().any(|rid| resolves_to_concrete_string(model, rid, path))
    })
}

/// Whether `path` on `rid` resolves to any concrete string, collapsing an
/// `Fn::If` to its true branch and treating a `{}` wildcard as a match against
/// every list element — mirroring how the enum rules read the value.
fn resolves_to_concrete_string(model: &SemanticModel, rid: &str, path: &str) -> bool {
    let Some(resolved) = resolve_for_detection(model, rid, path) else {
        return false;
    };
    any_concrete_string(&resolved)
}

/// Resolves `path` (which may contain a `{}` wildcard) for the advisory detector.
fn resolve_for_detection(model: &SemanticModel, rid: &str, path: &str) -> Option<ResolvedValue> {
    if path.contains("{}") {
        let resource = model.resources.get(rid)?;
        let prop_path = path.strip_prefix("Properties.").unwrap_or(path);
        let mut segments = prop_path.splitn(2, '.');
        let top_key = segments.next()?;
        let resolved = resource.properties.get(top_key)?;
        return match segments.next() {
            Some(rest) if !rest.is_empty() => resolved_value_at_path(resolved, rest),
            _ => Some(resolved.clone()),
        };
    }
    model.resolve_deep(rid, path).or_else(|| model.resolve(rid, path).cloned())
}

/// Whether a resolved value yields any concrete string, descending through the
/// composite variants the enum rules also descend (lists, `Fn::If` true branches,
/// enum candidates).
fn any_concrete_string(value: &ResolvedValue) -> bool {
    match value {
        ResolvedValue::Concrete { value } => value.0.is_string(),
        ResolvedValue::List { items } | ResolvedValue::Enum { variants: items } => {
            items.iter().any(any_concrete_string)
        }
        ResolvedValue::Conditional { if_true, if_false, .. } => {
            any_concrete_string(if_true) || any_concrete_string(if_false)
        }
        _ => false,
    }
}

/// Fragment used in place of a region name in a diagnostic message when no region
/// is configured and the value was validated against the union of all regions.
pub const ANY_REGION_LABEL: &str = "any region";

/// The label naming what a region-scoped value was validated against: the
/// configured region, or [`ANY_REGION_LABEL`] when none was configured.
pub fn region_label(region: Option<&str>) -> &str {
    region.unwrap_or(ANY_REGION_LABEL)
}

/// Diagnostic message for a flat instance-type / node-type enum value that is not
/// valid for the effective scope. With a region configured this is today's
/// message verbatim; with none configured it states the value is valid in no
/// region. Built here so both engines emit byte-identical text.
pub fn flat_invalid_message(value: &str, region: Option<&str>) -> String {
    match region {
        Some(region) => format!("'{value}' is not valid for region '{region}'"),
        None => format!("'{value}' is not valid in any region"),
    }
}

/// Diagnostic message for a conditional RDS instance-class value that is not one
/// of the allowed classes for the effective scope, rendering the candidate enum.
/// With a region configured this is today's message verbatim; with none
/// configured it states the value is one of none in any region.
pub fn conditional_invalid_message(value: &str, allowed_sorted: &[String], region: Option<&str>) -> String {
    let rendered = render_str_list(allowed_sorted);
    match region {
        Some(region) => format!("'{value}' is not one of {rendered} in '{region}'"),
        None => format!("'{value}' is not one of {rendered} in any region"),
    }
}

/// Whether any AWS region key is present in the document — i.e. whether the
/// document can validate anything at all when no region is configured.
fn has_any_region(doc: &serde_json::Map<String, serde_json::Value>) -> bool {
    AWS_REGIONS.iter().any(|r| doc.contains_key(*r))
}

/// The allowed values from a flat enum document for the effective scope: the
/// single `region` when configured, or the union across all AWS regions when not.
/// Returns `None` when the document has no entry for the effective scope, so the
/// caller skips validation — a dynamic or unknown configured region is not
/// validated, matching today's per-region lookup that returns `None` for a
/// missing region.
pub fn flat_allowed_values<'a>(
    doc: &'a serde_json::Map<String, serde_json::Value>,
    region: Option<&str>,
) -> Option<BTreeSet<&'a str>> {
    match region {
        Some(region) => {
            let values = doc.get(region)?.get("enum")?.as_array()?;
            Some(values.iter().filter_map(|v| v.as_str()).collect())
        }
        None => {
            if !has_any_region(doc) {
                return None;
            }
            let mut union = BTreeSet::new();
            for region in AWS_REGIONS {
                if let Some(values) = doc.get(*region).and_then(|r| r.get("enum")).and_then(|e| e.as_array()) {
                    union.extend(values.iter().filter_map(|v| v.as_str()));
                }
            }
            Some(union)
        }
    }
}

/// For a conditional RDS document (`{ "<region>": { "allOf": [...] } }`), returns
/// the sorted enum to render when `value` is invalid for the effective scope, or
/// `None` when the value is valid or the document does not apply. `resolve_prop`
/// supplies the resource's scalar property values (Engine, LicenseModel) that the
/// branch `if.required` consts key on.
///
/// With a region configured, this validates against that one region's
/// matching-branch intersection (today's behavior). With no region configured, a
/// value is valid when it is valid in *any* region, so it is flagged only when it
/// fails in every region; the rendered enum is then the largest failing branch
/// across all regions — the most informative candidate list.
pub fn conditional_invalid_enum<F>(
    doc: &serde_json::Map<String, serde_json::Value>,
    region: Option<&str>,
    target_prop: &str,
    normalize_engine_case: bool,
    value: &str,
    resolve_prop: F,
) -> Option<Vec<String>>
where
    F: Fn(&str) -> Option<String>,
{
    match region {
        Some(region) => {
            let region_doc = doc.get(region)?;
            let branch_enums = conditional_branch_enums(region_doc, target_prop, normalize_engine_case, &resolve_prop);
            invalid_branch_enum(&branch_enums, value)
        }
        None => {
            if !has_any_region(doc) {
                return None;
            }
            // Valid when valid in any region; flag only when invalid in every
            // region. Collect each region's matching-branch enums, and treat the
            // value as invalid only if no region has a matching branch that
            // contains it. Report the largest branch enum the value is missing
            // from, across all regions.
            let mut valid_somewhere = false;
            let mut had_matching_branch = false;
            let mut failing_largest: Option<Vec<String>> = None;
            for r in AWS_REGIONS {
                let Some(region_doc) = doc.get(*r) else {
                    continue;
                };
                let branch_enums =
                    conditional_branch_enums(region_doc, target_prop, normalize_engine_case, &resolve_prop);
                if branch_enums.is_empty() {
                    continue;
                }
                had_matching_branch = true;
                if branch_enums.iter().all(|allowed| allowed.iter().any(|v| v == value)) {
                    valid_somewhere = true;
                    break;
                }
                if let Some(sorted) = invalid_branch_enum(&branch_enums, value)
                    && failing_largest.as_ref().is_none_or(|cur| sorted.len() > cur.len())
                {
                    failing_largest = Some(sorted);
                }
            }
            // No region had a matching branch (dynamic/unmatched Engine) → not
            // validated, exactly as the per-region path leaves it unvalidated.
            if !had_matching_branch || valid_somewhere {
                return None;
            }
            failing_largest
        }
    }
}

/// Collects every `then.<target_prop>.enum` from a conditional region document
/// whose `allOf` branch `if.required` consts all match the resolved properties.
/// Returns one enum per matching branch (the whole schema is evaluated, so EVERY
/// matching branch applies), or empty when no branch matches — so a resource with
/// a dynamic or unmatched Engine is not validated. The `Engine` const is matched
/// case-insensitively when `normalize_engine_case` is set.
fn conditional_branch_enums<F>(
    region_doc: &serde_json::Value,
    target_prop: &str,
    normalize_engine_case: bool,
    resolve_prop: &F,
) -> Vec<HashSet<String>>
where
    F: Fn(&str) -> Option<String>,
{
    let mut enums = Vec::new();
    let Some(branches) = region_doc.get("allOf").and_then(|v| v.as_array()) else {
        return enums;
    };
    for branch in branches {
        let (Some(required), Some(if_props)) = (
            branch.get("if").and_then(|c| c.get("required")).and_then(|v| v.as_array()),
            branch.get("if").and_then(|c| c.get("properties")).and_then(|v| v.as_object()),
        ) else {
            continue;
        };
        let all_required_match = required.iter().filter_map(|r| r.as_str()).filter(|p| *p != target_prop).all(|prop| {
            let Some(expected) = if_props.get(prop).and_then(|p| p.get("const")).and_then(|c| c.as_str()) else {
                return false;
            };
            let Some(actual) = resolve_prop(prop) else {
                return false;
            };
            if normalize_engine_case && prop == "Engine" {
                actual.eq_ignore_ascii_case(expected)
            } else {
                actual == expected
            }
        });
        if all_required_match
            && let Some(enum_vals) = branch
                .get("then")
                .and_then(|t| t.get("properties"))
                .and_then(|p| p.get(target_prop))
                .and_then(|d| d.get("enum"))
                .and_then(|e| e.as_array())
        {
            enums.push(enum_vals.iter().filter_map(|v| v.as_str().map(String::from)).collect::<HashSet<String>>());
        }
    }
    enums
}

/// The enum to render when `value` is not in the intersection of all matching
/// branch enums: the largest branch enum missing the value. `None` when the value
/// is in every branch (valid) or there are no matching branches.
fn invalid_branch_enum(branch_enums: &[HashSet<String>], value: &str) -> Option<Vec<String>> {
    let failing_largest = branch_enums
        .iter()
        .filter(|allowed| !allowed.iter().any(|v| v == value))
        .max_by_key(|allowed| allowed.len())?;
    let mut sorted: Vec<String> = failing_largest.iter().cloned().collect();
    sorted.sort();
    Some(sorted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn flat_doc() -> serde_json::Map<String, serde_json::Value> {
        // us-east-1 lacks "special.type"; ap-east-2 has it. "all"/"description"
        // are synthetic non-region keys that must never contribute.
        json!({
            "us-east-1": { "enum": ["common.type", "east.type"] },
            "ap-east-2": { "enum": ["common.type", "special.type"] },
            "all": { "enum": ["should.be.ignored"] },
            "description": "generated"
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn region_label_uses_region_or_any_region() {
        assert_eq!(region_label(Some("us-west-2")), "us-west-2");
        assert_eq!(region_label(None), "any region");
    }

    #[test]
    fn flat_with_region_validates_that_region_only() {
        let doc = flat_doc();
        let allowed = flat_allowed_values(&doc, Some("us-east-1")).unwrap();
        assert!(allowed.contains("east.type"));
        assert!(!allowed.contains("special.type"), "special.type is not valid in us-east-1");
    }

    #[test]
    fn flat_without_region_unions_all_regions() {
        let doc = flat_doc();
        let allowed = flat_allowed_values(&doc, None).unwrap();
        assert!(allowed.contains("east.type"));
        assert!(allowed.contains("special.type"), "special.type is valid in ap-east-2, so present in the union");
        assert!(!allowed.contains("should.be.ignored"), "the synthetic 'all' key must not contribute");
    }

    #[test]
    fn flat_unknown_configured_region_returns_none() {
        let doc = flat_doc();
        assert!(flat_allowed_values(&doc, Some("mars-north-1")).is_none());
    }

    #[test]
    fn flat_without_region_returns_none_when_no_region_keys() {
        let doc = json!({ "description": "x", "all": { "enum": ["a"] } }).as_object().unwrap().clone();
        assert!(flat_allowed_values(&doc, None).is_none(), "no real region keys → nothing to validate");
    }

    fn conditional_doc() -> serde_json::Map<String, serde_json::Value> {
        // mysql in us-east-1 allows only db.small; ap-east-2 also allows db.big.
        let branch = |class: &str| {
            json!({
                "if": { "required": ["Engine", "DBInstanceClass"], "properties": { "Engine": { "const": "mysql" } } },
                "then": { "properties": { "DBInstanceClass": { "enum": [class] } } }
            })
        };
        json!({
            "us-east-1": { "allOf": [branch("db.small")] },
            "ap-east-2": { "allOf": [ { "if": { "required": ["Engine", "DBInstanceClass"], "properties": { "Engine": { "const": "mysql" } } }, "then": { "properties": { "DBInstanceClass": { "enum": ["db.small", "db.big"] } } } } ] }
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn conditional_with_region_flags_value_absent_from_that_region() {
        let doc = conditional_doc();
        let engine = |p: &str| (p == "Engine").then(|| "mysql".to_string());
        // db.big is not valid for mysql in us-east-1.
        let invalid = conditional_invalid_enum(&doc, Some("us-east-1"), "DBInstanceClass", true, "db.big", engine);
        assert_eq!(invalid, Some(vec!["db.small".to_string()]));
    }

    #[test]
    fn conditional_without_region_accepts_value_valid_in_any_region() {
        let doc = conditional_doc();
        let engine = |p: &str| (p == "Engine").then(|| "mysql".to_string());
        // db.big is valid for mysql in ap-east-2, so with no region it is accepted.
        let invalid = conditional_invalid_enum(&doc, None, "DBInstanceClass", true, "db.big", engine);
        assert!(invalid.is_none(), "db.big is valid in ap-east-2 → not flagged when region is unset");
    }

    #[test]
    fn conditional_without_region_flags_value_valid_nowhere() {
        let doc = conditional_doc();
        let engine = |p: &str| (p == "Engine").then(|| "mysql".to_string());
        let invalid = conditional_invalid_enum(&doc, None, "DBInstanceClass", true, "db.bogus", engine);
        assert!(invalid.is_some(), "db.bogus is valid in no region → flagged");
        let rendered = invalid.unwrap();
        assert!(rendered.contains(&"db.big".to_string()), "renders the largest failing branch across regions");
    }

    #[test]
    fn conditional_unmatched_engine_is_not_validated() {
        let doc = conditional_doc();
        // Engine resolves to something no branch matches → no matching branch in
        // any region → not validated (mirrors the per-region contract).
        let engine = |p: &str| (p == "Engine").then(|| "oracle".to_string());
        assert!(conditional_invalid_enum(&doc, None, "DBInstanceClass", true, "db.bogus", engine).is_none());
        assert!(
            conditional_invalid_enum(&doc, Some("us-east-1"), "DBInstanceClass", true, "db.bogus", engine).is_none()
        );
    }
}
