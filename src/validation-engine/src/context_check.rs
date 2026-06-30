//! Diagnostic W9100 — flags templates that lack `Metadata.Context` design
//! intent at every level.
//!
//! Context can be expressed at two scopes:
//!
//! 1. **Template-level** — top-level `Metadata.Context` documenting stack-wide
//!    intent (what the stack is, schema version, cross-resource invariants).
//! 2. **Per-resource** — each resource's `Metadata.Context` documenting why
//!    that specific resource exists and any constraints that govern it.
//!
//! A template is considered to carry design intent if **any** of its resources
//! has meaningful Context **or** the template itself has meaningful Context at
//! the top level. The diagnostic fires exactly once when context is missing
//! at every level — not per resource.
//!
//! "Meaningful" Context means a non-empty `Context` object containing at least
//! one of the recognized fields (`why`, `decisions`, `constraints`,
//! `mutability`, `metricsGuidance`) with a non-empty value.

use diagnostics::Diagnostic;
use template_model::SemanticModel;

use crate::engine::make_resource_diagnostic;

const RULE_ID: &str = "W9100";

/// The minimal set of Context fields that count as "design intent present".
const RECOGNIZED_CONTEXT_FIELDS: &[&str] =
    &["why", "decisions", "constraints", "mutability", "metricsGuidance"];

/// Returns true when at least one recognized field exists and carries a
/// non-empty value (non-empty string, non-empty array, non-empty object,
/// non-null primitive).
fn has_meaningful_context(metadata: Option<&serde_json::Value>) -> bool {
    let metadata = match metadata {
        Some(serde_json::Value::Object(m)) => m,
        _ => return false,
    };
    let context = match metadata.get("Context") {
        Some(serde_json::Value::Object(c)) => c,
        _ => return false,
    };
    if context.is_empty() {
        return false;
    }
    RECOGNIZED_CONTEXT_FIELDS.iter().any(|field| {
        context
            .get(*field)
            .map(|v| match v {
                serde_json::Value::Null => false,
                serde_json::Value::String(s) => !s.trim().is_empty(),
                serde_json::Value::Array(a) => !a.is_empty(),
                serde_json::Value::Object(o) => !o.is_empty(),
                serde_json::Value::Bool(_) | serde_json::Value::Number(_) => true,
            })
            .unwrap_or(false)
    })
}

/// True when the top-level template `Metadata.Context` carries design intent.
fn template_has_context(model: &SemanticModel) -> bool {
    has_meaningful_context(model.template_metadata.as_ref())
}

/// True when at least one resource has a meaningful `Metadata.Context`.
fn any_resource_has_context(model: &SemanticModel) -> bool {
    model.resources.values().any(|r| has_meaningful_context(r.metadata.as_deref()))
}

/// Emits a single W9100 diagnostic when neither the template nor any resource
/// carries meaningful design-intent metadata. Returns an empty vector when
/// context is present at any level.
pub fn check_missing_context(model: &SemanticModel) -> Vec<Diagnostic> {
    if template_has_context(model) || any_resource_has_context(model) {
        return Vec::new();
    }
    let message =
        "Template is missing Metadata.Context. No design intent is documented at the template \
         level or on any resource."
            .to_string();
    let suggested_fix = "Add a Metadata.Context block with a 'why' field at the template level, \
on at least one resource, or both. Recognized fields: why (required), constraints (array), \
decisions (array), mutability (map), metricsGuidance (string).\n\n\
Example - template level:\n\
\n\
  Metadata:\n    \
  Context:\n      \
  why: \"Event-processing pipeline for the orders domain\"\n\
\n\
Example - per resource:\n\
\n\
  Resources:\n    \
  ProcessorFunction:\n      \
  Type: AWS::Lambda::Function\n      \
  Metadata:\n        \
  Context:\n          \
  why: \"Processes incoming SQS messages\"\n          \
  constraints:\n            \
  - \"Timeout must be >= 45s for P99 processing\"\n      \
  Properties: { ... }";
    // Empty resource_id makes make_resource_diagnostic resolve to a section-level
    // span and omit the resource attachment, so the diagnostic surfaces against
    // the template rather than any single resource.
    vec![make_resource_diagnostic(RULE_ID, &message, model, "", "", Some(suggested_fix))]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---------- has_meaningful_context unit tests ----------

    #[test]
    fn missing_metadata_is_not_meaningful() {
        assert!(!has_meaningful_context(None));
    }

    #[test]
    fn metadata_without_context_is_not_meaningful() {
        let m = json!({"Other": {"k": "v"}});
        assert!(!has_meaningful_context(Some(&m)));
    }

    #[test]
    fn empty_context_is_not_meaningful() {
        let m = json!({"Context": {}});
        assert!(!has_meaningful_context(Some(&m)));
    }

    #[test]
    fn context_with_empty_why_is_not_meaningful() {
        let m = json!({"Context": {"why": ""}});
        assert!(!has_meaningful_context(Some(&m)));
    }

    #[test]
    fn context_with_only_unknown_field_is_not_meaningful() {
        let m = json!({"Context": {"randomField": "value"}});
        assert!(!has_meaningful_context(Some(&m)));
    }

    #[test]
    fn context_with_nonempty_why_is_meaningful() {
        let m = json!({"Context": {"why": "Buffers events for async processing"}});
        assert!(has_meaningful_context(Some(&m)));
    }

    #[test]
    fn context_with_nonempty_constraints_is_meaningful() {
        let m = json!({"Context": {"constraints": ["VisibilityTimeout >= 3x function timeout"]}});
        assert!(has_meaningful_context(Some(&m)));
    }

    #[test]
    fn empty_constraints_alone_is_not_meaningful() {
        let m = json!({"Context": {"constraints": []}});
        assert!(!has_meaningful_context(Some(&m)));
    }

    // ---------- check_missing_context end-to-end tests ----------

    #[test]
    fn fires_once_when_template_and_all_resources_lack_context() {
        let yaml = br#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  BucketA:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: a
  BucketB:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: b
"#;
        let model = SemanticModel::from_bytes(yaml).expect("model parses");
        let diags = check_missing_context(&model);
        assert_eq!(diags.len(), 1, "expected exactly one diagnostic, got {}", diags.len());
        assert_eq!(diags[0].rule_id, "W9100");
        assert!(diags[0].resource.is_none(), "template-level diagnostic should not target a specific resource");
    }

    #[test]
    fn does_not_fire_when_one_resource_has_context() {
        // Even partial annotation (one resource out of three) is enough to satisfy the check.
        let yaml = br#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  BucketA:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: a
  BucketB:
    Type: AWS::S3::Bucket
    Metadata:
      Context:
        why: "Audit log archive - retention required for compliance"
    Properties:
      BucketName: b
  BucketC:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: c
"#;
        let model = SemanticModel::from_bytes(yaml).expect("model parses");
        let diags = check_missing_context(&model);
        assert!(diags.is_empty(), "expected zero diagnostics, got {:?}", diags);
    }

    #[test]
    fn does_not_fire_when_template_level_context_present() {
        // No resource has Context but the template top-level does — should not fire.
        let yaml = br#"
AWSTemplateFormatVersion: "2010-09-09"
Metadata:
  Context:
    why: "Event-processing pipeline for the orders domain"
Resources:
  BucketA:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: a
"#;
        let model = SemanticModel::from_bytes(yaml).expect("model parses");
        let diags = check_missing_context(&model);
        assert!(diags.is_empty(), "expected zero diagnostics with template-level Context, got {:?}", diags);
    }

    #[test]
    fn empty_template_context_does_not_satisfy_check() {
        // Top-level Metadata.Context exists but is empty — should still fire.
        let yaml = br#"
AWSTemplateFormatVersion: "2010-09-09"
Metadata:
  Context: {}
Resources:
  BucketA:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: a
"#;
        let model = SemanticModel::from_bytes(yaml).expect("model parses");
        let diags = check_missing_context(&model);
        assert_eq!(diags.len(), 1, "empty template-level Context should not satisfy the check");
    }

    #[test]
    fn diagnostic_message_does_not_mention_ai_agents() {
        let yaml = br#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  BucketA:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: a
"#;
        let model = SemanticModel::from_bytes(yaml).expect("model parses");
        let diags = check_missing_context(&model);
        let combined = format!(
            "{} {}",
            diags[0].message,
            diags[0].suggested_fix.as_deref().unwrap_or("")
        );
        let lc = combined.to_lowercase();
        assert!(!lc.contains("ai "), "diagnostic must not mention 'AI ': {}", combined);
        assert!(!lc.contains("agent"), "diagnostic must not mention 'agent': {}", combined);
    }

    #[test]
    fn suggested_fix_contains_concrete_example() {
        let yaml = br#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  BucketA:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: a
"#;
        let model = SemanticModel::from_bytes(yaml).expect("model parses");
        let diags = check_missing_context(&model);
        let fix = diags[0].suggested_fix.as_deref().expect("suggested_fix should be set");
        // Must show the shape at both scopes so a reader can copy-paste either one.
        assert!(fix.contains("Metadata:"), "fix should show Metadata block: {}", fix);
        assert!(fix.contains("Context:"), "fix should show Context key: {}", fix);
        assert!(fix.contains("why:"), "fix should show 'why' field: {}", fix);
        assert!(fix.contains("template level"), "fix should label the template-level example: {}", fix);
        assert!(fix.contains("per resource"), "fix should label the per-resource example: {}", fix);
    }
}
