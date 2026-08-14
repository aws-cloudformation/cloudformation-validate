//! Parses Guard DSL files into an engine-agnostic IR.
//!
//! Engine-specific translation (IR → Rego, IR → CEL) lives in each engine crate.

pub mod ir;
pub(crate) mod lower;

use std::fs;
use std::path::Path;

use ir::{BlockIR, ConjunctionsIR, GuardClauseIR, GuardFile, RuleClauseIR, WhenClauseIR};

pub fn parse_guard(source: &str, file_name: &str) -> Result<GuardFile, String> {
    let span = guard_lang::parser::Span::new_extra(source, file_name);
    match guard_lang::parser::rules_file(span) {
        Ok(Some(rules_file)) => Ok(lower::lower_rules_file(&rules_file)),
        Ok(None) => Ok(GuardFile { assignments: Vec::new(), rules: Vec::new(), parameterized_rules: Vec::new() }),
        Err(e) => Err(format!("Failed to parse Guard file '{}': {}", file_name, e)),
    }
}

/// Rejects a Guard file that uses a construct with no faithful translation, so it
/// fails fast at load time instead of being silently mistranslated or crashing a
/// downstream expression parser.
///
/// Each Guard rule is translated to a self-contained expression evaluated once per
/// resource, with no shared namespace holding other rules' results. Cross-rule
/// references (one rule invoking another by name, or a parameterized rule that
/// exists only to be called) therefore have nothing to resolve to and cannot be
/// translated. Such a file is refused with a message naming the rule and the remedy
/// (inline the referenced checks).
pub fn ensure_translatable(file: &GuardFile) -> Result<(), String> {
    if let Some(parameterized) = file.parameterized_rules.first() {
        return Err(format!(
            "Guard rule '{}' is a parameterized rule, which is not supported: a parameterized rule \
             is defined only to be called by other rules, and rules are translated as self-contained \
             per-resource checks that cannot invoke one another. Inline its checks into the calling rule.",
            parameterized.rule.name
        ));
    }
    for rule in &file.rules {
        if let Some(conditions) = &rule.conditions {
            ensure_when_conditions_translatable(&rule.name, conditions)?;
        }
        ensure_rule_block_translatable(&rule.name, &rule.block)?;
    }
    Ok(())
}

fn ensure_rule_block_translatable(rule_name: &str, block: &BlockIR<RuleClauseIR>) -> Result<(), String> {
    for clause in block.conjunctions.iter().flatten() {
        match clause {
            RuleClauseIR::Guard(clause) => ensure_guard_clause_translatable(rule_name, clause)?,
            RuleClauseIR::WhenBlock(conditions, body) => {
                ensure_when_conditions_translatable(rule_name, conditions)?;
                ensure_guard_block_translatable(rule_name, body)?;
            }
            RuleClauseIR::TypeBlock(type_block) => {
                if let Some(conditions) = &type_block.conditions {
                    ensure_when_conditions_translatable(rule_name, conditions)?;
                }
                ensure_guard_block_translatable(rule_name, &type_block.block)?;
            }
        }
    }
    Ok(())
}

fn ensure_guard_block_translatable(rule_name: &str, block: &BlockIR<GuardClauseIR>) -> Result<(), String> {
    for clause in block.conjunctions.iter().flatten() {
        ensure_guard_clause_translatable(rule_name, clause)?;
    }
    Ok(())
}

fn ensure_guard_clause_translatable(rule_name: &str, clause: &GuardClauseIR) -> Result<(), String> {
    match clause {
        GuardClauseIR::Access(_) => Ok(()),
        GuardClauseIR::NamedRule(reference) => Err(cross_rule_reference_error(rule_name, &reference.rule_name)),
        GuardClauseIR::ParameterizedNamedRule(reference) => {
            Err(cross_rule_reference_error(rule_name, &reference.rule_name))
        }
        GuardClauseIR::Block(block) => ensure_guard_block_translatable(rule_name, &block.block),
        GuardClauseIR::WhenBlock(conditions, body) => {
            ensure_when_conditions_translatable(rule_name, conditions)?;
            ensure_guard_block_translatable(rule_name, body)
        }
    }
}

fn ensure_when_conditions_translatable(
    rule_name: &str,
    conditions: &ConjunctionsIR<WhenClauseIR>,
) -> Result<(), String> {
    for condition in conditions.iter().flatten() {
        match condition {
            WhenClauseIR::Access(_) => {}
            WhenClauseIR::NamedRule(reference) => {
                return Err(cross_rule_reference_error(rule_name, &reference.rule_name));
            }
            WhenClauseIR::ParameterizedNamedRule(reference) => {
                return Err(cross_rule_reference_error(rule_name, &reference.rule_name));
            }
        }
    }
    Ok(())
}

fn cross_rule_reference_error(rule_name: &str, referenced_rule: &str) -> String {
    format!(
        "Guard rule '{rule_name}' references another rule ('{referenced_rule}'), which is not supported: \
         each rule is translated to a self-contained per-resource check with no access to another rule's \
         result, so the reference has nothing to resolve to. Inline the checks from '{referenced_rule}' \
         into '{rule_name}' instead."
    )
}

/// Load all `.guard` files from a single directory (non-recursive).
pub fn load_pack_directory(dir: &str) -> Result<Vec<(String, String)>, String> {
    let path = Path::new(dir);
    if !path.is_dir() {
        return Err(format!("Guard rule pack directory not found: {}", dir));
    }
    let mut sources = Vec::new();
    let entries = fs::read_dir(path).map_err(|e| format!("Failed to read pack directory '{}': {}", dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry in '{}': {}", dir, e))?;
        let file_path = entry.path();
        if file_path.extension().and_then(|e| e.to_str()) == Some("guard") {
            let path_str = file_path.display().to_string();
            let content =
                fs::read_to_string(&file_path).map_err(|e| format!("Failed to read '{}': {}", path_str, e))?;
            sources.push((path_str, content));
        }
    }
    if sources.is_empty() {
        return Err(format!("No .guard files found in pack directory: {}", dir));
    }
    sources.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(sources)
}

/// Load all `.guard` files from a directory tree (recursive).
pub fn load_guard_sources_recursive(dir: &str) -> Result<Vec<(String, String)>, String> {
    let path = Path::new(dir);
    if !path.is_dir() {
        return Err(format!("Guard rule directory not found: {}", dir));
    }
    let mut sources = Vec::new();
    collect_guard_files_recursive(path, &mut sources)?;
    if sources.is_empty() {
        return Err(format!("No .guard files found in directory (recursive): {}", dir));
    }
    sources.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(sources)
}

fn collect_guard_files_recursive(dir: &Path, out: &mut Vec<(String, String)>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("Failed to read directory '{}': {}", dir.display(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry in '{}': {}", dir.display(), e))?;
        let path = entry.path();
        if path.is_dir() {
            collect_guard_files_recursive(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("guard") {
            let path_str = path.display().to_string();
            let content = fs::read_to_string(&path).map_err(|e| format!("Failed to read '{}': {}", path_str, e))?;
            out.push((path_str, content));
        }
    }
    Ok(())
}

/// Derive a pack name from a file path by taking the file stem and replacing
/// non-alphanumeric characters with `_`.
///
/// e.g. `"security-policies/elb-listener.guard"` → `"elb_listener"`
pub fn pack_name_from_path(path: &str) -> String {
    let stem = path.rsplit('/').next().unwrap_or(path).trim_end_matches(".guard").trim_end_matches(".ruleset");
    stem.chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

#[cfg(test)]
mod translatable_tests {
    use super::*;

    #[test]
    fn plain_type_block_rule_is_translatable() {
        let file = parse_guard(
            r#"
rule check_bucket {
    AWS::S3::Bucket {
        Properties.BucketName EXISTS
        <<BucketName required>>
    }
}
"#,
            "t.guard",
        )
        .unwrap();
        ensure_translatable(&file).expect("a self-contained type-block rule must be translatable");
    }

    #[test]
    fn named_rule_reference_in_body_is_rejected() {
        let file = parse_guard(
            r#"
rule base_check {
    AWS::S3::Bucket {
        Properties.BucketName EXISTS
    }
}
rule dependent_check {
    base_check
    AWS::S3::Bucket {
        Properties.VersioningConfiguration EXISTS
    }
}
"#,
            "t.guard",
        )
        .unwrap();
        let err = ensure_translatable(&file).expect_err("a rule that references another rule must be rejected");
        assert!(err.contains("dependent_check"), "error should name the referencing rule, got: {err}");
        assert!(err.contains("base_check"), "error should name the referenced rule, got: {err}");
    }

    #[test]
    fn named_rule_reference_in_when_condition_is_rejected() {
        // `when base_check` is a cross-rule reference in the rule's guard condition.
        let file = parse_guard(
            r#"
rule base_check {
    AWS::S3::Bucket {
        Properties.BucketName EXISTS
    }
}
rule derived when base_check {
    AWS::S3::Bucket {
        Properties.Tags EXISTS
    }
}
"#,
            "t.guard",
        )
        .unwrap();
        let err = ensure_translatable(&file).expect_err("a when-condition rule reference must be rejected");
        assert!(err.contains("base_check"), "error should name the referenced rule, got: {err}");
    }

    #[test]
    fn parameterized_rule_is_rejected() {
        let file = parse_guard(
            r#"
rule check_type(expected) {
    Properties.Type == %expected
}
"#,
            "t.guard",
        )
        .unwrap();
        let err = ensure_translatable(&file).expect_err("a parameterized rule must be rejected");
        assert!(err.contains("check_type"), "error should name the parameterized rule, got: {err}");
    }

    #[test]
    fn empty_file_is_translatable() {
        let file = parse_guard("", "empty.guard").unwrap();
        ensure_translatable(&file).expect("an empty guard file has nothing untranslatable");
    }
}
