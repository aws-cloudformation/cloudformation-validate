//! Guard DSL support shared by every rule engine.
//!
//! A Guard rule file is parsed once when it is loaded and evaluated by the
//! CloudFormation Guard evaluator itself (`cloudformation-guard-lang`) against the
//! template as the author wrote it. Every engine therefore reports exactly the
//! checks `cfn-guard validate` reports, and none of them re-implements Guard
//! semantics. This crate turns the evaluator's report into engine-agnostic
//! [`GuardFinding`]s; the validation pipeline maps those onto diagnostics.

use guard_lang::Status;
use guard_lang::UnResolved;
use guard_lang::eval::eval_rules_file;
use guard_lang::eval_context::{
    BinaryCheck, ClauseReport, GuardClauseReport, Messages, UnaryCheck, root_scope, simplified_json_from_root,
};
use guard_lang::exprs::{Block, GuardClause, Rule, RuleClause, RulesFile};
use guard_lang::parser::{Span, rules_file};
use guard_lang::path_value::{Path as GuardPath, PathAwareValue};
use std::fs;
use std::path::Path;
use std::rc::Rc;

/// A Guard rule declared in a rule file, with the metadata the rule listing shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardRuleInfo {
    pub name: String,
    /// The first `<<message>>` the rule carries, which is the best available
    /// one-line description of what the rule checks.
    pub custom_message: Option<String>,
}

/// One failed Guard check, located by the template path the evaluator reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardFinding {
    /// The top-level rule the failed check belongs to.
    pub rule_name: String,
    /// Slash-separated path from the template root to the value the check was
    /// evaluated against (`Resources/Bucket/Properties/BucketName`), or to the
    /// deepest value that exists when the checked property is missing. `None`
    /// when the failure has no template location, such as a failed dependency
    /// on another rule.
    pub path: Option<String>,
    /// The remainder of the query the evaluator could not resolve from `path`,
    /// present exactly when the check failed because a property is missing.
    pub missing_query: Option<String>,
    /// The author's `<<message>>` for the failed check, when one was written.
    pub custom_message: Option<String>,
    /// The failed check as the evaluator describes it, whitespace-normalized
    /// (`Properties.BucketName EQUALS "foo"`).
    pub check: String,
}

/// A parsed Guard rule file, ready to be evaluated against any template.
///
/// The Guard parser borrows from the source text, so the file keeps the text
/// and re-parses it per evaluation; a syntax error is still caught once, here,
/// at load time.
#[derive(Debug, Clone)]
pub struct GuardRuleFile {
    name: String,
    pack: String,
    source: String,
    rules: Vec<GuardRuleInfo>,
}

impl GuardRuleFile {
    /// Parses `source`, reporting a syntax error with the file name, and records
    /// each declared rule's name and first custom message.
    pub fn parse(name: impl Into<String>, source: impl Into<String>) -> Result<Self, String> {
        let name = name.into();
        let source = source.into();
        let rules = match parse_rules(&source, &name)? {
            Some(rules_file) => rules_file
                .guard_rules
                .iter()
                .map(|rule| GuardRuleInfo { name: rule.rule_name.clone(), custom_message: first_custom_message(rule) })
                .collect(),
            None => Vec::new(),
        };
        let pack = pack_name_from_path(&name);
        Ok(Self { name, pack, source, rules })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The pack the file's rules belong to, derived from the file name.
    pub fn pack(&self) -> &str {
        &self.pack
    }

    pub fn rules(&self) -> &[GuardRuleInfo] {
        &self.rules
    }

    /// Evaluates every rule in the file against `template`, the authored template
    /// as CloudFormation JSON, and returns one finding per failed check. Rules that
    /// pass or are skipped by their `when` conditions produce nothing.
    pub fn evaluate(&self, template: &serde_json::Value) -> Result<Vec<GuardFinding>, String> {
        let Some(rules_file) = parse_rules(&self.source, &self.name)? else {
            return Ok(Vec::new());
        };
        let root = PathAwareValue::try_from((template, GuardPath::root()))
            .map_err(|error| format!("Failed to load the template for Guard file '{}': {}", self.name, error))?;
        let mut scope = root_scope(&rules_file, Rc::new(root));
        let status = eval_rules_file(&rules_file, &mut scope, Some(&self.name))
            .map_err(|error| format!("Guard file '{}' failed to evaluate: {}", self.name, error))?;
        if status != Status::FAIL {
            return Ok(Vec::new());
        }
        let mut recorder = scope.reset_recorder();
        let record = recorder
            .final_event
            .take()
            .ok_or_else(|| format!("Guard file '{}' produced no evaluation record", self.name))?;
        let report = simplified_json_from_root(&record).map_err(|error| {
            format!("Guard file '{}' produced an unreadable evaluation record: {}", self.name, error)
        })?;

        let mut findings = Vec::new();
        for failed_rule in &report.not_compliant {
            if let ClauseReport::Rule(rule) = failed_rule {
                for check in &rule.checks {
                    collect_findings(check, rule.name, &mut findings);
                }
            }
        }
        Ok(findings)
    }
}

fn parse_rules<'source>(source: &'source str, name: &'source str) -> Result<Option<RulesFile<'source>>, String> {
    rules_file(Span::new_extra(source, name))
        .map_err(|error| format!("Failed to parse Guard file '{}': {}", name, error))
}

fn first_custom_message(rule: &Rule<'_>) -> Option<String> {
    rule.block.conjunctions.iter().flatten().find_map(|clause| match clause {
        RuleClause::Clause(guard_clause) => guard_clause_custom_message(guard_clause),
        RuleClause::WhenBlock(_, block) => block_custom_message(block),
        RuleClause::TypeBlock(type_block) => block_custom_message(&type_block.block),
    })
}

fn block_custom_message(block: &Block<'_, GuardClause<'_>>) -> Option<String> {
    block.conjunctions.iter().flatten().find_map(guard_clause_custom_message)
}

fn guard_clause_custom_message(clause: &GuardClause<'_>) -> Option<String> {
    match clause {
        GuardClause::Clause(access) => access.access_clause.custom_message.clone(),
        GuardClause::NamedRule(named) => named.custom_message.clone(),
        GuardClause::ParameterizedNamedRule(parameterized) => parameterized.named_rule.custom_message.clone(),
        GuardClause::BlockClause(block) => block_custom_message(&block.block),
        GuardClause::WhenBlock(_, block) => block_custom_message(block),
    }
}

/// Flattens the evaluator's report tree for one rule into findings. A group of
/// alternatives (`A OR B`) fails as a whole, so it yields a single finding that
/// names every alternative and is located at the first alternative that has a
/// location; nested rule reports are attributed to the top-level rule that
/// invoked them.
fn collect_findings(report: &ClauseReport<'_>, rule_name: &str, findings: &mut Vec<GuardFinding>) {
    match report {
        ClauseReport::Rule(nested) => {
            for check in &nested.checks {
                collect_findings(check, rule_name, findings);
            }
        }
        ClauseReport::Disjunctions(alternatives) => {
            let mut alternative_findings = Vec::new();
            for alternative in &alternatives.checks {
                collect_findings(alternative, rule_name, &mut alternative_findings);
            }
            if let Some(merged) = merge_alternatives(alternative_findings) {
                findings.push(merged);
            }
        }
        ClauseReport::Block(block) => {
            let (path, missing_query) = match &block.unresolved {
                Some(unresolved) => unresolved_location(unresolved),
                None => (None, None),
            };
            let check = match &block.unresolved {
                Some(unresolved) => unresolved.remaining_query.clone(),
                None => normalize_whitespace(&block.context),
            };
            findings.push(GuardFinding {
                rule_name: rule_name.to_string(),
                path,
                missing_query,
                custom_message: custom_message(&block.messages),
                check,
            });
        }
        ClauseReport::Clause(GuardClauseReport::Unary(unary)) => {
            let (path, missing_query) = match &unary.check {
                UnaryCheck::Resolved(comparison) => (Some(template_path(&comparison.value)), None),
                UnaryCheck::UnResolved(unresolved) => unresolved_location(&unresolved.value),
                UnaryCheck::UnResolvedContext(_) => (None, None),
            };
            findings.push(GuardFinding {
                rule_name: rule_name.to_string(),
                path,
                missing_query,
                custom_message: custom_message(&unary.messages),
                check: normalize_whitespace(&unary.context),
            });
        }
        ClauseReport::Clause(GuardClauseReport::Binary(binary)) => {
            let (path, missing_query) = match &binary.check {
                BinaryCheck::Resolved(comparison) => (Some(template_path(&comparison.from)), None),
                BinaryCheck::InResolved(comparison) => (Some(template_path(&comparison.from)), None),
                BinaryCheck::UnResolved(unresolved) => unresolved_location(&unresolved.value),
            };
            findings.push(GuardFinding {
                rule_name: rule_name.to_string(),
                path,
                missing_query,
                custom_message: custom_message(&binary.messages),
                check: normalize_whitespace(&binary.context),
            });
        }
    }
}

fn merge_alternatives(alternatives: Vec<GuardFinding>) -> Option<GuardFinding> {
    let mut alternatives = alternatives.into_iter();
    let mut merged = alternatives.next()?;
    for alternative in alternatives {
        if merged.path.is_none() {
            merged.path = alternative.path;
            merged.missing_query = alternative.missing_query;
        }
        if merged.custom_message.is_none() {
            merged.custom_message = alternative.custom_message;
        }
        merged.check.push_str(" OR ");
        merged.check.push_str(&alternative.check);
    }
    Some(merged)
}

fn unresolved_location(unresolved: &UnResolved) -> (Option<String>, Option<String>) {
    (Some(template_path(&unresolved.traversed_to)), Some(unresolved.remaining_query.clone()))
}

/// The evaluator addresses values with a leading slash (`/Resources/Bucket`); the
/// template root is the empty path.
fn template_path(value: &PathAwareValue) -> String {
    value.self_path().0.trim_start_matches('/').to_string()
}

/// The evaluator records an empty custom message when the author wrote none.
fn custom_message(messages: &Messages) -> Option<String> {
    messages.custom_message.as_deref().map(str::trim).filter(|message| !message.is_empty()).map(str::to_string)
}

fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
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
