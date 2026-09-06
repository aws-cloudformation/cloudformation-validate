//! Enforcement scan proving that every direct built-in handwritten violation
//! clause begins its body with `cfn_rule_active("<its own rule id>")`, and that
//! the aggregator clauses are deliberately left unguarded. Scanning the embedded
//! policy sources keeps guard coverage from rotting: a new violation clause that
//! forgets the guard, carries the wrong rule id, or is written in an
//! unrecognized shape fails this test.

use crate::policies::HANDWRITTEN_REGO_POLICIES;

/// A clause head that emits a diagnostic through one of the `make_diag*` builtins.
const DIRECT_CLAUSE_HEAD: &str = "violation contains make_diag";
/// The aggregator clause head; these fan the per-category violation sets into the
/// top-level set and must not be guarded.
const AGGREGATOR_HEAD: &str = "violation contains v if {";
const VIOLATION_HEAD: &str = "violation contains ";

/// The literal rule id in a `make_diag*("<id>", ...)` head - the text between the
/// first pair of double quotes on the line.
fn rule_id_of(head_line: &str) -> Option<&str> {
    let after_open = head_line.find('"')? + 1;
    let rest = &head_line[after_open..];
    let close = rest.find('"')?;
    Some(&rest[..close])
}

struct GuardScan {
    direct_clauses: usize,
    aggregators: usize,
}

/// Walks every clause in one policy source, asserting each direct clause is
/// guarded first and each aggregator is unguarded, and panics on any violation
/// clause written in an unrecognized shape.
fn scan_policy(path: &str, source: &str) -> GuardScan {
    let lines: Vec<&str> = source.lines().collect();
    let mut direct_clauses = 0;
    let mut aggregators = 0;
    let mut index = 0;

    while index < lines.len() {
        let trimmed = lines[index].trim();
        if !trimmed.starts_with(VIOLATION_HEAD) {
            index += 1;
            continue;
        }

        if trimmed.starts_with(DIRECT_CLAUSE_HEAD) {
            let rule_id = rule_id_of(trimmed)
                .unwrap_or_else(|| panic!("{path}: direct clause head has no literal rule id: {trimmed}"));

            let opener = (index..lines.len())
                .find(|&candidate| lines[candidate].trim_end().ends_with("if {"))
                .unwrap_or_else(|| panic!("{path}: no body opener for clause '{rule_id}'"));

            let first_condition = (opener + 1..lines.len())
                .map(|line| lines[line].trim())
                .find(|body_line| !body_line.is_empty())
                .unwrap_or_else(|| panic!("{path}: clause '{rule_id}' has an empty body"));

            let expected = format!("cfn_rule_active(\"{rule_id}\")");
            assert_eq!(
                first_condition, expected,
                "{path}: clause '{rule_id}' must begin its body with {expected}, found: {first_condition}"
            );
            direct_clauses += 1;
            index = opener + 1;
        } else if trimmed.starts_with(AGGREGATOR_HEAD) {
            assert!(
                trimmed.contains(".violation }"),
                "{path}: '{trimmed}' looks like an aggregator but does not fan in a category violation set"
            );
            assert!(!trimmed.contains("cfn_rule_active"), "{path}: aggregator clauses must not be guarded: {trimmed}");
            aggregators += 1;
            index += 1;
        } else {
            panic!(
                "{path}: unrecognized violation clause shape - every clause must be a make_diag* direct clause or an \
                 all_violations aggregator so guard coverage stays enforceable: {trimmed}"
            );
        }
    }

    GuardScan { direct_clauses, aggregators }
}

#[test]
fn every_direct_builtin_clause_is_guarded_and_aggregators_are_not() {
    let mut direct_clauses = 0;
    let mut aggregators = 0;
    for (path, source) in HANDWRITTEN_REGO_POLICIES {
        let scan = scan_policy(path, source);
        direct_clauses += scan.direct_clauses;
        aggregators += scan.aggregators;
    }

    // The five aggregators (one per category) are the only unguarded violation
    // clauses; the exemption is locked so a new unguarded direct clause cannot
    // masquerade as one.
    assert_eq!(aggregators, 5, "expected exactly five all_violations aggregators, found {aggregators}");

    // A sanity floor so a parsing regression that finds no clauses cannot pass
    // vacuously. The per-clause assertions above are what actually prevent rot.
    assert!(
        direct_clauses >= 300,
        "expected the full set of guarded built-in violation clauses, only scanned {direct_clauses}"
    );
}
