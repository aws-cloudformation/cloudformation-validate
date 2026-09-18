//! Enforcement scan proving that every built-in handwritten violation clause
//! begins its body with `cfn_rule_active("<its own rule id>")`. Scanning the
//! embedded policy sources keeps guard coverage from rotting: a new violation
//! clause that forgets the guard, carries the wrong rule id, or is written in an
//! unrecognized shape fails this test.

use crate::policies::HANDWRITTEN_REGO_POLICIES;

/// A clause head that emits a diagnostic through one of the `make_diag*` builtins.
const DIRECT_CLAUSE_HEAD: &str = "violation contains make_diag";
const VIOLATION_HEAD: &str = "violation contains ";

/// The literal rule id in a `make_diag*("<id>", ...)` head - the text between the
/// first pair of double quotes on the line.
fn rule_id_of(head_line: &str) -> Option<&str> {
    let after_open = head_line.find('"')? + 1;
    let rest = &head_line[after_open..];
    let close = rest.find('"')?;
    Some(&rest[..close])
}

/// Walks every clause in one policy source, asserting each is a direct clause
/// whose body starts with its own guard, and panics on any violation clause
/// written in an unrecognized shape. Returns the number of clauses checked.
fn scan_policy(path: &str, source: &str) -> usize {
    let lines: Vec<&str> = source.lines().collect();
    let mut direct_clauses = 0;
    let mut index = 0;

    while index < lines.len() {
        let trimmed = lines[index].trim();
        if !trimmed.starts_with(VIOLATION_HEAD) {
            index += 1;
            continue;
        }

        assert!(
            trimmed.starts_with(DIRECT_CLAUSE_HEAD),
            "{path}: unrecognized violation clause shape - every clause must be a make_diag* direct clause so guard \
             coverage stays enforceable: {trimmed}"
        );
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
    }

    direct_clauses
}

#[test]
fn every_builtin_violation_clause_is_guarded() {
    let direct_clauses: usize = HANDWRITTEN_REGO_POLICIES.iter().map(|(path, source)| scan_policy(path, source)).sum();

    // A sanity floor so a parsing regression that finds no clauses cannot pass
    // vacuously. The per-clause assertions above are what actually prevent rot.
    assert!(
        direct_clauses >= 300,
        "expected the full set of guarded built-in violation clauses, only scanned {direct_clauses}"
    );
}
