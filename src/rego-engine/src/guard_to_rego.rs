use guard_translator::ir::*;
use rules::Severity;
use std::collections::HashMap;
use template_model::consts::KEY_TYPE;

pub fn translate_to_rego(
    file: &GuardFile,
    pack_name: &str,
    controls: &[(String, Vec<String>)],
) -> Vec<TranslatedRule> {
    let pkg = sanitize_identifier(pack_name);
    let mut lines = Vec::new();
    lines.push(format!("package guard_{}", pkg));
    lines.push("import rego.v1".into());
    lines.push(String::new());

    // Resource type variable assignments are resolved via resources_of_type() in rule bodies.
    let resource_type_vars = extract_resource_type_vars(&file.assignments);

    for assign in &file.assignments {
        if resource_type_vars.contains_key(&assign.var) {
            continue;
        }
        emit_let_assignment(&mut lines, assign, "");
    }

    let mut rule_ids = Vec::new();
    for rule in &file.rules {
        rule_ids.push(rule.name.clone());
        emit_rule(&mut lines, rule, &resource_type_vars);
    }

    for pr in &file.parameterized_rules {
        emit_parameterized_rule(&mut lines, pr);
    }

    let source = lines.join("\n");

    rule_ids
        .iter()
        .zip(file.rules.iter())
        .map(|(rule_id, rule)| {
            let description = first_custom_message(&rule.block)
                .unwrap_or_else(|| format!("Rule {} failed", rule_id));
            TranslatedRule {
                path: format!("guard/{}/{}.rego", pkg, rule_id),
                source: source.clone(),
                rule_id: rule_id.clone(),
                category: Some(format!("guard:{}", pack_name)),
                description,
                controls: find_controls(controls, rule_id),
            }
        })
        .collect()
}

fn first_custom_message(block: &BlockIR<RuleClauseIR>) -> Option<String> {
    block
        .conjunctions
        .iter()
        .flatten()
        .find_map(|clause| match clause {
            RuleClauseIR::Guard(gc) => extract_custom_message(gc),
            RuleClauseIR::WhenBlock(_, inner) => extract_custom_message_from_block(inner),
            RuleClauseIR::TypeBlock(tb) => extract_custom_message_from_block(&tb.block),
        })
}

fn emit_rule(
    lines: &mut Vec<String>,
    rule: &GuardRule,
    resource_type_vars: &HashMap<String, Vec<String>>,
) {
    let scoped_types = rule
        .conditions
        .as_ref()
        .and_then(|conds| find_resource_types_from_when(conds, resource_type_vars));

    for disj in rule.block.conjunctions.iter() {
        for clause in disj {
            match clause {
                RuleClauseIR::TypeBlock(tb) => {
                    emit_type_block_violation(
                        lines,
                        &rule.name,
                        tb,
                        &rule.conditions,
                        &rule.block.assignments,
                    );
                }
                RuleClauseIR::Guard(gc) => {
                    if let Some(ref types) = scoped_types {
                        for rtype in types {
                            emit_resource_scoped_violation(lines, &rule.name, gc, rtype);
                        }
                    } else {
                        emit_guard_clause_violation(lines, &rule.name, gc, &rule.conditions);
                    }
                }
                RuleClauseIR::WhenBlock(conds, block) => {
                    let mut merged = rule.conditions.clone().unwrap_or_default();
                    merged.extend(conds.clone());
                    for disj2 in &block.conjunctions {
                        for gc in disj2 {
                            if let Some(ref types) = scoped_types {
                                for rtype in types {
                                    emit_resource_scoped_violation(lines, &rule.name, gc, rtype);
                                }
                            } else {
                                emit_guard_clause_violation(
                                    lines,
                                    &rule.name,
                                    gc,
                                    &Some(merged.clone()),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

fn emit_type_block_violation(
    lines: &mut Vec<String>,
    rule_name: &str,
    tb: &TypeBlockIR,
    rule_conditions: &Option<ConjunctionsIR<WhenClauseIR>>,
    assignments: &[LetExprIR],
) {
    let msg = extract_custom_message_from_block(&tb.block)
        .unwrap_or_else(|| format!("Rule {} failed", rule_name));
    let sanitized_msg = sanitize_rego_string(&msg);

    // Each clause must be true; violation fires when any clause fails (negated).
    let mut checks = Vec::new();
    for disj in &tb.block.conjunctions {
        for gc in disj {
            collect_access_checks(gc, &mut checks);
        }
    }

    for gc in &checks {
        lines.push(format!(
            "violation contains make_diag(\"{}\", \"{}\", name, \"{}\") if {{",
            rule_name,
            Severity::Error.as_str(),
            sanitized_msg,
        ));
        lines.push(format!(
            "    some name in resources_of_type(\"{}\")",
            tb.type_name
        ));
        if let Some(conds) = rule_conditions {
            emit_when_conditions_body(lines, conds, "    ");
        }
        for assign in assignments {
            emit_let_assignment(lines, assign, "    ");
        }
        for assign in &tb.block.assignments {
            emit_let_assignment(lines, assign, "    ");
        }
        emit_negated_guard_clause(lines, gc, "    ", "name");
        lines.push("}".into());
        lines.push(String::new());
    }
}

fn emit_guard_clause_violation(
    lines: &mut Vec<String>,
    rule_name: &str,
    gc: &GuardClauseIR,
    conditions: &Option<ConjunctionsIR<WhenClauseIR>>,
) {
    let msg = extract_custom_message(gc).unwrap_or_else(|| format!("Rule {} failed", rule_name));
    lines.push(format!(
        "violation contains make_diag(\"{}\", \"{}\", \"\", \"{}\") if {{",
        rule_name,
        Severity::Error.as_str(),
        sanitize_rego_string(&msg),
    ));
    if let Some(conds) = conditions {
        emit_when_conditions_body(lines, conds, "    ");
    }
    emit_negated_guard_clause(lines, gc, "    ", "\"\"");
    lines.push("}".into());
    lines.push(String::new());
}

fn emit_guard_clause_body(
    lines: &mut Vec<String>,
    gc: &GuardClauseIR,
    indent: &str,
    resource_var: &str,
) {
    match gc {
        GuardClauseIR::Access(ac) => {
            lines.push(format!(
                "{}{}",
                indent,
                access_to_rego_check(ac, resource_var)
            ));
        }
        GuardClauseIR::NamedRule(nr) => {
            let op = if nr.negated { "> 0" } else { "== 0" };
            lines.push(format!(
                "{}count(data.guard_{}.violation) {}",
                indent,
                sanitize_identifier(&nr.rule_name),
                op
            ));
        }
        GuardClauseIR::Block(bc) => {
            for disj in &bc.block.conjunctions {
                for inner in disj {
                    emit_guard_clause_body(lines, inner, indent, resource_var);
                }
            }
        }
        GuardClauseIR::WhenBlock(conds, block) => {
            emit_when_conditions_body(lines, conds, indent);
            for disj in &block.conjunctions {
                for inner in disj {
                    emit_guard_clause_body(lines, inner, indent, resource_var);
                }
            }
        }
        GuardClauseIR::ParameterizedNamedRule(_) => {
            lines.push(format!(
                "{}true # parameterized rule call (complex)",
                indent
            ));
        }
    }
}

fn emit_when_conditions_body(
    lines: &mut Vec<String>,
    conds: &ConjunctionsIR<WhenClauseIR>,
    indent: &str,
) {
    for disj in conds {
        for wc in disj {
            match wc {
                WhenClauseIR::Access(ac) => {
                    lines.push(format!("{}{}", indent, access_to_rego_check(ac, "name")));
                }
                WhenClauseIR::NamedRule(nr) => {
                    lines.push(format!(
                        "{}count(data.guard_{}.violation) == 0",
                        indent,
                        sanitize_identifier(&nr.rule_name)
                    ));
                }
                WhenClauseIR::ParameterizedNamedRule(_) => {
                    lines.push(format!("{}true # parameterized when condition", indent));
                }
            }
        }
    }
}

fn access_to_rego_check(ac: &AccessClauseIR, resource_var: &str) -> String {
    let raw_path = query_parts_to_path(&ac.query);
    let path = strip_variable_prefix(&raw_path);
    let neg = if ac.negated { "not " } else { "" };

    match ac.operator {
        Operator::Exists => {
            if ac.negated {
                format!("not has_property({}, \"{}\")", resource_var, path)
            } else {
                format!("has_property({}, \"{}\")", resource_var, path)
            }
        }
        Operator::Empty => {
            if ac.negated {
                format!("count(resolve({}, \"{}\")) > 0", resource_var, path)
            } else {
                format!("count(resolve({}, \"{}\")) == 0", resource_var, path)
            }
        }
        Operator::Eq => {
            let rhs = ac
                .compare_with
                .as_ref()
                .map(|v| let_value_to_string(v, ""))
                .unwrap_or_else(|| "true".into());
            let op = if ac.negated { "!=" } else { "==" };
            format!("resolve({}, \"{}\") {} {}", resource_var, path, op, rhs)
        }
        Operator::In => {
            let rhs = ac
                .compare_with
                .as_ref()
                .map(|v| let_value_to_string(v, ""))
                .unwrap_or_else(|| "[]".into());
            let val = format!("resolve({}, \"{}\")", resource_var, path);
            if ac.negated {
                format!("not {} in {}", val, rhs)
            } else {
                format!("{} in {}", val, rhs)
            }
        }
        Operator::Gt | Operator::Lt | Operator::Ge | Operator::Le => {
            let op_str = match ac.operator {
                Operator::Gt => ">",
                Operator::Lt => "<",
                Operator::Ge => ">=",
                Operator::Le => "<=",
                _ => unreachable!(),
            };
            let rhs = ac
                .compare_with
                .as_ref()
                .map(|v| let_value_to_string(v, ""))
                .unwrap_or_else(|| "0".into());
            format!("resolve({}, \"{}\") {} {}", resource_var, path, op_str, rhs)
        }
        Operator::IsString => format!("{}is_string(resolve({}, \"{}\"))", neg, resource_var, path),
        Operator::IsList => format!("{}is_array(resolve({}, \"{}\"))", neg, resource_var, path),
        Operator::IsMap => format!("{}is_object(resolve({}, \"{}\"))", neg, resource_var, path),
        Operator::IsBool => format!("{}is_boolean(resolve({}, \"{}\"))", neg, resource_var, path),
        Operator::IsInt | Operator::IsFloat => {
            format!("{}is_number(resolve({}, \"{}\"))", neg, resource_var, path)
        }
        Operator::IsNull => format!("{}is_null(resolve({}, \"{}\"))", neg, resource_var, path),
    }
}

fn emit_let_assignment(lines: &mut Vec<String>, assign: &LetExprIR, indent: &str) {
    lines.push(format!(
        "{}{} := {}",
        indent,
        assign.var,
        let_value_to_string(&assign.value, "")
    ));
}

fn emit_parameterized_rule(lines: &mut Vec<String>, pr: &ParameterizedGuardRule) {
    let params = pr.parameter_names.join(", ");
    lines.push(format!(
        "# Parameterized rule: {}({})",
        pr.rule.name, params
    ));
    lines.push(format!(
        "guard_{}({}) := true if {{",
        sanitize_identifier(&pr.rule.name),
        params
    ));
    for disj in &pr.rule.block.conjunctions {
        for clause in disj {
            match clause {
                RuleClauseIR::Guard(gc) => emit_guard_clause_body(lines, gc, "    ", "name"),
                RuleClauseIR::TypeBlock(tb) => {
                    for disj2 in &tb.block.conjunctions {
                        for gc in disj2 {
                            emit_guard_clause_body(lines, gc, "    ", "name");
                        }
                    }
                }
                _ => {}
            }
        }
    }
    lines.push("}".into());
    lines.push(String::new());
}

/// Strips Guard DSL variable prefixes (`%var.`, `[*].`, `*.`) from property paths.
fn strip_variable_prefix(path: &str) -> String {
    let mut p = path;
    if p.starts_with('%') {
        if let Some(dot_pos) = p.find('.') {
            p = &p[dot_pos + 1..];
        } else {
            return String::new();
        }
    }
    while p.starts_with("[*].") || p.starts_with("*.") {
        p = if p.starts_with("[*].") {
            &p[4..]
        } else {
            &p[2..]
        };
    }
    if p == "[*]" || p == "*" {
        return String::new();
    }
    p.to_string()
}

fn sanitize_rego_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
        .replace('\r', "")
        .replace('\t', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Emits the negation of a guard clause: violation fires when the original check fails.
fn emit_negated_guard_clause(
    lines: &mut Vec<String>,
    gc: &GuardClauseIR,
    indent: &str,
    resource_var: &str,
) {
    match gc {
        GuardClauseIR::Access(ac) => {
            let mut negated = ac.clone();
            negated.negated = !negated.negated;
            lines.push(format!(
                "{}{}",
                indent,
                access_to_rego_check(&negated, resource_var)
            ));
        }
        GuardClauseIR::Block(bc) => {
            for disj in &bc.block.conjunctions {
                if let Some(inner) = disj.iter().next() {
                    emit_negated_guard_clause(lines, inner, indent, resource_var);
                    return;
                }
            }
        }
        GuardClauseIR::WhenBlock(conds, block) => {
            emit_when_conditions_body(lines, conds, indent);
            for disj in &block.conjunctions {
                if let Some(inner) = disj.iter().next() {
                    emit_negated_guard_clause(lines, inner, indent, resource_var);
                    return;
                }
            }
        }
        _ => emit_guard_clause_body(lines, gc, indent, resource_var),
    }
}

fn collect_access_checks(gc: &GuardClauseIR, out: &mut Vec<GuardClauseIR>) {
    match gc {
        GuardClauseIR::Access(_) => out.push(gc.clone()),
        GuardClauseIR::Block(bc) => {
            for disj in &bc.block.conjunctions {
                for inner in disj {
                    collect_access_checks(inner, out);
                }
            }
        }
        GuardClauseIR::WhenBlock(_, block) => {
            for disj in &block.conjunctions {
                for inner in disj {
                    collect_access_checks(inner, out);
                }
            }
        }
        _ => out.push(gc.clone()),
    }
}

fn extract_resource_type_vars(assignments: &[LetExprIR]) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    for assign in assignments {
        if let LetValueIR::Access(parts, _) = &assign.value {
            let types = extract_types_from_filter(parts);
            if !types.is_empty() {
                map.insert(assign.var.clone(), types);
            }
        }
    }
    map
}

fn extract_types_from_filter(parts: &[QueryPartIR]) -> Vec<String> {
    for part in parts {
        if let QueryPartIR::Filter(_, conjunctions) = part {
            for disj in conjunctions {
                for clause in disj {
                    if let GuardClauseIR::Access(ac) = clause {
                        let path = query_parts_to_path(&ac.query);
                        if path != KEY_TYPE || ac.negated {
                            continue;
                        }
                        match ac.operator {
                            Operator::Eq => {
                                if let Some(LetValueIR::Value(ValueIR::String(s))) =
                                    &ac.compare_with
                                {
                                    return vec![s.clone()];
                                }
                            }
                            Operator::In => {
                                if let Some(LetValueIR::Value(ValueIR::List(items))) =
                                    &ac.compare_with
                                {
                                    let types: Vec<String> = items
                                        .iter()
                                        .filter_map(|v| match v {
                                            ValueIR::String(s) => Some(s.clone()),
                                            ValueIR::Regex(s) => Some(s.clone()),
                                            _ => None,
                                        })
                                        .collect();
                                    if !types.is_empty() {
                                        return types;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    Vec::new()
}

fn find_resource_types_from_when(
    conds: &ConjunctionsIR<WhenClauseIR>,
    resource_type_vars: &HashMap<String, Vec<String>>,
) -> Option<Vec<String>> {
    for disj in conds {
        for wc in disj {
            if let WhenClauseIR::Access(ac) = wc
                && let Some(QueryPartIR::Key(key)) = ac.query.first() {
                    let var_name = key.trim_start_matches('%');
                    if let Some(types) = resource_type_vars.get(var_name) {
                        return Some(types.clone());
                    }
                }
        }
    }
    None
}

fn emit_resource_scoped_violation(
    lines: &mut Vec<String>,
    rule_name: &str,
    gc: &GuardClauseIR,
    resource_type: &str,
) {
    let msg = extract_custom_message(gc).unwrap_or_else(|| format!("Rule {} failed", rule_name));
    lines.push(format!(
        "violation contains make_diag(\"{}\", \"{}\", name, \"{}\") if {{",
        rule_name,
        Severity::Error,
        sanitize_rego_string(&msg),
    ));
    lines.push(format!(
        "    some name in resources_of_type(\"{}\")",
        resource_type
    ));
    emit_negated_guard_clause(lines, gc, "    ", "name");
    lines.push("}".into());
    lines.push(String::new());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_variable_prefix_removes_percent_var() {
        assert_eq!(strip_variable_prefix("%var.Properties.X"), "Properties.X");
    }

    #[test]
    fn strip_variable_prefix_no_prefix() {
        assert_eq!(strip_variable_prefix("Properties.X"), "Properties.X");
    }

    #[test]
    fn strip_variable_prefix_percent_only_dot() {
        assert_eq!(strip_variable_prefix("%x.Y"), "Y");
    }

    #[test]
    fn strip_variable_prefix_percent_no_dot() {
        assert_eq!(strip_variable_prefix("%x"), "");
    }

    #[test]
    fn strip_variable_prefix_wildcard_star_dot() {
        assert_eq!(strip_variable_prefix("*.Properties.X"), "Properties.X");
    }

    #[test]
    fn strip_variable_prefix_bracket_star_dot() {
        assert_eq!(strip_variable_prefix("[*].Properties.X"), "Properties.X");
    }

    #[test]
    fn strip_variable_prefix_standalone_star() {
        assert_eq!(strip_variable_prefix("*"), "");
    }

    #[test]
    fn strip_variable_prefix_standalone_bracket_star() {
        assert_eq!(strip_variable_prefix("[*]"), "");
    }

    #[test]
    fn strip_variable_prefix_chained_wildcards() {
        assert_eq!(strip_variable_prefix("[*].*.Properties"), "Properties");
    }

    #[test]
    fn strip_variable_prefix_percent_then_wildcard() {
        // %v. is stripped, then [*]. is stripped, leaving X
        assert_eq!(strip_variable_prefix("%v.[*].X"), "X");
    }

    #[test]
    fn sanitize_rego_string_escapes_quotes() {
        assert_eq!(sanitize_rego_string(r#"say "hello""#), r#"say \"hello\""#);
    }

    #[test]
    fn sanitize_rego_string_escapes_backslash() {
        assert_eq!(sanitize_rego_string(r"path\to"), r"path\\to");
    }

    #[test]
    fn sanitize_rego_string_collapses_whitespace() {
        assert_eq!(sanitize_rego_string("a  b\n\tc"), "a b c");
    }

    #[test]
    fn sanitize_rego_string_removes_carriage_return() {
        assert_eq!(sanitize_rego_string("a\r\nb"), "a b");
    }

    #[test]
    fn sanitize_rego_string_empty() {
        assert_eq!(sanitize_rego_string(""), "");
    }

    fn make_access(
        op: Operator,
        negated: bool,
        compare_with: Option<LetValueIR>,
    ) -> AccessClauseIR {
        AccessClauseIR {
            query: vec![
                QueryPartIR::Key("Properties".into()),
                QueryPartIR::Key("Enabled".into()),
            ],
            match_all: false,
            operator: op,
            negated,
            compare_with,
            custom_message: None,
        }
    }

    #[test]
    fn access_to_rego_check_exists() {
        let ac = make_access(Operator::Exists, false, None);
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"has_property(name, "Properties.Enabled")"#);
    }

    #[test]
    fn access_to_rego_check_not_exists() {
        let ac = make_access(Operator::Exists, true, None);
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"not has_property(name, "Properties.Enabled")"#);
    }

    #[test]
    fn access_to_rego_check_eq() {
        let ac = make_access(
            Operator::Eq,
            false,
            Some(LetValueIR::Value(ValueIR::Bool(true))),
        );
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"resolve(name, "Properties.Enabled") == true"#);
    }

    #[test]
    fn access_to_rego_check_neq() {
        let ac = make_access(
            Operator::Eq,
            true,
            Some(LetValueIR::Value(ValueIR::String("prod".into()))),
        );
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"resolve(name, "Properties.Enabled") != "prod""#);
    }

    #[test]
    fn access_to_rego_check_in() {
        let ac = make_access(
            Operator::In,
            false,
            Some(LetValueIR::Value(ValueIR::List(vec![
                ValueIR::String("a".into()),
                ValueIR::String("b".into()),
            ]))),
        );
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(
            result,
            r#"resolve(name, "Properties.Enabled") in ["a", "b"]"#
        );
    }

    #[test]
    fn access_to_rego_check_not_in() {
        let ac = make_access(
            Operator::In,
            true,
            Some(LetValueIR::Value(ValueIR::List(vec![ValueIR::String(
                "x".into(),
            )]))),
        );
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(
            result,
            r#"not resolve(name, "Properties.Enabled") in ["x"]"#
        );
    }

    #[test]
    fn access_to_rego_check_gt() {
        let ac = make_access(
            Operator::Gt,
            false,
            Some(LetValueIR::Value(ValueIR::Int(10))),
        );
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"resolve(name, "Properties.Enabled") > 10"#);
    }

    #[test]
    fn access_to_rego_check_le() {
        let ac = make_access(
            Operator::Le,
            false,
            Some(LetValueIR::Value(ValueIR::Int(100))),
        );
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"resolve(name, "Properties.Enabled") <= 100"#);
    }

    #[test]
    fn access_to_rego_check_empty() {
        let ac = make_access(Operator::Empty, false, None);
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"count(resolve(name, "Properties.Enabled")) == 0"#);
    }

    #[test]
    fn access_to_rego_check_not_empty() {
        let ac = make_access(Operator::Empty, true, None);
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"count(resolve(name, "Properties.Enabled")) > 0"#);
    }

    #[test]
    fn access_to_rego_check_is_string() {
        let ac = make_access(Operator::IsString, false, None);
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"is_string(resolve(name, "Properties.Enabled"))"#);
    }

    #[test]
    fn access_to_rego_check_not_is_string() {
        let ac = make_access(Operator::IsString, true, None);
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(
            result,
            r#"not is_string(resolve(name, "Properties.Enabled"))"#
        );
    }

    #[test]
    fn access_to_rego_check_is_list() {
        let ac = make_access(Operator::IsList, false, None);
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"is_array(resolve(name, "Properties.Enabled"))"#);
    }

    #[test]
    fn access_to_rego_check_is_null() {
        let ac = make_access(Operator::IsNull, false, None);
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"is_null(resolve(name, "Properties.Enabled"))"#);
    }

    #[test]
    fn access_to_rego_check_strips_variable_prefix() {
        let ac = AccessClauseIR {
            query: vec![
                QueryPartIR::Key("%resource".into()),
                QueryPartIR::Key("Properties".into()),
                QueryPartIR::Key("Name".into()),
            ],
            match_all: false,
            operator: Operator::Exists,
            negated: false,
            compare_with: None,
            custom_message: None,
        };
        let result = access_to_rego_check(&ac, "name");
        assert_eq!(result, r#"has_property(name, "Properties.Name")"#);
    }

    #[test]
    fn extract_resource_type_vars_eq_filter() {
        let assignments = vec![LetExprIR {
            var: "buckets".into(),
            value: LetValueIR::Access(
                vec![
                    QueryPartIR::Key("Resources".into()),
                    QueryPartIR::AllValues(None),
                    QueryPartIR::Filter(
                        None,
                        vec![vec![GuardClauseIR::Access(AccessClauseIR {
                            query: vec![QueryPartIR::Key("Type".into())],
                            match_all: false,
                            operator: Operator::Eq,
                            negated: false,
                            compare_with: Some(LetValueIR::Value(ValueIR::String(
                                "AWS::S3::Bucket".into(),
                            ))),
                            custom_message: None,
                        })]],
                    ),
                ],
                false,
            ),
        }];
        let vars = extract_resource_type_vars(&assignments);
        assert_eq!(
            vars.get("buckets"),
            Some(&vec!["AWS::S3::Bucket".to_string()])
        );
    }

    #[test]
    fn extract_resource_type_vars_in_filter() {
        let assignments = vec![LetExprIR {
            var: "resources".into(),
            value: LetValueIR::Access(
                vec![
                    QueryPartIR::Key("Resources".into()),
                    QueryPartIR::AllValues(None),
                    QueryPartIR::Filter(
                        None,
                        vec![vec![GuardClauseIR::Access(AccessClauseIR {
                            query: vec![QueryPartIR::Key("Type".into())],
                            match_all: false,
                            operator: Operator::In,
                            negated: false,
                            compare_with: Some(LetValueIR::Value(ValueIR::List(vec![
                                ValueIR::String("AWS::S3::Bucket".into()),
                                ValueIR::String("AWS::EC2::Instance".into()),
                            ]))),
                            custom_message: None,
                        })]],
                    ),
                ],
                false,
            ),
        }];
        let vars = extract_resource_type_vars(&assignments);
        let types = vars.get("resources").unwrap();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&"AWS::S3::Bucket".to_string()));
        assert!(types.contains(&"AWS::EC2::Instance".to_string()));
    }

    #[test]
    fn extract_resource_type_vars_no_filter() {
        let assignments = vec![LetExprIR {
            var: "x".into(),
            value: LetValueIR::Value(ValueIR::String("hello".into())),
        }];
        let vars = extract_resource_type_vars(&assignments);
        assert!(vars.is_empty());
    }

    #[test]
    fn extract_types_from_filter_no_filter_parts() {
        let parts = vec![QueryPartIR::Key("Resources".into())];
        assert!(extract_types_from_filter(&parts).is_empty());
    }

    #[test]
    fn extract_types_from_filter_negated_ignored() {
        let parts = vec![QueryPartIR::Filter(
            None,
            vec![vec![GuardClauseIR::Access(AccessClauseIR {
                query: vec![QueryPartIR::Key("Type".into())],
                match_all: false,
                operator: Operator::Eq,
                negated: true,
                compare_with: Some(LetValueIR::Value(ValueIR::String("AWS::S3::Bucket".into()))),
                custom_message: None,
            })]],
        )];
        assert!(extract_types_from_filter(&parts).is_empty());
    }

    #[test]
    fn extract_types_from_filter_non_type_key_ignored() {
        let parts = vec![QueryPartIR::Filter(
            None,
            vec![vec![GuardClauseIR::Access(AccessClauseIR {
                query: vec![QueryPartIR::Key("Name".into())],
                match_all: false,
                operator: Operator::Eq,
                negated: false,
                compare_with: Some(LetValueIR::Value(ValueIR::String("MyBucket".into()))),
                custom_message: None,
            })]],
        )];
        assert!(extract_types_from_filter(&parts).is_empty());
    }

    #[test]
    fn translate_to_rego_empty_file() {
        let file = GuardFile {
            assignments: vec![],
            rules: vec![],
            parameterized_rules: vec![],
        };
        let results = translate_to_rego(&file, "test_pack", &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn translate_to_rego_simple_type_block() {
        let file = GuardFile {
            assignments: vec![],
            rules: vec![GuardRule {
                name: "check_bucket".into(),
                conditions: None,
                block: BlockIR {
                    assignments: vec![],
                    conjunctions: vec![vec![RuleClauseIR::TypeBlock(TypeBlockIR {
                        type_name: "AWS::S3::Bucket".into(),
                        conditions: None,
                        block: BlockIR {
                            assignments: vec![],
                            conjunctions: vec![vec![GuardClauseIR::Access(AccessClauseIR {
                                query: vec![
                                    QueryPartIR::Key("Properties".into()),
                                    QueryPartIR::Key("BucketName".into()),
                                ],
                                match_all: false,
                                operator: Operator::Exists,
                                negated: false,
                                compare_with: None,
                                custom_message: Some("BucketName must exist".into()),
                            })]],
                        },
                        query: vec![],
                    })]],
                },
            }],
            parameterized_rules: vec![],
        };
        let results = translate_to_rego(&file, "test_pack", &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "check_bucket");
        assert!(results[0].source.contains("package guard_test_pack"));
        assert!(results[0].source.contains("violation contains"));
        assert!(
            results[0]
                .source
                .contains(r#"resources_of_type("AWS::S3::Bucket")"#)
        );
        // Violation fires when property does NOT exist (negated)
        assert!(results[0].source.contains("not has_property"));
    }

    #[test]
    fn translate_to_rego_guard_clause_with_eq() {
        let file = GuardFile {
            assignments: vec![],
            rules: vec![GuardRule {
                name: "check_enabled".into(),
                conditions: None,
                block: BlockIR {
                    assignments: vec![],
                    conjunctions: vec![vec![RuleClauseIR::Guard(GuardClauseIR::Access(
                        AccessClauseIR {
                            query: vec![
                                QueryPartIR::Key("Properties".into()),
                                QueryPartIR::Key("Enabled".into()),
                            ],
                            match_all: false,
                            operator: Operator::Eq,
                            negated: false,
                            compare_with: Some(LetValueIR::Value(ValueIR::Bool(true))),
                            custom_message: Some("Must be enabled".into()),
                        },
                    ))]],
                },
            }],
            parameterized_rules: vec![],
        };
        let results = translate_to_rego(&file, "my_rules", &[]);
        assert_eq!(results.len(), 1);
        // Violation negates: Enabled != true
        assert!(results[0].source.contains(r#"!= true"#));
    }

    #[test]
    fn translate_to_rego_with_resource_type_var() {
        let file = GuardFile {
            assignments: vec![LetExprIR {
                var: "buckets".into(),
                value: LetValueIR::Access(
                    vec![
                        QueryPartIR::Key("Resources".into()),
                        QueryPartIR::AllValues(None),
                        QueryPartIR::Filter(
                            None,
                            vec![vec![GuardClauseIR::Access(AccessClauseIR {
                                query: vec![QueryPartIR::Key("Type".into())],
                                match_all: false,
                                operator: Operator::Eq,
                                negated: false,
                                compare_with: Some(LetValueIR::Value(ValueIR::String(
                                    "AWS::S3::Bucket".into(),
                                ))),
                                custom_message: None,
                            })]],
                        ),
                    ],
                    false,
                ),
            }],
            rules: vec![GuardRule {
                name: "bucket_check".into(),
                conditions: Some(vec![vec![WhenClauseIR::Access(AccessClauseIR {
                    query: vec![QueryPartIR::Key("%buckets".into())],
                    match_all: false,
                    operator: Operator::Empty,
                    negated: true,
                    compare_with: None,
                    custom_message: None,
                })]]),
                block: BlockIR {
                    assignments: vec![],
                    conjunctions: vec![vec![RuleClauseIR::Guard(GuardClauseIR::Access(
                        AccessClauseIR {
                            query: vec![
                                QueryPartIR::Key("Properties".into()),
                                QueryPartIR::Key("Tags".into()),
                            ],
                            match_all: false,
                            operator: Operator::Exists,
                            negated: false,
                            compare_with: None,
                            custom_message: Some("Tags required".into()),
                        },
                    ))]],
                },
            }],
            parameterized_rules: vec![],
        };
        let results = translate_to_rego(&file, "s3_rules", &[]);
        assert_eq!(results.len(), 1);
        // Should scope to AWS::S3::Bucket via resources_of_type
        assert!(
            results[0]
                .source
                .contains(r#"resources_of_type("AWS::S3::Bucket")"#)
        );
    }

    #[test]
    fn translate_to_rego_category_and_description() {
        let file = GuardFile {
            assignments: vec![],
            rules: vec![GuardRule {
                name: "my_rule".into(),
                conditions: None,
                block: BlockIR {
                    assignments: vec![],
                    conjunctions: vec![vec![RuleClauseIR::TypeBlock(TypeBlockIR {
                        type_name: "AWS::Lambda::Function".into(),
                        conditions: None,
                        block: BlockIR {
                            assignments: vec![],
                            conjunctions: vec![vec![GuardClauseIR::Access(AccessClauseIR {
                                query: vec![
                                    QueryPartIR::Key("Properties".into()),
                                    QueryPartIR::Key("Runtime".into()),
                                ],
                                match_all: false,
                                operator: Operator::Exists,
                                negated: false,
                                compare_with: None,
                                custom_message: Some("Runtime required".into()),
                            })]],
                        },
                        query: vec![],
                    })]],
                },
            }],
            parameterized_rules: vec![],
        };
        let results = translate_to_rego(&file, "lambda_checks", &[]);
        assert_eq!(results[0].category.as_deref(), Some("guard:lambda_checks"));
        assert_eq!(results[0].description, "Runtime required");
    }

    #[test]
    fn translate_to_rego_parameterized_rule_emitted() {
        let file = GuardFile {
            assignments: vec![],
            rules: vec![],
            parameterized_rules: vec![ParameterizedGuardRule {
                parameter_names: vec!["resource_type".into()],
                rule: GuardRule {
                    name: "check_type".into(),
                    conditions: None,
                    block: BlockIR {
                        assignments: vec![],
                        conjunctions: vec![vec![RuleClauseIR::Guard(GuardClauseIR::Access(
                            AccessClauseIR {
                                query: vec![QueryPartIR::Key("Type".into())],
                                match_all: false,
                                operator: Operator::Exists,
                                negated: false,
                                compare_with: None,
                                custom_message: None,
                            },
                        ))]],
                    },
                },
            }],
        };
        let results = translate_to_rego(&file, "param_test", &[]);
        // No rules emitted (only parameterized), but source should contain the function
        assert!(results.is_empty());
    }

    #[test]
    fn translate_to_rego_from_parsed_guard_source() {
        let source = r#"
rule check_s3_encryption {
    AWS::S3::Bucket {
        Properties.BucketEncryption EXISTS
        <<BucketEncryption must be configured>>
    }
}
"#;
        let file = guard_translator::parse_guard(source, "test.guard").unwrap();
        let results = translate_to_rego(&file, "s3_encryption", &[]);
        assert!(!results.is_empty());
        assert!(results[0].source.contains("violation contains"));
        assert!(results[0].source.contains("AWS::S3::Bucket"));
    }

    #[test]
    fn translate_to_rego_from_parsed_guard_eq_check() {
        let source = r#"
rule check_runtime {
    AWS::Lambda::Function {
        Properties.Runtime == "python3.12"
        <<Runtime must be python3.12>>
    }
}
"#;
        let file = guard_translator::parse_guard(source, "lambda.guard").unwrap();
        let results = translate_to_rego(&file, "lambda_runtime", &[]);
        assert!(!results.is_empty());
        let src = &results[0].source;
        assert!(src.contains("python3.12"));
    }

    #[test]
    fn access_to_rego_check_ge() {
        let ac = make_access(
            Operator::Ge,
            false,
            Some(LetValueIR::Value(ValueIR::Int(5))),
        );
        assert_eq!(
            access_to_rego_check(&ac, "r"),
            r#"resolve(r, "Properties.Enabled") >= 5"#
        );
    }

    #[test]
    fn access_to_rego_check_lt() {
        let ac = make_access(
            Operator::Lt,
            false,
            Some(LetValueIR::Value(ValueIR::Int(3))),
        );
        assert_eq!(
            access_to_rego_check(&ac, "r"),
            r#"resolve(r, "Properties.Enabled") < 3"#
        );
    }

    #[test]
    fn access_to_rego_check_is_map() {
        let ac = make_access(Operator::IsMap, false, None);
        assert_eq!(
            access_to_rego_check(&ac, "r"),
            r#"is_object(resolve(r, "Properties.Enabled"))"#
        );
    }

    #[test]
    fn access_to_rego_check_not_is_map() {
        let ac = make_access(Operator::IsMap, true, None);
        assert_eq!(
            access_to_rego_check(&ac, "r"),
            r#"not is_object(resolve(r, "Properties.Enabled"))"#
        );
    }

    #[test]
    fn access_to_rego_check_is_bool() {
        let ac = make_access(Operator::IsBool, false, None);
        assert_eq!(
            access_to_rego_check(&ac, "r"),
            r#"is_boolean(resolve(r, "Properties.Enabled"))"#
        );
    }

    #[test]
    fn access_to_rego_check_is_int() {
        let ac = make_access(Operator::IsInt, false, None);
        assert_eq!(
            access_to_rego_check(&ac, "r"),
            r#"is_number(resolve(r, "Properties.Enabled"))"#
        );
    }

    #[test]
    fn access_to_rego_check_is_float() {
        let ac = make_access(Operator::IsFloat, false, None);
        assert_eq!(
            access_to_rego_check(&ac, "r"),
            r#"is_number(resolve(r, "Properties.Enabled"))"#
        );
    }

    #[test]
    fn access_to_rego_check_not_is_null() {
        let ac = make_access(Operator::IsNull, true, None);
        assert_eq!(
            access_to_rego_check(&ac, "r"),
            r#"not is_null(resolve(r, "Properties.Enabled"))"#
        );
    }

    #[test]
    fn access_to_rego_check_eq_no_rhs_defaults_true() {
        let ac = make_access(Operator::Eq, false, None);
        assert_eq!(
            access_to_rego_check(&ac, "r"),
            r#"resolve(r, "Properties.Enabled") == true"#
        );
    }

    #[test]
    fn access_to_rego_check_in_no_rhs_defaults_empty_list() {
        let ac = make_access(Operator::In, false, None);
        assert_eq!(
            access_to_rego_check(&ac, "r"),
            r#"resolve(r, "Properties.Enabled") in []"#
        );
    }

    #[test]
    fn access_to_rego_check_gt_no_rhs_defaults_zero() {
        let ac = make_access(Operator::Gt, false, None);
        assert_eq!(
            access_to_rego_check(&ac, "r"),
            r#"resolve(r, "Properties.Enabled") > 0"#
        );
    }

    #[test]
    fn negated_guard_clause_access_flips_negation() {
        // Guard: `Enabled == true` → violation when `Enabled != true`
        let file = guard_translator::parse_guard(
            r#"
rule r1 {
    AWS::S3::Bucket { Properties.Enabled == true <<must be enabled>> }
}
"#,
            "t.guard",
        )
        .unwrap();
        let results = translate_to_rego(&file, "neg", &[]);
        let src = &results[0].source;
        assert!(
            src.contains("!= true"),
            "negated access should flip == to !="
        );
    }

    #[test]
    fn negated_guard_clause_exists_flips_to_not() {
        let file = guard_translator::parse_guard(
            r#"
rule r1 {
    AWS::S3::Bucket { Properties.Name EXISTS <<name required>> }
}
"#,
            "t.guard",
        )
        .unwrap();
        let results = translate_to_rego(&file, "neg2", &[]);
        let src = &results[0].source;
        assert!(
            src.contains("not has_property"),
            "negated EXISTS should become not has_property"
        );
    }

    #[test]
    fn emit_guard_clause_body_named_rule() {
        let mut lines = Vec::new();
        let gc = GuardClauseIR::NamedRule(NamedRuleRefIR {
            rule_name: "other_rule".into(),
            negated: false,
            custom_message: None,
        });
        emit_guard_clause_body(&mut lines, &gc, "    ", "name");
        let joined = lines.join("\n");
        assert!(joined.contains("count(data.guard_other_rule.violation) == 0"));
    }

    #[test]
    fn emit_guard_clause_body_named_rule_negated() {
        let mut lines = Vec::new();
        let gc = GuardClauseIR::NamedRule(NamedRuleRefIR {
            rule_name: "dep".into(),
            negated: true,
            custom_message: None,
        });
        emit_guard_clause_body(&mut lines, &gc, "    ", "name");
        let joined = lines.join("\n");
        assert!(
            joined.contains("> 0"),
            "negated named rule should check > 0"
        );
    }

    #[test]
    fn emit_guard_clause_body_parameterized_named_rule() {
        let mut lines = Vec::new();
        let gc = GuardClauseIR::ParameterizedNamedRule(ParameterizedNamedRuleRefIR {
            rule_name: "check".into(),
            parameters: vec![LetValueIR::Value(ValueIR::String("x".into()))],
            negated: false,
            custom_message: None,
        });
        emit_guard_clause_body(&mut lines, &gc, "    ", "name");
        let joined = lines.join("\n");
        assert!(joined.contains("true # parameterized rule call"));
    }

    #[test]
    fn emit_guard_clause_body_block_recurses() {
        let mut lines = Vec::new();
        let inner = GuardClauseIR::Access(AccessClauseIR {
            query: vec![QueryPartIR::Key("X".into())],
            match_all: false,
            operator: Operator::Exists,
            negated: false,
            compare_with: None,
            custom_message: None,
        });
        let gc = GuardClauseIR::Block(BlockClauseIR {
            query: vec![],
            match_all: false,
            block: BlockIR {
                assignments: vec![],
                conjunctions: vec![vec![inner]],
            },
            not_empty: false,
        });
        emit_guard_clause_body(&mut lines, &gc, "    ", "name");
        let joined = lines.join("\n");
        assert!(joined.contains("has_property(name, \"X\")"));
    }

    #[test]
    fn emit_guard_clause_body_when_block() {
        let mut lines = Vec::new();
        let conds: ConjunctionsIR<WhenClauseIR> =
            vec![vec![WhenClauseIR::Access(AccessClauseIR {
                query: vec![QueryPartIR::Key("Env".into())],
                match_all: false,
                operator: Operator::Eq,
                negated: false,
                compare_with: Some(LetValueIR::Value(ValueIR::String("prod".into()))),
                custom_message: None,
            })]];
        let inner = GuardClauseIR::Access(AccessClauseIR {
            query: vec![QueryPartIR::Key("Tags".into())],
            match_all: false,
            operator: Operator::Exists,
            negated: false,
            compare_with: None,
            custom_message: None,
        });
        let gc = GuardClauseIR::WhenBlock(
            conds,
            BlockIR {
                assignments: vec![],
                conjunctions: vec![vec![inner]],
            },
        );
        emit_guard_clause_body(&mut lines, &gc, "    ", "name");
        let joined = lines.join("\n");
        assert!(
            joined.contains(r#"resolve(name, "Env") == "prod""#),
            "should emit when condition"
        );
        assert!(
            joined.contains(r#"has_property(name, "Tags")"#),
            "should emit inner clause"
        );
    }

    #[test]
    fn emit_when_conditions_body_named_rule() {
        let mut lines = Vec::new();
        let conds: ConjunctionsIR<WhenClauseIR> =
            vec![vec![WhenClauseIR::NamedRule(NamedRuleRefIR {
                rule_name: "prereq".into(),
                negated: false,
                custom_message: None,
            })]];
        emit_when_conditions_body(&mut lines, &conds, "    ");
        let joined = lines.join("\n");
        assert!(joined.contains("count(data.guard_prereq.violation) == 0"));
    }

    #[test]
    fn emit_when_conditions_body_parameterized_named_rule() {
        let mut lines = Vec::new();
        let conds: ConjunctionsIR<WhenClauseIR> = vec![vec![WhenClauseIR::ParameterizedNamedRule(
            ParameterizedNamedRuleRefIR {
                rule_name: "check_param".into(),
                parameters: vec![],
                negated: false,
                custom_message: None,
            },
        )]];
        emit_when_conditions_body(&mut lines, &conds, "    ");
        let joined = lines.join("\n");
        assert!(joined.contains("true # parameterized when condition"));
    }

    #[test]
    fn collect_access_checks_access_clause() {
        let gc = GuardClauseIR::Access(AccessClauseIR {
            query: vec![QueryPartIR::Key("X".into())],
            match_all: false,
            operator: Operator::Exists,
            negated: false,
            compare_with: None,
            custom_message: None,
        });
        let mut out = Vec::new();
        collect_access_checks(&gc, &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn collect_access_checks_block_recurses() {
        let inner = GuardClauseIR::Access(AccessClauseIR {
            query: vec![QueryPartIR::Key("A".into())],
            match_all: false,
            operator: Operator::Exists,
            negated: false,
            compare_with: None,
            custom_message: None,
        });
        let gc = GuardClauseIR::Block(BlockClauseIR {
            query: vec![],
            match_all: false,
            block: BlockIR {
                assignments: vec![],
                conjunctions: vec![vec![inner]],
            },
            not_empty: false,
        });
        let mut out = Vec::new();
        collect_access_checks(&gc, &mut out);
        assert_eq!(out.len(), 1, "should recurse into Block");
    }

    #[test]
    fn collect_access_checks_when_block_recurses() {
        let inner = GuardClauseIR::Access(AccessClauseIR {
            query: vec![QueryPartIR::Key("B".into())],
            match_all: false,
            operator: Operator::Exists,
            negated: false,
            compare_with: None,
            custom_message: None,
        });
        let gc = GuardClauseIR::WhenBlock(
            vec![],
            BlockIR {
                assignments: vec![],
                conjunctions: vec![vec![inner]],
            },
        );
        let mut out = Vec::new();
        collect_access_checks(&gc, &mut out);
        assert_eq!(out.len(), 1, "should recurse into WhenBlock");
    }

    #[test]
    fn collect_access_checks_named_rule_pushed_as_is() {
        let gc = GuardClauseIR::NamedRule(NamedRuleRefIR {
            rule_name: "dep".into(),
            negated: false,
            custom_message: None,
        });
        let mut out = Vec::new();
        collect_access_checks(&gc, &mut out);
        assert_eq!(out.len(), 1, "NamedRule pushed directly");
    }

    #[test]
    fn emit_resource_scoped_violation_output() {
        let mut lines = Vec::new();
        let gc = GuardClauseIR::Access(AccessClauseIR {
            query: vec![
                QueryPartIR::Key("Properties".into()),
                QueryPartIR::Key("Encrypted".into()),
            ],
            match_all: false,
            operator: Operator::Eq,
            negated: false,
            compare_with: Some(LetValueIR::Value(ValueIR::Bool(true))),
            custom_message: Some("Must be encrypted".into()),
        });
        emit_resource_scoped_violation(&mut lines, "enc_check", &gc, "AWS::S3::Bucket");
        let joined = lines.join("\n");
        assert!(joined.contains("violation contains make_diag"));
        assert!(joined.contains(r#"resources_of_type("AWS::S3::Bucket")"#));
        assert!(joined.contains("!= true"), "should negate the check");
        assert!(joined.contains("Must be encrypted"));
    }

    #[test]
    fn translate_guard_with_when_and_resource_type_var() {
        let source = r#"
let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]
rule check_tags when %buckets !empty {
    %buckets.Properties.Tags EXISTS
    <<Tags are required on S3 buckets>>
}
"#;
        let file = guard_translator::parse_guard(source, "tags.guard").unwrap();
        let results = translate_to_rego(&file, "tags", &[]);
        assert!(!results.is_empty());
        let src = &results[0].source;
        assert!(src.contains(r#"resources_of_type("AWS::S3::Bucket")"#));
    }

    #[test]
    fn translate_guard_multiple_checks_in_type_block() {
        let source = r#"
rule multi_check {
    AWS::Lambda::Function {
        Properties.Runtime EXISTS
        Properties.Handler EXISTS
        <<Runtime and Handler are required>>
    }
}
"#;
        let file = guard_translator::parse_guard(source, "multi.guard").unwrap();
        let results = translate_to_rego(&file, "multi", &[]);
        assert_eq!(results.len(), 1);
        let src = &results[0].source;
        // Should produce separate violation rules for each check
        let violation_count = src.matches("violation contains").count();
        assert!(
            violation_count >= 2,
            "each check should produce a violation rule, got {}",
            violation_count
        );
    }
}
