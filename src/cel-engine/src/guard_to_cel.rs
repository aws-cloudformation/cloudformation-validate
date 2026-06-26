//! Translates Guard IR into CEL custom rule descriptors.
//!
//! Guard rules use pass semantics (expression must be true). CEL custom rules use
//! violation semantics (expression triggers a diagnostic when true). Each Guard clause
//! is therefore negated during translation.

use guard_translator::ir::*;
use rules::Severity;
use std::collections::HashMap;
use template_model::consts::KEY_TYPE;

const CEL_PATH_PREFIX: &str = "resource.";

pub fn translate_to_cel(
    file: &GuardFile,
    pack_name: &str,
    controls: &[(String, Vec<String>)],
) -> Vec<TranslatedCelRule> {
    let resource_type_vars = extract_resource_type_vars(&file.assignments);

    let scoped_types_for_rule = |rule: &GuardRule| -> Option<Vec<String>> {
        rule.conditions.as_ref().and_then(|conds| find_resource_types_from_when(conds, &resource_type_vars))
    };

    let mut rules = Vec::new();
    for rule in &file.rules {
        let scoped_types = scoped_types_for_rule(rule);
        let target_types: Vec<Option<String>> = match &scoped_types {
            Some(types) => types.iter().map(|t| Some(t.clone())).collect(),
            None => vec![None],
        };

        for disj in &rule.block.conjunctions {
            for clause in disj {
                match clause {
                    RuleClauseIR::TypeBlock(tb) => {
                        emit_type_block_cel(&mut rules, &rule.name, tb, pack_name, controls);
                    }
                    RuleClauseIR::Guard(gc) => {
                        for rtype in &target_types {
                            rules.push(build_cel_violation_rule(&rule.name, gc, rtype.as_deref(), pack_name, controls));
                        }
                    }
                    RuleClauseIR::WhenBlock(_conds, block) => {
                        for disj2 in &block.conjunctions {
                            for gc in disj2 {
                                for rtype in &target_types {
                                    rules.push(build_cel_violation_rule(
                                        &rule.name,
                                        gc,
                                        rtype.as_deref(),
                                        pack_name,
                                        controls,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    rules
}

fn emit_type_block_cel(
    rules: &mut Vec<TranslatedCelRule>,
    rule_name: &str,
    tb: &TypeBlockIR,
    pack_name: &str,
    controls: &[(String, Vec<String>)],
) {
    let ctrl = find_controls(controls, rule_name);
    for disj in &tb.block.conjunctions {
        for gc in disj {
            let msg = extract_custom_message(gc).unwrap_or_else(|| format!("Rule {} failed", rule_name));
            let expr = negate_cel_expr(&guard_clause_to_cel_expr(gc));
            rules.push(TranslatedCelRule {
                rule_id: rule_name.to_string(),
                severity: Severity::Error,
                category: Some(format!("guard:{}", pack_name)),
                resource_type: Some(tb.type_name.clone()),
                expression: expr,
                message: msg,
                prop_path: None,
                suggested_fix: None,
                controls: ctrl.clone(),
            });
        }
    }
}

fn build_cel_violation_rule(
    rule_name: &str,
    gc: &GuardClauseIR,
    resource_type: Option<&str>,
    pack_name: &str,
    controls: &[(String, Vec<String>)],
) -> TranslatedCelRule {
    TranslatedCelRule {
        rule_id: rule_name.to_string(),
        severity: Severity::Error,
        category: Some(format!("guard:{}", pack_name)),
        resource_type: resource_type.map(String::from),
        expression: negate_cel_expr(&guard_clause_to_cel_expr(gc)),
        message: extract_custom_message(gc).unwrap_or_else(|| format!("Rule {} failed", rule_name)),
        prop_path: None,
        suggested_fix: None,
        controls: find_controls(controls, rule_name),
    }
}

fn guard_clause_to_cel_expr(gc: &GuardClauseIR) -> String {
    match gc {
        GuardClauseIR::Access(ac) => access_to_cel(ac),
        GuardClauseIR::Block(bc) => {
            let exprs: Vec<String> =
                bc.block.conjunctions.iter().flat_map(|disj| disj.iter().map(guard_clause_to_cel_expr)).collect();
            if exprs.is_empty() { "true".into() } else { exprs.join(" && ") }
        }
        GuardClauseIR::WhenBlock(conds, block) => {
            let body_exprs: Vec<String> =
                block.conjunctions.iter().flat_map(|disj| disj.iter().map(guard_clause_to_cel_expr)).collect();
            let body = if body_exprs.is_empty() { "true".into() } else { body_exprs.join(" && ") };
            match when_conditions_to_cel(conds) {
                Some(we) => format!("({}) && ({})", we, body),
                None => body,
            }
        }
        GuardClauseIR::NamedRule(nr) => format!("true /* depends on rule: {} */", nr.rule_name),
        GuardClauseIR::ParameterizedNamedRule(pnr) => {
            format!("true /* depends on parameterized rule: {} */", pnr.rule_name)
        }
    }
}

fn access_to_cel(ac: &AccessClauseIR) -> String {
    let path = query_to_cel_path(&ac.query);
    let neg_prefix = if ac.negated { "!" } else { "" };
    let resource_path = if path.is_empty() { "resource".into() } else { format!("resource.{}", path) };

    match ac.operator {
        Operator::Exists => format!("{}has({})", neg_prefix, resource_path),
        Operator::Empty => {
            if ac.negated {
                format!("size({}) > 0", resource_path)
            } else {
                format!("size({}) == 0", resource_path)
            }
        }
        Operator::Eq => {
            let rhs = ac
                .compare_with
                .as_ref()
                .map(|v| let_value_to_string(v, CEL_PATH_PREFIX))
                .unwrap_or_else(|| "true".into());
            let op = if ac.negated { "!=" } else { "==" };
            format!("{} {} {}", resource_path, op, rhs)
        }
        Operator::In => {
            let rhs = ac
                .compare_with
                .as_ref()
                .map(|v| let_value_to_string(v, CEL_PATH_PREFIX))
                .unwrap_or_else(|| "[]".into());
            if ac.negated {
                format!("!({} in {})", resource_path, rhs)
            } else {
                format!("{} in {}", resource_path, rhs)
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
            let rhs =
                ac.compare_with.as_ref().map(|v| let_value_to_string(v, CEL_PATH_PREFIX)).unwrap_or_else(|| "0".into());
            format!("{} {} {}", resource_path, op_str, rhs)
        }
        Operator::IsString => format!("{}(type({}) == \"string\")", neg_prefix, resource_path),
        Operator::IsList => format!("{}(type({}) == \"list\")", neg_prefix, resource_path),
        Operator::IsMap => format!("{}(type({}) == \"map\")", neg_prefix, resource_path),
        Operator::IsBool => format!("{}(type({}) == \"bool\")", neg_prefix, resource_path),
        Operator::IsInt | Operator::IsFloat => {
            format!("{}(type({}) == \"int\" || type({}) == \"double\")", neg_prefix, resource_path, resource_path)
        }
        Operator::IsNull => format!("{}({} == null)", neg_prefix, resource_path),
    }
}

fn when_conditions_to_cel(conds: &ConjunctionsIR<WhenClauseIR>) -> Option<String> {
    let parts: Vec<String> = conds
        .iter()
        .flat_map(|disj| {
            disj.iter().map(|wc| match wc {
                WhenClauseIR::Access(ac) => access_to_cel(ac),
                WhenClauseIR::NamedRule(nr) => {
                    format!("true /* when rule: {} */", nr.rule_name)
                }
                WhenClauseIR::ParameterizedNamedRule(pnr) => {
                    format!("true /* when param rule: {} */", pnr.rule_name)
                }
            })
        })
        .collect();
    if parts.is_empty() { None } else { Some(parts.join(" && ")) }
}

fn query_to_cel_path(parts: &[QueryPartIR]) -> String {
    parts
        .iter()
        .filter_map(|p| match p {
            QueryPartIR::Key(k) => {
                if let Some(stripped) = k.strip_prefix('%') {
                    Some(stripped.to_string())
                } else {
                    Some(k.clone())
                }
            }
            QueryPartIR::Index(i) => Some(format!("[{}]", i)),
            QueryPartIR::AllValues(_) | QueryPartIR::AllIndices(_) | QueryPartIR::This => None,
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(".")
}

pub fn to_custom_rule_json(rules: &[TranslatedCelRule]) -> Result<String, String> {
    #[derive(serde::Serialize)]
    struct Wrapper<'a> {
        rules: &'a [TranslatedCelRule],
    }
    serde_json::to_string(&Wrapper { rules }).map_err(|e| format!("Failed to serialize guard rules to CEL JSON: {}", e))
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
                                if let Some(LetValueIR::Value(ValueIR::String(s))) = &ac.compare_with {
                                    return vec![s.clone()];
                                }
                            }
                            Operator::In => {
                                if let Some(LetValueIR::Value(ValueIR::List(items))) = &ac.compare_with {
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
                && let Some(QueryPartIR::Key(key)) = ac.query.first()
            {
                let var_name = key.trim_start_matches('%');
                if let Some(types) = resource_type_vars.get(var_name) {
                    return Some(types.clone());
                }
            }
        }
    }
    None
}

fn negate_cel_expr(expr: &str) -> String {
    if let Some(inner) = expr.strip_prefix("has(") {
        // has(a.b.c) → !has(a.b) || !has(a.b.c)
        // Each intermediate must be guarded because CEL errors on missing parents.
        let prop = inner.trim_end_matches(')');
        let segments: Vec<&str> = prop.splitn(2, '.').collect();
        if segments.len() < 2 {
            return format!("!has({})", prop);
        }
        // Build chain: !has(root.a) || !has(root.a.b) || ...
        let parts: Vec<&str> = prop.split('.').collect();
        let mut conditions = Vec::new();
        for i in 1..parts.len() {
            let path = parts[..=i].join(".");
            conditions.push(format!("!has({})", path));
        }
        return conditions.join(" || ");
    }
    if let Some(rest) = expr.strip_prefix("!has(") {
        return format!("has({}", rest);
    }
    if expr.contains(" == ") {
        return expr.replacen(" == ", " != ", 1);
    }
    if expr.contains(" != ") {
        return expr.replacen(" != ", " == ", 1);
    }
    if expr.contains(" in ") && !expr.starts_with("!(") {
        return format!("!({})", expr);
    }
    if expr.starts_with("size(") {
        if expr.contains(") == 0") {
            return expr.replacen(") == 0", ") > 0", 1);
        }
        if expr.contains(") > 0") {
            return expr.replacen(") > 0", ") == 0", 1);
        }
    }
    format!("({}) == false", expr)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use guard_translator::ir::*;

    #[test]
    fn negate_has_expr_guards_intermediate_paths() {
        assert_eq!(
            negate_cel_expr("has(resource.Properties.BucketEncryption)"),
            "!has(resource.Properties) || !has(resource.Properties.BucketEncryption)"
        );
    }

    #[test]
    fn negate_has_single_segment() {
        assert_eq!(negate_cel_expr("has(resource)"), "!has(resource)");
    }

    #[test]
    fn negate_not_has_restores_has() {
        assert_eq!(negate_cel_expr("!has(resource.X)"), "has(resource.X)");
    }

    #[test]
    fn negate_eq_flips_to_neq() {
        assert_eq!(negate_cel_expr("resource.X == \"foo\""), "resource.X != \"foo\"");
    }

    #[test]
    fn negate_neq_flips_to_eq() {
        assert_eq!(negate_cel_expr("resource.X != \"foo\""), "resource.X == \"foo\"");
    }

    #[test]
    fn negate_in_wraps_with_not() {
        // Bug fix: previously produced `!(resource.X in [...]) == true`
        assert_eq!(negate_cel_expr("resource.X in [\"a\", \"b\"]"), "!(resource.X in [\"a\", \"b\"])");
    }

    #[test]
    fn negate_already_negated_in_unchanged() {
        // Already starts with `!(` — should fall through to default
        let expr = "!(resource.X in [\"a\"])";
        assert_eq!(negate_cel_expr(expr), "(!(resource.X in [\"a\"])) == false");
    }

    #[test]
    fn negate_size_eq_zero_hits_eq_branch_first() {
        // `size(X) == 0` contains ` == ` so the equality branch fires first.
        // Result `!= 0` is semantically equivalent to `> 0`.
        assert_eq!(negate_cel_expr("size(resource.X) == 0"), "size(resource.X) != 0");
    }

    #[test]
    fn negate_size_gt_zero_flips_to_eq_zero() {
        // `size(X) > 0` has no ` == ` or ` != `, so the size branch handles it.
        assert_eq!(negate_cel_expr("size(resource.X) > 0"), "size(resource.X) == 0");
    }

    #[test]
    fn negate_fallback_wraps_with_eq_false() {
        assert_eq!(negate_cel_expr("some_func(resource.X)"), "(some_func(resource.X)) == false");
    }

    #[test]
    fn query_to_cel_path_keys_joined_with_dots() {
        let parts = vec![QueryPartIR::Key("Properties".into()), QueryPartIR::Key("BucketName".into())];
        assert_eq!(query_to_cel_path(&parts), "Properties.BucketName");
    }

    #[test]
    fn query_to_cel_path_strips_percent_prefix() {
        let parts = vec![QueryPartIR::Key("%myVar".into())];
        assert_eq!(query_to_cel_path(&parts), "myVar");
    }

    #[test]
    fn query_to_cel_path_index_formatted() {
        let parts = vec![QueryPartIR::Key("Items".into()), QueryPartIR::Index(2)];
        assert_eq!(query_to_cel_path(&parts), "Items.[2]");
    }

    #[test]
    fn query_to_cel_path_skips_this_and_wildcards() {
        let parts = vec![
            QueryPartIR::This,
            QueryPartIR::Key("X".into()),
            QueryPartIR::AllValues(None),
            QueryPartIR::AllIndices(None),
        ];
        assert_eq!(query_to_cel_path(&parts), "X");
    }

    #[test]
    fn query_to_cel_path_empty() {
        assert_eq!(query_to_cel_path(&[]), "");
    }

    fn make_access(op: Operator, negated: bool, compare_with: Option<LetValueIR>) -> AccessClauseIR {
        AccessClauseIR {
            query: vec![QueryPartIR::Key("Properties".into()), QueryPartIR::Key("Enabled".into())],
            match_all: false,
            operator: op,
            negated,
            compare_with,
            custom_message: None,
        }
    }

    #[test]
    fn access_exists_positive() {
        let ac = make_access(Operator::Exists, false, None);
        assert_eq!(access_to_cel(&ac), "has(resource.Properties.Enabled)");
    }

    #[test]
    fn access_exists_negated() {
        let ac = make_access(Operator::Exists, true, None);
        assert_eq!(access_to_cel(&ac), "!has(resource.Properties.Enabled)");
    }

    #[test]
    fn access_empty_positive() {
        let ac = make_access(Operator::Empty, false, None);
        assert_eq!(access_to_cel(&ac), "size(resource.Properties.Enabled) == 0");
    }

    #[test]
    fn access_empty_negated() {
        let ac = make_access(Operator::Empty, true, None);
        assert_eq!(access_to_cel(&ac), "size(resource.Properties.Enabled) > 0");
    }

    #[test]
    fn access_eq_with_string_value() {
        let ac = make_access(Operator::Eq, false, Some(LetValueIR::Value(ValueIR::String("yes".into()))));
        assert_eq!(access_to_cel(&ac), "resource.Properties.Enabled == \"yes\"");
    }

    #[test]
    fn access_eq_negated() {
        let ac = make_access(Operator::Eq, true, Some(LetValueIR::Value(ValueIR::Int(42))));
        assert_eq!(access_to_cel(&ac), "resource.Properties.Enabled != 42");
    }

    #[test]
    fn access_in_with_list() {
        let ac = make_access(
            Operator::In,
            false,
            Some(LetValueIR::Value(ValueIR::List(vec![ValueIR::String("a".into()), ValueIR::String("b".into())]))),
        );
        assert_eq!(access_to_cel(&ac), "resource.Properties.Enabled in [\"a\", \"b\"]");
    }

    #[test]
    fn access_in_negated() {
        let ac = make_access(Operator::In, true, Some(LetValueIR::Value(ValueIR::List(vec![ValueIR::Int(1)]))));
        assert_eq!(access_to_cel(&ac), "!(resource.Properties.Enabled in [1])");
    }

    #[test]
    fn access_gt() {
        let ac = make_access(Operator::Gt, false, Some(LetValueIR::Value(ValueIR::Int(10))));
        assert_eq!(access_to_cel(&ac), "resource.Properties.Enabled > 10");
    }

    #[test]
    fn access_lt() {
        let ac = make_access(Operator::Lt, false, Some(LetValueIR::Value(ValueIR::Int(5))));
        assert_eq!(access_to_cel(&ac), "resource.Properties.Enabled < 5");
    }

    #[test]
    fn access_ge() {
        let ac = make_access(Operator::Ge, false, Some(LetValueIR::Value(ValueIR::Int(0))));
        assert_eq!(access_to_cel(&ac), "resource.Properties.Enabled >= 0");
    }

    #[test]
    fn access_le() {
        let ac = make_access(Operator::Le, false, Some(LetValueIR::Value(ValueIR::Float(3.14))));
        assert_eq!(access_to_cel(&ac), "resource.Properties.Enabled <= 3.14");
    }

    #[test]
    fn access_is_string() {
        let ac = make_access(Operator::IsString, false, None);
        assert_eq!(access_to_cel(&ac), "(type(resource.Properties.Enabled) == \"string\")");
    }

    #[test]
    fn access_is_string_negated() {
        let ac = make_access(Operator::IsString, true, None);
        assert_eq!(access_to_cel(&ac), "!(type(resource.Properties.Enabled) == \"string\")");
    }

    #[test]
    fn access_is_list() {
        let ac = make_access(Operator::IsList, false, None);
        assert_eq!(access_to_cel(&ac), "(type(resource.Properties.Enabled) == \"list\")");
    }

    #[test]
    fn access_is_null() {
        let ac = make_access(Operator::IsNull, false, None);
        assert_eq!(access_to_cel(&ac), "(resource.Properties.Enabled == null)");
    }

    #[test]
    fn access_is_null_negated() {
        let ac = make_access(Operator::IsNull, true, None);
        assert_eq!(access_to_cel(&ac), "!(resource.Properties.Enabled == null)");
    }

    #[test]
    fn access_is_int() {
        let ac = make_access(Operator::IsInt, false, None);
        assert!(access_to_cel(&ac).contains("\"int\""));
        assert!(access_to_cel(&ac).contains("\"double\""));
    }

    #[test]
    fn access_is_map() {
        let ac = make_access(Operator::IsMap, false, None);
        assert_eq!(access_to_cel(&ac), "(type(resource.Properties.Enabled) == \"map\")");
    }

    #[test]
    fn access_is_bool() {
        let ac = make_access(Operator::IsBool, false, None);
        assert_eq!(access_to_cel(&ac), "(type(resource.Properties.Enabled) == \"bool\")");
    }

    #[test]
    fn access_empty_query_uses_resource() {
        let ac = AccessClauseIR {
            query: vec![],
            match_all: false,
            operator: Operator::Exists,
            negated: false,
            compare_with: None,
            custom_message: None,
        };
        assert_eq!(access_to_cel(&ac), "has(resource)");
    }

    #[test]
    fn guard_clause_access_delegates_to_access_to_cel() {
        let ac = make_access(Operator::Eq, false, Some(LetValueIR::Value(ValueIR::Bool(true))));
        let gc = GuardClauseIR::Access(ac);
        assert_eq!(guard_clause_to_cel_expr(&gc), "resource.Properties.Enabled == true");
    }

    #[test]
    fn guard_clause_block_joins_with_and() {
        let ac1 = GuardClauseIR::Access(make_access(
            Operator::Eq,
            false,
            Some(LetValueIR::Value(ValueIR::String("a".into()))),
        ));
        let ac2 = GuardClauseIR::Access(make_access(Operator::Exists, false, None));
        let block = GuardClauseIR::Block(BlockClauseIR {
            query: vec![],
            match_all: false,
            block: BlockIR { assignments: vec![], conjunctions: vec![vec![ac1, ac2]] },
            not_empty: false,
        });
        let result = guard_clause_to_cel_expr(&block);
        assert!(result.contains(" && "));
        assert!(result.contains("== \"a\""));
        assert!(result.contains("has("));
    }

    #[test]
    fn guard_clause_empty_block_returns_true() {
        let block = GuardClauseIR::Block(BlockClauseIR {
            query: vec![],
            match_all: false,
            block: BlockIR { assignments: vec![], conjunctions: vec![] },
            not_empty: false,
        });
        assert_eq!(guard_clause_to_cel_expr(&block), "true");
    }

    #[test]
    fn guard_clause_named_rule_produces_placeholder() {
        let gc = GuardClauseIR::NamedRule(NamedRuleRefIR {
            rule_name: "my_rule".into(),
            negated: false,
            custom_message: None,
        });
        let result = guard_clause_to_cel_expr(&gc);
        assert!(result.contains("my_rule"));
        assert!(result.contains("true"));
    }

    #[test]
    fn guard_clause_parameterized_named_rule_produces_placeholder() {
        let gc = GuardClauseIR::ParameterizedNamedRule(ParameterizedNamedRuleRefIR {
            rule_name: "param_rule".into(),
            parameters: vec![],
            negated: false,
            custom_message: None,
        });
        let result = guard_clause_to_cel_expr(&gc);
        assert!(result.contains("param_rule"));
    }

    #[test]
    fn translate_type_block_produces_negated_rules() {
        let ac = AccessClauseIR {
            query: vec![QueryPartIR::Key("Properties".into()), QueryPartIR::Key("Status".into())],
            match_all: false,
            operator: Operator::Eq,
            negated: false,
            compare_with: Some(LetValueIR::Value(ValueIR::String("Enabled".into()))),
            custom_message: Some("Must be enabled".into()),
        };
        let tb = TypeBlockIR {
            type_name: "AWS::S3::Bucket".into(),
            conditions: None,
            block: BlockIR { assignments: vec![], conjunctions: vec![vec![GuardClauseIR::Access(ac)]] },
            query: vec![],
        };
        let file = GuardFile {
            assignments: vec![],
            rules: vec![GuardRule {
                name: "test_rule".into(),
                conditions: None,
                block: BlockIR { assignments: vec![], conjunctions: vec![vec![RuleClauseIR::TypeBlock(tb)]] },
            }],
            parameterized_rules: vec![],
        };
        let result = translate_to_cel(&file, "test_pack", &[]);
        assert!(!result.is_empty());
        let rule = &result[0];
        assert_eq!(rule.rule_id, "test_rule");
        assert_eq!(rule.resource_type, Some("AWS::S3::Bucket".into()));
        assert_eq!(rule.category.as_deref(), Some("guard:test_pack"));
        assert_eq!(rule.message, "Must be enabled");
        // Expression should be negated (violation semantics)
        assert!(rule.expression.contains("!="), "Expected negated == to !=, got: {}", rule.expression);
    }

    #[test]
    fn translate_guard_clause_without_type_block() {
        let ac = AccessClauseIR {
            query: vec![QueryPartIR::Key("Properties".into())],
            match_all: false,
            operator: Operator::Exists,
            negated: false,
            compare_with: None,
            custom_message: None,
        };
        let file = GuardFile {
            assignments: vec![],
            rules: vec![GuardRule {
                name: "global_rule".into(),
                conditions: None,
                block: BlockIR {
                    assignments: vec![],
                    conjunctions: vec![vec![RuleClauseIR::Guard(GuardClauseIR::Access(ac))]],
                },
            }],
            parameterized_rules: vec![],
        };
        let result = translate_to_cel(&file, "pack", &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].resource_type, None);
    }

    #[test]
    fn to_custom_rule_json_serializes_correctly() {
        let rules = vec![TranslatedCelRule {
            rule_id: "R001".into(),
            severity: Severity::Error,
            category: Some("guard:test".into()),
            resource_type: Some("AWS::S3::Bucket".into()),
            expression: "resource.X != null".into(),
            message: "X required".into(),
            prop_path: Some("Properties.X".into()),
            suggested_fix: None,
            controls: None,
        }];
        let json = to_custom_rule_json(&rules).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = parsed["rules"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["rule_id"], "R001");
        assert_eq!(arr[0]["resource_type"], "AWS::S3::Bucket");
    }

    #[test]
    fn to_custom_rule_json_empty_rules() {
        let json = to_custom_rule_json(&[]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["rules"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn translate_with_controls_attaches_control_ids() {
        let ac = AccessClauseIR {
            query: vec![QueryPartIR::Key("X".into())],
            match_all: false,
            operator: Operator::Exists,
            negated: false,
            compare_with: None,
            custom_message: None,
        };
        let file = GuardFile {
            assignments: vec![],
            rules: vec![GuardRule {
                name: "ctrl_rule".into(),
                conditions: None,
                block: BlockIR {
                    assignments: vec![],
                    conjunctions: vec![vec![RuleClauseIR::Guard(GuardClauseIR::Access(ac))]],
                },
            }],
            parameterized_rules: vec![],
        };
        let controls = vec![("ctrl_rule".into(), vec!["NIST-1".into(), "CIS-2".into()])];
        let result = translate_to_cel(&file, "p", &controls);
        assert_eq!(result[0].controls, Some(vec!["NIST-1".into(), "CIS-2".into()]));
    }

    #[test]
    fn translate_when_block_produces_rules() {
        let inner_ac = AccessClauseIR {
            query: vec![QueryPartIR::Key("X".into())],
            match_all: false,
            operator: Operator::Eq,
            negated: false,
            compare_with: Some(LetValueIR::Value(ValueIR::Int(1))),
            custom_message: Some("X must be 1".into()),
        };
        let when_ac = WhenClauseIR::Access(AccessClauseIR {
            query: vec![QueryPartIR::Key("Y".into())],
            match_all: false,
            operator: Operator::Exists,
            negated: false,
            compare_with: None,
            custom_message: None,
        });
        let file = GuardFile {
            assignments: vec![],
            rules: vec![GuardRule {
                name: "when_rule".into(),
                conditions: None,
                block: BlockIR {
                    assignments: vec![],
                    conjunctions: vec![vec![RuleClauseIR::WhenBlock(
                        vec![vec![when_ac]],
                        BlockIR { assignments: vec![], conjunctions: vec![vec![GuardClauseIR::Access(inner_ac)]] },
                    )]],
                },
            }],
            parameterized_rules: vec![],
        };
        let result = translate_to_cel(&file, "p", &[]);
        assert!(!result.is_empty());
    }

    #[test]
    fn when_conditions_empty_returns_none() {
        let conds: ConjunctionsIR<WhenClauseIR> = vec![];
        assert_eq!(when_conditions_to_cel(&conds), None, "empty conditions should return None");
    }

    #[test]
    fn when_conditions_access_clause() {
        let conds = vec![vec![WhenClauseIR::Access(AccessClauseIR {
            query: vec![QueryPartIR::Key("Properties".into()), QueryPartIR::Key("Enabled".into())],
            match_all: false,
            operator: Operator::Eq,
            compare_with: Some(LetValueIR::Value(ValueIR::Bool(true))),
            negated: false,
            custom_message: None,
        })]];
        let result = when_conditions_to_cel(&conds);
        let cel = result.expect("when_conditions_to_cel should return Some for valid conditions");
        assert!(cel.contains("Properties"), "CEL expression should reference Properties, got: {cel}");
    }

    #[test]
    fn when_conditions_named_rule_produces_placeholder() {
        let conds = vec![vec![WhenClauseIR::NamedRule(NamedRuleRefIR {
            rule_name: "my_rule".into(),
            negated: false,
            custom_message: None,
        })]];
        let result = when_conditions_to_cel(&conds).unwrap();
        assert!(result.contains("my_rule"));
    }

    #[test]
    fn when_conditions_parameterized_rule_produces_placeholder() {
        let conds = vec![vec![WhenClauseIR::ParameterizedNamedRule(ParameterizedNamedRuleRefIR {
            rule_name: "param_rule".into(),
            negated: false,
            custom_message: None,
            parameters: vec![],
        })]];
        let result = when_conditions_to_cel(&conds).unwrap();
        assert!(result.contains("param_rule"));
    }

    #[test]
    fn extract_vars_from_type_filter() {
        let assignments = vec![LetExprIR {
            var: "s3_buckets".into(),
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
                            compare_with: Some(LetValueIR::Value(ValueIR::String("AWS::S3::Bucket".into()))),
                            negated: false,
                            custom_message: None,
                        })]],
                    ),
                ],
                false,
            ),
        }];
        let vars = extract_resource_type_vars(&assignments);
        assert_eq!(vars.get("s3_buckets"), Some(&vec!["AWS::S3::Bucket".to_string()]));
    }

    #[test]
    fn extract_vars_no_filter_returns_empty() {
        let assignments =
            vec![LetExprIR { var: "x".into(), value: LetValueIR::Value(ValueIR::String("hello".into())) }];
        let vars = extract_resource_type_vars(&assignments);
        assert!(vars.is_empty());
    }

    #[test]
    fn extract_types_in_operator() {
        let parts = vec![QueryPartIR::Filter(
            None,
            vec![vec![GuardClauseIR::Access(AccessClauseIR {
                query: vec![QueryPartIR::Key("Type".into())],
                match_all: false,
                operator: Operator::In,
                compare_with: Some(LetValueIR::Value(ValueIR::List(vec![
                    ValueIR::String("AWS::EC2::Instance".into()),
                    ValueIR::String("AWS::EC2::VPC".into()),
                ]))),
                negated: false,
                custom_message: None,
            })]],
        )];
        let types = extract_types_from_filter(&parts);
        assert_eq!(types, vec!["AWS::EC2::Instance", "AWS::EC2::VPC"]);
    }

    #[test]
    fn find_types_from_when_resolves_variable() {
        let mut vars = HashMap::new();
        vars.insert("s3_buckets".to_string(), vec!["AWS::S3::Bucket".to_string()]);
        let conds = vec![vec![WhenClauseIR::Access(AccessClauseIR {
            query: vec![QueryPartIR::Key("%s3_buckets".into())],
            match_all: false,
            operator: Operator::Exists,
            compare_with: None,
            negated: false,
            custom_message: None,
        })]];
        let result = find_resource_types_from_when(&conds, &vars);
        assert_eq!(result, Some(vec!["AWS::S3::Bucket".to_string()]));
    }

    #[test]
    fn find_types_from_when_no_match() {
        let vars = HashMap::new();
        let conds = vec![vec![WhenClauseIR::Access(AccessClauseIR {
            query: vec![QueryPartIR::Key("unknown".into())],
            match_all: false,
            operator: Operator::Exists,
            compare_with: None,
            negated: false,
            custom_message: None,
        })]];
        assert_eq!(find_resource_types_from_when(&conds, &vars), None, "empty conditions should return None");
    }
}
