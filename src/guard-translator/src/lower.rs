//! Converts borrowed parser AST types into owned IR types.

use guard_lang::eval_context::FunctionName;
use guard_lang::exprs;
use guard_lang::path_value::PathAwareValue;
use guard_lang::values::CmpOperator;
use indexmap::IndexMap;

use crate::ir::*;

pub fn lower_rules_file(file: &exprs::RulesFile<'_>) -> GuardFile {
    GuardFile {
        assignments: file.assignments.iter().map(lower_let_expr).collect(),
        rules: file.guard_rules.iter().map(lower_rule).collect(),
        parameterized_rules: file
            .parameterized_rules
            .iter()
            .map(lower_parameterized_rule)
            .collect(),
    }
}

fn lower_rule(rule: &exprs::Rule<'_>) -> GuardRule {
    GuardRule {
        name: rule.rule_name.clone(),
        conditions: rule.conditions.as_ref().map(lower_when_conditions),
        block: lower_block_rule(&rule.block),
    }
}

fn lower_parameterized_rule(pr: &exprs::ParameterizedRule<'_>) -> ParameterizedGuardRule {
    ParameterizedGuardRule {
        parameter_names: pr.parameter_names.iter().cloned().collect(),
        rule: lower_rule(&pr.rule),
    }
}

fn lower_block_rule(block: &exprs::Block<'_, exprs::RuleClause<'_>>) -> BlockIR<RuleClauseIR> {
    BlockIR {
        assignments: block.assignments.iter().map(lower_let_expr).collect(),
        conjunctions: block
            .conjunctions
            .iter()
            .map(|disj| disj.iter().map(lower_rule_clause).collect())
            .collect(),
    }
}

fn lower_block_guard(block: &exprs::Block<'_, exprs::GuardClause<'_>>) -> BlockIR<GuardClauseIR> {
    BlockIR {
        assignments: block.assignments.iter().map(lower_let_expr).collect(),
        conjunctions: block
            .conjunctions
            .iter()
            .map(|disj| disj.iter().map(lower_guard_clause).collect())
            .collect(),
    }
}

fn lower_rule_clause(clause: &exprs::RuleClause<'_>) -> RuleClauseIR {
    match clause {
        exprs::RuleClause::Clause(gc) => RuleClauseIR::Guard(lower_guard_clause(gc)),
        exprs::RuleClause::WhenBlock(conds, block) => {
            RuleClauseIR::WhenBlock(lower_when_conditions(conds), lower_block_guard(block))
        }
        exprs::RuleClause::TypeBlock(tb) => RuleClauseIR::TypeBlock(lower_type_block(tb)),
    }
}

fn lower_type_block(tb: &exprs::TypeBlock<'_>) -> TypeBlockIR {
    TypeBlockIR {
        type_name: tb.type_name.clone(),
        conditions: tb.conditions.as_ref().map(lower_when_conditions),
        block: lower_block_guard(&tb.block),
        query: tb.query.iter().map(lower_query_part).collect(),
    }
}

fn lower_guard_clause(clause: &exprs::GuardClause<'_>) -> GuardClauseIR {
    match clause {
        exprs::GuardClause::Clause(gac) => GuardClauseIR::Access(lower_access_clause(gac)),
        exprs::GuardClause::NamedRule(nr) => GuardClauseIR::NamedRule(lower_named_rule(nr)),
        exprs::GuardClause::ParameterizedNamedRule(pnr) => {
            GuardClauseIR::ParameterizedNamedRule(ParameterizedNamedRuleRefIR {
                rule_name: pnr.named_rule.dependent_rule.clone(),
                parameters: pnr.parameters.iter().map(lower_let_value).collect(),
                negated: pnr.named_rule.negation,
                custom_message: pnr.named_rule.custom_message.clone(),
            })
        }
        exprs::GuardClause::BlockClause(bc) => GuardClauseIR::Block(BlockClauseIR {
            query: bc.query.query.iter().map(lower_query_part).collect(),
            match_all: bc.query.match_all,
            block: lower_block_guard(&bc.block),
            not_empty: bc.not_empty,
        }),
        exprs::GuardClause::WhenBlock(conds, block) => {
            GuardClauseIR::WhenBlock(lower_when_conditions(conds), lower_block_guard(block))
        }
    }
}

fn lower_access_clause(gac: &exprs::GuardAccessClause<'_>) -> AccessClauseIR {
    let ac = &gac.access_clause;
    let (op, negated_op) = ac.comparator;
    AccessClauseIR {
        query: ac.query.query.iter().map(lower_query_part).collect(),
        match_all: ac.query.match_all,
        operator: lower_operator(op),
        negated: gac.negation ^ negated_op,
        compare_with: ac.compare_with.as_ref().map(lower_let_value),
        custom_message: ac.custom_message.clone(),
    }
}

fn lower_named_rule(nr: &exprs::GuardNamedRuleClause<'_>) -> NamedRuleRefIR {
    NamedRuleRefIR {
        rule_name: nr.dependent_rule.clone(),
        negated: nr.negation,
        custom_message: nr.custom_message.clone(),
    }
}

fn lower_when_conditions(conds: &exprs::WhenConditions<'_>) -> ConjunctionsIR<WhenClauseIR> {
    conds
        .iter()
        .map(|disj| disj.iter().map(lower_when_clause).collect())
        .collect()
}

fn lower_when_clause(wc: &exprs::WhenGuardClause<'_>) -> WhenClauseIR {
    match wc {
        exprs::WhenGuardClause::Clause(gac) => WhenClauseIR::Access(lower_access_clause(gac)),
        exprs::WhenGuardClause::NamedRule(nr) => WhenClauseIR::NamedRule(lower_named_rule(nr)),
        exprs::WhenGuardClause::ParameterizedNamedRule(pnr) => {
            WhenClauseIR::ParameterizedNamedRule(ParameterizedNamedRuleRefIR {
                rule_name: pnr.named_rule.dependent_rule.clone(),
                parameters: pnr.parameters.iter().map(lower_let_value).collect(),
                negated: pnr.named_rule.negation,
                custom_message: pnr.named_rule.custom_message.clone(),
            })
        }
    }
}

fn lower_query_part(qp: &exprs::QueryPart<'_>) -> QueryPartIR {
    match qp {
        exprs::QueryPart::This => QueryPartIR::This,
        exprs::QueryPart::Key(k) => QueryPartIR::Key(k.clone()),
        exprs::QueryPart::AllValues(n) => QueryPartIR::AllValues(n.clone()),
        exprs::QueryPart::AllIndices(n) => QueryPartIR::AllIndices(n.clone()),
        exprs::QueryPart::Index(i) => QueryPartIR::Index(*i),
        exprs::QueryPart::Filter(name, conjunctions) => {
            let lowered = conjunctions
                .iter()
                .map(|disj| disj.iter().map(lower_guard_clause).collect())
                .collect();
            QueryPartIR::Filter(name.clone(), lowered)
        }
        exprs::QueryPart::MapKeyFilter(name, mkf) => {
            let (op, neg) = mkf.comparator;
            QueryPartIR::MapKeyFilter(
                name.clone(),
                lower_operator(op),
                neg,
                lower_let_value(&mkf.compare_with),
            )
        }
    }
}

fn lower_let_expr(le: &exprs::LetExpr<'_>) -> LetExprIR {
    LetExprIR {
        var: le.var.clone(),
        value: lower_let_value(&le.value),
    }
}

fn lower_let_value(lv: &exprs::LetValue<'_>) -> LetValueIR {
    match lv {
        exprs::LetValue::Value(pav) => LetValueIR::Value(lower_path_aware_value(pav)),
        exprs::LetValue::AccessClause(aq) => LetValueIR::Access(
            aq.query.iter().map(lower_query_part).collect(),
            aq.match_all,
        ),
        exprs::LetValue::FunctionCall(fe) => LetValueIR::FunctionCall(FunctionCallIR {
            name: lower_function_name(&fe.name),
            parameters: fe.parameters.iter().map(lower_let_value).collect(),
        }),
    }
}

fn lower_path_aware_value(pav: &PathAwareValue) -> ValueIR {
    match pav {
        PathAwareValue::Null(_) => ValueIR::Null,
        PathAwareValue::String((_, s)) => ValueIR::String(s.clone()),
        PathAwareValue::Regex((_, s)) => ValueIR::Regex(s.clone()),
        PathAwareValue::Bool((_, b)) => ValueIR::Bool(*b),
        PathAwareValue::Int((_, i)) => ValueIR::Int(*i),
        PathAwareValue::Float((_, f)) => ValueIR::Float(*f),
        PathAwareValue::Char((_, c)) => ValueIR::String(c.to_string()),
        PathAwareValue::List((_, items)) => {
            ValueIR::List(items.iter().map(lower_path_aware_value).collect())
        }
        PathAwareValue::Map((_, mv)) => {
            let mut map = IndexMap::new();
            for (k, v) in &mv.values {
                map.insert(k.clone(), lower_path_aware_value(v));
            }
            ValueIR::Map(map)
        }
        PathAwareValue::RangeInt(_)
        | PathAwareValue::RangeFloat(_)
        | PathAwareValue::RangeChar(_) => {
            ValueIR::Null // ranges not directly translatable
        }
    }
}

fn lower_operator(op: CmpOperator) -> Operator {
    match op {
        CmpOperator::Eq => Operator::Eq,
        CmpOperator::In => Operator::In,
        CmpOperator::Gt => Operator::Gt,
        CmpOperator::Lt => Operator::Lt,
        CmpOperator::Le => Operator::Le,
        CmpOperator::Ge => Operator::Ge,
        CmpOperator::Exists => Operator::Exists,
        CmpOperator::Empty => Operator::Empty,
        CmpOperator::IsString => Operator::IsString,
        CmpOperator::IsList => Operator::IsList,
        CmpOperator::IsMap => Operator::IsMap,
        CmpOperator::IsBool => Operator::IsBool,
        CmpOperator::IsInt => Operator::IsInt,
        CmpOperator::IsFloat => Operator::IsFloat,
        CmpOperator::IsNull => Operator::IsNull,
    }
}

fn lower_function_name(name: &FunctionName) -> String {
    match name {
        FunctionName::Count => "count".into(),
        FunctionName::Join => "join".into(),
        FunctionName::JsonParse => "json_parse".into(),
        FunctionName::Now => "now".into(),
        FunctionName::ParseBoolean => "parse_boolean".into(),
        FunctionName::ParseChar => "parse_char".into(),
        FunctionName::ParseEpoch => "parse_epoch".into(),
        FunctionName::ParseFloat => "parse_float".into(),
        FunctionName::ParseInt => "parse_int".into(),
        FunctionName::ParseString => "parse_string".into(),
        FunctionName::RegexReplace => "regex_replace".into(),
        FunctionName::Substring => "substring".into(),
        FunctionName::ToLower => "to_lower".into(),
        FunctionName::ToUpper => "to_upper".into(),
        FunctionName::UrlDecode => "url_decode".into(),
    }
}
