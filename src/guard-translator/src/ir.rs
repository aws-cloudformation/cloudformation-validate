//! Owned, engine-agnostic intermediate representation of Guard DSL rules.
//! All types are `'static` - no borrowed references to the parser AST.

use indexmap::IndexMap;
use rules::Severity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct GuardFile {
    pub assignments: Vec<LetExprIR>,
    pub rules: Vec<GuardRule>,
    pub parameterized_rules: Vec<ParameterizedGuardRule>,
}

#[derive(Debug, Clone)]
pub struct GuardRule {
    pub name: String,
    pub conditions: Option<ConjunctionsIR<WhenClauseIR>>,
    pub block: BlockIR<RuleClauseIR>,
}

#[derive(Debug, Clone)]
pub struct ParameterizedGuardRule {
    pub parameter_names: Vec<String>,
    pub rule: GuardRule,
}

#[derive(Debug, Clone)]
pub struct BlockIR<T> {
    pub assignments: Vec<LetExprIR>,
    pub conjunctions: ConjunctionsIR<T>,
}

/// AND of disjunctions (OR groups).
pub type ConjunctionsIR<T> = Vec<Vec<T>>;

#[derive(Debug, Clone)]
pub enum RuleClauseIR {
    Guard(GuardClauseIR),
    WhenBlock(ConjunctionsIR<WhenClauseIR>, BlockIR<GuardClauseIR>),
    TypeBlock(TypeBlockIR),
}

/// Scopes checks to resources matching a specific type name.
#[derive(Debug, Clone)]
pub struct TypeBlockIR {
    pub type_name: String,
    pub conditions: Option<ConjunctionsIR<WhenClauseIR>>,
    pub block: BlockIR<GuardClauseIR>,
    pub query: Vec<QueryPartIR>,
}

#[derive(Debug, Clone)]
pub enum GuardClauseIR {
    Access(AccessClauseIR),
    NamedRule(NamedRuleRefIR),
    ParameterizedNamedRule(ParameterizedNamedRuleRefIR),
    Block(BlockClauseIR),
    WhenBlock(ConjunctionsIR<WhenClauseIR>, BlockIR<GuardClauseIR>),
}

#[derive(Debug, Clone)]
pub struct AccessClauseIR {
    pub query: Vec<QueryPartIR>,
    pub match_all: bool,
    pub operator: Operator,
    pub negated: bool,
    pub compare_with: Option<LetValueIR>,
    pub custom_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NamedRuleRefIR {
    pub rule_name: String,
    pub negated: bool,
    pub custom_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParameterizedNamedRuleRefIR {
    pub rule_name: String,
    pub parameters: Vec<LetValueIR>,
    pub negated: bool,
    pub custom_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BlockClauseIR {
    pub query: Vec<QueryPartIR>,
    pub match_all: bool,
    pub block: BlockIR<GuardClauseIR>,
    pub not_empty: bool,
}

#[derive(Debug, Clone)]
pub enum WhenClauseIR {
    Access(AccessClauseIR),
    NamedRule(NamedRuleRefIR),
    ParameterizedNamedRule(ParameterizedNamedRuleRefIR),
}

#[derive(Debug, Clone)]
pub enum QueryPartIR {
    This,
    Key(String),
    AllValues(Option<String>),
    AllIndices(Option<String>),
    Index(i32),
    Filter(Option<String>, ConjunctionsIR<GuardClauseIR>),
    MapKeyFilter(Option<String>, Operator, bool, LetValueIR),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    Eq,
    In,
    Gt,
    Lt,
    Le,
    Ge,
    Exists,
    Empty,
    IsString,
    IsList,
    IsMap,
    IsBool,
    IsInt,
    IsFloat,
    IsNull,
}

#[derive(Debug, Clone)]
pub enum ValueIR {
    Null,
    String(String),
    Regex(String),
    Bool(bool),
    Int(i64),
    Float(f64),
    List(Vec<ValueIR>),
    Map(IndexMap<String, ValueIR>),
}

#[derive(Debug, Clone)]
pub struct LetExprIR {
    pub var: String,
    pub value: LetValueIR,
}

#[derive(Debug, Clone)]
pub enum LetValueIR {
    Value(ValueIR),
    Access(Vec<QueryPartIR>, bool),
    FunctionCall(FunctionCallIR),
}

#[derive(Debug, Clone)]
pub struct FunctionCallIR {
    pub name: String,
    pub parameters: Vec<LetValueIR>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslatedRule {
    pub path: String,
    pub source: String,
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslatedCelRule {
    pub rule_id: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub resource_type: Option<String>,
    pub expression: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prop_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_fix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controls: Option<Vec<String>>,
}

/// Serialize a [`ValueIR`] to a string literal (e.g. `"hello"`, `42`, `[1, 2]`).
pub fn value_ir_to_string(v: &ValueIR) -> String {
    match v {
        ValueIR::Null => "null".into(),
        ValueIR::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        ValueIR::Regex(s) => format!("\"{}\"", s),
        ValueIR::Bool(b) => b.to_string(),
        ValueIR::Int(i) => i.to_string(),
        ValueIR::Float(f) => f.to_string(),
        ValueIR::List(items) => {
            let inner = items.iter().map(value_ir_to_string).collect::<Vec<_>>().join(", ");
            format!("[{}]", inner)
        }
        ValueIR::Map(entries) => {
            let inner = entries
                .iter()
                .map(|(k, v)| format!("\"{}\": {}", k, value_ir_to_string(v)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{}}}", inner)
        }
    }
}

/// Serialize a [`LetValueIR`] to a string. Access expressions are prefixed with
/// `path_prefix` (e.g. `""` for Rego, `"resource."` for CEL).
pub fn let_value_to_string(val: &LetValueIR, path_prefix: &str) -> String {
    match val {
        LetValueIR::Value(v) => value_ir_to_string(v),
        LetValueIR::Access(parts, _) => format!("{}{}", path_prefix, query_parts_to_path(parts)),
        LetValueIR::FunctionCall(fc) => {
            let params =
                fc.parameters.iter().map(|p| let_value_to_string(p, path_prefix)).collect::<Vec<_>>().join(", ");
            format!("{}({})", fc.name, params)
        }
    }
}

/// Join query parts into a dotted path (e.g. `"Properties.Name"`).
pub fn query_parts_to_path(parts: &[QueryPartIR]) -> String {
    parts
        .iter()
        .filter_map(|p| match p {
            QueryPartIR::Key(k) => Some(k.clone()),
            QueryPartIR::AllValues(_) => Some("*".into()),
            QueryPartIR::AllIndices(_) => Some("[*]".into()),
            QueryPartIR::Index(i) => Some(format!("[{}]", i)),
            QueryPartIR::This => Some("_".into()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Walk a guard clause tree and return the first custom error message found.
pub fn extract_custom_message(clause: &GuardClauseIR) -> Option<String> {
    match clause {
        GuardClauseIR::Access(ac) => ac.custom_message.clone(),
        GuardClauseIR::Block(bc) => extract_custom_message_from_block(&bc.block),
        GuardClauseIR::WhenBlock(_, block) => extract_custom_message_from_block(block),
        _ => None,
    }
}

pub fn extract_custom_message_from_block(block: &BlockIR<GuardClauseIR>) -> Option<String> {
    block.conjunctions.iter().flat_map(|disj| disj.iter()).find_map(extract_custom_message)
}

/// Replace non-alphanumeric characters (except `_`) with `_`.
pub fn sanitize_identifier(name: &str) -> String {
    name.chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

/// Look up control IDs whose path contains `rule_name`.
pub fn find_controls(controls: &[(String, Vec<String>)], rule_name: &str) -> Option<Vec<String>> {
    controls.iter().find(|(path, _)| path.contains(rule_name)).map(|(_, c)| c.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_ir_to_string_escapes_backslash_and_quotes_in_strings() {
        assert_eq!(value_ir_to_string(&ValueIR::String("a\"b\\c".into())), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn value_ir_to_string_formats_nested_list() {
        let v = ValueIR::List(vec![ValueIR::Int(1), ValueIR::String("x".into())]);
        assert_eq!(value_ir_to_string(&v), "[1, \"x\"]");
    }

    #[test]
    fn value_ir_to_string_formats_map_with_entries() {
        let mut m = IndexMap::new();
        m.insert("k".into(), ValueIR::Bool(false));
        assert_eq!(value_ir_to_string(&ValueIR::Map(m)), "{\"k\": false}");
    }

    #[test]
    fn let_value_to_string_renders_access_with_prefix() {
        let lv = LetValueIR::Access(vec![QueryPartIR::Key("X".into())], false);
        assert_eq!(let_value_to_string(&lv, "resource."), "resource.X");
    }

    #[test]
    fn let_value_to_string_renders_function_call() {
        let lv = LetValueIR::FunctionCall(FunctionCallIR {
            name: "count".into(),
            parameters: vec![LetValueIR::Value(ValueIR::List(vec![]))],
        });
        assert_eq!(let_value_to_string(&lv, ""), "count([])");
    }

    #[test]
    fn query_parts_to_path_joins_keys_with_dots() {
        let parts = vec![QueryPartIR::Key("Properties".into()), QueryPartIR::Key("Name".into())];
        assert_eq!(query_parts_to_path(&parts), "Properties.Name");
    }

    #[test]
    fn query_parts_to_path_renders_wildcards_and_indices() {
        let parts = vec![QueryPartIR::Key("Items".into()), QueryPartIR::AllValues(None)];
        assert_eq!(query_parts_to_path(&parts), "Items.*");

        let parts = vec![QueryPartIR::Key("A".into()), QueryPartIR::Index(0)];
        assert_eq!(query_parts_to_path(&parts), "A.[0]");

        let parts = vec![QueryPartIR::Key("List".into()), QueryPartIR::AllIndices(None)];
        assert_eq!(query_parts_to_path(&parts), "List.[*]");
    }

    #[test]
    fn query_parts_to_path_skips_filter_parts() {
        let parts = vec![QueryPartIR::Key("A".into()), QueryPartIR::Filter(None, vec![]), QueryPartIR::Key("B".into())];
        assert_eq!(query_parts_to_path(&parts), "A.B");
    }

    #[test]
    fn extract_custom_message_finds_message_in_access_clause() {
        let clause = GuardClauseIR::Access(AccessClauseIR {
            query: vec![],
            match_all: false,
            operator: Operator::Exists,
            negated: false,
            compare_with: None,
            custom_message: Some("must exist".into()),
        });
        assert_eq!(extract_custom_message(&clause), Some("must exist".into()));
    }

    #[test]
    fn extract_custom_message_finds_message_in_nested_block() {
        let inner = GuardClauseIR::Access(AccessClauseIR {
            query: vec![],
            match_all: false,
            operator: Operator::Eq,
            negated: false,
            compare_with: None,
            custom_message: Some("nested msg".into()),
        });
        let clause = GuardClauseIR::Block(BlockClauseIR {
            query: vec![],
            match_all: false,
            block: BlockIR { assignments: vec![], conjunctions: vec![vec![inner]] },
            not_empty: false,
        });
        assert_eq!(extract_custom_message(&clause), Some("nested msg".into()));
    }

    #[test]
    fn extract_custom_message_returns_none_for_named_rule() {
        let clause =
            GuardClauseIR::NamedRule(NamedRuleRefIR { rule_name: "r".into(), negated: false, custom_message: None });
        assert_eq!(extract_custom_message(&clause), None);
    }

    #[test]
    fn sanitize_identifier_replaces_special_chars_with_underscore() {
        assert_eq!(sanitize_identifier("my-rule.v2"), "my_rule_v2");
    }

    #[test]
    fn find_controls_returns_matching_control_ids() {
        let controls = vec![("s3_encryption".into(), vec!["NIST-1".into()])];
        assert_eq!(find_controls(&controls, "s3_encryption"), Some(vec!["NIST-1".to_string()]));
    }

    #[test]
    fn find_controls_returns_none_when_no_match() {
        let controls = vec![("other".into(), vec!["X".into()])];
        assert_eq!(find_controls(&controls, "missing"), None, "missing control should return None");
    }
}
