use crate::consts::*;
pub(crate) use diagnostics::{Diagnostic, SourceSpan, UNKNOWN_SPAN};
use std::collections::HashMap;
use std::error;
use std::fmt;

pub type NodeRef = u32;

pub const NULL_REF: NodeRef = u32::MAX;

static SENTINEL_NODE: SpannedNode = SpannedNode { node: Node::Null, span: UNKNOWN_SPAN, path: String::new() };

#[derive(Debug)]
pub struct Arena {
    nodes: Vec<SpannedNode>,
}

impl Arena {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    pub fn alloc(&mut self, node: SpannedNode) -> NodeRef {
        let idx = self.nodes.len() as u32;
        self.nodes.push(node);
        idx
    }

    pub fn get(&self, r: NodeRef) -> &SpannedNode {
        match self.nodes.get(r as usize) {
            Some(node) => node,
            None => {
                log::warn!("NodeRef {} out of bounds (arena size {}), returning sentinel", r, self.nodes.len());
                &SENTINEL_NODE
            }
        }
    }

    pub fn is_valid(&self, r: NodeRef) -> bool {
        (r as usize) < self.nodes.len()
    }

    pub fn node(&self, r: NodeRef) -> &Node {
        &self.get(r).node
    }

    pub fn span(&self, r: NodeRef) -> SourceSpan {
        self.get(r).span
    }

    pub fn as_str(&self, r: NodeRef) -> Option<&str> {
        match &self.get(r).node {
            Node::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_map(&self, r: NodeRef) -> Option<&[(String, NodeRef)]> {
        if r == NULL_REF || (r as usize) >= self.nodes.len() {
            return None;
        }
        match &self.nodes[r as usize].node {
            Node::Map(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn map_get(&self, r: NodeRef, key: &str) -> Option<NodeRef> {
        self.as_map(r)?.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
    }

    pub fn as_list(&self, r: NodeRef) -> Option<&[NodeRef]> {
        if r == NULL_REF || (r as usize) >= self.nodes.len() {
            return None;
        }
        match &self.nodes[r as usize].node {
            Node::List(items) => Some(items),
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct SpannedNode {
    pub node: Node,
    pub span: SourceSpan,
    pub path: String,
}

#[derive(Debug, Clone)]
pub enum Node {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    List(Vec<NodeRef>),
    Map(Vec<(String, NodeRef)>),
    Intrinsic(IntrinsicFn),
}

#[derive(Debug, Clone)]
pub enum IntrinsicFn {
    Ref(String),
    GetAtt(String, String),
    Sub(String, Option<Vec<(String, NodeRef)>>),
    Join(NodeRef, NodeRef),
    Select(NodeRef, NodeRef),
    If(String, NodeRef, NodeRef),
    IfExpr(NodeRef, NodeRef, NodeRef),
    FindInMap(NodeRef, NodeRef, NodeRef, Option<NodeRef>),
    Split(NodeRef, NodeRef),
    Base64(NodeRef),
    Cidr(NodeRef, NodeRef, NodeRef),
    GetAZs(NodeRef),
    ImportValue(NodeRef),
    GetStackOutput(Vec<(String, NodeRef)>),
    Transform(String, Vec<(String, NodeRef)>),
    And(Vec<NodeRef>),
    Or(Vec<NodeRef>),
    Not(NodeRef),
    Equals(NodeRef, NodeRef),
    ToJsonString(NodeRef),
    Length(NodeRef),
    ForEach(String, String, NodeRef, NodeRef),
    ValueOf(String, String),
    ValueOfAll(String, String),
    RefAll(String),
    Contains(NodeRef, NodeRef),
    EachMemberEquals(NodeRef, NodeRef),
    EachMemberIn(NodeRef, NodeRef),
}

pub type GlobalIndex = HashMap<String, NodeRef>;

/// Returns the CloudFormation function name as it appears in templates (e.g. `"Fn::GetAtt"`).
pub fn cfn_function_name(intrinsic: &IntrinsicFn) -> &'static str {
    match intrinsic {
        IntrinsicFn::Ref(name) if name.starts_with(CONDITION_REF_PREFIX) => FN_CONDITION,
        IntrinsicFn::Ref(_) => FN_REF,
        IntrinsicFn::GetAtt(_, _) => FN_GET_ATT,
        IntrinsicFn::Sub(_, _) => FN_SUB,
        IntrinsicFn::Join(_, _) => FN_JOIN,
        IntrinsicFn::Select(_, _) => FN_SELECT,
        IntrinsicFn::If(_, _, _) | IntrinsicFn::IfExpr(_, _, _) => FN_IF,
        IntrinsicFn::FindInMap(_, _, _, _) => FN_FIND_IN_MAP,
        IntrinsicFn::Split(_, _) => FN_SPLIT,
        IntrinsicFn::Base64(_) => FN_BASE64,
        IntrinsicFn::Cidr(_, _, _) => FN_CIDR,
        IntrinsicFn::GetAZs(_) => FN_GET_AZS,
        IntrinsicFn::ImportValue(_) => FN_IMPORT_VALUE,
        IntrinsicFn::GetStackOutput(_) => FN_GET_STACK_OUTPUT,
        IntrinsicFn::Transform(_, _) => FN_TRANSFORM,
        IntrinsicFn::And(_) => FN_AND,
        IntrinsicFn::Or(_) => FN_OR,
        IntrinsicFn::Not(_) => FN_NOT,
        IntrinsicFn::Equals(_, _) => FN_EQUALS,
        IntrinsicFn::ToJsonString(_) => FN_TO_JSON_STRING,
        IntrinsicFn::Length(_) => FN_LENGTH,
        IntrinsicFn::ForEach(_, _, _, _) => FN_FOR_EACH,
        IntrinsicFn::ValueOf(_, _) => FN_VALUE_OF,
        IntrinsicFn::ValueOfAll(_, _) => FN_VALUE_OF_ALL,
        IntrinsicFn::RefAll(_) => FN_REF_ALL,
        IntrinsicFn::Contains(_, _) => FN_CONTAINS,
        IntrinsicFn::EachMemberEquals(_, _) => FN_EACH_MEMBER_EQUALS,
        IntrinsicFn::EachMemberIn(_, _) => FN_EACH_MEMBER_IN,
    }
}
pub type SourceSpanIndex = HashMap<String, SourceSpan>;

#[derive(Debug)]
pub struct TemplateIR {
    pub(crate) arena: Arena,
    pub(crate) global_index: GlobalIndex,
    pub(crate) span_index: SourceSpanIndex,
    pub(crate) parameters: NodeRef,
    pub(crate) mappings: NodeRef,
    pub(crate) conditions: NodeRef,
    pub(crate) resources: NodeRef,
    pub(crate) outputs: NodeRef,
    pub(crate) rules: NodeRef,
    pub(crate) template_metadata: NodeRef,
    pub(crate) format_version: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) transforms: Vec<String>,
    pub(crate) raw_top_level_keys: Vec<String>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) globals: NodeRef,
}

#[derive(Debug)]
pub struct ParseError {
    pub message: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.line, self.column) {
            (Some(l), Some(c)) => write!(f, "{}:{}: {}", l, c, self.message),
            _ => write!(f, "{}", self.message),
        }
    }
}

impl error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arena_alloc_get_roundtrip() {
        let mut arena = Arena::new();
        let r = arena.alloc(SpannedNode {
            node: Node::String("hello".into()),
            span: SourceSpan { start_line: 1, start_column: 1, end_line: 1, end_column: 5 },
            path: "test".into(),
        });
        assert_eq!(arena.as_str(r), Some("hello"));
    }

    #[test]
    fn arena_multiple_nodes() {
        let mut arena = Arena::new();
        let refs: Vec<NodeRef> = (0..100)
            .map(|i| arena.alloc(SpannedNode { node: Node::Int(i), span: UNKNOWN_SPAN, path: format!("{}", i) }))
            .collect();
        for (i, r) in refs.iter().enumerate() {
            match arena.node(*r) {
                Node::Int(v) => assert_eq!(*v, i as i64),
                _ => panic!("wrong type"),
            }
        }
    }

    #[test]
    fn node_accessor_map_get() {
        let mut arena = Arena::new();
        let child =
            arena.alloc(SpannedNode { node: Node::String("value".into()), span: UNKNOWN_SPAN, path: "map/key".into() });
        let map = arena.alloc(SpannedNode {
            node: Node::Map(vec![("key".into(), child)]),
            span: UNKNOWN_SPAN,
            path: "map".into(),
        });
        assert_eq!(arena.map_get(map, "key"), Some(child));
        assert_eq!(arena.map_get(map, "missing"), None);
    }

    #[test]
    fn source_span_unknown_sentinel() {
        assert_eq!(UNKNOWN_SPAN.start_line, u32::MAX);
        assert_eq!(UNKNOWN_SPAN.end_column, u32::MAX);
    }

    #[test]
    fn arena_out_of_bounds_returns_sentinel() {
        let arena = Arena::new();
        let node = arena.get(999);
        assert!(matches!(node.node, Node::Null));
        assert_eq!(node.span, UNKNOWN_SPAN);
        assert!(!arena.is_valid(999));
        assert_eq!(arena.as_map(999), None, "out-of-bounds as_map should return None");
        assert_eq!(arena.as_list(999), None, "out-of-bounds as_list should return None");
    }
}
