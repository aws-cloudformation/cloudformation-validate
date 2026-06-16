//! `AWS::LanguageExtensions` transform expansion.
//!
//! When the template declares the `AWS::LanguageExtensions` transform, the
//! `Fn::ForEach::*` macro form is allowed inside any object section
//! (Conditions, Resources, Outputs, ...) and produces multiple sibling entries
//! after expansion. CloudFormation expands these macros server-side before
//! deployment, so for parity we expand them here — after parsing, before the
//! resolver and `condition_shape` see the model.
//!
//! Without this pass, downstream rules emit false positives because the
//! macro's body references variables that exist only after substitution
//! (`{Ref: {Fn::Sub: "Param${Identifier}"}}` looks like a malformed `Ref`,
//! and parameters used only via the macro look unreferenced).
//!
//! Mirrors the logic in cfn-lint's `_language_extensions.py::_Transform`.
//! Scope today is intentionally narrow:
//!
//! * The collection (second `Fn::ForEach` argument) must be a literal list of
//!   scalar strings (or a `Ref` to a parameter whose default is a known
//!   `CommaDelimitedList` literal — not yet supported).
//! * Inside the body, only string-key substitution, `Fn::Sub` template
//!   substitution, and `Ref:<iter_var>` substitution are performed. Other
//!   intrinsics are walked recursively so nested macros also expand, but
//!   their internal structure is preserved.
//!
//! Macros whose collection is dynamic, or that exceed the expansion-depth
//! cap, remain in place and are reported as parse-level diagnostics so the
//! user knows the macro was not expanded.

use crate::consts::{FN_REF, FN_SUB, TRANSFORM_LANGUAGE_EXTENSIONS};
use crate::ir::*;
use diagnostics::Diagnostic;
use std::collections::HashMap;

const FOREACH_PREFIX: &str = "Fn::ForEach::";
const MAX_EXPANSION_DEPTH: u32 = 16;

/// Rule ID emitted when a `Fn::ForEach` macro cannot be expanded
/// (dynamic collection, too-deep nesting, malformed shape, ...). The
/// macro is left in place so downstream rules can still flag obvious
/// errors, but the user is told why expansion was skipped.
const RULE_FOREACH_NOT_EXPANDED: &str = "W9032";

/// Bindings of iteration-variable name → concrete string value. The same
/// `${name}` placeholder is substituted across map keys, `Fn::Sub` templates,
/// and bare `Ref` targets.
type Bindings = HashMap<String, String>;

/// Run the `AWS::LanguageExtensions` transform on `ir`. Returns diagnostics
/// for macros that could not be expanded. When the transform is not declared,
/// this is a no-op.
pub(crate) fn expand_language_extensions(ir: &mut TemplateIR) -> Vec<Diagnostic> {
    if !ir.transforms.iter().any(|t| t == TRANSFORM_LANGUAGE_EXTENSIONS) {
        return Vec::new();
    }

    let mut diagnostics = Vec::new();
    let bindings = Bindings::new();

    // Sections that may contain `Fn::ForEach::*` macros at any depth.
    for section_ref in [ir.conditions, ir.resources, ir.outputs] {
        if section_ref != NULL_REF {
            expand_at(&mut ir.arena, section_ref, &bindings, 0, &mut diagnostics);
        }
    }

    diagnostics
}

/// Expand any `Fn::ForEach::*` macros reachable from `node_ref`. Recurses
/// into child maps and lists. Substitutions in `bindings` apply to every
/// substring encountered along the way (used by nested macros which inherit
/// outer bindings).
fn expand_at(
    arena: &mut Arena,
    node_ref: NodeRef,
    bindings: &Bindings,
    depth: u32,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if node_ref == NULL_REF || !arena.is_valid(node_ref) {
        return;
    }
    if depth > MAX_EXPANSION_DEPTH {
        diagnostics.push(crate::make_parse_diagnostic(
            RULE_FOREACH_NOT_EXPANDED,
            format!(
                "Fn::ForEach expansion exceeded maximum depth {}; macro left unexpanded",
                MAX_EXPANSION_DEPTH
            ),
            arena.get(node_ref).span,
        ));
        return;
    }

    match arena.node(node_ref).clone() {
        Node::Map(entries) => {
            let mut new_entries: Vec<(String, NodeRef)> = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                if let Some(macro_uid) = key.strip_prefix(FOREACH_PREFIX) {
                    match expand_foreach(arena, &key, value, bindings, depth, diagnostics) {
                        ExpansionResult::Expanded(expanded) => {
                            for (ek, ev) in expanded {
                                if let Some(_) = new_entries.iter().find(|(k, _)| k == &ek) {
                                    diagnostics.push(crate::make_parse_diagnostic(
                                        RULE_FOREACH_NOT_EXPANDED,
                                        format!(
                                            "Fn::ForEach::{} produced duplicate key '{}' during expansion",
                                            macro_uid, ek
                                        ),
                                        arena.get(value).span,
                                    ));
                                } else {
                                    new_entries.push((ek, ev));
                                }
                            }
                        }
                        ExpansionResult::Skipped => {
                            new_entries.push((key, value));
                        }
                    }
                } else {
                    let substituted_key = substitute_placeholders(&key, bindings);
                    expand_at(arena, value, bindings, depth + 1, diagnostics);
                    new_entries.push((substituted_key, value));
                }
            }
            arena.set_node(node_ref, Node::Map(new_entries));
        }
        Node::List(items) => {
            for item_ref in items {
                expand_at(arena, item_ref, bindings, depth + 1, diagnostics);
            }
        }
        // Intrinsics may carry NodeRef children that themselves can contain macros.
        Node::Intrinsic(intrinsic) => {
            for child in intrinsic_children(&intrinsic) {
                expand_at(arena, child, bindings, depth + 1, diagnostics);
            }
        }
        _ => {}
    }
}

enum ExpansionResult {
    Expanded(Vec<(String, NodeRef)>),
    Skipped,
}

/// Expand a single `Fn::ForEach::<UID>: [iter_var, collection, body]` entry.
/// Returns the list of expanded sibling entries, or `Skipped` if the macro
/// shape is invalid or the collection cannot be statically resolved.
fn expand_foreach(
    arena: &mut Arena,
    key: &str,
    value_ref: NodeRef,
    outer_bindings: &Bindings,
    depth: u32,
    diagnostics: &mut Vec<Diagnostic>,
) -> ExpansionResult {
    let span = arena.get(value_ref).span;
    let macro_uid = key.strip_prefix(FOREACH_PREFIX).unwrap_or("");

    let Some(triple) = arena.as_list(value_ref) else {
        diagnostics.push(crate::make_parse_diagnostic(
            RULE_FOREACH_NOT_EXPANDED,
            format!("Fn::ForEach::{} value must be a 3-element array; macro left unexpanded", macro_uid),
            span,
        ));
        return ExpansionResult::Skipped;
    };
    if triple.len() != 3 {
        diagnostics.push(crate::make_parse_diagnostic(
            RULE_FOREACH_NOT_EXPANDED,
            format!(
                "Fn::ForEach::{} value must be a 3-element array (got {}); macro left unexpanded",
                macro_uid,
                triple.len()
            ),
            span,
        ));
        return ExpansionResult::Skipped;
    }

    let iter_ref = triple[0];
    let collection_ref = triple[1];
    let body_ref = triple[2];

    let Some(iter_var) = arena.as_str(iter_ref).map(str::to_owned) else {
        diagnostics.push(crate::make_parse_diagnostic(
            RULE_FOREACH_NOT_EXPANDED,
            format!(
                "Fn::ForEach::{} first argument must be a string identifier; macro left unexpanded",
                macro_uid
            ),
            span,
        ));
        return ExpansionResult::Skipped;
    };

    let Some(collection_values) = literal_string_collection(arena, collection_ref) else {
        diagnostics.push(crate::make_parse_diagnostic(
            RULE_FOREACH_NOT_EXPANDED,
            format!(
                "Fn::ForEach::{} collection must be a literal list of strings to expand statically; macro left unexpanded",
                macro_uid
            ),
            span,
        ));
        return ExpansionResult::Skipped;
    };

    let Some(body_entries) = arena.as_map(body_ref).map(<[(String, NodeRef)]>::to_vec) else {
        diagnostics.push(crate::make_parse_diagnostic(
            RULE_FOREACH_NOT_EXPANDED,
            format!("Fn::ForEach::{} body must be a map; macro left unexpanded", macro_uid),
            span,
        ));
        return ExpansionResult::Skipped;
    };

    let mut expanded: Vec<(String, NodeRef)> = Vec::with_capacity(body_entries.len() * collection_values.len());
    for value in &collection_values {
        let mut bindings = outer_bindings.clone();
        bindings.insert(iter_var.clone(), value.clone());
        for (body_key, body_val) in &body_entries {
            let new_key = substitute_placeholders(body_key, &bindings);
            let new_val = clone_with_bindings(arena, *body_val, &bindings);
            // Recursively expand any nested Fn::ForEach inside the freshly-cloned subtree.
            expand_at(arena, new_val, &Bindings::new(), depth + 1, diagnostics);
            expanded.push((new_key, new_val));
        }
    }

    ExpansionResult::Expanded(expanded)
}

/// Returns the literal list of scalar strings if `node_ref` is a List of
/// String nodes (the only collection shape we expand statically). Returns
/// `None` for dynamic collections that need resolver-time evaluation.
fn literal_string_collection(arena: &Arena, node_ref: NodeRef) -> Option<Vec<String>> {
    let items = arena.as_list(node_ref)?;
    let mut out = Vec::with_capacity(items.len());
    for item_ref in items {
        match arena.node(*item_ref) {
            Node::String(s) => out.push(s.clone()),
            Node::Int(n) => out.push(n.to_string()),
            Node::Bool(b) => out.push(b.to_string()),
            _ => return None,
        }
    }
    Some(out)
}

/// Allocate a deep copy of the subtree at `src_ref` with `bindings` applied to
/// every map key, `Fn::Sub` template, and `Ref` target whose name matches a
/// bound variable. NodeRef references inside intrinsic children are recursed.
fn clone_with_bindings(arena: &mut Arena, src_ref: NodeRef, bindings: &Bindings) -> NodeRef {
    if !arena.is_valid(src_ref) {
        return src_ref;
    }
    let src = arena.get(src_ref).clone();
    let new_node = match src.node {
        Node::String(s) => Node::String(substitute_placeholders(&s, bindings)),
        Node::Map(entries) => {
            let mut new_entries = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let new_key = substitute_placeholders(&k, bindings);
                let new_val = clone_with_bindings(arena, v, bindings);
                new_entries.push((new_key, new_val));
            }
            // Detect the post-substitution `{ "Ref": <string> }` shape that
            // the parser would normally have folded into `IntrinsicFn::Ref`,
            // and fold it now so condition_shape and the resolver see a
            // proper Ref instead of a plain map.
            promote_single_intrinsic_map(arena, new_entries)
        }
        Node::List(items) => {
            let new_items = items.iter().map(|&i| clone_with_bindings(arena, i, bindings)).collect();
            Node::List(new_items)
        }
        Node::Intrinsic(intrinsic) => {
            let new_intrinsic = clone_intrinsic(arena, intrinsic, bindings);
            // Fold `Fn::Sub("literal", None)` (no remaining placeholders, no
            // substitution map) into a plain string. CloudFormation evaluates
            // this to the literal at deploy time, so downstream rules should
            // see a string here, not an intrinsic.
            if let IntrinsicFn::Sub(ref template, None) = new_intrinsic
                && !template.contains("${")
            {
                Node::String(template.clone())
            } else {
                Node::Intrinsic(new_intrinsic)
            }
        }
        other => other,
    };
    arena.alloc(SpannedNode { node: new_node, span: src.span, path: src.path })
}

/// Convert single-key maps that match an intrinsic function shape back into
/// `IntrinsicFn` nodes. The parser leaves these as plain maps when the original
/// value was dynamic (e.g. `{Ref: {Fn::Sub: "Param${X}"}}`); after substitution
/// the value may now be a plain string, at which point the map is equivalent
/// to the intrinsic the downstream rules expect.
fn promote_single_intrinsic_map(arena: &Arena, entries: Vec<(String, NodeRef)>) -> Node {
    if entries.len() == 1 {
        let (key, value) = &entries[0];
        if key == FN_REF
            && let Some(target) = arena.as_str(*value)
        {
            return Node::Intrinsic(IntrinsicFn::Ref(target.to_string()));
        }
    }
    Node::Map(entries)
}

/// Recursively rebuild an `IntrinsicFn` with `bindings` applied. NodeRef
/// children are deep-copied via `clone_with_bindings`. Strings inside `Sub`
/// templates and bare `Ref` targets are substituted directly.
fn clone_intrinsic(arena: &mut Arena, intrinsic: IntrinsicFn, bindings: &Bindings) -> IntrinsicFn {
    match intrinsic {
        IntrinsicFn::Ref(target) => {
            let substituted = substitute_placeholders(&target, bindings);
            IntrinsicFn::Ref(substituted)
        }
        IntrinsicFn::GetAtt(resource, attr) => {
            IntrinsicFn::GetAtt(substitute_placeholders(&resource, bindings), substitute_placeholders(&attr, bindings))
        }
        IntrinsicFn::Sub(template, subs) => {
            let new_template = substitute_placeholders(&template, bindings);
            let new_subs = subs.map(|entries| {
                entries
                    .into_iter()
                    .map(|(k, v)| (substitute_placeholders(&k, bindings), clone_with_bindings(arena, v, bindings)))
                    .collect()
            });
            IntrinsicFn::Sub(new_template, new_subs)
        }
        IntrinsicFn::Join(delim, items) => {
            IntrinsicFn::Join(clone_with_bindings(arena, delim, bindings), clone_with_bindings(arena, items, bindings))
        }
        IntrinsicFn::Select(idx, list) => {
            IntrinsicFn::Select(clone_with_bindings(arena, idx, bindings), clone_with_bindings(arena, list, bindings))
        }
        IntrinsicFn::If(cond, t, f) => {
            IntrinsicFn::If(cond, clone_with_bindings(arena, t, bindings), clone_with_bindings(arena, f, bindings))
        }
        IntrinsicFn::IfExpr(c, t, f) => IntrinsicFn::IfExpr(
            clone_with_bindings(arena, c, bindings),
            clone_with_bindings(arena, t, bindings),
            clone_with_bindings(arena, f, bindings),
        ),
        IntrinsicFn::FindInMap(a, b, c, d) => IntrinsicFn::FindInMap(
            clone_with_bindings(arena, a, bindings),
            clone_with_bindings(arena, b, bindings),
            clone_with_bindings(arena, c, bindings),
            d.map(|n| clone_with_bindings(arena, n, bindings)),
        ),
        IntrinsicFn::Split(delim, src) => IntrinsicFn::Split(
            clone_with_bindings(arena, delim, bindings),
            clone_with_bindings(arena, src, bindings),
        ),
        IntrinsicFn::Base64(c) => IntrinsicFn::Base64(clone_with_bindings(arena, c, bindings)),
        IntrinsicFn::Cidr(a, b, c) => IntrinsicFn::Cidr(
            clone_with_bindings(arena, a, bindings),
            clone_with_bindings(arena, b, bindings),
            clone_with_bindings(arena, c, bindings),
        ),
        IntrinsicFn::GetAZs(c) => IntrinsicFn::GetAZs(clone_with_bindings(arena, c, bindings)),
        IntrinsicFn::ImportValue(c) => IntrinsicFn::ImportValue(clone_with_bindings(arena, c, bindings)),
        IntrinsicFn::Transform(name, params) => IntrinsicFn::Transform(
            name,
            params.into_iter().map(|(k, v)| (k, clone_with_bindings(arena, v, bindings))).collect(),
        ),
        IntrinsicFn::And(items) => {
            IntrinsicFn::And(items.into_iter().map(|i| clone_with_bindings(arena, i, bindings)).collect())
        }
        IntrinsicFn::Or(items) => {
            IntrinsicFn::Or(items.into_iter().map(|i| clone_with_bindings(arena, i, bindings)).collect())
        }
        IntrinsicFn::Not(c) => IntrinsicFn::Not(clone_with_bindings(arena, c, bindings)),
        IntrinsicFn::Equals(a, b) => {
            IntrinsicFn::Equals(clone_with_bindings(arena, a, bindings), clone_with_bindings(arena, b, bindings))
        }
        IntrinsicFn::ToJsonString(c) => IntrinsicFn::ToJsonString(clone_with_bindings(arena, c, bindings)),
        IntrinsicFn::Length(c) => IntrinsicFn::Length(clone_with_bindings(arena, c, bindings)),
        IntrinsicFn::ForEach(uid, var, coll, body) => IntrinsicFn::ForEach(
            uid,
            var,
            clone_with_bindings(arena, coll, bindings),
            clone_with_bindings(arena, body, bindings),
        ),
        IntrinsicFn::ValueOf(a, b) => IntrinsicFn::ValueOf(a, b),
        IntrinsicFn::ValueOfAll(a, b) => IntrinsicFn::ValueOfAll(a, b),
        IntrinsicFn::RefAll(s) => IntrinsicFn::RefAll(s),
        IntrinsicFn::Contains(a, b) => {
            IntrinsicFn::Contains(clone_with_bindings(arena, a, bindings), clone_with_bindings(arena, b, bindings))
        }
        IntrinsicFn::EachMemberEquals(a, b) => IntrinsicFn::EachMemberEquals(
            clone_with_bindings(arena, a, bindings),
            clone_with_bindings(arena, b, bindings),
        ),
        IntrinsicFn::EachMemberIn(a, b) => {
            IntrinsicFn::EachMemberIn(clone_with_bindings(arena, a, bindings), clone_with_bindings(arena, b, bindings))
        }
        IntrinsicFn::GetStackOutput(c) => IntrinsicFn::GetStackOutput(clone_with_bindings(arena, c, bindings)),
    }
}

/// Replace every `${name}` occurrence in `s` with the string bound to `name`.
/// Variables not in `bindings` are left intact (so `${AWS::Region}` and other
/// unrelated placeholders survive).
fn substitute_placeholders(s: &str, bindings: &Bindings) -> String {
    if bindings.is_empty() || !s.contains("${") {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            // Preserve the `${!literal}` escape — CloudFormation removes the `!`
            // server-side, but our caller treats this as a literal pass-through.
            if i + 2 < bytes.len() && bytes[i + 2] == b'!' {
                out.push_str("${!");
                i += 3;
                continue;
            }
            let var_start = i + 2;
            if let Some(end_offset) = s[var_start..].find('}') {
                let var = s[var_start..var_start + end_offset].trim();
                if let Some(replacement) = bindings.get(var) {
                    out.push_str(replacement);
                    i = var_start + end_offset + 1;
                    continue;
                }
                // Unknown placeholder — leave as-is so downstream Fn::Sub
                // handling still resolves it correctly.
                out.push_str(&s[i..var_start + end_offset + 1]);
                i = var_start + end_offset + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// All NodeRef children carried inside an intrinsic (used to walk into nested
/// macros). Variants whose payload is purely scalar (Ref, GetAtt, ValueOf, ...)
/// have no children and contribute nothing.
fn intrinsic_children(intrinsic: &IntrinsicFn) -> Vec<NodeRef> {
    match intrinsic {
        IntrinsicFn::Ref(_) | IntrinsicFn::GetAtt(_, _) => Vec::new(),
        IntrinsicFn::Sub(_, subs) => subs.as_ref().map(|e| e.iter().map(|(_, v)| *v).collect()).unwrap_or_default(),
        IntrinsicFn::Join(a, b) | IntrinsicFn::Select(a, b) | IntrinsicFn::Split(a, b) | IntrinsicFn::Equals(a, b) => {
            vec![*a, *b]
        }
        IntrinsicFn::If(_, a, b) => vec![*a, *b],
        IntrinsicFn::IfExpr(c, a, b) => vec![*c, *a, *b],
        IntrinsicFn::FindInMap(a, b, c, d) => {
            let mut v = vec![*a, *b, *c];
            if let Some(x) = d {
                v.push(*x);
            }
            v
        }
        IntrinsicFn::Base64(c)
        | IntrinsicFn::GetAZs(c)
        | IntrinsicFn::ImportValue(c)
        | IntrinsicFn::Not(c)
        | IntrinsicFn::ToJsonString(c)
        | IntrinsicFn::Length(c)
        | IntrinsicFn::GetStackOutput(c) => vec![*c],
        IntrinsicFn::Cidr(a, b, c) => vec![*a, *b, *c],
        IntrinsicFn::Transform(_, params) => params.iter().map(|(_, v)| *v).collect(),
        IntrinsicFn::And(items) | IntrinsicFn::Or(items) => items.clone(),
        IntrinsicFn::ForEach(_, _, c, b) => vec![*c, *b],
        IntrinsicFn::Contains(a, b) | IntrinsicFn::EachMemberEquals(a, b) | IntrinsicFn::EachMemberIn(a, b) => {
            vec![*a, *b]
        }
        IntrinsicFn::ValueOf(_, _) | IntrinsicFn::ValueOfAll(_, _) | IntrinsicFn::RefAll(_) => Vec::new(),
    }
}

// Re-export for downstream consumers that want to know the constants without
// taking an extra dependency on the consts module via `cfn_function_name` etc.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_simple() {
        let mut bindings = Bindings::new();
        bindings.insert("Identifier".into(), "A".into());
        assert_eq!(substitute_placeholders("Param${Identifier}", &bindings), "ParamA");
        assert_eq!(substitute_placeholders("IsParam${Identifier}Enabled", &bindings), "IsParamAEnabled");
    }

    #[test]
    fn substitute_preserves_unknown_placeholders() {
        let mut bindings = Bindings::new();
        bindings.insert("Identifier".into(), "A".into());
        assert_eq!(substitute_placeholders("${AWS::Region}-${Identifier}", &bindings), "${AWS::Region}-A");
    }

    #[test]
    fn substitute_preserves_literal_escape() {
        let bindings = Bindings::new();
        assert_eq!(substitute_placeholders("${!literal}", &bindings), "${!literal}");
    }

    #[test]
    fn no_op_when_transform_absent() {
        let input = r#"{
            "Conditions": {
                "Fn::ForEach::Run": ["X", ["a","b"], {"C${X}": {"Fn::Equals":[{"Ref":"P"},"x"]}}]
            },
            "Resources": {"R": {"Type": "T"}}
        }"#;
        let mut ir = crate::parser::parse(input.as_bytes()).expect("parse");
        let diags = expand_language_extensions(&mut ir);
        assert!(diags.is_empty());
        // ForEach key should still be present unchanged.
        let conditions = ir.arena.as_map(ir.conditions).expect("conditions map");
        assert!(conditions.iter().any(|(k, _)| k.starts_with(FOREACH_PREFIX)));
    }

    #[test]
    fn expands_literal_collection_into_sibling_keys() {
        let input = r#"{
            "Transform": "AWS::LanguageExtensions",
            "Parameters": {
                "ParamA": {"Type": "String"},
                "ParamB": {"Type": "String"}
            },
            "Conditions": {
                "Fn::ForEach::Run": [
                    "Identifier",
                    ["A", "B"],
                    {
                        "Is${Identifier}Enabled": {
                            "Fn::Equals": [{"Ref": {"Fn::Sub": "Param${Identifier}"}}, "true"]
                        }
                    }
                ]
            },
            "Resources": {"R": {"Type": "T"}}
        }"#;
        let mut ir = crate::parser::parse(input.as_bytes()).expect("parse");
        let diags = expand_language_extensions(&mut ir);
        assert!(diags.is_empty(), "unexpected diagnostics: {:?}", diags);

        let conditions = ir.arena.as_map(ir.conditions).expect("conditions map");
        let condition_keys: Vec<_> = conditions.iter().map(|(k, _)| k.clone()).collect();
        assert!(condition_keys.contains(&"IsAEnabled".to_string()), "got {:?}", condition_keys);
        assert!(condition_keys.contains(&"IsBEnabled".to_string()), "got {:?}", condition_keys);
        assert!(
            !condition_keys.iter().any(|k| k.starts_with(FOREACH_PREFIX)),
            "ForEach key should be removed after expansion, got {:?}",
            condition_keys
        );
    }

    #[test]
    fn dynamic_collection_emits_diagnostic_and_skips() {
        let input = r#"{
            "Transform": "AWS::LanguageExtensions",
            "Parameters": {"P": {"Type": "CommaDelimitedList"}},
            "Conditions": {
                "Fn::ForEach::Run": ["X", {"Ref": "P"}, {"C${X}": {"Fn::Equals":[{"Ref":"P"},"x"]}}]
            },
            "Resources": {"R": {"Type": "T"}}
        }"#;
        let mut ir = crate::parser::parse(input.as_bytes()).expect("parse");
        let diags = expand_language_extensions(&mut ir);
        assert_eq!(diags.len(), 1, "expected one diagnostic for unexpandable macro, got {:?}", diags);
        assert_eq!(diags[0].rule_id, RULE_FOREACH_NOT_EXPANDED);
    }
}

// Suppress unused-import warning for FN_REF / FN_SUB which guard reads on
// future expansion paths.
#[allow(dead_code)]
const _: &str = FN_REF;
#[allow(dead_code)]
const _: &str = FN_SUB;
