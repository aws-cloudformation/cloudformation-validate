//! Runtime compilation and merging of overlay CloudFormation resource provider
//! schemas on top of the bundled compiled schemas.
//!
//! Bundled schemas are compiled at build time from raw CloudFormation registry
//! JSON into the compiled representation baked into the binary. This module runs
//! the *same* transform at engine construction time, so callers can supply
//! additional schemas — for example properties a service has shipped but not yet
//! published to the CloudFormation registry — and have templates using them
//! validate without false findings.
//!
//! # Merge model
//!
//! One model, applied uniformly: an overlay may **add** entries to a collection
//! and **restate** a single-valued constraint or a logical group, and it never
//! silently drops a constraint the bundled schema already carries. Adding an
//! entry to `required` or to a dependency list is stating a constraint, so it can
//! legitimately produce a finding on a template that violates it; what an overlay
//! cannot do is make a bundled constraint disappear. Concretely, for every field
//! of a schema or property:
//!
//! | Field kind | Rule |
//! |------------|------|
//! | Keyed collections — `properties`, `definitions`, `patternProperties` | deep-merged by key: new keys are added, shared keys recurse |
//! | Independent-fact collections — `required`, the `/properties/...` lifecycle metadata lists, and each key of `dependentRequired`/`dependentExcluded` | unioned, order-preserving, deduplicated |
//! | Single-valued constraints — `type`, `pattern`, `const`, numeric bounds, lengths, item and property counts, `uniqueItems`, `format`, `description`, `additionalProperties`, `not.enum` | replaced when the overlay supplies them, inherited otherwise |
//! | Logical groups — `requiredOr`, `requiredXor`, `primaryIdentifier` | replaced as a whole when supplied. Each is *one* group ("at least one of", "exactly one of", "these properties identify the resource"), so unioning two groups would fabricate a third constraint that neither schema states |
//! | Composition — `allOf`/`anyOf`/`oneOf`/`if`-`then`-`else` | replaced when supplied, because a complete overlay restates the whole composition and appending would duplicate branches. `allOf` splits into plain and conditional entries during compilation, so an overlay supplying `allOf` replaces both halves together |
//! | Singleton subschemas — `items` (the schema every array element must satisfy) | deep-merged, like one keyed entry: an overlay stating only `pattern` narrows the element schema without discarding the rest of it |
//! | Schema-level metadata — `replacementStrategy`, `documentationUrl`, `sourceUrl` | replaced when supplied. These enrich reporting and constrain nothing |
//! | Enums | `enum` and `enumCaseInsensitive` are two representations of one field and are never both populated for a property. Supplying either replaces whichever the bundled schema used, keeping the bundled comparison semantics: widening a case-insensitive enum with a plain `enum` stays case-insensitive, so previously accepted casings keep validating |
//!
//! A `$ref` is never folded into the property that points at it. An overlay
//! extending a `$ref` property has its fields merged *beside* the reference, and
//! `PropSchema::resolve` combines the
//! whole chain at validation time — each hop's own constraints applied over its
//! target, nearest hop winning. So a constraint-only overlay (say, just `enum`)
//! takes effect, a chain of references is followed to its end, and a definition
//! changed by a later overlay still reaches every property referencing it. It
//! also means the merge never depends on the order definitions are visited in.
//! Within a chain the same rules decide each field, so a hop that restates a
//! single-valued constraint overrides the one further along, while collections
//! accumulate across every hop.
//!
//! Overlays for the same type are applied in the order given; a later overlay
//! sees the result of the earlier ones.
//!
//! # Scope limits
//!
//! - An overlay cannot make a bundled `required` property optional, and cannot
//!   remove an entry from a metadata list — those collections only ever grow.
//! - Constraints inside `if`/`then`/`else` branches and other composition
//!   subschemas are replaced as whole list entries, never deep-merged.
//! - Constructs the compiled model does not represent — a `$ref` outside
//!   `#/definitions/`, tuple-form `items`, a `type` that is neither a string nor
//!   an array of strings — are rejected
//!   rather than compiled into something weaker than the caller wrote.
//! - Keywords the compiled model has no representation for at all — `not` other
//!   than `not.enum`, `multipleOf`, `propertyNames`, `contains` — constrain
//!   nothing, for bundled and overlay schemas alike. An overlay stating one is
//!   logged rather than dropped silently.
//! - Keywords written beside a `$ref` have no effect, matching draft-07 and the
//!   bundled pipeline; a constraining one is logged rather than dropped silently.
//!   To extend a referenced shape, overlay the *property* — those fields are
//!   merged onto whatever the reference points at.
//! - `enum` and `enumCaseInsensitive` are one field in two comparison modes; an
//!   overlay cannot switch a property the service treats case-insensitively over
//!   to case-sensitive comparison, because doing so would reject casings that
//!   validate today.
//! - Conditional constraints the build pipeline contributes as extension
//!   fragments are validated from a separate embedded artifact that overlays do
//!   not merge into, so an overlay cannot suppress a finding originating there.
//! - Overlays reach schema validation only. Rule-engine data compiled at build
//!   time (the known-resource-type catalog aside, which construction propagates)
//!   is not derived from overlays, so e.g. a regional instance-type table still
//!   reflects the bundled data.

use crate::compiled::{CompiledSchema, MAX_REF_CHAIN, PropSchema};
use data_source::compiled_schema::compile_schema;
use log::warn;
use serde_json::Value;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::error::Error;
use std::fmt;

/// Keywords that carry no validation meaning, so their presence beside a `$ref`
/// is not worth reporting. Published provider schemas routinely document a
/// referenced property this way.
const REF_ANNOTATION_KEYWORDS: [&str; 7] =
    ["description", "markdownDescription", "title", "examples", "default", "$comment", "insertionOrder"];

/// Validation keywords the compiled schema model has no field for, so nothing
/// enforces them. Bundled schemas do not use them; an overlay author writing one
/// would otherwise believe it applies, which is the one case worth saying out
/// loud. `not` is handled separately because only its nested `enum` is modelled.
const UNREPRESENTED_CONSTRAINT_KEYWORDS: [&str; 8] = [
    "multipleOf",
    "propertyNames",
    "contains",
    "minContains",
    "maxContains",
    "additionalItems",
    "dependencies",
    "unevaluatedProperties",
];

/// Maximum JSON nesting accepted in an overlay schema.
///
/// Compilation and merging walk the structure recursively, so an unbounded input
/// could exhaust the stack and abort the host process. The bound matches the
/// nesting limit `serde_json` applies when parsing, so a programmatically built
/// `serde_json::Value` is held to the same limit as the same schema supplied as
/// text. Real provider schemas nest far shallower — the deepest published
/// schema measures 18 levels.
pub const MAX_OVERLAY_DEPTH: usize = 128;

/// Why an overlay schema was rejected.
///
/// Every overlay entry point is fallible and validates its input up front: a
/// rejected overlay leaves the schema store untouched rather than registering a
/// half-usable schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaOverlayError {
    /// The resource type name was empty.
    MissingTypeName,
    /// The schema was not a JSON object.
    NotAnObject { type_name: String },
    /// The schema nests deeper than [`MAX_OVERLAY_DEPTH`].
    TooDeep { type_name: String, max_depth: usize },
    /// The schema uses a construct the compiled model cannot represent, which
    /// would otherwise compile to a weaker schema than the caller wrote.
    Unsupported { type_name: String, path: String, detail: String },
    /// The schema carried no keyword the compiler understands, so applying it
    /// would change nothing.
    NoEffect { type_name: String },
    /// The definition `$ref` graph contains a cycle, naming the definitions on it.
    CyclicRef { type_name: String, cycle: Vec<String> },
    /// A chain of `$ref`s longer than resolution can follow to its end, which
    /// would leave the constraints at the end of the chain unenforced.
    RefChainTooLong { type_name: String, definition: String, hops: usize },
    /// A property ended up with both enum representations populated, which the
    /// compiled model forbids.
    ConflictingEnums { type_name: String, property: String },
}

impl fmt::Display for SchemaOverlayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaOverlayError::MissingTypeName => write!(
                f,
                "Additional schema is missing a resource type name (no explicit type name and none in the schema)"
            ),
            SchemaOverlayError::NotAnObject { type_name } => write!(
                f,
                "Invalid additional schema for '{type_name}': expected a JSON object describing a CloudFormation \
                 resource provider schema"
            ),
            SchemaOverlayError::TooDeep { type_name, max_depth } => write!(
                f,
                "Invalid additional schema for '{type_name}': nested deeper than the supported limit of {max_depth} \
                 levels"
            ),
            SchemaOverlayError::Unsupported { type_name, path, detail } => write!(
                f,
                "Invalid additional schema for '{type_name}': {detail} at '{path}'. Applying it would validate less \
                 than the schema states"
            ),
            SchemaOverlayError::NoEffect { type_name } => write!(
                f,
                "Invalid additional schema for '{type_name}': the schema states no properties, definitions or \
                 constraints, so applying it would have no effect"
            ),
            SchemaOverlayError::CyclicRef { type_name, cycle } => write!(
                f,
                "Invalid additional schema for '{type_name}': definitions reference each other in a cycle ({})",
                cycle.join(" -> ")
            ),
            SchemaOverlayError::RefChainTooLong { type_name, definition, hops } => write!(
                f,
                "Invalid additional schema for '{type_name}': the '$ref' chain starting at definition \
                 '{definition}' is {hops} hops long, more than the {MAX_DEFINITION_REF_CHAIN} that can be resolved, \
                 so the constraints at the end of it would not be enforced"
            ),
            SchemaOverlayError::ConflictingEnums { type_name, property } => write!(
                f,
                "Invalid additional schema for '{type_name}': property '{property}' would carry both a case-sensitive \
                 and a case-insensitive list of allowed values"
            ),
        }
    }
}

impl Error for SchemaOverlayError {}

/// Compile a raw CloudFormation resource provider schema (registry JSON) into the
/// runtime [`CompiledSchema`], rejecting input the merge cannot handle safely.
///
/// The raw → compiled transform is single-sourced in `data_source`, the same
/// function the build pipeline uses for bundled schemas; the result is converted
/// into the runtime type field by field. The transform is shared but the input is
/// not enriched the way the build pipeline enriches bundled schemas — see the
/// `data_source::compiled_schema` module docs.
pub(crate) fn compile(type_name: &str, raw: &Value) -> Result<CompiledSchema, SchemaOverlayError> {
    if type_name.trim().is_empty() {
        return Err(SchemaOverlayError::MissingTypeName);
    }
    if !raw.is_object() {
        return Err(SchemaOverlayError::NotAnObject { type_name: type_name.to_string() });
    }
    check_depth(type_name, raw)?;
    check_supported(type_name, raw)?;
    let compiled: CompiledSchema = compile_schema(type_name, raw).into();
    if states_nothing(&compiled) {
        return Err(SchemaOverlayError::NoEffect { type_name: type_name.to_string() });
    }
    Ok(compiled)
}

/// Whether a compiled overlay carries no information at all — the shape a
/// misspelled or wrong-format JSON object compiles to. Destructured exhaustively
/// so a new field cannot be omitted from the check.
fn states_nothing(schema: &CompiledSchema) -> bool {
    let CompiledSchema {
        type_name: _,
        properties,
        definitions,
        required,
        additional_properties,
        read_only_properties,
        write_only_properties,
        create_only_properties,
        deprecated_properties,
        conditional_create_only_properties,
        primary_identifier,
        replacement_strategy,
        documentation_url,
        source_url,
        description,
        all_of,
        any_of,
        one_of,
        if_then_else,
        dependent_required,
        dependent_excluded,
        required_or,
        required_xor,
    } = schema;
    properties.is_empty()
        && definitions.is_empty()
        && required.is_empty()
        && additional_properties.is_none()
        && read_only_properties.is_empty()
        && write_only_properties.is_empty()
        && create_only_properties.is_empty()
        && deprecated_properties.is_empty()
        && conditional_create_only_properties.is_empty()
        && primary_identifier.is_empty()
        && replacement_strategy.is_none()
        && documentation_url.is_none()
        && source_url.is_none()
        && description.is_none()
        && all_of.is_empty()
        && any_of.is_empty()
        && one_of.is_empty()
        && if_then_else.is_empty()
        && dependent_required.is_empty()
        && dependent_excluded.is_empty()
        && required_or.is_empty()
        && required_xor.is_empty()
}

/// Rejects overlay JSON that nests deeper than [`MAX_OVERLAY_DEPTH`].
///
/// The walk is iterative: a recursive check would itself overflow on the input it
/// exists to reject.
fn check_depth(type_name: &str, raw: &Value) -> Result<(), SchemaOverlayError> {
    let mut stack = vec![(raw, 1usize)];
    while let Some((value, depth)) = stack.pop() {
        if depth > MAX_OVERLAY_DEPTH {
            return Err(SchemaOverlayError::TooDeep { type_name: type_name.to_string(), max_depth: MAX_OVERLAY_DEPTH });
        }
        match value {
            Value::Object(members) => stack.extend(members.values().map(|child| (child, depth + 1))),
            Value::Array(items) => stack.extend(items.iter().map(|child| (child, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

/// Rejects schema constructs the compiled model cannot represent.
///
/// The compiler was written for the curated schemas the build pipeline produces
/// and reduces a shape it does not model to an empty one. That is invisible on
/// curated input and unacceptable on caller input: an overlay that silently
/// validates less than it states is worse than a rejected one. The walk follows
/// schema positions only — `properties`, `definitions`, `patternProperties`,
/// `items`, and composition entries — so a value that merely happens to contain a
/// key like `type` is not mistaken for a schema.
fn check_supported(type_name: &str, raw: &Value) -> Result<(), SchemaOverlayError> {
    let reject = |path: &str, detail: &str| SchemaOverlayError::Unsupported {
        type_name: type_name.to_string(),
        path: path.to_string(),
        detail: detail.to_string(),
    };

    let mut stack: Vec<(String, &Value)> = Vec::new();
    push_schema_children(String::new(), raw, &mut stack);

    while let Some((path, value)) = stack.pop() {
        let Some(members) = value.as_object() else {
            continue;
        };
        if let Some(reference) = members.get("$ref") {
            match reference.as_str() {
                Some(target) if target.starts_with("#/definitions/") => {}
                Some(target) => {
                    return Err(reject(&path, &format!("'$ref' target '{target}' is not '#/definitions/<name>'")));
                }
                None => return Err(reject(&path, "'$ref' must be a string")),
            }
            // Draft-07, which provider schemas are written against, ignores
            // keywords beside a `$ref` — and so does the compiler, for bundled and
            // overlay schemas alike. Annotations beside a reference are common in
            // published schemas and are simply dropped; anything that would have
            // constrained the value is worth saying out loud, because a caller may
            // expect it to apply.
            let ignored: Vec<&str> = members
                .keys()
                .map(String::as_str)
                .filter(|key| *key != "$ref" && !REF_ANNOTATION_KEYWORDS.contains(key))
                .collect();
            if !ignored.is_empty() {
                warn!(
                    "Additional schema for '{type_name}': '{}' at '{path}' sits beside a '$ref' and has no effect, \
                     because a reference resolves to its target. State it in an overlay for the property instead.",
                    ignored.join("', '")
                );
            }
        }
        if let Some(items) = members.get("items")
            && !items.is_object()
        {
            return Err(reject(&path, "'items' must be a single schema object; tuple form is not supported"));
        }
        if !members.contains_key("$ref") {
            warn_unrepresented_keywords(type_name, &path, members);
        }
        if let Some(prop_type) = members.get("type") {
            let supported = match prop_type {
                Value::String(_) => true,
                Value::Array(names) => names.iter().all(Value::is_string),
                _ => false,
            };
            if !supported {
                return Err(reject(&path, "'type' must be a string or an array of strings"));
            }
        }
        push_schema_children(path, value, &mut stack);
    }
    Ok(())
}

/// Logs validation keywords at `path` that nothing will enforce.
///
/// The compiler was written for the curated schemas the build pipeline produces
/// and simply ignores a keyword it has no field for. That is invisible on curated
/// input, but an overlay author who writes one would otherwise be left believing
/// the constraint applies.
fn warn_unrepresented_keywords(type_name: &str, path: &str, members: &serde_json::Map<String, Value>) {
    let unrepresented: Vec<&str> =
        members.keys().map(String::as_str).filter(|key| UNREPRESENTED_CONSTRAINT_KEYWORDS.contains(key)).collect();
    if !unrepresented.is_empty() {
        warn!(
            "Additional schema for '{type_name}': '{}' at '{path}' has no representation in the compiled schema \
             model, so nothing enforces it.",
            unrepresented.join("', '")
        );
    }
    if members.get("not").is_some_and(|negated| negated.get("enum").is_none()) {
        warn!(
            "Additional schema for '{type_name}': 'not' at '{path}' is only enforced when it contains an 'enum', \
             so nothing enforces this one."
        );
    }
}

/// Pushes every child of `value` that is itself in a schema position.
fn push_schema_children<'a>(path: String, value: &'a Value, stack: &mut Vec<(String, &'a Value)>) {
    let Some(members) = value.as_object() else {
        return;
    };
    let child_path = |suffix: &str| if path.is_empty() { suffix.to_string() } else { format!("{path}.{suffix}") };

    for keyword in ["properties", "definitions", "patternProperties"] {
        if let Some(map) = members.get(keyword).and_then(Value::as_object) {
            for (name, child) in map {
                stack.push((child_path(&format!("{keyword}.{name}")), child));
            }
        }
    }
    if let Some(items) = members.get("items") {
        stack.push((child_path("items"), items));
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(entries) = members.get(keyword).and_then(Value::as_array) {
            for (index, entry) in entries.iter().enumerate() {
                stack.push((child_path(&format!("{keyword}[{index}]")), entry));
            }
        }
    }
    for keyword in ["if", "then", "else"] {
        if let Some(branch) = members.get(keyword) {
            stack.push((child_path(keyword), branch));
        }
    }
}

/// Checks the invariants the compiled model relies on: an acyclic definition
/// `$ref` graph, and at most one enum representation per property.
///
/// Runs on the schema as it will be stored, so it covers both a freshly inserted
/// overlay and the result of merging one into a bundled schema.
pub(crate) fn validate_schema(schema: &CompiledSchema) -> Result<(), SchemaOverlayError> {
    match find_ref_chain_defect(&schema.definitions) {
        Some(RefChainDefect::Cycle(cycle)) => {
            return Err(SchemaOverlayError::CyclicRef { type_name: schema.type_name.clone(), cycle });
        }
        Some(RefChainDefect::TooLong { start, hops }) => {
            return Err(SchemaOverlayError::RefChainTooLong {
                type_name: schema.type_name.clone(),
                definition: start,
                hops,
            });
        }
        None => {}
    }
    for (name, prop) in schema.properties.iter().chain(schema.definitions.iter()) {
        if let Some(path) = find_conflicting_enum(name, prop) {
            return Err(SchemaOverlayError::ConflictingEnums { type_name: schema.type_name.clone(), property: path });
        }
    }
    Ok(())
}

/// Maximum `$ref` hops in a chain of definitions. One shorter than
/// [`MAX_REF_CHAIN`], because resolution starts at the property referencing the
/// first definition — so a chain of this length still resolves in full instead of
/// being cut short.
const MAX_DEFINITION_REF_CHAIN: usize = MAX_REF_CHAIN - 1;

/// A definition `$ref` graph resolution could not follow faithfully.
enum RefChainDefect {
    /// The definitions on a cycle, in the order they were walked.
    Cycle(Vec<String>),
    /// A chain resolution would cut short before reaching its end.
    TooLong { start: String, hops: usize },
}

/// Returns the first defect in the definition `$ref` graph, or `None` when every
/// chain is acyclic and short enough to resolve in full.
fn find_ref_chain_defect(defs: &HashMap<String, PropSchema>) -> Option<RefChainDefect> {
    let mut names: Vec<&String> = defs.keys().collect();
    names.sort();
    for start in names {
        let mut chain: Vec<String> = Vec::new();
        let mut current = start.clone();
        loop {
            if chain.contains(&current) {
                chain.push(current);
                return Some(RefChainDefect::Cycle(chain));
            }
            chain.push(current.clone());
            match defs.get(&current).and_then(|def| def.ref_name.clone()) {
                Some(next) => current = next,
                None => break,
            }
            if chain.len() > MAX_DEFINITION_REF_CHAIN {
                return Some(RefChainDefect::TooLong { start: start.clone(), hops: chain.len() });
            }
        }
    }
    None
}

/// Logs every `$ref` pointing at a definition the schema does not contain.
///
/// Such a property carries no constraints at all, so a mistyped definition name
/// would otherwise quietly stop validating anything. It is a warning rather than a
/// rejection because overlays apply in sequence, and an earlier one may reference a
/// definition a later one supplies.
pub(crate) fn warn_dangling_refs(schema: &CompiledSchema) {
    let mut stack: Vec<(String, &PropSchema)> =
        schema.properties.iter().chain(schema.definitions.iter()).map(|(name, prop)| (name.clone(), prop)).collect();
    while let Some((path, current)) = stack.pop() {
        if let Some(target) = &current.ref_name
            && !schema.definitions.contains_key(target)
        {
            warn!(
                "Additional schema for '{}': '{path}' references '#/definitions/{target}', which the schema does \
                 not define, so nothing constrains it.",
                schema.type_name
            );
        }
        for (name, child) in current.properties.iter().chain(current.pattern_properties.iter()) {
            stack.push((format!("{path}.{name}"), child));
        }
        if let Some(items) = &current.items {
            stack.push((format!("{path}[]"), items));
        }
    }
}

/// Returns the path of the first property carrying both enum representations.
fn find_conflicting_enum(name: &str, prop: &PropSchema) -> Option<String> {
    let mut stack = vec![(name.to_string(), prop)];
    while let Some((path, current)) = stack.pop() {
        if !current.enum_values.is_empty() && !current.enum_case_insensitive.is_empty() {
            return Some(path);
        }
        for (child_name, child) in current.properties.iter().chain(current.pattern_properties.iter()) {
            stack.push((format!("{path}.{child_name}"), child));
        }
        if let Some(items) = current.items.as_deref() {
            stack.push((format!("{path}[]"), items));
        }
    }
    None
}

/// Deep-merge an overlay [`CompiledSchema`] into an existing bundled schema in
/// place, following the model documented at the module level.
pub(crate) fn merge_into(base: &mut CompiledSchema, overlay: CompiledSchema) {
    merge_definitions(&mut base.definitions, overlay.definitions);
    merge_prop_map(&mut base.properties, overlay.properties);

    union_extend(&mut base.required, overlay.required);

    replace_if_some(&mut base.additional_properties, overlay.additional_properties);
    replace_if_some(&mut base.replacement_strategy, overlay.replacement_strategy);
    replace_if_some(&mut base.documentation_url, overlay.documentation_url);
    replace_if_some(&mut base.source_url, overlay.source_url);
    replace_if_some(&mut base.description, overlay.description);

    // Property-path metadata lists are sets of independent facts, each one driving
    // its own diagnostic, so they are unioned: an overlay that names one more
    // deprecated property must not delete the bundled deprecations.
    union_extend(&mut base.read_only_properties, overlay.read_only_properties);
    union_extend(&mut base.write_only_properties, overlay.write_only_properties);
    union_extend(&mut base.create_only_properties, overlay.create_only_properties);
    union_extend(&mut base.deprecated_properties, overlay.deprecated_properties);
    union_extend(&mut base.conditional_create_only_properties, overlay.conditional_create_only_properties);
    // The primary identifier is one identity tuple, not a set of independent
    // facts, so a supplied one replaces the bundled tuple.
    replace_if_present(&mut base.primary_identifier, overlay.primary_identifier);

    // `allOf` is split during compilation into plain subschemas and conditional
    // `if`/`then`/`else` entries. They come from one keyword, so an overlay that
    // supplies it replaces both halves together — replacing only the half it
    // happens to populate would leave a composition matching neither schema.
    if !overlay.all_of.is_empty() || !overlay.if_then_else.is_empty() {
        base.all_of = overlay.all_of;
        base.if_then_else = overlay.if_then_else;
    }
    replace_if_present(&mut base.any_of, overlay.any_of);
    replace_if_present(&mut base.one_of, overlay.one_of);

    merge_dependency_map(&mut base.dependent_required, overlay.dependent_required);
    merge_dependency_map(&mut base.dependent_excluded, overlay.dependent_excluded);

    // Each of these is a single logical group, so a supplied group replaces the
    // bundled one; unioning would state a constraint neither schema makes.
    replace_if_present(&mut base.required_or, overlay.required_or);
    replace_if_present(&mut base.required_xor, overlay.required_xor);
}

/// Merges overlay definitions into `base`.
///
/// New definitions are inserted and shared ones are merged in place. Nothing here
/// depends on the order definitions are visited, because a `$ref` is never folded
/// into the property or definition that points at it — resolution happens at
/// validation time against the final definition set (see
/// `PropSchema::resolve`).
fn merge_definitions(base: &mut HashMap<String, PropSchema>, overlay: HashMap<String, PropSchema>) {
    for (name, def) in overlay {
        match base.entry(name) {
            Entry::Occupied(mut existing) => merge_prop(existing.get_mut(), def),
            Entry::Vacant(slot) => {
                slot.insert(def);
            }
        }
    }
}

/// Deep-merge an overlay property schema into an existing one in place.
pub(crate) fn merge_prop(base: &mut PropSchema, overlay: PropSchema) {
    // An overlay that redefines the property as a `$ref` replaces it wholesale;
    // mixing a ref with the base's inline shape would be ambiguous.
    if overlay.ref_name.is_some() {
        *base = overlay;
        return;
    }
    if is_no_op(&overlay) {
        return;
    }

    // A `$ref` on the base is deliberately left in place. The overlay's fields are
    // merged beside it and combined with the referenced definition when validation
    // resolves the property, so a definition changed by a later overlay still
    // reaches every property that points at it.
    replace_if_some(&mut base.prop_type, overlay.prop_type);
    merge_enums(base, overlay.enum_values, overlay.enum_case_insensitive);
    replace_if_present(&mut base.not_enum, overlay.not_enum);
    replace_if_some(&mut base.const_value, overlay.const_value);
    replace_if_some(&mut base.pattern, overlay.pattern);
    replace_if_some(&mut base.minimum, overlay.minimum);
    replace_if_some(&mut base.maximum, overlay.maximum);
    replace_if_some(&mut base.exclusive_minimum, overlay.exclusive_minimum);
    replace_if_some(&mut base.exclusive_maximum, overlay.exclusive_maximum);
    replace_if_some(&mut base.min_length, overlay.min_length);
    replace_if_some(&mut base.max_length, overlay.max_length);
    replace_if_some(&mut base.min_items, overlay.min_items);
    replace_if_some(&mut base.max_items, overlay.max_items);
    replace_if_some(&mut base.unique_items, overlay.unique_items);
    replace_if_some(&mut base.min_properties, overlay.min_properties);
    replace_if_some(&mut base.max_properties, overlay.max_properties);
    replace_if_some(&mut base.format, overlay.format);
    replace_if_some(&mut base.description, overlay.description);
    replace_if_some(&mut base.additional_properties, overlay.additional_properties);

    merge_prop_map(&mut base.properties, overlay.properties);
    merge_prop_map(&mut base.pattern_properties, overlay.pattern_properties);
    union_extend(&mut base.required, overlay.required);

    if let Some(overlay_items) = overlay.items {
        match base.items.as_mut() {
            Some(base_items) => merge_prop(base_items, *overlay_items),
            None => base.items = Some(overlay_items),
        }
    }
    replace_if_present(&mut base.all_of, overlay.all_of);
    replace_if_present(&mut base.any_of, overlay.any_of);
    replace_if_present(&mut base.one_of, overlay.one_of);
    merge_dependency_map(&mut base.dependent_required, overlay.dependent_required);
    merge_dependency_map(&mut base.dependent_excluded, overlay.dependent_excluded);
}

/// Applies the overlay's allowed-value list, keeping the two enum
/// representations mutually exclusive.
///
/// `enum` and `enumCaseInsensitive` are the same field in two comparison modes,
/// evaluated independently by the validator, so leaving both populated would
/// report a value twice with contradictory allowed sets. When the bundled schema
/// compares case-insensitively — because the service accepts any casing — a
/// plain `enum` overlay keeps that mode: the overlay author is widening the value
/// list, not tightening the comparison, and reinterpreting it as case-sensitive
/// would reject casings that validate today.
fn merge_enums(base: &mut PropSchema, overlay_exact: Vec<Value>, overlay_insensitive: Vec<Value>) {
    if !overlay_insensitive.is_empty() {
        base.enum_case_insensitive = overlay_insensitive;
        base.enum_values.clear();
    } else if !overlay_exact.is_empty() {
        if base.enum_case_insensitive.is_empty() {
            base.enum_values = overlay_exact;
        } else {
            base.enum_case_insensitive = overlay_exact;
            base.enum_values.clear();
        }
    }
}

fn merge_prop_map(base: &mut HashMap<String, PropSchema>, overlay: HashMap<String, PropSchema>) {
    for (name, prop) in overlay {
        match base.get_mut(&name) {
            Some(existing) => merge_prop(existing, prop),
            None => {
                base.insert(name, prop);
            }
        }
    }
}

/// Unions each trigger's dependency list rather than replacing it, so an overlay
/// naming one dependency of an existing trigger keeps the bundled ones.
fn merge_dependency_map(base: &mut HashMap<String, Vec<String>>, overlay: HashMap<String, Vec<String>>) {
    for (trigger, dependencies) in overlay {
        union_extend(base.entry(trigger).or_default(), dependencies);
    }
}

/// Whether merging this overlay property would change nothing.
///
/// Destructured exhaustively so a new field cannot be forgotten here and make an
/// overlay silently look empty.
fn is_no_op(prop: &PropSchema) -> bool {
    let PropSchema {
        ref_name,
        prop_type,
        enum_values,
        enum_case_insensitive,
        not_enum,
        const_value,
        pattern,
        minimum,
        maximum,
        exclusive_minimum,
        exclusive_maximum,
        min_length,
        max_length,
        min_items,
        max_items,
        unique_items,
        min_properties,
        max_properties,
        format,
        description,
        properties,
        required,
        additional_properties,
        pattern_properties,
        items,
        all_of,
        any_of,
        one_of,
        dependent_required,
        dependent_excluded,
    } = prop;
    ref_name.is_none()
        && prop_type.is_none()
        && enum_values.is_empty()
        && enum_case_insensitive.is_empty()
        && not_enum.is_empty()
        && const_value.is_none()
        && pattern.is_none()
        && minimum.is_none()
        && maximum.is_none()
        && exclusive_minimum.is_none()
        && exclusive_maximum.is_none()
        && min_length.is_none()
        && max_length.is_none()
        && min_items.is_none()
        && max_items.is_none()
        && unique_items.is_none()
        && min_properties.is_none()
        && max_properties.is_none()
        && format.is_none()
        && description.is_none()
        && properties.is_empty()
        && required.is_empty()
        && additional_properties.is_none()
        && pattern_properties.is_empty()
        && items.is_none()
        && all_of.is_empty()
        && any_of.is_empty()
        && one_of.is_empty()
        && dependent_required.is_empty()
        && dependent_excluded.is_empty()
}

/// Append items from `extra` not already present in `base`.
fn union_extend(base: &mut Vec<String>, extra: Vec<String>) {
    for item in extra {
        if !base.contains(&item) {
            base.push(item);
        }
    }
}

/// Replace `base` with `overlay` only when the overlay is non-empty.
fn replace_if_present<T>(base: &mut Vec<T>, overlay: Vec<T>) {
    if !overlay.is_empty() {
        *base = overlay;
    }
}

/// Replace `base` with `overlay` only when the overlay supplies a value.
fn replace_if_some<T>(base: &mut Option<T>, overlay: Option<T>) {
    if overlay.is_some() {
        *base = overlay;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn compiled(raw: Value) -> CompiledSchema {
        compile("AWS::Test::T", &raw).expect("test schema must compile")
    }

    #[test]
    fn compile_basic_schema() {
        let c = compiled(json!({
            "typeName": "AWS::Foo::Bar",
            "properties": {
                "Name": { "type": "string" },
                "Size": { "type": "integer", "enum": [1, 2, 3] }
            },
            "required": ["Name"],
            "additionalProperties": false
        }));
        assert_eq!(c.type_name, "AWS::Test::T");
        assert!(c.properties.contains_key("Name"));
        assert_eq!(c.additional_properties, Some(false));
        assert_eq!(c.required, vec!["Name".to_string()]);
        assert_eq!(c.properties["Size"].enum_values, vec![json!(1), json!(2), json!(3)]);
    }

    #[test]
    fn compile_ref_and_property_paths() {
        let c = compiled(json!({
            "properties": { "Cfg": { "$ref": "#/definitions/Config" } },
            "definitions": { "Config": { "type": "object" } },
            "readOnlyProperties": ["/properties/Arn", "/properties/Nested/Id"],
            "primaryIdentifier": ["/properties/Id"]
        }));
        assert_eq!(c.properties["Cfg"].ref_name.as_deref(), Some("Config"));
        assert!(c.definitions.contains_key("Config"));
        assert_eq!(c.read_only_properties, vec!["Arn".to_string(), "Nested.Id".to_string()]);
        assert_eq!(c.primary_identifier, vec!["Id".to_string()]);
    }

    #[test]
    fn compile_rejects_empty_type_name() {
        let error = compile("", &json!({})).expect_err("an empty type name must be rejected");
        assert_eq!(error, SchemaOverlayError::MissingTypeName);
    }

    #[test]
    fn compile_rejects_non_object() {
        let error = compile("AWS::Test::T", &json!(42)).expect_err("a non-object schema must be rejected");
        assert!(matches!(error, SchemaOverlayError::NotAnObject { .. }), "got {error:?}");
    }

    #[test]
    fn compile_rejects_overlay_nested_past_the_depth_limit() {
        let mut node = json!({ "type": "string" });
        for _ in 0..MAX_OVERLAY_DEPTH {
            node = json!({ "type": "object", "properties": { "N": node } });
        }
        let error = compile("AWS::Test::Deep", &json!({ "properties": { "Top": node } }))
            .expect_err("an over-deep overlay must be rejected, not overflow the stack");
        assert!(matches!(error, SchemaOverlayError::TooDeep { .. }), "got {error:?}");
    }

    #[test]
    fn compile_accepts_overlay_within_the_depth_limit() {
        // Each `properties` wrapper contributes two levels (the map, then the
        // schema inside it), on top of the three the outer schema already uses, so
        // this is the deepest nesting the limit admits.
        let deepest_accepted_wrappers = (MAX_OVERLAY_DEPTH - 4) / 2;
        let mut node = json!({ "type": "string" });
        for _ in 0..deepest_accepted_wrappers {
            node = json!({ "type": "object", "properties": { "N": node } });
        }
        compile("AWS::Test::Deep", &json!({ "properties": { "Top": node } })).expect("ordinary nesting is accepted");
    }

    /// Builds a value whose deepest member sits exactly `depth` levels down, so the
    /// accept/reject boundary can be stated to the level rather than to the two
    /// levels a `properties` wrapper adds at a time.
    fn value_nested_to_depth(depth: usize) -> Value {
        let mut value = json!("leaf");
        for _ in 1..depth {
            value = json!({ "N": value });
        }
        value
    }

    #[test]
    fn depth_check_accepts_nesting_exactly_at_the_limit() {
        check_depth("AWS::Test::Deep", &value_nested_to_depth(MAX_OVERLAY_DEPTH))
            .expect("nesting exactly at the limit must be accepted");
    }

    #[test]
    fn depth_check_rejects_nesting_one_level_past_the_limit() {
        let error = check_depth("AWS::Test::Deep", &value_nested_to_depth(MAX_OVERLAY_DEPTH + 1))
            .expect_err("one level past the limit must be rejected");
        assert!(matches!(error, SchemaOverlayError::TooDeep { .. }), "got {error:?}");
    }

    #[test]
    fn compile_rejects_a_ref_outside_definitions() {
        let error = compile("AWS::Test::T", &json!({ "properties": { "P": { "$ref": "other.json#/Thing" } } }))
            .expect_err("a non-local $ref cannot be represented and must be rejected");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    #[test]
    fn compile_rejects_tuple_form_items() {
        let error = compile(
            "AWS::Test::T",
            &json!({ "properties": { "P": { "type": "array", "items": [{ "type": "string" }] } } }),
        )
        .expect_err("tuple-form items cannot be represented and must be rejected");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    #[test]
    fn compile_rejects_a_non_string_type() {
        let error = compile("AWS::Test::T", &json!({ "properties": { "P": { "type": { "nested": true } } } }))
            .expect_err("an object-valued 'type' cannot be represented and must be rejected");
        match error {
            SchemaOverlayError::Unsupported { path, .. } => {
                assert_eq!(path, "properties.P", "the error must name the offending path")
            }
            other => panic!("expected an unsupported-construct error, got {other:?}"),
        }
    }

    #[test]
    fn compile_rejects_unsupported_constructs_nested_in_definitions_and_composition() {
        for raw in [
            json!({ "definitions": { "D": { "properties": { "P": { "items": [{ "type": "string" }] } } } } }),
            json!({ "oneOf": [{ "properties": { "P": { "$ref": "https://example.com/schema" } } }] }),
            json!({
                "allOf": [{
                    "if": { "properties": { "A": { "enum": ["x"] } } },
                    "then": { "properties": { "B": { "type": [1, 2] } } }
                }]
            }),
        ] {
            let error = compile("AWS::Test::T", &raw).expect_err("nested unsupported constructs must be rejected");
            assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?} for {raw}");
        }
    }

    #[test]
    fn compile_accepts_a_property_named_like_a_keyword() {
        // A property literally named `type` or `items` is ordinary schema content
        // and must not be mistaken for the keyword.
        compile(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "type": { "type": "string" },
                    "items": { "type": "array", "items": { "type": "string" } }
                }
            }),
        )
        .expect("keyword-named properties are ordinary content");
    }

    #[test]
    fn compile_accepts_an_enum_value_that_contains_schema_like_keys() {
        // Enum values are data, not schemas, so a key like `type` inside one must
        // not be inspected as a schema keyword.
        compile("AWS::Test::T", &json!({ "properties": { "P": { "enum": [{ "type": [1, 2] }] } } }))
            .expect("enum values are data and are not inspected as schemas");
    }

    #[test]
    fn validate_schema_rejects_a_property_carrying_both_enum_representations() {
        // A schema stating both forms for one property is reachable from caller
        // input: the compiler parses both keywords, and the validator evaluates
        // them independently, which would report one value against two different
        // allowed-value lists.
        let schema = compiled(json!({
            "properties": { "P": { "type": "string", "enum": ["A"], "enumCaseInsensitive": ["a"] } }
        }));
        let error = validate_schema(&schema).expect_err("both enum representations must be rejected");
        match error {
            SchemaOverlayError::ConflictingEnums { property, .. } => assert_eq!(property, "P"),
            other => panic!("expected a conflicting-enum error, got {other:?}"),
        }
    }

    #[test]
    fn validate_schema_finds_a_conflicting_enum_nested_in_a_definition() {
        let schema = compiled(json!({
            "definitions": {
                "D": { "properties": { "Inner": { "enum": ["A"], "enumCaseInsensitive": ["a"] } } }
            }
        }));
        let error = validate_schema(&schema).expect_err("a nested conflict must be rejected");
        match error {
            SchemaOverlayError::ConflictingEnums { property, .. } => {
                assert_eq!(property, "D.Inner", "the error must name the nested path")
            }
            other => panic!("expected a conflicting-enum error, got {other:?}"),
        }
    }

    #[test]
    fn validate_schema_rejects_a_self_referential_definition() {
        let schema = compiled(json!({
            "properties": { "P": { "$ref": "#/definitions/D" } },
            "definitions": { "D": { "$ref": "#/definitions/D" } }
        }));
        let error = validate_schema(&schema).expect_err("a self-referential definition must be rejected");
        match error {
            SchemaOverlayError::CyclicRef { cycle, .. } => assert!(cycle.contains(&"D".to_string()), "got {cycle:?}"),
            other => panic!("expected a cycle error, got {other:?}"),
        }
    }

    #[test]
    fn validate_schema_rejects_a_multi_node_definition_cycle() {
        let schema = compiled(json!({
            "definitions": {
                "A": { "$ref": "#/definitions/B" },
                "B": { "$ref": "#/definitions/C" },
                "C": { "$ref": "#/definitions/A" }
            }
        }));
        validate_schema(&schema).expect_err("a multi-node definition cycle must be rejected");
    }

    #[test]
    fn validate_schema_accepts_an_acyclic_ref_chain() {
        let schema = compiled(json!({
            "properties": { "P": { "$ref": "#/definitions/A" } },
            "definitions": {
                "A": { "$ref": "#/definitions/B" },
                "B": { "type": "object" }
            }
        }));
        validate_schema(&schema).expect("an acyclic chain is valid");
    }

    #[test]
    fn merge_adds_new_property_and_keeps_base() {
        let mut base =
            compiled(json!({ "properties": { "Handler": { "type": "string" } }, "additionalProperties": false }));
        merge_into(&mut base, compiled(json!({ "properties": { "NewThing": { "type": "object" } } })));
        assert!(base.properties.contains_key("Handler"), "bundled property must be retained");
        assert!(base.properties.contains_key("NewThing"), "overlay property must be added");
        assert_eq!(base.additional_properties, Some(false), "bundled additionalProperties must be retained");
    }

    #[test]
    fn merge_replaces_enum_for_property() {
        let mut base = compiled(json!({ "properties": { "Mode": { "type": "string", "enum": ["A", "B"] } } }));
        merge_into(&mut base, compiled(json!({ "properties": { "Mode": { "enum": ["A", "B", "C"] } } })));
        let values: Vec<&str> = base.properties["Mode"].enum_values.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(values, vec!["A", "B", "C"], "overlay enum must replace the bundled enum");
    }

    #[test]
    fn merge_keeps_case_insensitive_comparison_when_widening_with_a_plain_enum() {
        let mut base =
            compiled(json!({ "properties": { "Mode": { "type": "string", "enumCaseInsensitive": ["a", "b"] } } }));
        merge_into(&mut base, compiled(json!({ "properties": { "Mode": { "enum": ["a", "b", "c"] } } })));
        let prop = &base.properties["Mode"];
        assert!(prop.enum_values.is_empty(), "the exact list must stay empty so the value is not checked twice");
        let values: Vec<&str> = prop.enum_case_insensitive.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(values, vec!["a", "b", "c"], "widening must land on the case-insensitive list");
    }

    #[test]
    fn merge_case_insensitive_overlay_clears_a_bundled_exact_enum() {
        let mut base = compiled(json!({ "properties": { "Mode": { "type": "string", "enum": ["A", "B"] } } }));
        merge_into(&mut base, compiled(json!({ "properties": { "Mode": { "enumCaseInsensitive": ["a", "b"] } } })));
        let prop = &base.properties["Mode"];
        assert!(prop.enum_values.is_empty(), "the exact list must be cleared");
        assert_eq!(prop.enum_case_insensitive.len(), 2);
        validate_schema(&base).expect("the two enum representations must stay mutually exclusive");
    }

    #[test]
    fn merge_unions_required() {
        let mut base = compiled(json!({ "required": ["A"] }));
        merge_into(&mut base, compiled(json!({ "required": ["A", "B"] })));
        assert_eq!(
            base.required,
            vec!["A".to_string(), "B".to_string()],
            "required must be unioned without duplicates"
        );
    }

    #[test]
    fn merge_unions_property_path_metadata() {
        let mut base = compiled(json!({ "deprecatedProperties": ["/properties/Old"] }));
        merge_into(&mut base, compiled(json!({ "deprecatedProperties": ["/properties/New"] })));
        assert_eq!(
            base.deprecated_properties,
            vec!["Old".to_string(), "New".to_string()],
            "an additive metadata overlay must keep the bundled entries"
        );
    }

    #[test]
    fn merge_replaces_the_primary_identifier_tuple() {
        let mut base = compiled(json!({ "primaryIdentifier": ["/properties/Name"] }));
        merge_into(&mut base, compiled(json!({ "primaryIdentifier": ["/properties/Region", "/properties/Name"] })));
        assert_eq!(
            base.primary_identifier,
            vec!["Region".to_string(), "Name".to_string()],
            "the identifier tuple is replaced, not unioned into a different tuple"
        );
    }

    #[test]
    fn merge_replaces_logical_groups_instead_of_unioning_them() {
        let mut base = compiled(json!({ "requiredXor": ["A", "B"], "requiredOr": ["C", "D"] }));
        merge_into(&mut base, compiled(json!({ "requiredXor": ["A", "B", "E"], "requiredOr": ["C", "D", "F"] })));
        assert_eq!(base.required_xor, vec!["A".to_string(), "B".to_string(), "E".to_string()]);
        assert_eq!(base.required_or, vec!["C".to_string(), "D".to_string(), "F".to_string()]);
    }

    #[test]
    fn merge_keeps_logical_groups_when_the_overlay_omits_them() {
        let mut base = compiled(json!({ "requiredXor": ["A", "B"] }));
        merge_into(&mut base, compiled(json!({ "properties": { "P": { "type": "string" } } })));
        assert_eq!(base.required_xor, vec!["A".to_string(), "B".to_string()]);
    }

    #[test]
    fn merge_unions_dependency_lists_per_trigger() {
        let mut base = compiled(json!({ "dependentRequired": { "A": ["B", "C"] } }));
        merge_into(
            &mut base,
            compiled(json!({ "dependentRequired": { "A": ["D"] }, "dependentExcluded": { "E": ["F"] } })),
        );
        assert_eq!(
            base.dependent_required.get("A"),
            Some(&vec!["B".to_string(), "C".to_string(), "D".to_string()]),
            "an overlay entry for an existing trigger must extend, not replace"
        );
        assert_eq!(base.dependent_excluded.get("E"), Some(&vec!["F".to_string()]));
    }

    #[test]
    fn merge_deep_merges_nested_properties() {
        let mut base = compiled(json!({
            "properties": {
                "Cfg": {
                    "type": "object",
                    "properties": { "X": { "type": "string" } },
                    "additionalProperties": false
                }
            }
        }));
        merge_into(
            &mut base,
            compiled(json!({ "properties": { "Cfg": { "properties": { "Y": { "type": "integer" } } } } })),
        );
        let cfg = &base.properties["Cfg"];
        assert!(cfg.properties.contains_key("X"), "nested bundled property must be retained");
        assert!(cfg.properties.contains_key("Y"), "nested overlay property must be added");
        assert_eq!(cfg.additional_properties, Some(false), "nested additionalProperties must be retained");
    }

    #[test]
    fn merge_deep_merges_pattern_property_values() {
        let mut base = compiled(json!({
            "properties": {
                "Map": {
                    "type": "object",
                    "patternProperties": {
                        "^k$": { "type": "object", "properties": { "X": { "type": "string" } } }
                    }
                }
            }
        }));
        merge_into(
            &mut base,
            compiled(json!({
                "properties": {
                    "Map": { "patternProperties": { "^k$": { "properties": { "Y": { "type": "string" } } } } }
                }
            })),
        );
        let value = &base.properties["Map"].pattern_properties["^k$"];
        assert!(value.properties.contains_key("X"), "the bundled pattern value schema must be retained");
        assert!(value.properties.contains_key("Y"), "the overlay pattern value schema must be merged in");
    }

    #[test]
    fn merge_prop_overrides_all_scalar_constraints() {
        let mut base = compiled(json!({ "properties": { "P": { "type": "string" } } }));
        merge_into(
            &mut base,
            compiled(json!({
                "properties": {
                    "P": {
                        "type": "string",
                        "pattern": "^a+$",
                        "minLength": 1, "maxLength": 10,
                        "minimum": 0.0, "maximum": 100.0,
                        "exclusiveMinimum": 1.0, "exclusiveMaximum": 99.0,
                        "minItems": 1, "maxItems": 5,
                        "uniqueItems": true,
                        "minProperties": 1, "maxProperties": 3,
                        "format": "uri",
                        "description": "desc",
                        "const": "a",
                        "not": { "enum": ["bad"] },
                        "additionalProperties": false
                    }
                }
            })),
        );
        let p = &base.properties["P"];
        assert_eq!(p.pattern.as_deref(), Some("^a+$"));
        assert_eq!(p.min_length, Some(1));
        assert_eq!(p.max_length, Some(10));
        assert_eq!(p.minimum, Some(0.0));
        assert_eq!(p.maximum, Some(100.0));
        assert_eq!(p.exclusive_minimum, Some(1.0));
        assert_eq!(p.exclusive_maximum, Some(99.0));
        assert_eq!(p.min_items, Some(1));
        assert_eq!(p.max_items, Some(5));
        assert_eq!(p.unique_items, Some(true));
        assert_eq!(p.min_properties, Some(1));
        assert_eq!(p.max_properties, Some(3));
        assert_eq!(p.format.as_deref(), Some("uri"));
        assert_eq!(p.description.as_deref(), Some("desc"));
        assert_eq!(p.const_value, Some(json!("a")));
        assert_eq!(p.not_enum, vec![json!("bad")]);
        assert_eq!(p.additional_properties, Some(false));
    }

    #[test]
    fn merge_prop_explicit_unique_items_false_clears_bundled_true() {
        let mut base = compiled(json!({ "properties": { "Arr": { "type": "array", "uniqueItems": true } } }));
        merge_into(&mut base, compiled(json!({ "properties": { "Arr": { "uniqueItems": false } } })));
        assert_eq!(
            base.properties["Arr"].unique_items,
            Some(false),
            "an explicitly relaxed uniqueItems must override the bundled true"
        );
    }

    #[test]
    fn merge_prop_omitted_unique_items_keeps_bundled_true() {
        let mut base = compiled(json!({ "properties": { "Arr": { "type": "array", "uniqueItems": true } } }));
        merge_into(&mut base, compiled(json!({ "properties": { "Arr": { "minItems": 1 } } })));
        assert_eq!(base.properties["Arr"].unique_items, Some(true), "an omitted uniqueItems must inherit");
    }

    #[test]
    fn merge_prop_merges_items() {
        let mut base = compiled(json!({
            "properties": {
                "Arr": { "type": "array", "items": { "type": "string" } },
                "Empty": { "type": "array" }
            }
        }));
        merge_into(
            &mut base,
            compiled(json!({
                "properties": {
                    "Arr": { "items": { "pattern": "^x$" } },
                    "Empty": { "items": { "type": "string" } }
                }
            })),
        );
        let items = base.properties["Arr"].items.as_ref().expect("items retained");
        assert_eq!(items.pattern.as_deref(), Some("^x$"), "nested items must be merged");
        assert!(base.properties["Empty"].items.is_some(), "items must be inserted when the base has none");
    }

    #[test]
    fn merge_prop_ref_overlay_replaces_wholesale() {
        let mut base = compiled(json!({
            "properties": { "P": { "type": "string" } },
            "definitions": { "D": { "type": "object" } }
        }));
        merge_into(
            &mut base,
            compiled(json!({
                "properties": { "P": { "$ref": "#/definitions/D" } },
                "definitions": { "D": { "type": "object" } }
            })),
        );
        assert_eq!(base.properties["P"].ref_name.as_deref(), Some("D"), "a $ref overlay replaces the property");
    }

    /// The schema that actually applies to a top-level property, i.e. what
    /// validation sees: the `$ref` chain resolved and any fields stated beside the
    /// reference merged on top.
    fn effective(schema: &CompiledSchema, property: &str) -> PropSchema {
        schema.properties[property].resolve(&schema.definitions).into_owned()
    }

    #[test]
    fn constraint_only_overlay_on_a_ref_base_takes_effect() {
        let mut base = compiled(json!({
            "properties": { "P": { "$ref": "#/definitions/D" } },
            "definitions": { "D": { "type": "string", "enum": ["A", "B"] } }
        }));
        merge_into(&mut base, compiled(json!({ "properties": { "P": { "enum": ["A", "B", "C"] } } })));
        assert_eq!(
            base.properties["P"].ref_name.as_deref(),
            Some("D"),
            "the reference stays live so a later change to the definition still reaches the property"
        );
        let p = effective(&base, "P");
        assert_eq!(p.enum_values.len(), 3, "the overlay enum must take effect");
        assert_eq!(
            p.prop_type.as_ref().and_then(crate::compiled::PropType::primary),
            Some("string"),
            "the referenced definition's own constraints must be preserved"
        );
    }

    #[test]
    fn overlay_on_a_ref_base_follows_the_whole_chain() {
        let mut base = compiled(json!({
            "properties": { "P": { "$ref": "#/definitions/Level1" } },
            "definitions": {
                "Level1": { "$ref": "#/definitions/Level2" },
                "Level2": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": { "Old": { "type": "string" } }
                }
            }
        }));
        merge_into(
            &mut base,
            compiled(json!({ "properties": { "P": { "properties": { "New": { "type": "integer" } } } } })),
        );
        let p = effective(&base, "P");
        assert!(p.properties.contains_key("Old"), "the terminal definition's properties must be preserved");
        assert!(p.properties.contains_key("New"), "the overlay property must be merged in");
        assert_eq!(p.additional_properties, Some(false), "the terminal definition's constraints must be preserved");
    }

    #[test]
    fn merge_no_op_overlay_leaves_a_ref_base_untouched() {
        let mut base = compiled(json!({
            "properties": { "P": { "$ref": "#/definitions/D" } },
            "definitions": { "D": { "type": "object" } }
        }));
        merge_into(&mut base, compiled(json!({ "properties": { "P": {} } })));
        assert_eq!(
            base.properties["P"].ref_name.as_deref(),
            Some("D"),
            "an overlay with nothing to say must not rewrite the property"
        );
    }

    #[test]
    fn a_ref_to_an_overlay_only_definition_resolves() {
        // The bundled definition `Config` references `Common`, which only the
        // overlay supplies.
        let mut base = compiled(json!({
            "properties": { "Cfg": { "$ref": "#/definitions/Config" } },
            "definitions": { "Config": { "$ref": "#/definitions/Common" } }
        }));
        merge_into(
            &mut base,
            compiled(json!({
                "definitions": {
                    "Common": { "type": "object", "required": ["FromCommon"] },
                    "Config": { "properties": { "Extra": { "type": "string" } } }
                }
            })),
        );
        let cfg = effective(&base, "Cfg");
        assert_eq!(
            cfg.required,
            vec!["FromCommon".to_string()],
            "the overlay-only definition's constraints must reach the property"
        );
        assert!(cfg.properties.contains_key("Extra"), "the overlay definition content must be merged in");
    }

    #[test]
    fn a_definition_updated_by_a_later_merge_reaches_an_already_extended_property() {
        // The regression that merge-time inlining caused: extending a `$ref`
        // property and then widening the definition it points at.
        let mut base = compiled(json!({
            "properties": { "P": { "$ref": "#/definitions/D" } },
            "definitions": { "D": { "type": "string", "enum": ["alpha", "beta"] } }
        }));
        merge_into(&mut base, compiled(json!({ "properties": { "P": { "description": "documented" } } })));
        merge_into(&mut base, compiled(json!({ "definitions": { "D": { "enum": ["alpha", "beta", "gamma"] } } })));
        let p = effective(&base, "P");
        assert_eq!(
            p.enum_values.len(),
            3,
            "the later definition update must reach the property, got {:?}",
            p.enum_values
        );
        assert_eq!(p.description.as_deref(), Some("documented"), "the earlier property extension must survive");
    }

    #[test]
    fn merge_into_overrides_schema_metadata() {
        let mut base = compiled(json!({ "additionalProperties": true, "description": "old" }));
        merge_into(
            &mut base,
            compiled(json!({
                "additionalProperties": false,
                "replacementStrategy": "delete",
                "documentationUrl": "http://docs",
                "sourceUrl": "http://src",
                "description": "new"
            })),
        );
        assert_eq!(base.additional_properties, Some(false));
        assert_eq!(base.replacement_strategy.as_deref(), Some("delete"));
        assert_eq!(base.documentation_url.as_deref(), Some("http://docs"));
        assert_eq!(base.source_url.as_deref(), Some("http://src"));
        assert_eq!(base.description.as_deref(), Some("new"));
    }

    #[test]
    fn merge_into_merges_existing_definition_and_inserts_new() {
        let mut base = compiled(json!({
            "definitions": {
                "D": { "type": "object", "properties": { "X": { "type": "string" } }, "additionalProperties": false }
            }
        }));
        merge_into(
            &mut base,
            compiled(json!({
                "definitions": {
                    "D": { "properties": { "Y": { "type": "integer" } } },
                    "E": { "type": "string" }
                }
            })),
        );
        let d = &base.definitions["D"];
        assert!(d.properties.contains_key("X"), "existing definition property must be retained");
        assert!(d.properties.contains_key("Y"), "overlay definition property must be merged in");
        assert_eq!(d.additional_properties, Some(false), "existing definition metadata must be retained");
        assert!(base.definitions.contains_key("E"), "a new definition must be inserted");
    }

    #[test]
    fn merge_replaces_composition_keywords_instead_of_appending() {
        let mut base = compiled(json!({ "oneOf": [{ "required": ["A"] }, { "required": ["B"] }] }));
        assert_eq!(base.one_of.len(), 2);
        merge_into(&mut base, compiled(json!({ "oneOf": [{ "required": ["C"] }] })));
        assert_eq!(base.one_of.len(), 1, "overlay oneOf must replace the bundled oneOf");
        assert_eq!(base.one_of[0].required, vec!["C".to_string()]);
    }

    #[test]
    fn merge_replaces_both_halves_of_a_split_all_of() {
        // `allOf` compiles into plain entries plus conditional ones. An overlay
        // supplying only conditional entries must still clear the bundled plain
        // entries, or the merged composition matches neither schema.
        let mut base = compiled(json!({
            "allOf": [
                { "required": ["Plain"] },
                { "if": { "properties": { "A": { "enum": ["x"] } } }, "then": { "required": ["B"] } }
            ]
        }));
        assert_eq!(base.all_of.len(), 1);
        assert_eq!(base.if_then_else.len(), 1);
        merge_into(
            &mut base,
            compiled(json!({
                "allOf": [{ "if": { "properties": { "A": { "enum": ["y"] } } }, "then": { "required": ["C"] } }]
            })),
        );
        assert!(base.all_of.is_empty(), "the bundled plain allOf entry must not survive a replacing overlay");
        assert_eq!(base.if_then_else.len(), 1);
    }

    #[test]
    fn merge_keeps_composition_when_overlay_omits_it() {
        let mut base = compiled(json!({ "oneOf": [{ "required": ["A"] }] }));
        merge_into(&mut base, compiled(json!({ "properties": { "P": { "type": "string" } } })));
        assert_eq!(base.one_of.len(), 1, "bundled oneOf must be kept when the overlay omits it");
    }

    #[test]
    fn merge_prop_recurses_into_shared_nested_property() {
        let mut base = compiled(json!({
            "properties": {
                "Cfg": {
                    "type": "object",
                    "properties": { "Inner": { "type": "object", "properties": { "A": { "type": "string" } } } }
                }
            }
        }));
        merge_into(
            &mut base,
            compiled(json!({
                "properties": {
                    "Cfg": { "properties": { "Inner": { "properties": { "B": { "type": "integer" } } } } }
                }
            })),
        );
        let inner = &base.properties["Cfg"].properties["Inner"].properties;
        assert!(inner.contains_key("A"), "deep bundled sub-property must be retained");
        assert!(inner.contains_key("B"), "deep overlay sub-property must be merged in");
    }

    #[test]
    fn merge_result_is_independent_of_map_iteration_order() {
        // Many definitions merged at once, one of them referenced by another: the
        // effective schema must not depend on which order the map happens to yield.
        let mut base_raw = serde_json::Map::new();
        for i in 0..32 {
            base_raw.insert(format!("D{i}"), json!({ "type": "object" }));
        }
        base_raw.insert("Holder".into(), json!({ "$ref": "#/definitions/Target" }));
        base_raw.insert("Target".into(), json!({ "type": "object" }));
        let mut overlay_raw = serde_json::Map::new();
        for i in 0..32 {
            overlay_raw.insert(format!("D{i}"), json!({ "description": "touched" }));
        }
        overlay_raw.insert("Target".into(), json!({ "required": ["Late"] }));
        overlay_raw.insert("Holder".into(), json!({ "properties": { "X": { "type": "string" } } }));

        for _ in 0..8 {
            let mut base = compiled(json!({
                "properties": { "P": { "$ref": "#/definitions/Holder" } },
                "definitions": base_raw
            }));
            merge_into(&mut base, compiled(json!({ "definitions": overlay_raw })));
            let p = effective(&base, "P");
            assert_eq!(p.required, vec!["Late".to_string()], "the referenced definition's update must be visible");
            assert!(p.properties.contains_key("X"), "the referencing definition's own content must be visible");
        }
    }
}
