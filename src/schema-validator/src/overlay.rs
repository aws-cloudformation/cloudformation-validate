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
//! | `required` | replaced when the overlay states the keyword (even as `[]` — that is how a requirement is cleared, and a removal is logged); unioned into the base when the keyword is omitted |
//! | Independent-fact collections — the `/properties/...` lifecycle metadata lists, and each key of `dependentRequired`/`dependentExcluded` | unioned, order-preserving, deduplicated |
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
//! An overlay that supplies a `$ref` for a property updates the reference target
//! (`ref_name`) but preserves the base property's existing inline/additive
//! constraints (e.g. pattern, maxLength). This means an overlay can redirect a
//! property to a different definition without discarding constraints the bundled
//! schema already carries.
//!
//! Overlays for the same type are applied in the order given; a later overlay
//! sees the result of the earlier ones.
//!
//! # Scope limits
//!
//! - An overlay cannot remove an entry from a lifecycle metadata list — those
//!   collections only ever grow. `required` is the one collection with
//!   replacement semantics (below), and any requirement a replacement removes
//!   is logged.
//! - Composition entries (`allOf`/`anyOf`/`oneOf` branches) are full property
//!   schemas: branch `required`, `additionalProperties`, dependency maps, value
//!   constraints, and nested conditionals are all evaluated when the branch is
//!   matched or (for a selected `then`/`else` branch) enforced.
//! - Constructs the compiled model does not represent — a `$ref` outside
//!   `#/definitions/`, tuple-form `items`, an unknown property type, malformed
//!   keyword values, or invalid regular expressions — are rejected.
//! - Validation keywords with no compiled representation (`propertyNames`,
//!   `contains`, and `not` other than `not.enum`) are rejected.
//!   `multipleOf` and `dependencies` (array-form property dependencies) ARE
//!   represented and accepted.
//! - Constraint siblings beside a `$ref` are accepted when they have a compiled
//!   representation (e.g. `pattern`, `maxLength`, `enum`). Only genuinely
//!   unrepresented keywords are rejected. Annotation-only siblings
//!   (`description`, `title`) are always accepted. Bundled schemas are compiled
//!   with draft-07 `$ref` evaluation instead (siblings ignored), so the engine
//!   never enforces more than CloudFormation's own contract on them; an overlay
//!   author states siblings deliberately and gets them enforced.
//! - `enum` and `enumCaseInsensitive` are one field in two comparison modes; an
//!   overlay cannot switch a property the service treats case-insensitively over
//!   to case-sensitive comparison, because doing so would reject casings that
//!   validate today.
//! - `required` has authoritative replacement semantics: an overlay that
//!   explicitly states `required` (even as `required: []`) replaces the prior
//!   required list at that schema level, including clearing it. Omitting
//!   `required` from the overlay preserves the base's list unchanged.
//! - Conditional constraints the build pipeline contributes as extension
//!   fragments are validated from a separate embedded artifact that overlays do
//!   not merge into, so an overlay cannot suppress a finding originating there.
//! - Schema-level metadata (`description`, `documentationUrl`, `sourceUrl`,
//!   `replacementStrategy`) alone is not sufficient — the overlay must carry at
//!   least one validatable constraint. Metadata enriches diagnostic context only
//!   when combined with properties, required, or other constraints.
//! - Overlay-derived resource types, GetAtt attributes and types, Ref return
//!   types, primary identifiers, and schema metadata are propagated to both rule
//!   engines. Region-specific availability and enum snapshots remain bundled.
//!
//! # Catalog vs. config separation
//!
//! The [`SchemaValidator`](crate::SchemaValidator) separates its schema store
//! (the validated/merged catalog of all compiled schemas) from its construction
//! config ([`SchemaValidatorConfig`](crate::SchemaValidatorConfig)) so embedders
//! can serialize/deserialize the config and rebuild the validator without keeping
//! the merged store around. The overlay catalog exposes overlay-aware metadata
//! (type names, GetAtt/Ref types, primary identifiers) without re-merging.

use crate::compiled::{CompiledSchema, ConditionSchema, MAX_REF_CHAIN, PropSchema};
use data_source::compiled_schema::compile_schema;
use data_source::compiled_schema::keywords;
use log::warn;
use serde_json::Value;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::error::Error;
use std::fmt;

/// Keywords that carry no validation meaning, so their presence beside a `$ref`
/// is not worth reporting. Published provider schemas routinely document a
/// referenced property this way.
///
/// Sourced from the shared vocabulary in `data_source::compiled_schema::keywords`.
const REF_ANNOTATION_KEYWORDS: &[&str] = keywords::REF_ANNOTATION_KEYWORDS;

/// Validation keywords the compiled schema model has no field for, so nothing
/// enforces them. An overlay stating one would silently weaken the author's
/// intent — rejected so embedders cannot accidentally rely on a constraint that
/// nothing checks. `not` is handled separately because only its nested `enum` is
/// modelled.
///
/// Sourced from the shared vocabulary in `data_source::compiled_schema::keywords`.
const UNREPRESENTED_CONSTRAINT_KEYWORDS: &[&str] = keywords::UNREPRESENTED_VALIDATION_KEYWORDS;

/// The set of fields the runtime evaluates when matching a composition branch.
/// Since composition branches are now full `PropSchema`s, the runtime evaluates
/// all representable constraint fields. This list gates what the overlay
/// preflight accepts — any field not here is rejected so the overlay author
/// knows it would not fire.
const COMPOSITION_ALLOWED_FIELDS: &[&str] = &[
    keywords::REF,
    keywords::TYPE,
    keywords::ENUM,
    keywords::ENUM_CASE_INSENSITIVE,
    keywords::NOT,
    keywords::CONST,
    keywords::PATTERN,
    keywords::FORMAT,
    keywords::MINIMUM,
    keywords::MAXIMUM,
    keywords::EXCLUSIVE_MINIMUM,
    keywords::EXCLUSIVE_MAXIMUM,
    keywords::MULTIPLE_OF,
    keywords::MIN_LENGTH,
    keywords::MAX_LENGTH,
    keywords::MIN_ITEMS,
    keywords::MAX_ITEMS,
    keywords::UNIQUE_ITEMS,
    keywords::MIN_PROPERTIES,
    keywords::MAX_PROPERTIES,
    keywords::REQUIRED,
    keywords::PROPERTIES,
    keywords::ADDITIONAL_PROPERTIES,
    keywords::PATTERN_PROPERTIES,
    keywords::ITEMS,
    keywords::ALL_OF,
    keywords::ANY_OF,
    keywords::ONE_OF,
    keywords::DEPENDENT_REQUIRED,
    keywords::DEPENDENT_EXCLUDED,
    keywords::IF,
    keywords::THEN,
    keywords::ELSE,
    keywords::DEPENDENCIES,
];

/// Fields the conditional matcher evaluates on the `if` schema itself.
///
/// `type` on the `if` schema constrains the instance type: the evaluation
/// point is always a property object, so `"object"` is a no-op and any other
/// type makes the condition unsatisfiable there.
const CONDITION_ALLOWED_FIELDS: [&str; 3] = [keywords::PROPERTIES, keywords::REQUIRED, keywords::TYPE];

/// Fields `condition_matches` evaluates for a property named by an `if` schema.
/// Every listed field participates in matching: value constraints
/// (`enum`/`not`/`const`/`pattern`/`type`), nested `required`, and the
/// length/count bounds (each scoped to its instance type per draft-07).
const CONDITION_PROPERTY_ALLOWED_FIELDS: [&str; 13] = [
    keywords::REF,
    keywords::TYPE,
    keywords::ENUM,
    keywords::NOT,
    keywords::CONST,
    keywords::PATTERN,
    keywords::REQUIRED,
    keywords::MIN_ITEMS,
    keywords::MAX_ITEMS,
    keywords::MIN_LENGTH,
    keywords::MAX_LENGTH,
    keywords::MIN_PROPERTIES,
    keywords::MAX_PROPERTIES,
];

/// JSON/property type names enforced by `schema-validator`.
const SUPPORTED_PROPERTY_TYPES: [&str; 9] =
    ["string", "integer", "number", "double", "float", "boolean", "array", "object", "null"];

/// Fields allowed inside `then`/`else` of conditional `allOf` entries. Since
/// branches are full `PropSchema`s now, the same set as composition branches
/// (minus the condition keywords themselves) applies.
const CONDITIONAL_THEN_ELSE_ALLOWED_FIELDS: &[&str] = COMPOSITION_ALLOWED_FIELDS;

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
    /// After the whole overlay sequence was applied, a `$ref` still points at a
    /// definition the schema does not contain, so the property it sits on
    /// validates nothing.
    DanglingRef { type_name: String, path: String, target: String },
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
            SchemaOverlayError::DanglingRef { type_name, path, target } => write!(
                f,
                "Invalid additional schema for '{type_name}': after every overlay was applied, '{path}' still \
                 references '#/definitions/{target}', which no overlay defines, so nothing would constrain it"
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
    if type_name != type_name.trim() {
        return Err(SchemaOverlayError::Unsupported {
            type_name: type_name.to_string(),
            path: String::new(),
            detail: "type name has leading or trailing whitespace".to_string(),
        });
    }
    if let Some(declared_type_name) = raw.get(keywords::TYPE_NAME) {
        let in_schema = declared_type_name.as_str().ok_or_else(|| SchemaOverlayError::Unsupported {
            type_name: type_name.to_string(),
            path: keywords::TYPE_NAME.to_string(),
            detail: "'typeName' must be a string".to_string(),
        })?;
        if in_schema != in_schema.trim() {
            return Err(SchemaOverlayError::Unsupported {
                type_name: type_name.to_string(),
                path: keywords::TYPE_NAME.to_string(),
                detail: "type name has leading or trailing whitespace".to_string(),
            });
        }
        if !in_schema.is_empty() && in_schema != type_name {
            return Err(SchemaOverlayError::Unsupported {
                type_name: type_name.to_string(),
                path: keywords::TYPE_NAME.to_string(),
                detail: format!(
                    "the schema declares typeName '{in_schema}' but was submitted as '{type_name}'; remove one or make them match"
                ),
            });
        }
    }
    if !raw.is_object() {
        return Err(SchemaOverlayError::NotAnObject { type_name: type_name.to_string() });
    }
    check_depth(type_name, raw)?;
    check_supported(type_name, raw)?;
    let mut compiled: CompiledSchema = compile_schema(type_name, raw).into();
    // Track whether the overlay explicitly stated `required` (even as `[]`), so
    // merging knows whether to replace the base's required list authoritatively.
    compiled.required_present = raw.get(keywords::REQUIRED).is_some();
    // Propagate required_present into property-level and definition-level schemas
    // where `required` was explicitly stated in their source objects.
    propagate_required_present(raw, &mut compiled);
    // Conditionals an overlay author states are enforced in full — no dedicated
    // rule covers them, unlike bundled conditionals (see
    // `IfThenElse::enforce_full_branch`).
    mark_conditionals_for_full_enforcement(&mut compiled);
    if states_nothing(&compiled) {
        return Err(SchemaOverlayError::NoEffect { type_name: type_name.to_string() });
    }
    Ok(compiled)
}

/// Marks every conditional in the compiled overlay — at the schema root, on
/// properties and definitions at any nesting depth, and inside composition
/// branches — for full branch enforcement.
fn mark_conditionals_for_full_enforcement(schema: &mut CompiledSchema) {
    for ite in &mut schema.if_then_else {
        mark_ite(ite);
    }
    for prop in schema.properties.values_mut().chain(schema.definitions.values_mut()) {
        mark_prop_conditionals(prop);
    }
    for branch in schema.all_of.iter_mut().chain(schema.any_of.iter_mut()).chain(schema.one_of.iter_mut()) {
        mark_prop_conditionals(branch);
    }
}

fn mark_ite(ite: &mut crate::compiled::IfThenElse) {
    ite.enforce_full_branch = true;
    for branch in ite.then_schema.iter_mut().chain(ite.else_schema.iter_mut()) {
        mark_prop_conditionals(branch);
    }
}

fn mark_prop_conditionals(prop: &mut PropSchema) {
    for ite in &mut prop.if_then_else {
        mark_ite(ite);
    }
    for child in prop.properties.values_mut().chain(prop.pattern_properties.values_mut()) {
        mark_prop_conditionals(child);
    }
    if let Some(items) = prop.items.as_mut() {
        mark_prop_conditionals(items);
    }
    for branch in prop.all_of.iter_mut().chain(prop.any_of.iter_mut()).chain(prop.one_of.iter_mut()) {
        mark_prop_conditionals(branch);
    }
}

/// Whether a compiled overlay carries no information that would affect
/// validation — the shape a misspelled or wrong-format JSON object compiles to.
/// Destructured exhaustively so a new field cannot be omitted from the check.
///
/// Schema-level metadata that enriches reporting but constrains nothing
/// (`description`, `documentationUrl`, `sourceUrl`, `replacementStrategy`) is
/// not sufficient on its own. These fields enrich diagnostic context when another
/// constraint fires, but alone they state nothing validatable.
fn states_nothing(schema: &CompiledSchema) -> bool {
    let CompiledSchema {
        type_name: _,
        properties,
        definitions,
        required,
        required_present,
        additional_properties,
        read_only_properties,
        write_only_properties,
        create_only_properties,
        deprecated_properties,
        conditional_create_only_properties,
        primary_identifier,
        replacement_strategy: _,
        documentation_url: _,
        source_url: _,
        description: _,
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
        && !required_present
        && additional_properties.is_none()
        && read_only_properties.is_empty()
        && write_only_properties.is_empty()
        && create_only_properties.is_empty()
        && deprecated_properties.is_empty()
        && conditional_create_only_properties.is_empty()
        && primary_identifier.is_empty()
        && all_of.is_empty()
        && any_of.is_empty()
        && one_of.is_empty()
        && if_then_else.is_empty()
        && dependent_required.is_empty()
        && dependent_excluded.is_empty()
        && required_or.is_empty()
        && required_xor.is_empty()
}

/// Sets `required_present` on each compiled property/definition whose raw source
/// explicitly contained a `required` keyword. Walks the schema maps in lockstep
/// with the raw JSON so presence can be determined per sub-schema.
fn propagate_required_present(raw: &Value, compiled: &mut CompiledSchema) {
    fn mark_prop_map(raw_map: Option<&Value>, compiled_map: &mut HashMap<String, PropSchema>) {
        let Some(raw_obj) = raw_map.and_then(Value::as_object) else {
            return;
        };
        for (name, raw_prop) in raw_obj {
            if let Some(compiled_prop) = compiled_map.get_mut(name) {
                mark_prop(raw_prop, compiled_prop);
            }
        }
    }

    fn mark_prop(raw: &Value, compiled: &mut PropSchema) {
        if raw.get(keywords::REQUIRED).is_some() {
            compiled.required_present = true;
        }
        mark_prop_map(raw.get(keywords::PROPERTIES), &mut compiled.properties);
        mark_prop_map(raw.get(keywords::PATTERN_PROPERTIES), &mut compiled.pattern_properties);
        if let Some(raw_items) = raw.get(keywords::ITEMS)
            && let Some(compiled_items) = compiled.items.as_mut()
        {
            mark_prop(raw_items, compiled_items);
        }
    }

    mark_prop_map(raw.get(keywords::PROPERTIES), &mut compiled.properties);
    mark_prop_map(raw.get(keywords::DEFINITIONS), &mut compiled.definitions);
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

    // Also validate root-level keywords directly.
    if let Some(root_obj) = raw.as_object() {
        validate_keyword_types(type_name, "", root_obj)?;
        reject_unrepresented_keywords(type_name, "", root_obj)?;
        reject_direct_if_then_else(type_name, "", root_obj)?;
    }

    while let Some((path, value)) = stack.pop() {
        let Some(members) = value.as_object() else {
            continue;
        };
        if let Some(reference) = members.get(keywords::REF) {
            match reference.as_str() {
                Some(target) if target.starts_with(keywords::DEFINITIONS_REF_PREFIX) => {}
                Some(target) => {
                    return Err(reject(&path, &format!("'$ref' target '{target}' is not '#/definitions/<name>'")));
                }
                None => return Err(reject(&path, "'$ref' must be a string")),
            }
            // compile_prop now preserves represented constraint siblings beside
            // a $ref — they are merged at validation time via PropSchema::resolve.
            // Only reject siblings that are genuinely unrepresented (keywords with
            // no compiled field), so the overlay author is warned rather than
            // silently weakened.
            let unrepresented_siblings: Vec<&str> = members
                .keys()
                .map(String::as_str)
                .filter(|key| {
                    *key != keywords::REF
                        && !REF_ANNOTATION_KEYWORDS.contains(key)
                        && UNREPRESENTED_CONSTRAINT_KEYWORDS.contains(key)
                })
                .collect();
            if !unrepresented_siblings.is_empty() {
                return Err(reject(
                    &path,
                    &format!(
                        "'{}' beside a '$ref' has no representation in the compiled schema model",
                        unrepresented_siblings.join("', '")
                    ),
                ));
            }
        }
        if let Some(items) = members.get(keywords::ITEMS)
            && !items.is_object()
        {
            return Err(reject(&path, "'items' must be a single schema object; tuple form is not supported"));
        }
        if !members.contains_key(keywords::REF) {
            reject_unrepresented_keywords(type_name, &path, members)?;
        }
        if let Some(prop_type) = members.get(keywords::TYPE) {
            let type_names: Vec<&str> = match prop_type {
                Value::String(name) => vec![name.as_str()],
                Value::Array(names) if !names.is_empty() => names
                    .iter()
                    .map(|name| name.as_str())
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| reject(&path, "'type' must be a string or an array of strings"))?,
                _ => return Err(reject(&path, "'type' must be a string or a non-empty array of strings")),
            };
            if let Some(unsupported) = type_names.into_iter().find(|name| {
                !(SUPPORTED_PROPERTY_TYPES.contains(name) || (path.is_empty() && ["RESOURCE", "object"].contains(name)))
            }) {
                return Err(reject(&path, &format!("unsupported property type '{unsupported}'")));
            }
        }
        // Validate keyword types for every schema position (not only root).
        validate_keyword_types(type_name, &path, members)?;
        // Reject direct if/then/else at property level.
        reject_direct_if_then_else(type_name, &path, members)?;
        push_schema_children(path, value, &mut stack);
    }
    Ok(())
}

/// Validates the type/domain of every keyword the compiler represents.
///
/// The compiler silently ignores a wrongly-typed keyword (e.g. `required: 42`
/// instead of an array of strings). That is invisible on curated input and
/// dangerous on overlay input: the constraint is silently dropped.
fn validate_keyword_types(
    type_name: &str,
    path: &str,
    members: &serde_json::Map<String, Value>,
) -> Result<(), SchemaOverlayError> {
    let reject = |detail: &str| SchemaOverlayError::Unsupported {
        type_name: type_name.to_string(),
        path: path.to_string(),
        detail: detail.to_string(),
    };

    // String arrays: required, enum, not.enum
    for keyword in keywords::STRING_ARRAY_CONSTRAINTS {
        if let Some(val) = members.get(*keyword) {
            if let Some(arr) = val.as_array() {
                for item in arr {
                    if !item.is_string() {
                        return Err(reject(&format!("'{keyword}' must be an array of strings")));
                    }
                }
            } else {
                return Err(reject(&format!("'{keyword}' must be an array")));
            }
        }
    }

    // Metadata path arrays: these accept arrays of strings.
    for keyword in keywords::METADATA_POINTER_ARRAYS {
        if let Some(value) = members.get(*keyword) {
            let paths = value.as_array().ok_or_else(|| reject(&format!("'{keyword}' must be an array")))?;
            for path_value in paths {
                let property_path =
                    path_value.as_str().ok_or_else(|| reject(&format!("'{keyword}' must be an array of strings")))?;
                if !property_path.starts_with(keywords::PROPERTIES_PATH_PREFIX)
                    || property_path.len() == keywords::PROPERTIES_PATH_PREFIX.len()
                {
                    return Err(reject(&format!("'{keyword}' entries must be JSON pointers below '/properties/'")));
                }
            }
        }
    }

    for keyword in keywords::ENUM_KEYWORDS {
        if let Some(value) = members.get(*keyword) {
            let values = value.as_array().ok_or_else(|| reject(&format!("'{keyword}' must be an array")))?;
            if values.is_empty() {
                return Err(reject(&format!("'{keyword}' must contain at least one value")));
            }
        }
    }
    if let Some(negated) = members.get(keywords::NOT) {
        let negated_members =
            negated.as_object().ok_or_else(|| reject("'not' must be an object containing an enum"))?;
        let unsupported: Vec<&str> = negated_members
            .keys()
            .map(String::as_str)
            .filter(|key| *key != keywords::ENUM && !REF_ANNOTATION_KEYWORDS.contains(key))
            .collect();
        if !unsupported.is_empty() {
            return Err(reject("'not' is only supported when it contains an enum"));
        }
        let values = negated_members
            .get(keywords::ENUM)
            .and_then(Value::as_array)
            .ok_or_else(|| reject("'not.enum' must be an array"))?;
        if values.is_empty() {
            return Err(reject("'not.enum' must contain at least one value"));
        }
    }

    // Dependent maps: { "trigger": ["dep1", "dep2"] }
    for keyword in keywords::DEPENDENCY_MAPS {
        if let Some(val) = members.get(*keyword) {
            if let Some(obj) = val.as_object() {
                for (key, deps) in obj {
                    if let Some(arr) = deps.as_array() {
                        for item in arr {
                            if !item.is_string() {
                                return Err(reject(&format!("'{keyword}.{key}' must be an array of strings")));
                            }
                        }
                    } else {
                        return Err(reject(&format!("'{keyword}.{key}' must be an array")));
                    }
                }
            } else {
                return Err(reject(&format!("'{keyword}' must be an object")));
            }
        }
    }

    // Numeric fields (f64)
    for keyword in keywords::NUMERIC_CONSTRAINTS {
        if let Some(val) = members.get(*keyword)
            && !val.is_number()
        {
            return Err(reject(&format!("'{keyword}' must be a number")));
        }
    }

    // multipleOf: a positive number
    if let Some(val) = members.get(keywords::MULTIPLE_OF) {
        if !val.is_number() {
            return Err(reject("'multipleOf' must be a number"));
        }
        if val.as_f64().is_some_and(|n| n <= 0.0) {
            return Err(reject("'multipleOf' must be a positive number"));
        }
    }

    // dependencies: object where values are arrays of strings (property deps)
    // or schema objects (schema-form, rejected as unrepresented)
    if let Some(val) = members.get(keywords::DEPENDENCIES) {
        let obj = val.as_object().ok_or_else(|| reject("'dependencies' must be an object"))?;
        for (key, dep_value) in obj {
            if dep_value.is_array() {
                // Array-form: property dependencies — accepted
                let arr = dep_value.as_array().expect("confirmed array");
                for item in arr {
                    if !item.is_string() {
                        return Err(reject(&format!("'dependencies.{key}' array items must be strings")));
                    }
                }
            } else if dep_value.is_object() {
                // Schema-form: not represented in the compiled model
                return Err(reject(&format!(
                    "'dependencies.{key}' is a schema-form dependency which has no representation in the compiled model"
                )));
            } else {
                return Err(reject(&format!("'dependencies.{key}' must be an array or object")));
            }
        }
    }

    // u64 fields
    for keyword in keywords::U64_CONSTRAINTS {
        if let Some(value) = members.get(*keyword)
            && value.as_u64().is_none()
        {
            return Err(reject(&format!("'{keyword}' must be a non-negative integer")));
        }
    }

    // Boolean fields
    for keyword in keywords::BOOL_CONSTRAINTS {
        if let Some(val) = members.get(*keyword)
            && !val.is_boolean()
        {
            return Err(reject(&format!("'{keyword}' must be a boolean")));
        }
    }

    // String fields
    for keyword in keywords::STRING_CONSTRAINTS {
        if let Some(val) = members.get(*keyword)
            && !val.is_string()
        {
            return Err(reject(&format!("'{keyword}' must be a string")));
        }
    }

    // Validate regex patterns using the shared template-model compiler
    if let Some(Value::String(pattern)) = members.get(keywords::PATTERN)
        && !template_model::pattern::is_service_valid(pattern)
    {
        return Err(reject(&format!("'pattern' contains an invalid regex: {pattern}")));
    }

    // Properties/definitions/patternProperties must be objects with object values
    for keyword in keywords::SCHEMA_MAPS {
        if let Some(val) = members.get(*keyword) {
            if let Some(obj) = val.as_object() {
                for (name, child) in obj {
                    if !child.is_object() {
                        return Err(reject(&format!("'{keyword}.{name}' must be a JSON object")));
                    }
                }
            } else {
                return Err(reject(&format!("'{keyword}' must be a JSON object")));
            }
        }
    }

    // Validate patternProperties keys are valid regexes
    if let Some(Value::Object(pat_props)) = members.get(keywords::PATTERN_PROPERTIES) {
        for key in pat_props.keys() {
            if !template_model::pattern::is_service_valid(key) {
                return Err(reject(&format!("'patternProperties' key '{key}' is not a valid regex")));
            }
        }
    }

    // Items must be an object (tuple form already checked above)
    if let Some(val) = members.get(keywords::ITEMS)
        && !val.is_object()
    {
        return Err(reject("'items' must be a single schema object; tuple form is not supported"));
    }

    // Composition arrays: entries must be objects
    for keyword in keywords::COMPOSITION {
        if let Some(val) = members.get(*keyword) {
            if let Some(arr) = val.as_array() {
                for (i, entry) in arr.iter().enumerate() {
                    if !entry.is_object() {
                        return Err(reject(&format!("'{keyword}[{i}]' must be a JSON object")));
                    }
                }
                // Validate composition entries contain only enforced fields
                validate_composition_entries(type_name, path, keyword, arr)?;
            } else {
                return Err(reject(&format!("'{keyword}' must be an array")));
            }
        }
    }

    Ok(())
}

/// Rejects composition entries (`allOf`/`anyOf`/`oneOf`) that contain fields the
/// compiled model cannot represent or the runtime does not evaluate.
///
/// With composition branches being full `PropSchema`s, most constraint keywords
/// are allowed. Only genuinely unrepresented keywords are rejected.
fn validate_composition_entries(
    type_name: &str,
    path: &str,
    keyword: &str,
    entries: &[Value],
) -> Result<(), SchemaOverlayError> {
    let reject = |detail: &str| SchemaOverlayError::Unsupported {
        type_name: type_name.to_string(),
        path: path.to_string(),
        detail: detail.to_string(),
    };

    for (index, entry) in entries.iter().enumerate() {
        let Some(entry_members) = entry.as_object() else {
            continue;
        };

        if keyword == keywords::ALL_OF && entry_members.contains_key(keywords::IF) {
            validate_conditional_allof_entry(type_name, path, index, entry_members)?;
            continue;
        }

        let unsupported: Vec<&str> = entry_members
            .keys()
            .map(String::as_str)
            .filter(|key| {
                !COMPOSITION_ALLOWED_FIELDS.contains(key)
                    && !REF_ANNOTATION_KEYWORDS.contains(key)
                    && *key != keywords::DESCRIPTION
            })
            .collect();
        if !unsupported.is_empty() {
            return Err(reject(&format!(
                "'{keyword}[{index}]' contains fields not supported in composition branches: '{}'",
                unsupported.join("', '")
            )));
        }
    }
    Ok(())
}

/// Validates a conditional `allOf` entry (`if`/`then`/`else`).
///
/// The condition (`if`) may use `properties` and `required`; property conditions
/// are limited to fields `condition_matches` evaluates. The `then`/`else`
/// branches are restricted to `dependentRequired`/`dependentExcluded`, the only
/// fields conditional branch evaluation enforces.
fn validate_conditional_allof_entry(
    type_name: &str,
    path: &str,
    index: usize,
    entry_members: &serde_json::Map<String, Value>,
) -> Result<(), SchemaOverlayError> {
    let reject = |detail: &str| SchemaOverlayError::Unsupported {
        type_name: type_name.to_string(),
        path: path.to_string(),
        detail: detail.to_string(),
    };

    let unsupported_entry_fields: Vec<&str> = entry_members
        .keys()
        .map(String::as_str)
        .filter(|key| !keywords::CONDITIONALS.contains(key) && !REF_ANNOTATION_KEYWORDS.contains(key))
        .collect();
    if !unsupported_entry_fields.is_empty() {
        return Err(reject(&format!(
            "'allOf[{index}]' contains unsupported conditional fields: '{}'",
            unsupported_entry_fields.join("', '")
        )));
    }

    let condition = entry_members
        .get(keywords::IF)
        .and_then(Value::as_object)
        .ok_or_else(|| reject(&format!("'allOf[{index}].if' must be a JSON object")))?;
    let unsupported_condition_fields: Vec<&str> = condition
        .keys()
        .map(String::as_str)
        .filter(|key| !CONDITION_ALLOWED_FIELDS.contains(key) && !REF_ANNOTATION_KEYWORDS.contains(key))
        .collect();
    if !unsupported_condition_fields.is_empty() {
        return Err(reject(&format!(
            "'allOf[{index}].if' contains fields the conditional matcher does not enforce: '{}'",
            unsupported_condition_fields.join("', '")
        )));
    }
    if let Some(properties) = condition.get(keywords::PROPERTIES).and_then(Value::as_object) {
        for (property_name, property_schema) in properties {
            let property_members = property_schema.as_object().ok_or_else(|| {
                reject(&format!("'allOf[{index}].if.properties.{property_name}' must be a JSON object"))
            })?;
            let unsupported_property_fields: Vec<&str> = property_members
                .keys()
                .map(String::as_str)
                .filter(|key| {
                    !CONDITION_PROPERTY_ALLOWED_FIELDS.contains(key) && !REF_ANNOTATION_KEYWORDS.contains(key)
                })
                .collect();
            if !unsupported_property_fields.is_empty() {
                return Err(reject(&format!(
                    "'allOf[{index}].if.properties.{property_name}' contains fields the conditional matcher does not enforce: '{}'",
                    unsupported_property_fields.join("', '")
                )));
            }
        }
    }

    if !entry_members.contains_key(keywords::THEN) && !entry_members.contains_key(keywords::ELSE) {
        return Err(reject(&format!("'allOf[{index}]' must contain 'then' or 'else'")));
    }
    for branch_name in [keywords::THEN, keywords::ELSE] {
        let Some(branch_value) = entry_members.get(branch_name) else {
            continue;
        };
        let branch = branch_value
            .as_object()
            .ok_or_else(|| reject(&format!("'allOf[{index}].{branch_name}' must be a JSON object")))?;
        let unsupported: Vec<&str> = branch
            .keys()
            .map(String::as_str)
            .filter(|key| {
                !CONDITIONAL_THEN_ELSE_ALLOWED_FIELDS.contains(key)
                    && !REF_ANNOTATION_KEYWORDS.contains(key)
                    && *key != keywords::DESCRIPTION
            })
            .collect();
        if !unsupported.is_empty() {
            return Err(reject(&format!(
                "'allOf[{index}].{branch_name}' contains unsupported fields: '{}'",
                unsupported.join("', '")
            )));
        }
    }
    Ok(())
}

/// Rejects direct `if`/`then`/`else` at root or property level.
///
/// Standalone `if`/`then`/`else` (outside `allOf`) is not supported in the
/// compiled model — it is only recognized inside `allOf` entries. Accepting it
/// silently would drop the constraint.
fn reject_direct_if_then_else(
    type_name: &str,
    path: &str,
    members: &serde_json::Map<String, Value>,
) -> Result<(), SchemaOverlayError> {
    for keyword in keywords::CONDITIONALS {
        if members.contains_key(*keyword) && !members.contains_key(keywords::REF) {
            // Direct if/then/else is supported at property level (compiled into
            // if_then_else) and inside allOf entries. At the schema root the
            // compiler only reads conditionals from inside `allOf`, so a
            // root-level standalone conditional would be silently dropped — a
            // sibling `allOf` key does not move the root conditional into that
            // array.
            if path.is_empty() {
                return Err(SchemaOverlayError::Unsupported {
                    type_name: type_name.to_string(),
                    path: path.to_string(),
                    detail: format!(
                        "standalone '{keyword}' is not supported at the root level; place conditional logic \
                         inside an allOf array or at property level"
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Rejects validation keywords the compiled model has no field for.
///
/// Promoted from warning-only to an error so embedders cannot silently weaken
/// schemas by stating constraints nothing enforces.
fn reject_unrepresented_keywords(
    type_name: &str,
    path: &str,
    members: &serde_json::Map<String, Value>,
) -> Result<(), SchemaOverlayError> {
    let unrepresented: Vec<&str> =
        members.keys().map(String::as_str).filter(|key| UNREPRESENTED_CONSTRAINT_KEYWORDS.contains(key)).collect();
    if !unrepresented.is_empty() {
        return Err(SchemaOverlayError::Unsupported {
            type_name: type_name.to_string(),
            path: path.to_string(),
            detail: format!(
                "'{}' has no representation in the compiled schema model and would silently weaken the overlay",
                unrepresented.join("', '")
            ),
        });
    }
    if members.get(keywords::NOT).is_some_and(|negated| negated.get(keywords::ENUM).is_none()) {
        return Err(SchemaOverlayError::Unsupported {
            type_name: type_name.to_string(),
            path: path.to_string(),
            detail: "'not' is only enforced when it contains an 'enum'; this form would silently \
                     weaken the overlay"
                .to_string(),
        });
    }
    Ok(())
}

/// Pushes every child of `value` that is itself in a schema position.
fn push_schema_children<'a>(path: String, value: &'a Value, stack: &mut Vec<(String, &'a Value)>) {
    let Some(members) = value.as_object() else {
        return;
    };
    let child_path = |suffix: &str| if path.is_empty() { suffix.to_string() } else { format!("{path}.{suffix}") };

    for keyword in keywords::SCHEMA_MAPS {
        if let Some(map) = members.get(*keyword).and_then(Value::as_object) {
            for (name, child) in map {
                stack.push((child_path(&format!("{keyword}.{name}")), child));
            }
        }
    }
    if let Some(items) = members.get(keywords::ITEMS) {
        stack.push((child_path("items"), items));
    }
    for keyword in keywords::COMPOSITION {
        if let Some(entries) = members.get(*keyword).and_then(Value::as_array) {
            for (index, entry) in entries.iter().enumerate() {
                stack.push((child_path(&format!("{keyword}[{index}]")), entry));
            }
        }
    }
    for keyword in keywords::CONDITIONALS {
        if let Some(branch) = members.get(*keyword) {
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
    // Collect all conflicting-enum paths, including from composition property
    // maps, then sort deterministically before reporting the first one.
    let mut conflicts: Vec<String> = Vec::new();
    for (name, prop) in schema.properties.iter().chain(schema.definitions.iter()) {
        collect_conflicting_enums(name, prop, &mut conflicts);
    }
    // Traverse composition/condition property maps too.
    for sub in schema.all_of.iter().chain(schema.any_of.iter()).chain(schema.one_of.iter()) {
        for (name, prop) in &sub.properties {
            collect_conflicting_enums(&format!("allOf.{name}"), prop, &mut conflicts);
        }
    }
    for ite in &schema.if_then_else {
        collect_conflicting_enums_in_condition("if", &ite.condition, &mut conflicts);
        if let Some(then_sub) = &ite.then_schema {
            for (name, prop) in &then_sub.properties {
                collect_conflicting_enums(&format!("then.{name}"), prop, &mut conflicts);
            }
        }
        if let Some(else_sub) = &ite.else_schema {
            for (name, prop) in &else_sub.properties {
                collect_conflicting_enums(&format!("else.{name}"), prop, &mut conflicts);
            }
        }
    }
    conflicts.sort();
    if let Some(first) = conflicts.into_iter().next() {
        return Err(SchemaOverlayError::ConflictingEnums { type_name: schema.type_name.clone(), property: first });
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

/// Logs every requirement that merging `merged` over `base` removed.
///
/// An overlay that states `required` replaces the base's list at that schema
/// level; a complete provider schema does this deliberately, while a partial
/// overlay that restates `required` does it by accident. Either way a bundled
/// constraint disappearing is worth saying out loud — silently weakening the
/// schema is the failure mode this module exists to prevent.
pub(crate) fn warn_removed_required(base: &CompiledSchema, merged: &CompiledSchema) {
    for (path, removed) in removed_required(base, merged) {
        let location = if path.is_empty() { "the resource".to_string() } else { format!("'{path}'") };
        warn!(
            "Additional schema for '{}': the stated 'required' list removes {} from {location}. An overlay that \
             states 'required' replaces the previous list; omit the keyword to keep it.",
            merged.type_name,
            removed.iter().map(|name| format!("'{name}'")).collect::<Vec<_>>().join(", "),
        );
    }
}

/// Every `(path, removed names)` pair where `merged` requires less than `base`
/// at the same schema position. Paths are sorted so repeated runs report
/// identically.
pub(crate) fn removed_required(base: &CompiledSchema, merged: &CompiledSchema) -> Vec<(String, Vec<String>)> {
    let mut removals: Vec<(String, Vec<String>)> = Vec::new();
    collect_removed(String::new(), &base.required, &merged.required, &mut removals);

    let mut stack: Vec<(String, &PropSchema, &PropSchema)> = Vec::new();
    push_shared_children(String::new(), &base.properties, &merged.properties, &mut stack);
    push_shared_children("definitions".to_string(), &base.definitions, &merged.definitions, &mut stack);
    while let Some((path, before, after)) = stack.pop() {
        collect_removed(path.clone(), &before.required, &after.required, &mut removals);
        push_shared_children(path.clone(), &before.properties, &after.properties, &mut stack);
        push_shared_children(
            format!("{path}<patternProperties>"),
            &before.pattern_properties,
            &after.pattern_properties,
            &mut stack,
        );
        if let (Some(before_items), Some(after_items)) = (&before.items, &after.items) {
            stack.push((format!("{path}[]"), before_items, after_items));
        }
    }

    removals.sort();
    removals
}

/// Records the names present in `before` but missing from `after`.
fn collect_removed(path: String, before: &[String], after: &[String], out: &mut Vec<(String, Vec<String>)>) {
    let removed: Vec<String> = before.iter().filter(|name| !after.contains(name)).cloned().collect();
    if !removed.is_empty() {
        out.push((path, removed));
    }
}

/// Pushes every key the base and merged maps share, pairing the two sides.
fn push_shared_children<'a>(
    path: String,
    before: &'a HashMap<String, PropSchema>,
    after: &'a HashMap<String, PropSchema>,
    stack: &mut Vec<(String, &'a PropSchema, &'a PropSchema)>,
) {
    for (name, before_prop) in before {
        if let Some(after_prop) = after.get(name) {
            let child_path = if path.is_empty() { name.clone() } else { format!("{path}.{name}") };
            stack.push((child_path, before_prop, after_prop));
        }
    }
}

/// Logs every `$ref` pointing at a definition the schema does not contain.
///
/// Such a property carries no constraints at all, so a mistyped definition name
/// would otherwise quietly stop validating anything. It is a warning rather than a
/// rejection because overlays apply in sequence, and an earlier one may reference a
/// definition a later one supplies.
pub(crate) fn warn_dangling_refs(schema: &CompiledSchema) {
    for (path, target) in find_dangling_refs(schema) {
        warn!(
            "Additional schema for '{}': '{path}' references '#/definitions/{target}', which the schema does \
             not define, so nothing constrains it (a later overlay may still supply the definition).",
            schema.type_name
        );
    }
}

/// Every `(path, target)` pair where a `$ref` points at a definition the schema
/// does not contain, sorted for deterministic reporting.
///
/// Walked per overlay for a warning (a later overlay in the sequence may supply
/// the definition) and again after the whole sequence, where a survivor is
/// rejected — a property referencing nothing validates nothing, which is the
/// silent weakening this module exists to prevent.
pub(crate) fn find_dangling_refs(schema: &CompiledSchema) -> Vec<(String, String)> {
    let mut dangling: Vec<(String, String)> = Vec::new();
    let mut stack: Vec<(String, &PropSchema)> =
        schema.properties.iter().chain(schema.definitions.iter()).map(|(name, prop)| (name.clone(), prop)).collect();
    // Also traverse composition/condition property maps.
    for sub in schema.all_of.iter().chain(schema.any_of.iter()).chain(schema.one_of.iter()) {
        for (name, prop) in &sub.properties {
            stack.push((format!("allOf.{name}"), prop));
        }
    }
    for ite in &schema.if_then_else {
        push_condition_props("if", &ite.condition, &mut stack);
        if let Some(then_sub) = &ite.then_schema {
            for (name, prop) in &then_sub.properties {
                stack.push((format!("then.{name}"), prop));
            }
        }
        if let Some(else_sub) = &ite.else_schema {
            for (name, prop) in &else_sub.properties {
                stack.push((format!("else.{name}"), prop));
            }
        }
    }
    while let Some((path, current)) = stack.pop() {
        if let Some(target) = &current.ref_name
            && !schema.definitions.contains_key(target)
        {
            dangling.push((path.clone(), target.clone()));
        }
        for (name, child) in current.properties.iter().chain(current.pattern_properties.iter()) {
            stack.push((format!("{path}.{name}"), child));
        }
        if let Some(items) = &current.items {
            stack.push((format!("{path}[]"), items));
        }
    }
    dangling.sort();
    dangling
}

/// Helper: push condition schema properties onto the traversal stack.
fn push_condition_props<'a>(prefix: &str, cond: &'a ConditionSchema, stack: &mut Vec<(String, &'a PropSchema)>) {
    for (name, prop) in &cond.properties {
        stack.push((format!("{prefix}.{name}"), prop));
    }
    for (i, sub_cond) in cond.any_of.iter().enumerate() {
        push_condition_props(&format!("{prefix}.anyOf[{i}]"), sub_cond, stack);
    }
}

/// Collect all conflicting-enum paths into the `out` vec (does not short-circuit).
fn collect_conflicting_enums(name: &str, prop: &PropSchema, out: &mut Vec<String>) {
    let mut stack = vec![(name.to_string(), prop)];
    while let Some((path, current)) = stack.pop() {
        if !current.enum_values.is_empty() && !current.enum_case_insensitive.is_empty() {
            out.push(path.clone());
        }
        for (child_name, child) in current.properties.iter().chain(current.pattern_properties.iter()) {
            stack.push((format!("{path}.{child_name}"), child));
        }
        if let Some(items) = current.items.as_deref() {
            stack.push((format!("{path}[]"), items));
        }
    }
}

/// Collect conflicting enums from a condition schema.
fn collect_conflicting_enums_in_condition(prefix: &str, cond: &ConditionSchema, out: &mut Vec<String>) {
    for (name, prop) in &cond.properties {
        collect_conflicting_enums(&format!("{prefix}.{name}"), prop, out);
    }
    for (i, sub_cond) in cond.any_of.iter().enumerate() {
        collect_conflicting_enums_in_condition(&format!("{prefix}.anyOf[{i}]"), sub_cond, out);
    }
}

/// Deep-merge an overlay [`CompiledSchema`] into an existing bundled schema in
/// place, following the model documented at the module level.
pub(crate) fn merge_into(base: &mut CompiledSchema, overlay: CompiledSchema) {
    merge_definitions(&mut base.definitions, overlay.definitions);
    merge_prop_map(&mut base.properties, overlay.properties);

    // An overlay that explicitly states `required` (even as `[]`) authoritatively
    // replaces the prior required list — this is how an overlay clears required
    // properties. Omitting `required` from the overlay preserves the base.
    // `apply_overlay` reports any requirement a replacement removes, so a
    // partial overlay that restates `required` carelessly is called out.
    if overlay.required_present {
        base.required = overlay.required;
    } else {
        union_extend(&mut base.required, overlay.required);
    }

    replace_if_some(&mut base.additional_properties, overlay.additional_properties);
    replace_if_some(&mut base.replacement_strategy, overlay.replacement_strategy);
    replace_if_some(&mut base.documentation_url, overlay.documentation_url);
    replace_if_some(&mut base.source_url, overlay.source_url);
    replace_if_some(&mut base.description, overlay.description);

    // Property-path metadata lists only ever grow: an overlay that names one
    // more deprecated property must not delete the bundled deprecations.
    // `write_only`/`create_only`/`deprecated` drive their own diagnostics;
    // `read_only` and the primary identifier feed the overlay catalog (GetAtt
    // and Ref metadata for the rule engines); `conditional_create_only` is
    // carried for completeness and has no runtime consumer today.
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
    //
    // This replacement does NOT suppress extension-origin findings: conditional
    // constraints from the build pipeline's extension fragments are stored in a
    // separately embedded ExtensionStore that overlays do not merge into. An
    // overlay replacing `allOf` here only affects the main schema's composition
    // — the extension-contributed conditionals remain validated independently.
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
    let mut overlay = overlay;
    // An overlay that supplies a `$ref` updates the reference target, and its
    // remaining fields merge normally below — constraint siblings the overlay
    // states beside its reference are preserved, not discarded. The base's
    // existing inline constraints also survive, so redirecting a reference
    // never silently weakens the property.
    if overlay.ref_name.is_some() {
        base.ref_name = overlay.ref_name.take();
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
    replace_if_some(&mut base.multiple_of, overlay.multiple_of);
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
    if overlay.required_present {
        base.required = overlay.required;
    } else {
        union_extend(&mut base.required, overlay.required);
    }

    if let Some(overlay_items) = overlay.items {
        match base.items.as_mut() {
            Some(base_items) => merge_prop(base_items, *overlay_items),
            None => base.items = Some(overlay_items),
        }
    }
    replace_if_present(&mut base.all_of, overlay.all_of);
    replace_if_present(&mut base.any_of, overlay.any_of);
    replace_if_present(&mut base.one_of, overlay.one_of);
    replace_if_present(&mut base.if_then_else, overlay.if_then_else);
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
        multiple_of,
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
        required_present,
        additional_properties,
        pattern_properties,
        items,
        all_of,
        any_of,
        one_of,
        if_then_else,
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
        && multiple_of.is_none()
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
        && !required_present
        && additional_properties.is_none()
        && pattern_properties.is_empty()
        && items.is_none()
        && all_of.is_empty()
        && any_of.is_empty()
        && one_of.is_empty()
        && if_then_else.is_empty()
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
    fn merge_prop_ref_overlay_updates_ref_preserving_base_constraints() {
        let mut base = compiled(json!({
            "properties": { "P": { "type": "string", "pattern": "^a", "maxLength": 10 } },
            "definitions": { "D": { "type": "object" } }
        }));
        merge_into(
            &mut base,
            compiled(json!({
                "properties": { "P": { "$ref": "#/definitions/D" } },
                "definitions": { "D": { "type": "object" } }
            })),
        );
        assert_eq!(base.properties["P"].ref_name.as_deref(), Some("D"), "a $ref overlay must update the reference");
        assert_eq!(
            base.properties["P"].pattern.as_deref(),
            Some("^a"),
            "the base pattern must be preserved when a $ref overlay is applied"
        );
        assert_eq!(
            base.properties["P"].max_length,
            Some(10),
            "the base maxLength must be preserved when a $ref overlay is applied"
        );
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
                { "if": { "properties": { "A": { "enum": ["x"] } } }, "then": { "dependentRequired": { "A": ["B"] } } }
            ]
        }));
        assert_eq!(base.all_of.len(), 1);
        assert_eq!(base.if_then_else.len(), 1);
        merge_into(
            &mut base,
            compiled(json!({
                "allOf": [{ "if": { "properties": { "A": { "enum": ["y"] } } }, "then": { "dependentRequired": { "A": ["C"] } } }]
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

    // -------------------------------------------------- keyword type validation

    #[test]
    fn compile_rejects_malformed_required_array() {
        let error = compile("AWS::Test::T", &json!({ "properties": { "P": { "type": "string" } }, "required": 42 }))
            .expect_err("non-array required must be rejected");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    #[test]
    fn compile_rejects_required_containing_non_strings() {
        let error =
            compile("AWS::Test::T", &json!({ "properties": { "P": { "type": "string" } }, "required": ["A", 42] }))
                .expect_err("required with non-string entries must be rejected");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    #[test]
    fn compile_rejects_invalid_property_pattern() {
        let error =
            compile("AWS::Test::T", &json!({ "properties": { "P": { "type": "string", "pattern": "^(unbalanced" } } }))
                .expect_err("an invalid regex in pattern must be rejected");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    #[test]
    fn compile_rejects_invalid_pattern_properties_regex() {
        let error = compile(
            "AWS::Test::T",
            &json!({ "properties": { "Map": { "type": "object", "patternProperties": { "^(bad": { "type": "string" } } } } }),
        )
        .expect_err("an invalid regex in patternProperties key must be rejected");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    #[test]
    fn compile_rejects_root_not_without_enum() {
        let error = compile(
            "AWS::Test::T",
            &json!({ "properties": { "P": { "type": "string", "not": { "pattern": "^x" } } } }),
        )
        .expect_err("'not' without 'enum' must be rejected as unsupported");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    // ------------------------------------------ composition rejection

    #[test]
    fn compile_rejects_composition_entry_with_ref() {
        compile(
            "AWS::Test::T",
            &json!({
                "definitions": { "D": { "type": "object" } },
                "allOf": [{ "$ref": "#/definitions/D" }]
            }),
        )
        .expect("a $ref inside a composition entry is accepted and resolved at validation time");
    }

    #[test]
    fn compile_accepts_composition_entry_with_scalar_constraint() {
        compile(
            "AWS::Test::T",
            &json!({
                "oneOf": [{ "required": ["A"], "minLength": 5 }]
            }),
        )
        .expect("scalar constraints inside composition entries are accepted and evaluated");
    }

    #[test]
    fn compile_accepts_conditional_allof_then_with_required() {
        compile(
            "AWS::Test::T",
            &json!({
                "allOf": [{
                    "if": { "properties": { "A": { "enum": ["x"] } } },
                    "then": { "required": ["B"] }
                }]
            }),
        )
        .expect("conditional then with 'required' is now supported");
    }

    #[test]
    fn compile_accepts_conditional_allof_then_with_dependent_required() {
        compile(
            "AWS::Test::T",
            &json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{
                    "if": { "properties": { "A": { "enum": ["x"] } } },
                    "then": { "dependentRequired": { "A": ["B"] } }
                }]
            }),
        )
        .expect("a conditional then with only dependentRequired must be accepted");
    }

    #[test]
    fn compile_rejects_direct_root_if_then_else() {
        let error = compile(
            "AWS::Test::T",
            &json!({
                "properties": { "A": { "type": "string" } },
                "if": { "properties": { "A": { "enum": ["x"] } } },
                "then": { "required": ["B"] }
            }),
        )
        .expect_err("direct root if/then/else must be rejected");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    #[test]
    fn compile_accepts_plain_composition_with_allowed_fields() {
        compile(
            "AWS::Test::T",
            &json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "oneOf": [{ "required": ["A"] }, { "required": ["B"] }]
            }),
        )
        .expect("composition with only required must be accepted");
    }

    // ------------------------------------------ deterministic conflict reporting

    #[test]
    fn conflicting_enum_check_reports_alphabetically_first_path() {
        let schema = compiled(json!({
            "properties": {
                "Zeta": { "type": "string", "enum": ["A"], "enumCaseInsensitive": ["a"] },
                "Alpha": { "type": "string", "enum": ["B"], "enumCaseInsensitive": ["b"] }
            }
        }));
        let error = validate_schema(&schema).expect_err("both conflicts must be detected");
        match error {
            SchemaOverlayError::ConflictingEnums { property, .. } => {
                assert_eq!(property, "Alpha", "the alphabetically first path must be reported");
            }
            other => panic!("expected conflicting-enum error, got {other:?}"),
        }
    }

    // ------------------------------------------ low-level compile whitespace/mismatch

    #[test]
    fn compile_rejects_leading_whitespace_in_type_name() {
        let error = compile(" AWS::Test::T", &json!({ "properties": { "P": { "type": "string" } } }))
            .expect_err("leading whitespace must be rejected");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    #[test]
    fn compile_rejects_trailing_whitespace_in_type_name() {
        let error = compile("AWS::Test::T ", &json!({ "properties": { "P": { "type": "string" } } }))
            .expect_err("trailing whitespace must be rejected");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    #[test]
    fn compile_rejects_type_name_mismatch_with_schema_typename() {
        let error = compile(
            "AWS::Test::A",
            &json!({ "typeName": "AWS::Test::B", "properties": { "P": { "type": "string" } } }),
        )
        .expect_err("a typeName mismatch must be rejected");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    // ------------------------------------------ unrepresented keywords now error

    #[test]
    fn compile_rejects_unrepresented_constraint_keywords() {
        for keyword in ["propertyNames", "contains"] {
            let schema = json!({ "properties": { "P": { "type": "string", keyword: 42 } } });
            let error =
                compile("AWS::Test::T", &schema).expect_err(&format!("'{keyword}' must be rejected, not warned"));
            assert!(
                matches!(error, SchemaOverlayError::Unsupported { .. }),
                "expected Unsupported for '{keyword}', got {error:?}"
            );
        }
    }

    #[test]
    fn compile_accepts_multiple_of() {
        compile("AWS::Test::T", &json!({ "properties": { "P": { "type": "number", "multipleOf": 5 } } }))
            .expect("multipleOf is represented and enforced");
    }

    // ------------------------------------------ $ref preserves base constraints

    #[test]
    fn ref_overlay_preserves_base_pattern_and_max_length() {
        let mut base = compiled(json!({
            "properties": { "P": { "type": "string", "pattern": "^[a-z]+$", "maxLength": 50 } },
            "definitions": { "D": { "type": "string" } }
        }));
        merge_into(
            &mut base,
            compiled(json!({
                "properties": { "P": { "$ref": "#/definitions/D" } },
                "definitions": { "D": { "type": "string" } }
            })),
        );
        let p = &base.properties["P"];
        assert_eq!(p.ref_name.as_deref(), Some("D"), "the reference must be set");
        assert_eq!(p.pattern.as_deref(), Some("^[a-z]+$"), "base pattern must be preserved");
        assert_eq!(p.max_length, Some(50), "base maxLength must be preserved");
    }

    #[test]
    fn compile_accepts_composition_properties() {
        compile("AWS::Test::T", &json!({ "oneOf": [{ "properties": { "A": { "enum": ["x"] } }, "required": ["A"] }] }))
            .expect("composition branches with property constraints are now accepted and evaluated");
    }

    #[test]
    fn compile_rejects_conditional_fields_the_matcher_does_not_evaluate() {
        // anyOf inside a condition `if` block is still not supported (nested
        // condition schemas are not reachable from caller-supplied overlays).
        let error = compile(
            "AWS::Test::T",
            &json!({ "allOf": [{ "if": { "anyOf": [{ "required": ["A"] }] }, "then": { "dependentRequired": { "A": ["B"] } } }] }),
        )
        .expect_err("unsupported conditional fields must be rejected");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    #[test]
    fn compile_accepts_conditional_with_maxlength_in_property() {
        compile(
            "AWS::Test::T",
            &json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{
                    "if": { "properties": { "A": { "maxLength": 3 } } },
                    "then": { "dependentRequired": { "A": ["B"] } }
                }]
            }),
        )
        .expect("maxLength in condition property is now accepted");
    }

    #[test]
    fn compile_accepts_condition_fields_the_matcher_evaluates() {
        compile(
            "AWS::Test::T",
            &json!({
                "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
                "allOf": [{
                    "if": { "properties": { "A": { "type": "string", "enum": ["x"] } }, "required": ["A"] },
                    "then": { "dependentRequired": { "A": ["B"] } }
                }]
            }),
        )
        .expect("fully enforced conditional fields must remain supported");
    }

    #[test]
    fn compile_rejects_unknown_or_empty_property_types() {
        for prop_type in [json!("strng"), json!([])] {
            let error = compile("AWS::Test::T", &json!({ "properties": { "P": { "type": prop_type } } }))
                .expect_err("a type the validator cannot enforce must be rejected");
            assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
        }
    }

    #[test]
    fn compile_rejects_non_string_schema_type_name() {
        let error = compile("AWS::Test::T", &json!({ "typeName": 42, "properties": { "P": { "type": "string" } } }))
            .expect_err("typeName must be a string");
        assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
    }

    #[test]
    fn compile_rejects_malformed_property_metadata_paths() {
        for pointer in [json!("P"), json!("/properties/"), json!(42)] {
            let error = compile(
                "AWS::Test::T",
                &json!({
                    "properties": { "P": { "type": "string" } },
                    "readOnlyProperties": [pointer]
                }),
            )
            .expect_err("metadata paths must be valid property pointers");
            assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
        }
    }

    #[test]
    fn compile_rejects_malformed_not_enum() {
        for negated in [json!({ "enum": "x" }), json!({ "enum": [] }), json!({ "type": "string" })] {
            let error =
                compile("AWS::Test::T", &json!({ "properties": { "P": { "type": "string", "not": negated } } }))
                    .expect_err("only a non-empty not.enum array is enforceable");
            assert!(matches!(error, SchemaOverlayError::Unsupported { .. }), "got {error:?}");
        }
    }

    #[test]
    fn compile_rejects_constraints_beside_a_ref() {
        compile(
            "AWS::Test::T",
            &json!({
                "properties": { "P": { "$ref": "#/definitions/D", "maxLength": 3 } },
                "definitions": { "D": { "type": "string" } }
            }),
        )
        .expect("represented constraints beside a $ref are accepted and merged at validation time");
    }

    #[test]
    fn overlay_with_explicit_required_replaces_base_required() {
        let mut base = compiled(json!({
            "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
            "required": ["A", "B"]
        }));
        let overlay = compiled(json!({
            "properties": { "C": { "type": "string" } },
            "required": ["C"]
        }));
        merge_into(&mut base, overlay);
        assert_eq!(base.required, vec!["C".to_string()], "explicit required replaces, not unions");
    }

    #[test]
    fn overlay_with_empty_required_clears_base_required() {
        let mut base = compiled(json!({
            "properties": { "A": { "type": "string" }, "B": { "type": "string" } },
            "required": ["A", "B"]
        }));
        let overlay = compiled(json!({
            "properties": { "C": { "type": "string" } },
            "required": []
        }));
        merge_into(&mut base, overlay);
        assert!(base.required.is_empty(), "explicit empty required clears the base's required list");
    }

    #[test]
    fn overlay_without_required_preserves_base_required() {
        let mut base = compiled(json!({
            "properties": { "A": { "type": "string" } },
            "required": ["A"]
        }));
        let overlay = compiled(json!({
            "properties": { "B": { "type": "string" } }
        }));
        merge_into(&mut base, overlay);
        assert_eq!(base.required, vec!["A".to_string()], "omitting required from overlay preserves base");
    }

    #[test]
    fn property_level_required_present_replaces() {
        let mut base = compiled(json!({
            "properties": {
                "Nested": { "type": "object", "properties": { "X": { "type": "string" } }, "required": ["X"] }
            }
        }));
        let overlay = compiled(json!({
            "properties": {
                "Nested": { "type": "object", "properties": { "Y": { "type": "string" } }, "required": ["Y"] }
            }
        }));
        merge_into(&mut base, overlay);
        assert_eq!(
            base.properties["Nested"].required,
            vec!["Y".to_string()],
            "property-level explicit required replaces base"
        );
    }

    #[test]
    fn states_nothing_rejects_description_only_overlay() {
        let error = compile("AWS::Test::DescOnly", &json!({ "description": "just a note" }))
            .expect_err("a description-only overlay carries no validatable constraint");
        assert!(matches!(error, SchemaOverlayError::NoEffect { .. }), "got {error:?}");
    }

    #[test]
    fn states_nothing_accepts_documentation_url_with_property() {
        compile(
            "AWS::Test::DocUrl",
            &json!({
                "properties": { "P": { "type": "string" } },
                "documentationUrl": "https://example.com"
            }),
        )
        .expect("documentation URL with a property is valid");
    }

    #[test]
    fn states_nothing_rejects_documentation_url_only() {
        let error = compile("AWS::Test::DocOnly", &json!({ "documentationUrl": "https://example.com" }))
            .expect_err("documentation URL alone has no validatable constraint");
        assert!(matches!(error, SchemaOverlayError::NoEffect { .. }), "got {error:?}");
    }

    #[test]
    fn required_present_set_when_raw_has_required_keyword() {
        let overlay = compiled(json!({
            "properties": { "A": { "type": "string" } },
            "required": ["A"]
        }));
        assert!(overlay.required_present, "required_present must be set when source has 'required'");
    }

    #[test]
    fn required_present_not_set_when_raw_omits_required() {
        let overlay = compiled(json!({
            "properties": { "A": { "type": "string" } }
        }));
        assert!(!overlay.required_present, "required_present must not be set when source omits 'required'");
    }

    #[test]
    fn required_present_propagates_into_pattern_properties() {
        // `required` stated inside a patternProperties value schema must carry
        // the same replacement semantics as every other schema position.
        let mut base = compiled(json!({
            "properties": {
                "Map": {
                    "type": "object",
                    "patternProperties": {
                        "^k$": { "type": "object", "required": ["A", "B"] }
                    }
                }
            }
        }));
        merge_into(
            &mut base,
            compiled(json!({
                "properties": {
                    "Map": { "patternProperties": { "^k$": { "required": ["A"] } } }
                }
            })),
        );
        assert_eq!(
            base.properties["Map"].pattern_properties["^k$"].required,
            vec!["A".to_string()],
            "a stated required inside patternProperties must replace, not union"
        );
    }

    #[test]
    fn removed_required_reports_every_position_deterministically() {
        let base = compiled(json!({
            "properties": {
                "Cfg": { "type": "object", "required": ["Inner", "Kept"] },
                "List": { "type": "array", "items": { "type": "object", "required": ["Elem"] } },
                "Map": { "type": "object", "patternProperties": { "^k$": { "required": ["P"] } } }
            },
            "required": ["Cfg", "List"]
        }));
        let mut merged = base.clone();
        merge_into(
            &mut merged,
            compiled(json!({
                "properties": {
                    "Cfg": { "required": ["Kept"] },
                    "List": { "items": { "required": [] } },
                    "Map": { "patternProperties": { "^k$": { "required": [] } } }
                },
                "required": ["Cfg"]
            })),
        );
        let removals = removed_required(&base, &merged);
        assert_eq!(
            removals,
            vec![
                (String::new(), vec!["List".to_string()]),
                ("Cfg".to_string(), vec!["Inner".to_string()]),
                ("List[]".to_string(), vec!["Elem".to_string()]),
                ("Map<patternProperties>.^k$".to_string(), vec!["P".to_string()]),
            ],
            "every removal must be reported with its schema position, in sorted order"
        );
    }

    #[test]
    fn removed_required_is_empty_when_nothing_is_removed() {
        let base = compiled(json!({ "properties": { "A": { "type": "string" } }, "required": ["A"] }));
        let mut merged = base.clone();
        merge_into(
            &mut merged,
            compiled(json!({ "properties": { "B": { "type": "string" } }, "required": ["A", "B"] })),
        );
        assert!(removed_required(&base, &merged).is_empty(), "adding a requirement is not a removal");

        let mut unioned = base.clone();
        merge_into(&mut unioned, compiled(json!({ "properties": { "B": { "type": "string" } } })));
        assert!(removed_required(&base, &unioned).is_empty(), "an omitted 'required' keeps the base list");
    }
}
