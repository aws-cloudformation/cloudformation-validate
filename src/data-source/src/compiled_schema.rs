//! Shared CloudFormation resource-provider schema model and the raw-JSON →
//! compiled-schema transform.
//!
//! This is the single source of truth for turning a raw CloudFormation registry
//! schema (`$ref`, `type`, `enum`, `/properties/...` paths, `allOf`+`if`, …) into
//! the compiled representation that the schema validator consumes.
//!
//! - At **build time**, `codegen_schema_validator` compiles every bundled schema
//!   with [`compile_schema`] and serializes the results to `compiled_schemas.json`
//!   (embedded into the binary). `BTreeMap` fields make that output deterministic.
//! - At **run time**, the `schema-validator` crate applies additional/overlay
//!   schemas by calling [`compile_schema`] and converting the result into its own
//!   runtime schema type. Routing overlays through this exact function guarantees
//!   the *transform* is the same one bundled schemas go through.
//!
//! The transform is shared; the **input** is not. Bundled schemas are compiled
//! from the build pipeline's patched archive, which adds keywords the raw registry
//! does not carry (case-insensitive enums, `requiredOr`/`requiredXor`,
//! `dependentExcluded`, injected conditional `allOf` fragments). A caller-supplied
//! overlay is compiled straight from the JSON it provides, so anything the
//! pipeline would have contributed is absent unless the caller states it
//! explicitly. Callers must not assume an overlay for a bundled type reproduces
//! that type's enriched schema.
//!
//! This module is intentionally dependency-free (only `serde`/`serde_json` +
//! `std`) and is **not** behind the `full` feature, so the runtime can use the
//! transform without pulling in the build pipeline's heavy dependencies.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Named constants for every raw JSON-schema and CloudFormation provider-schema
/// keyword the compiler reads, grouped by how the compiled model represents
/// them. This module is the single source of truth for the vocabulary shared
/// between the build-time compilation pipeline and the runtime overlay
/// preflight in `schema-validator`.
pub mod keywords {
    // ─── Reference prefix ───────────────────────────────────────────────────

    /// The JSON pointer prefix under which definition references live.
    pub const DEFINITIONS_REF_PREFIX: &str = "#/definitions/";

    /// The JSON pointer prefix that metadata path arrays (`readOnlyProperties`,
    /// etc.) use to indicate a property path.
    pub const PROPERTIES_PATH_PREFIX: &str = "/properties/";

    // ─── Reference keyword ──────────────────────────────────────────────────

    /// The `$ref` keyword, pointing at a definition.
    pub const REF: &str = "$ref";

    // ─── Schema map keywords ────────────────────────────────────────────────
    //
    // These name JSON objects whose values are themselves schema objects,
    // compiled recursively into keyed maps.

    pub const PROPERTIES: &str = "properties";
    pub const DEFINITIONS: &str = "definitions";
    pub const PATTERN_PROPERTIES: &str = "patternProperties";

    /// The set of keywords naming schema-level maps compiled into keyed
    /// `BTreeMap<String, PropSchema>` fields.
    pub const SCHEMA_MAPS: &[&str] = &[PROPERTIES, DEFINITIONS, PATTERN_PROPERTIES];

    // ─── Composition keywords ───────────────────────────────────────────────
    //
    // Arrays of subschemas, each compiled into `Vec<SubSchema>` or split
    // into conditional entries.

    pub const ALL_OF: &str = "allOf";
    pub const ANY_OF: &str = "anyOf";
    pub const ONE_OF: &str = "oneOf";

    /// The full set of composition array keywords the compiler handles.
    pub const COMPOSITION: &[&str] = &[ALL_OF, ANY_OF, ONE_OF];

    // ─── Conditional keywords ───────────────────────────────────────────────
    //
    // The `if`/`then`/`else` conditional structure, only recognized inside
    // `allOf` entries by the compiler.

    pub const IF: &str = "if";
    pub const THEN: &str = "then";
    pub const ELSE: &str = "else";

    /// The set of conditional branch keywords the compiler recognizes inside
    /// `allOf` entries.
    pub const CONDITIONALS: &[&str] = &[IF, THEN, ELSE];

    // ─── Metadata pointer arrays ────────────────────────────────────────────
    //
    // Top-level arrays whose entries are `/properties/...` JSON pointers
    // converted to dot-notation property paths.

    pub const READ_ONLY_PROPERTIES: &str = "readOnlyProperties";
    pub const WRITE_ONLY_PROPERTIES: &str = "writeOnlyProperties";
    pub const CREATE_ONLY_PROPERTIES: &str = "createOnlyProperties";
    pub const DEPRECATED_PROPERTIES: &str = "deprecatedProperties";
    pub const CONDITIONAL_CREATE_ONLY_PROPERTIES: &str = "conditionalCreateOnlyProperties";
    pub const PRIMARY_IDENTIFIER: &str = "primaryIdentifier";

    /// Metadata pointer arrays that carry `/properties/...` paths.
    pub const METADATA_POINTER_ARRAYS: &[&str] = &[
        READ_ONLY_PROPERTIES,
        WRITE_ONLY_PROPERTIES,
        CREATE_ONLY_PROPERTIES,
        DEPRECATED_PROPERTIES,
        CONDITIONAL_CREATE_ONLY_PROPERTIES,
        PRIMARY_IDENTIFIER,
    ];

    // ─── String-array constraint keywords ───────────────────────────────────
    //
    // Keywords whose value is an array of property-name strings.

    pub const REQUIRED: &str = "required";
    pub const REQUIRED_OR: &str = "requiredOr";
    pub const REQUIRED_XOR: &str = "requiredXor";

    /// Keywords whose value is a JSON array of property-name strings, validated
    /// as `Vec<String>`.
    pub const STRING_ARRAY_CONSTRAINTS: &[&str] = &[REQUIRED, REQUIRED_OR, REQUIRED_XOR];

    // ─── Dependency map keywords ────────────────────────────────────────────
    //
    // Keywords whose value is `{ "trigger": ["dep1", "dep2"] }`.

    pub const DEPENDENT_REQUIRED: &str = "dependentRequired";
    pub const DEPENDENT_EXCLUDED: &str = "dependentExcluded";

    /// Keywords compiled into `BTreeMap<String, Vec<String>>` dependency maps.
    pub const DEPENDENCY_MAPS: &[&str] = &[DEPENDENT_REQUIRED, DEPENDENT_EXCLUDED];

    // ─── Enum keywords ──────────────────────────────────────────────────────

    pub const ENUM: &str = "enum";
    pub const ENUM_CASE_INSENSITIVE: &str = "enumCaseInsensitive";
    pub const NOT: &str = "not";

    /// The two enum array keywords (exact and case-insensitive).
    pub const ENUM_KEYWORDS: &[&str] = &[ENUM, ENUM_CASE_INSENSITIVE];

    // ─── Numeric constraint keywords (f64) ──────────────────────────────────

    pub const MINIMUM: &str = "minimum";
    pub const MAXIMUM: &str = "maximum";
    pub const EXCLUSIVE_MINIMUM: &str = "exclusiveMinimum";
    pub const EXCLUSIVE_MAXIMUM: &str = "exclusiveMaximum";

    /// Keywords compiled into `Option<f64>` numeric bounds.
    pub const NUMERIC_CONSTRAINTS: &[&str] = &[MINIMUM, MAXIMUM, EXCLUSIVE_MINIMUM, EXCLUSIVE_MAXIMUM];

    // ─── Unsigned integer constraint keywords (u64) ─────────────────────────

    pub const MIN_LENGTH: &str = "minLength";
    pub const MAX_LENGTH: &str = "maxLength";
    pub const MIN_ITEMS: &str = "minItems";
    pub const MAX_ITEMS: &str = "maxItems";
    pub const MIN_PROPERTIES: &str = "minProperties";
    pub const MAX_PROPERTIES: &str = "maxProperties";

    /// Keywords compiled into `Option<u64>` length/count bounds.
    pub const U64_CONSTRAINTS: &[&str] =
        &[MIN_LENGTH, MAX_LENGTH, MIN_ITEMS, MAX_ITEMS, MIN_PROPERTIES, MAX_PROPERTIES];

    // ─── Boolean constraint keywords ────────────────────────────────────────

    pub const ADDITIONAL_PROPERTIES: &str = "additionalProperties";
    pub const UNIQUE_ITEMS: &str = "uniqueItems";

    /// Keywords compiled into `Option<bool>` flags.
    pub const BOOL_CONSTRAINTS: &[&str] = &[ADDITIONAL_PROPERTIES, UNIQUE_ITEMS];

    // ─── String constraint/metadata keywords ────────────────────────────────

    pub const PATTERN: &str = "pattern";
    pub const FORMAT: &str = "format";
    pub const DESCRIPTION: &str = "description";
    pub const REPLACEMENT_STRATEGY: &str = "replacementStrategy";
    pub const DOCUMENTATION_URL: &str = "documentationUrl";
    pub const SOURCE_URL: &str = "sourceUrl";

    /// Keywords compiled into `Option<String>` string values.
    pub const STRING_CONSTRAINTS: &[&str] =
        &[PATTERN, FORMAT, DESCRIPTION, REPLACEMENT_STRATEGY, DOCUMENTATION_URL, SOURCE_URL];

    // ─── Other compiled keywords ────────────────────────────────────────────

    pub const TYPE: &str = "type";
    pub const CONST: &str = "const";
    pub const ITEMS: &str = "items";
    pub const TYPE_NAME: &str = "typeName";

    // ─── Unrepresented validation keywords ──────────────────────────────────
    //
    // JSON Schema validation keywords that exist in the spec but have no field
    // in the compiled schema model, so nothing enforces them. An overlay
    // stating any of these would silently weaken the author's intent.

    pub const UNREPRESENTED_VALIDATION_KEYWORDS: &[&str] =
        &["propertyNames", "contains", "minContains", "maxContains", "additionalItems", "unevaluatedProperties"];

    // ─── multipleOf keyword ─────────────────────────────────────────────────

    pub const MULTIPLE_OF: &str = "multipleOf";

    // ─── dependencies keyword ───────────────────────────────────────────────
    //
    // Draft-07 `dependencies` can be array-form (unioned into
    // `dependentRequired`) or schema-form (not represented).

    pub const DEPENDENCIES: &str = "dependencies";

    // ─── Relationship ref keyword ───────────────────────────────────────────

    pub const RELATIONSHIP_REF: &str = "relationshipRef";

    // ─── Annotation keywords ────────────────────────────────────────────────
    //
    // Keywords that carry no validation meaning and may appear beside a `$ref`
    // without causing an error.

    pub const REF_ANNOTATION_KEYWORDS: &[&str] = &[
        "description",
        "markdownDescription",
        "title",
        "examples",
        "default",
        "$comment",
        "insertionOrder",
        RELATIONSHIP_REF,
    ];

    // ─── compile_sub fields ─────────────────────────────────────────────────
    //
    // `compile_sub` now compiles a composition branch into a full `PropSchema`,
    // so it reads every constraint keyword that `compile_prop` reads. The
    // overlay's `COMPOSITION_ALLOWED_FIELDS` is validated against what the
    // runtime actually *evaluates* for composition entries — a separate,
    // narrower set managed in `schema-validator`.

    /// Fields read by `compile_sub`: since `SubSchema` is now `PropSchema`, this
    /// is the full set of property-schema keywords.
    pub const COMPILE_SUB_READS_ALL_PROP_FIELDS: bool = true;

    // ─── compile_condition_schema fields ────────────────────────────────────
    //
    // The exact set of keywords `compile_condition_schema` reads from an `if`
    // schema object.

    /// Fields read by `compile_condition_schema`: what a conditional `if` block
    /// may contain.
    pub const COMPILE_CONDITION_SCHEMA_FIELDS: &[&str] = &[PROPERTIES, REQUIRED, TYPE, ANY_OF];
}

#[derive(Serialize, Deserialize)]
pub struct CompiledSchema {
    pub type_name: String,
    #[serde(default)]
    pub properties: BTreeMap<String, PropSchema>,
    #[serde(default)]
    pub definitions: BTreeMap<String, PropSchema>,
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub additional_properties: Option<bool>,
    #[serde(default)]
    pub read_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub create_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deprecated_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditional_create_only_properties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub primary_identifier: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_strategy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub if_then_else: Vec<IfThenElse>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependent_required: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependent_excluded: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_or: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_xor: Vec<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct IfThenElse {
    pub condition: ConditionSchema,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub then_schema: Option<SubSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub else_schema: Option<SubSchema>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct ConditionSchema {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// The instance type the condition requires (`if: {"type": ...}`). A
    /// condition stating a type only matches an instance of that type; resource
    /// roots are always objects, so `"object"` is a no-op there while any other
    /// type makes the condition unsatisfiable at the root.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub prop_type: Option<PropType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<ConditionSchema>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct PropSchema {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub prop_type: Option<PropType>,
    #[serde(default, rename = "enum", skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_case_insensitive: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_enum: Vec<serde_json::Value>,
    #[serde(default, rename = "const", skip_serializing_if = "Option::is_none")]
    pub const_value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusive_minimum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusive_maximum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiple_of: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u64>,
    /// `None` when the source schema omits `uniqueItems`, so an overlay that
    /// explicitly sets it to `false` can relax a bundled `true`. Serialization
    /// only emits the field when it is `true`, keeping the encoding identical to
    /// the plain-boolean form this replaced.
    #[serde(default, skip_serializing_if = "skip_unless_true")]
    pub unique_items: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_properties: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_properties: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_properties: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pattern_properties: BTreeMap<String, PropSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<PropSchema>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<SubSchema>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub if_then_else: Vec<IfThenElse>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependent_required: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependent_excluded: BTreeMap<String, Vec<String>>,
}
fn skip_unless_true(value: &Option<bool>) -> bool {
    *value != Some(true)
}

/// A composition branch is now a full property schema — every constraint that
/// `compile_prop` produces is available in a branch and evaluated by the runtime.
/// This alias maintains naming clarity at usage sites.
pub type SubSchema = PropSchema;

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum PropType {
    Single(String),
    Multi(Vec<String>),
}

/// Convert `/properties/X/Y/Z` paths to `X.Y.Z` dot notation.
fn convert_property_paths(raw: &serde_json::Value) -> Vec<String> {
    raw.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    v.as_str()
                        .and_then(|s| s.strip_prefix(keywords::PROPERTIES_PATH_PREFIX))
                        .map(|s| s.replace('/', "."))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// How to treat constraint keywords written beside a `$ref`.
///
/// Draft-07 — the dialect provider schemas are written against, and the one the
/// CloudFormation registry itself validates with — ignores every keyword beside
/// a `$ref`. The build pipeline compiles bundled schemas with [`Self::Ignore`]
/// so the engine never enforces more than CloudFormation's own contract. Overlay
/// schemas are compiled with [`Self::Enforce`]: the author supplied the sibling
/// constraints deliberately, and they are merged onto the referenced definition
/// at validation time (`PropSchema::resolve`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefSiblings {
    /// Compile constraint siblings beside a `$ref` and enforce them.
    Enforce,
    /// Drop everything beside a `$ref`, matching draft-07 evaluation.
    Ignore,
}

/// Compiles a raw provider schema with [`RefSiblings::Enforce`] — the overlay
/// path. The build pipeline uses [`compile_schema_with`] and
/// [`RefSiblings::Ignore`] instead; see [`RefSiblings`].
pub fn compile_schema(type_name: &str, raw: &serde_json::Value) -> CompiledSchema {
    compile_schema_with(type_name, raw, RefSiblings::Enforce)
}

/// Compiles a raw CloudFormation resource provider schema into the compiled
/// representation.
///
/// This transform is richer than the one that produced older committed
/// `compiled_schemas.json` artifacts (full composition branches, property-level
/// conditionals, `multipleOf`, draft-07 array-form `dependencies`), so
/// **regenerating the committed artifact changes what bundled schemas enforce**.
/// A regeneration must be validated against the full template corpus on both
/// engines before it is committed.
pub fn compile_schema_with(type_name: &str, raw: &serde_json::Value, ref_siblings: RefSiblings) -> CompiledSchema {
    let mut defs = BTreeMap::new();
    if let Some(d) = raw.get(keywords::DEFINITIONS).and_then(|v| v.as_object()) {
        for (k, v) in d {
            defs.insert(k.clone(), compile_prop_with(v, ref_siblings));
        }
    }
    let mut props = BTreeMap::new();
    if let Some(p) = raw.get(keywords::PROPERTIES).and_then(|v| v.as_object()) {
        for (k, v) in p {
            props.insert(k.clone(), compile_prop_with(v, ref_siblings));
        }
    }

    let mut all_of = Vec::new();
    let mut if_then_else = Vec::new();
    if let Some(arr) = raw.get(keywords::ALL_OF).and_then(|v| v.as_array()) {
        for item in arr {
            if item.get(keywords::IF).is_some() {
                if let Some(ite) = compile_if_then_else(item, ref_siblings) {
                    if_then_else.push(ite);
                }
            } else {
                all_of.push(compile_sub(item, ref_siblings));
            }
        }
    }

    CompiledSchema {
        type_name: type_name.to_string(),
        properties: props,
        definitions: defs,
        required: str_arr(raw.get(keywords::REQUIRED)),
        additional_properties: raw.get(keywords::ADDITIONAL_PROPERTIES).and_then(|v| v.as_bool()),
        read_only_properties: convert_property_paths(
            raw.get(keywords::READ_ONLY_PROPERTIES).unwrap_or(&serde_json::Value::Null),
        ),
        write_only_properties: convert_property_paths(
            raw.get(keywords::WRITE_ONLY_PROPERTIES).unwrap_or(&serde_json::Value::Null),
        ),
        create_only_properties: convert_property_paths(
            raw.get(keywords::CREATE_ONLY_PROPERTIES).unwrap_or(&serde_json::Value::Null),
        ),
        deprecated_properties: convert_property_paths(
            raw.get(keywords::DEPRECATED_PROPERTIES).unwrap_or(&serde_json::Value::Null),
        ),
        conditional_create_only_properties: convert_property_paths(
            raw.get(keywords::CONDITIONAL_CREATE_ONLY_PROPERTIES).unwrap_or(&serde_json::Value::Null),
        ),
        primary_identifier: convert_property_paths(
            raw.get(keywords::PRIMARY_IDENTIFIER).unwrap_or(&serde_json::Value::Null),
        ),
        replacement_strategy: raw
            .get(keywords::REPLACEMENT_STRATEGY)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from),
        documentation_url: raw
            .get(keywords::DOCUMENTATION_URL)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from),
        source_url: raw.get(keywords::SOURCE_URL).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(String::from),
        description: raw
            .get(keywords::DESCRIPTION)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from),
        all_of,
        any_of: compile_subs(raw.get(keywords::ANY_OF), ref_siblings),
        one_of: compile_subs(raw.get(keywords::ONE_OF), ref_siblings),
        if_then_else,
        dependent_required: compile_dependent_required(raw),
        dependent_excluded: str_map(raw.get(keywords::DEPENDENT_EXCLUDED)),
        required_or: str_arr(raw.get(keywords::REQUIRED_OR)),
        required_xor: str_arr(raw.get(keywords::REQUIRED_XOR)),
    }
}

/// Compile `dependentRequired` and draft-07 `dependencies` (array-form) into a
/// unified dependent_required map.
fn compile_dependent_required(raw: &serde_json::Value) -> BTreeMap<String, Vec<String>> {
    let mut dep_req = str_map(raw.get(keywords::DEPENDENT_REQUIRED));
    if let Some(deps_obj) = raw.get(keywords::DEPENDENCIES).and_then(|v| v.as_object()) {
        for (trigger, value) in deps_obj {
            if let Some(arr) = value.as_array() {
                let names: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                if !names.is_empty() {
                    dep_req.entry(trigger.clone()).or_default().extend(names);
                }
            }
        }
    }
    for deps in dep_req.values_mut() {
        deps.sort();
        deps.dedup();
    }
    dep_req
}

fn compile_if_then_else(raw: &serde_json::Value, ref_siblings: RefSiblings) -> Option<IfThenElse> {
    let if_val = raw.get(keywords::IF)?;
    let condition = compile_condition_schema(if_val, ref_siblings);
    let then_schema = raw.get(keywords::THEN).map(|branch| compile_sub(branch, ref_siblings));
    let else_schema = raw.get(keywords::ELSE).map(|branch| compile_sub(branch, ref_siblings));
    if then_schema.is_none() && else_schema.is_none() {
        return None;
    }
    Some(IfThenElse { condition, then_schema, else_schema })
}

fn compile_condition_schema(raw: &serde_json::Value, ref_siblings: RefSiblings) -> ConditionSchema {
    let obj = match raw.as_object() {
        Some(o) => o,
        None => return ConditionSchema::default(),
    };
    let mut props = BTreeMap::new();
    if let Some(p) = obj.get(keywords::PROPERTIES).and_then(|v| v.as_object()) {
        for (k, v) in p {
            props.insert(k.clone(), compile_prop_with(v, ref_siblings));
        }
    }
    let any_of = obj
        .get(keywords::ANY_OF)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|entry| compile_condition_schema(entry, ref_siblings)).collect())
        .unwrap_or_default();
    let prop_type = obj.get(keywords::TYPE).map(compile_prop_type);
    ConditionSchema { properties: props, required: str_arr(obj.get(keywords::REQUIRED)), prop_type, any_of }
}

/// Compiles a raw `type` keyword value into the [`PropType`] representation:
/// a single name, an array of names, or (for a malformed value the preflight
/// rejects on overlay input) the historical `"string"` fallback.
fn compile_prop_type(raw: &serde_json::Value) -> PropType {
    match raw {
        serde_json::Value::String(s) => PropType::Single(s.clone()),
        serde_json::Value::Array(a) => PropType::Multi(a.iter().filter_map(|v| v.as_str().map(String::from)).collect()),
        _ => PropType::Single("string".into()),
    }
}

fn compile_prop_with(raw: &serde_json::Value, ref_siblings: RefSiblings) -> PropSchema {
    let obj = match raw.as_object() {
        Some(o) => o,
        None => return PropSchema::default(),
    };
    // When a $ref is present, compile it as the ref_name. Under
    // [`RefSiblings::Enforce`], represented sibling constraints beside the
    // reference are additionally compiled and merged at validation time via
    // `PropSchema::resolve`. Under [`RefSiblings::Ignore`] — draft-07
    // evaluation, used for bundled schemas — everything beside the reference is
    // dropped. Annotations beside a $ref are ignored either way.
    let raw_ref = obj.get(keywords::REF).and_then(|v| v.as_str());
    let ref_name = raw_ref.and_then(|ref_str| ref_str.strip_prefix(keywords::DEFINITIONS_REF_PREFIX).map(String::from));
    if raw_ref.is_some() && ref_siblings == RefSiblings::Ignore {
        return PropSchema { ref_name, ..Default::default() };
    }
    // If the property is $ref-only (no other constraint keywords), return early.
    if ref_name.is_some() {
        let has_constraint_siblings = obj.keys().any(|key| {
            key != keywords::REF
                && !keywords::REF_ANNOTATION_KEYWORDS.contains(&key.as_str())
                && key != keywords::RELATIONSHIP_REF
        });
        if !has_constraint_siblings {
            return PropSchema { ref_name, ..Default::default() };
        }
    }

    let prop_type = obj.get(keywords::TYPE).map(compile_prop_type);
    let mut sub_props = BTreeMap::new();
    if let Some(p) = obj.get(keywords::PROPERTIES).and_then(|v| v.as_object()) {
        for (k, v) in p {
            sub_props.insert(k.clone(), compile_prop_with(v, ref_siblings));
        }
    }
    let mut pat_props = BTreeMap::new();
    if let Some(p) = obj.get(keywords::PATTERN_PROPERTIES).and_then(|v| v.as_object()) {
        for (k, v) in p {
            pat_props.insert(k.clone(), compile_prop_with(v, ref_siblings));
        }
    }
    let items = obj.get(keywords::ITEMS).map(|v| Box::new(compile_prop_with(v, ref_siblings)));

    // Compile draft-07 `dependencies` array-form into dependent_required.
    let mut dep_req = str_map(obj.get(keywords::DEPENDENT_REQUIRED).cloned().as_ref());
    if let Some(deps_obj) = obj.get(keywords::DEPENDENCIES).and_then(|v| v.as_object()) {
        for (trigger, value) in deps_obj {
            if let Some(arr) = value.as_array() {
                let names: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                if !names.is_empty() {
                    dep_req.entry(trigger.clone()).or_default().extend(names);
                }
            }
            // Schema-form dependencies are not represented; they are handled by
            // the overlay preflight rejection path.
        }
    }
    // Deduplicate dependency arrays.
    for deps in dep_req.values_mut() {
        deps.sort();
        deps.dedup();
    }

    // Compile direct if/then/else at property level.
    let mut if_then_else = Vec::new();
    if obj.get(keywords::IF).is_some()
        && let Some(ite) = compile_if_then_else(raw, ref_siblings)
    {
        if_then_else.push(ite);
    }

    // Compile allOf, splitting conditionals.
    let mut all_of_branches = Vec::new();
    if let Some(arr) = obj.get(keywords::ALL_OF).and_then(|v| v.as_array()) {
        for item in arr {
            if item.get(keywords::IF).is_some() {
                if let Some(ite) = compile_if_then_else(item, ref_siblings) {
                    if_then_else.push(ite);
                }
            } else {
                all_of_branches.push(compile_sub(item, ref_siblings));
            }
        }
    }

    PropSchema {
        ref_name,
        prop_type,
        enum_values: obj.get(keywords::ENUM).and_then(|v| v.as_array()).cloned().unwrap_or_default(),
        enum_case_insensitive: obj
            .get(keywords::ENUM_CASE_INSENSITIVE)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        not_enum: obj
            .get(keywords::NOT)
            .and_then(|v| v.get(keywords::ENUM))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        const_value: obj.get(keywords::CONST).cloned(),
        pattern: obj.get(keywords::PATTERN).and_then(|v| v.as_str()).map(String::from),
        minimum: obj.get(keywords::MINIMUM).and_then(|v| v.as_f64()),
        maximum: obj.get(keywords::MAXIMUM).and_then(|v| v.as_f64()),
        exclusive_minimum: obj.get(keywords::EXCLUSIVE_MINIMUM).and_then(|v| v.as_f64()),
        exclusive_maximum: obj.get(keywords::EXCLUSIVE_MAXIMUM).and_then(|v| v.as_f64()),
        multiple_of: obj.get(keywords::MULTIPLE_OF).and_then(|v| v.as_f64()),
        min_length: obj.get(keywords::MIN_LENGTH).and_then(|v| v.as_u64()),
        max_length: obj.get(keywords::MAX_LENGTH).and_then(|v| v.as_u64()),
        min_items: obj.get(keywords::MIN_ITEMS).and_then(|v| v.as_u64()),
        max_items: obj.get(keywords::MAX_ITEMS).and_then(|v| v.as_u64()),
        unique_items: obj.get(keywords::UNIQUE_ITEMS).and_then(|v| v.as_bool()),
        min_properties: obj.get(keywords::MIN_PROPERTIES).and_then(|v| v.as_u64()),
        max_properties: obj.get(keywords::MAX_PROPERTIES).and_then(|v| v.as_u64()),
        format: obj.get(keywords::FORMAT).and_then(|v| v.as_str()).map(String::from),
        description: obj
            .get(keywords::DESCRIPTION)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from),
        properties: sub_props,
        required: str_arr(obj.get(keywords::REQUIRED).cloned().as_ref()),
        additional_properties: obj.get(keywords::ADDITIONAL_PROPERTIES).and_then(|v| v.as_bool()),
        pattern_properties: pat_props,
        items,
        all_of: all_of_branches,
        any_of: compile_subs(obj.get(keywords::ANY_OF).cloned().as_ref(), ref_siblings),
        one_of: compile_subs(obj.get(keywords::ONE_OF).cloned().as_ref(), ref_siblings),
        if_then_else,
        dependent_required: dep_req,
        dependent_excluded: str_map(obj.get(keywords::DEPENDENT_EXCLUDED).cloned().as_ref()),
    }
}

fn compile_sub(raw: &serde_json::Value, ref_siblings: RefSiblings) -> SubSchema {
    compile_prop_with(raw, ref_siblings)
}

fn compile_subs(val: Option<&serde_json::Value>, ref_siblings: RefSiblings) -> Vec<SubSchema> {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter().map(|entry| compile_sub(entry, ref_siblings)).collect()
}

fn str_arr(val: Option<&serde_json::Value>) -> Vec<String> {
    val.and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn str_map(val: Option<&serde_json::Value>) -> BTreeMap<String, Vec<String>> {
    val.and_then(|v| v.as_object())
        .map(|m| m.iter().map(|(k, v)| (k.clone(), str_arr(Some(v)))).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compiles_properties_definitions_and_refs() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "Name": { "type": "string", "pattern": "^a", "minLength": 1 },
                    "Cfg": { "$ref": "#/definitions/Config" },
                    "Kinds": { "type": ["string", "null"] }
                },
                "definitions": { "Config": { "type": "object", "required": ["Inner"] } },
                "required": ["Name"],
                "additionalProperties": false
            }),
        );
        assert_eq!(compiled.type_name, "AWS::Test::T");
        assert_eq!(compiled.required, vec!["Name".to_string()]);
        assert_eq!(compiled.additional_properties, Some(false));
        assert_eq!(compiled.properties["Cfg"].ref_name.as_deref(), Some("Config"));
        assert_eq!(compiled.definitions["Config"].required, vec!["Inner".to_string()]);
        assert_eq!(compiled.properties["Name"].pattern.as_deref(), Some("^a"));
        assert_eq!(compiled.properties["Name"].min_length, Some(1));
        match compiled.properties["Kinds"].prop_type.as_ref().expect("a multi type is compiled") {
            PropType::Multi(names) => assert_eq!(names, &vec!["string".to_string(), "null".to_string()]),
            PropType::Single(name) => panic!("expected a multi type, got {name}"),
        }
    }

    #[test]
    fn converts_property_pointer_paths_to_dot_notation() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "readOnlyProperties": ["/properties/Arn", "/properties/Nested/Id"],
                "writeOnlyProperties": ["/properties/Secret"],
                "createOnlyProperties": ["/properties/Name"],
                "deprecatedProperties": ["/properties/Old"],
                "conditionalCreateOnlyProperties": ["/properties/Maybe"],
                "primaryIdentifier": ["/properties/Name"]
            }),
        );
        assert_eq!(compiled.read_only_properties, vec!["Arn".to_string(), "Nested.Id".to_string()]);
        assert_eq!(compiled.write_only_properties, vec!["Secret".to_string()]);
        assert_eq!(compiled.create_only_properties, vec!["Name".to_string()]);
        assert_eq!(compiled.deprecated_properties, vec!["Old".to_string()]);
        assert_eq!(compiled.conditional_create_only_properties, vec!["Maybe".to_string()]);
        assert_eq!(compiled.primary_identifier, vec!["Name".to_string()]);
    }

    #[test]
    fn splits_all_of_into_plain_and_conditional_entries() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "allOf": [
                    { "required": ["Plain"] },
                    { "if": { "properties": { "A": { "enum": ["x"] } } }, "then": { "required": ["B"] } },
                    { "if": { "properties": { "A": { "enum": ["y"] } } } }
                ]
            }),
        );
        assert_eq!(compiled.all_of.len(), 1, "plain entries stay in all_of");
        assert_eq!(compiled.all_of[0].required, vec!["Plain".to_string()]);
        assert_eq!(compiled.if_then_else.len(), 1, "an if with neither then nor else is dropped");
        assert_eq!(compiled.if_then_else[0].then_schema.as_ref().expect("then branch").required, vec!["B".to_string()]);
    }

    #[test]
    fn preserves_unique_items_presence() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "Strict": { "type": "array", "uniqueItems": true },
                    "Relaxed": { "type": "array", "uniqueItems": false },
                    "Silent": { "type": "array" }
                }
            }),
        );
        assert_eq!(compiled.properties["Strict"].unique_items, Some(true));
        assert_eq!(
            compiled.properties["Relaxed"].unique_items,
            Some(false),
            "an explicit false must be distinguishable from an omitted keyword"
        );
        assert_eq!(compiled.properties["Silent"].unique_items, None);
    }

    #[test]
    fn unique_items_serialization_only_emits_true() {
        // The committed `compiled_schemas.json` was produced when this field was a
        // plain bool that was skipped unless true; the encoding must not change.
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "Strict": { "uniqueItems": true },
                    "Relaxed": { "uniqueItems": false },
                    "Silent": {}
                }
            }),
        );
        let json = serde_json::to_value(&compiled).expect("a compiled schema serializes");
        let properties = json.get("properties").and_then(|v| v.as_object()).expect("properties are serialized");
        assert_eq!(properties["Strict"].get("unique_items"), Some(&json!(true)));
        assert!(properties["Relaxed"].get("unique_items").is_none(), "explicit false must be omitted");
        assert!(properties["Silent"].get("unique_items").is_none(), "an absent keyword must be omitted");
    }

    #[test]
    fn compiles_both_enum_representations_and_constraint_keywords() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "Exact": { "enum": ["a", "b"] },
                    "Insensitive": { "enumCaseInsensitive": ["a", "b"] },
                    "Excluded": { "not": { "enum": ["bad"] } },
                    "Fixed": { "const": 7 }
                },
                "dependentRequired": { "A": ["B"] },
                "dependentExcluded": { "C": ["D"] },
                "requiredOr": ["A", "B"],
                "requiredXor": ["C", "D"]
            }),
        );
        assert_eq!(compiled.properties["Exact"].enum_values, vec![json!("a"), json!("b")]);
        assert_eq!(compiled.properties["Insensitive"].enum_case_insensitive, vec![json!("a"), json!("b")]);
        assert_eq!(compiled.properties["Excluded"].not_enum, vec![json!("bad")]);
        assert_eq!(compiled.properties["Fixed"].const_value, Some(json!(7)));
        assert_eq!(compiled.dependent_required.get("A"), Some(&vec!["B".to_string()]));
        assert_eq!(compiled.dependent_excluded.get("C"), Some(&vec!["D".to_string()]));
        assert_eq!(compiled.required_or, vec!["A".to_string(), "B".to_string()]);
        assert_eq!(compiled.required_xor, vec!["C".to_string(), "D".to_string()]);
    }

    #[test]
    fn compiles_nested_properties_items_and_pattern_properties() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "Cfg": { "type": "object", "properties": { "Inner": { "type": "string" } } },
                    "Arr": { "type": "array", "items": { "type": "string", "maxLength": 3 } },
                    "Map": { "type": "object", "patternProperties": { "^k$": { "type": "integer" } } }
                }
            }),
        );
        assert!(compiled.properties["Cfg"].properties["Inner"].prop_type.is_some(), "nested type is compiled");
        assert_eq!(compiled.properties["Arr"].items.as_ref().expect("items").max_length, Some(3));
        assert!(compiled.properties["Map"].pattern_properties.contains_key("^k$"));
    }

    // ─── Vocabulary pinning tests ───────────────────────────────────────────

    #[test]
    fn compile_sub_compiles_all_prop_schema_fields() {
        // compile_sub delegates to compile_prop, so a composition branch
        // can carry every constraint a property can.
        let sub = compile_sub(
            &json!({
                "required": ["A"],
                "properties": { "P": { "type": "string" } },
                "additionalProperties": false,
                "dependentRequired": { "A": ["B"] },
                "dependentExcluded": { "C": ["D"] },
                "type": "object",
                "enum": ["x"],
                "pattern": "^a",
                "minimum": 1.0,
                "multipleOf": 5.0,
                "minLength": 2,
                "anyOf": [{ "required": ["Z"] }]
            }),
            RefSiblings::Enforce,
        );
        assert_eq!(sub.required, vec!["A".to_string()]);
        assert!(sub.properties.contains_key("P"));
        assert_eq!(sub.additional_properties, Some(false));
        assert_eq!(sub.dependent_required.get("A"), Some(&vec!["B".to_string()]));
        assert_eq!(sub.dependent_excluded.get("C"), Some(&vec!["D".to_string()]));
        assert!(sub.prop_type.is_some());
        assert_eq!(sub.enum_values, vec![json!("x")]);
        assert_eq!(sub.pattern.as_deref(), Some("^a"));
        assert_eq!(sub.minimum, Some(1.0));
        assert_eq!(sub.multiple_of, Some(5.0));
        assert_eq!(sub.min_length, Some(2));
        assert_eq!(sub.any_of.len(), 1);
    }

    #[test]
    fn compile_condition_schema_fields_matches_behavior() {
        // Every keyword listed in COMPILE_CONDITION_SCHEMA_FIELDS must produce a
        // non-default ConditionSchema when supplied.
        let cond = compile_condition_schema(
            &json!({
                "properties": { "A": { "enum": ["x"] } },
                "required": ["A"],
                "type": "object",
                "anyOf": [{ "properties": { "B": { "enum": ["y"] } } }]
            }),
            RefSiblings::Enforce,
        );
        assert!(cond.properties.contains_key("A"));
        assert_eq!(cond.required, vec!["A".to_string()]);
        assert_eq!(cond.any_of.len(), 1);
        assert!(cond.prop_type.is_some(), "the condition's type must be compiled");
        assert_eq!(
            keywords::COMPILE_CONDITION_SCHEMA_FIELDS,
            &[keywords::PROPERTIES, keywords::REQUIRED, keywords::TYPE, keywords::ANY_OF]
        );
    }

    #[test]
    fn numeric_constraints_compile_into_option_f64_fields() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "P": {
                        "type": "number",
                        "minimum": 1.5,
                        "maximum": 99.9,
                        "exclusiveMinimum": 0.1,
                        "exclusiveMaximum": 100.0
                    }
                }
            }),
        );
        let p = &compiled.properties["P"];
        assert_eq!(p.minimum, Some(1.5));
        assert_eq!(p.maximum, Some(99.9));
        assert_eq!(p.exclusive_minimum, Some(0.1));
        assert_eq!(p.exclusive_maximum, Some(100.0));
    }

    #[test]
    fn u64_constraints_compile_into_option_u64_fields() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "P": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 256
                    },
                    "A": {
                        "type": "array",
                        "minItems": 0,
                        "maxItems": 10
                    },
                    "O": {
                        "type": "object",
                        "minProperties": 1,
                        "maxProperties": 5
                    }
                }
            }),
        );
        assert_eq!(compiled.properties["P"].min_length, Some(1));
        assert_eq!(compiled.properties["P"].max_length, Some(256));
        assert_eq!(compiled.properties["A"].min_items, Some(0));
        assert_eq!(compiled.properties["A"].max_items, Some(10));
        assert_eq!(compiled.properties["O"].min_properties, Some(1));
        assert_eq!(compiled.properties["O"].max_properties, Some(5));
    }

    #[test]
    fn string_constraints_compile_into_option_string_fields() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "P": { "type": "string", "pattern": "^x$", "format": "uri", "description": "desc" }
                },
                "replacementStrategy": "delete_then_create",
                "documentationUrl": "https://docs",
                "sourceUrl": "https://src"
            }),
        );
        let p = &compiled.properties["P"];
        assert_eq!(p.pattern.as_deref(), Some("^x$"));
        assert_eq!(p.format.as_deref(), Some("uri"));
        assert_eq!(p.description.as_deref(), Some("desc"));
        assert_eq!(compiled.replacement_strategy.as_deref(), Some("delete_then_create"));
        assert_eq!(compiled.documentation_url.as_deref(), Some("https://docs"));
        assert_eq!(compiled.source_url.as_deref(), Some("https://src"));
    }

    #[test]
    fn metadata_pointer_arrays_all_strip_properties_prefix() {
        // Confirm every keyword in METADATA_POINTER_ARRAYS is handled by
        // compile_schema and produces stripped dot-notation paths.
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "readOnlyProperties": ["/properties/A"],
                "writeOnlyProperties": ["/properties/B"],
                "createOnlyProperties": ["/properties/C"],
                "deprecatedProperties": ["/properties/D"],
                "conditionalCreateOnlyProperties": ["/properties/E"],
                "primaryIdentifier": ["/properties/F"]
            }),
        );
        assert_eq!(compiled.read_only_properties, vec!["A"]);
        assert_eq!(compiled.write_only_properties, vec!["B"]);
        assert_eq!(compiled.create_only_properties, vec!["C"]);
        assert_eq!(compiled.deprecated_properties, vec!["D"]);
        assert_eq!(compiled.conditional_create_only_properties, vec!["E"]);
        assert_eq!(compiled.primary_identifier, vec!["F"]);
    }

    #[test]
    fn definitions_ref_prefix_is_used_in_compile_prop() {
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": { "P": { "$ref": "#/definitions/D" } },
                "definitions": { "D": { "type": "object" } }
            }),
        );
        assert_eq!(compiled.properties["P"].ref_name.as_deref(), Some("D"));
    }

    #[test]
    fn schema_maps_slice_matches_recursive_compilation() {
        // All three SCHEMA_MAPS keywords produce keyed maps when present.
        let compiled = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": { "P": { "type": "string" } },
                "definitions": { "D": { "type": "object" } }
            }),
        );
        assert!(compiled.properties.contains_key("P"));
        assert!(compiled.definitions.contains_key("D"));
        // patternProperties are compiled at the property level, not root.
        let compiled_prop = compile_schema(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "Map": { "type": "object", "patternProperties": { "^k$": { "type": "string" } } }
                }
            }),
        );
        assert!(compiled_prop.properties["Map"].pattern_properties.contains_key("^k$"));
    }

    #[test]
    fn ref_siblings_enforce_keeps_constraints_beside_a_ref() {
        let compiled = compile_schema_with(
            "AWS::Test::T",
            &json!({
                "properties": { "P": { "$ref": "#/definitions/D", "maxLength": 3, "pattern": "^a" } },
                "definitions": { "D": { "type": "string" } }
            }),
            RefSiblings::Enforce,
        );
        let prop = &compiled.properties["P"];
        assert_eq!(prop.ref_name.as_deref(), Some("D"));
        assert_eq!(prop.max_length, Some(3), "Enforce must keep constraint siblings");
        assert_eq!(prop.pattern.as_deref(), Some("^a"));
    }

    #[test]
    fn ref_siblings_ignore_drops_everything_beside_a_ref() {
        // Draft-07 — the dialect the CloudFormation registry validates with —
        // ignores keywords beside a `$ref`. The build pipeline compiles bundled
        // schemas this way so the engine never enforces more than
        // CloudFormation's own contract.
        let compiled = compile_schema_with(
            "AWS::Test::T",
            &json!({
                "properties": {
                    "P": { "$ref": "#/definitions/D", "maxLength": 3, "pattern": "^a" },
                    "Q": { "$ref": "not-a-definitions-ref", "maxLength": 3 }
                },
                "definitions": { "D": { "type": "string" } }
            }),
            RefSiblings::Ignore,
        );
        let prop = &compiled.properties["P"];
        assert_eq!(prop.ref_name.as_deref(), Some("D"));
        assert_eq!(prop.max_length, None, "Ignore must drop constraint siblings");
        assert_eq!(prop.pattern, None);
        let unresolvable = &compiled.properties["Q"];
        assert_eq!(unresolvable.ref_name, None);
        assert_eq!(
            unresolvable.max_length, None,
            "a $ref outside definitions compiles to an unconstrained property under Ignore, matching the \
             historical bundled artifact"
        );
    }

    #[test]
    fn condition_schema_type_is_compiled() {
        let cond = compile_condition_schema(&json!({ "type": "object", "required": ["A"] }), RefSiblings::Enforce);
        match cond.prop_type.as_ref().expect("the condition's type must be compiled") {
            PropType::Single(name) => assert_eq!(name, "object"),
            PropType::Multi(names) => panic!("expected a single type, got {names:?}"),
        }
    }
}
