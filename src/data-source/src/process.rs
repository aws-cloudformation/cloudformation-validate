use crate::SyncStats;
use crate::cfnlint_tables::GETATT_ADDITIONS_NAME;
use crate::types::PRIMARY_IDENTIFIER_OVERRIDES;
use log::info;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SchemaTop {
    pub type_name: Option<String>,
    pub properties: Option<HashMap<String, serde_json::Value>>,
    pub required: Option<Vec<String>>,
    pub read_only_properties: Option<Vec<String>>,
    pub definitions: Option<HashMap<String, serde_json::Value>>,
}

pub(crate) fn resolve_schema(
    schema: &serde_json::Value,
    defs: Option<&HashMap<String, serde_json::Value>>,
    visited: &mut HashSet<String>,
) -> serde_json::Value {
    if let Some(ref_str) = schema.get("$ref").and_then(|v| v.as_str()) {
        if let Some(def_name) = ref_str.strip_prefix("#/definitions/") {
            if visited.contains(def_name) {
                return schema.clone();
            }
            if let Some(defs_map) = defs {
                if let Some(def) = defs_map.get(def_name) {
                    visited.insert(def_name.to_string());
                    let resolved = resolve_schema(def, defs, visited);
                    visited.remove(def_name);
                    return resolved;
                }
            }
        }
        return schema.clone();
    }
    schema.clone()
}

/// Extracts the primary type name from a JSON Schema `type` value: the string
/// itself for `"type": "string"`, and the first non-null member for a list such
/// as `["integer", "null"]` or `["object", "string"]`. A union names every form
/// the property accepts, so the first declared member is reported - the same
/// choice the schema validator makes when it resolves a compiled type.
fn extract_primary_type(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).find(|s| *s != "null").map(String::from),
        _ => None,
    }
}

/// The primary type of the property at a dot-separated path such as
/// `Endpoint.Address`, following `$ref` chains at every hop. `None` when a hop
/// does not exist, is not an object with properties, or the leaf declares no type.
fn resolve_attribute_path_type(
    properties: Option<&HashMap<String, serde_json::Value>>,
    defs: Option<&HashMap<String, serde_json::Value>>,
    path: &str,
) -> Option<String> {
    let mut parts = path.split('.');
    let mut node = resolve_schema(properties?.get(parts.next()?)?, defs, &mut HashSet::new());
    for part in parts {
        let child = node.get("properties")?.get(part)?;
        node = resolve_schema(child, defs, &mut HashSet::new());
    }
    node.get("type").and_then(extract_primary_type)
}

/// The allowed values for a property: its `enum`, or - when the provider marks
/// the values as matched case-insensitively - its `enumCaseInsensitive`. The two
/// keywords describe one value set in two comparison modes, so a property never
/// carries both.
fn extract_property_enum(resolved: &serde_json::Value) -> Option<Vec<serde_json::Value>> {
    for keyword in ["enum", "enumCaseInsensitive"] {
        if let Some(values) = resolved.get(keyword).and_then(|v| v.as_array())
            && !values.is_empty()
        {
            return Some(values.clone());
        }
    }
    None
}

/// A numeric bound in canonical JSON form: a whole number written as a float
/// (`1.0`) becomes the integer `1`, so a bound reads the same regardless of how
/// the provider schema spelled it and matches the form the runtime derivation
/// produces from its floating-point bounds.
fn canonical_number(value: &serde_json::Value) -> serde_json::Value {
    let Some(number) = value.as_number() else {
        return value.clone();
    };
    if !number.is_f64() {
        return value.clone();
    }
    match number.as_f64() {
        Some(f) if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 => {
            serde_json::Value::from(f as i64)
        }
        _ => value.clone(),
    }
}

/// Process schemas: load the (already-patched) raw schemas, apply extension
/// fragments, then generate shared metadata files consumed by all engine crates.
pub fn process_schemas(upstream_dir: &Path, generated_dir: &Path, handwritten_dir: &Path) -> anyhow::Result<SyncStats> {
    let mut stats = SyncStats::default();
    let schema_source = crate::schema::schema_dir(upstream_dir);
    if !schema_source.exists() {
        anyhow::bail!("Schema directory not found: {}\nRun sync first.", schema_source.display());
    }
    let data_dir = generated_dir.join("data");
    fs::create_dir_all(&data_dir)?;

    let mut raw_schemas: HashMap<String, serde_json::Value> = HashMap::new();
    for entry in fs::read_dir(&schema_source)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let content = fs::read_to_string(&path)?;
        // These are our own downloaded schema files - a parse failure means a
        // corrupt download, not an optional file, so surface it rather than
        // silently dropping a resource type.
        let json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("failed to parse schema {}: {}", path.display(), e))?;
        let Some(type_name) = json.get("typeName").and_then(|v| v.as_str()) else {
            anyhow::bail!("schema {} has no 'typeName'", path.display());
        };
        raw_schemas.insert(type_name.to_string(), json);
    }
    anyhow::ensure!(!raw_schemas.is_empty(), "no schemas loaded from {}", schema_source.display());
    info!("Loaded {} raw schemas", raw_schemas.len());

    // The downloaded schemas are already fully patched (provider + extension
    // patches are baked into the enhanced archive), so no patch pass runs here.
    // The extension fragments below are the separately-synced enum/constraint
    // documents the engines query at runtime, not schema patches.
    let extensions_dir = upstream_dir.join("extensions");
    anyhow::ensure!(extensions_dir.is_dir(), "Required extensions directory not found: {}", extensions_dir.display());
    let mut ext_count = 0;
    for (type_name, schema_json) in &mut raw_schemas {
        let ext_name = type_name.replace("::", "-").to_lowercase();
        let ext_file = extensions_dir.join(format!("{}.ext.json", ext_name));
        if !ext_file.exists() {
            continue;
        }
        let fragments: Vec<serde_json::Value> = serde_json::from_str(&fs::read_to_string(&ext_file)?)?;
        anyhow::ensure!(!fragments.is_empty(), "Required extension file is empty: {}", ext_file.display());
        if schema_json.get("allOf").is_none() {
            schema_json["allOf"] = serde_json::Value::Array(Vec::new());
        }
        if let Some(all_of) = schema_json["allOf"].as_array_mut() {
            for fragment in fragments {
                all_of.push(fragment);
            }
        }
        ext_count += 1;
    }
    info!("Applied extensions to {} schemas", ext_count);

    // Run after the extension merge: some dependentExcluded constraints arrive as
    // extension fragments (the same fragments that back a dedicated engine rule),
    // so stripping them earlier would miss them and leave a duplicate finding.
    let stripped = strip_superseded_dependent_excluded(&mut raw_schemas, handwritten_dir)?;
    if stripped > 0 {
        info!("Stripped {} dependentExcluded entries superseded by dedicated engine rules", stripped);
    }

    let mut schemas: HashMap<String, (String, SchemaTop)> = HashMap::new();
    for (type_name, json) in &raw_schemas {
        let content = serde_json::to_string(json)?;
        let schema: SchemaTop = serde_json::from_value(json.clone())
            .map_err(|e| anyhow::anyhow!("failed to deserialize schema for {}: {}", type_name, e))?;
        schemas.insert(type_name.clone(), (content, schema));
    }
    info!("Parsed {} schemas for metadata generation", schemas.len());

    let patched_dir = generated_dir.join("patched_schemas");
    fs::create_dir_all(&patched_dir)?;
    for (type_name, json) in &raw_schemas {
        let filename = type_name.replace("::", "-").to_lowercase();
        fs::write(patched_dir.join(format!("{}.json", filename)), serde_json::to_string_pretty(json)?)?;
        stats.files_written += 1;
    }
    info!("Wrote {} patched schemas to patched_schemas/", raw_schemas.len());

    fs::write(data_dir.join("schema_metadata.json"), generate_schema_metadata(&schemas, &raw_schemas))?;
    // getatt_additions is a raw intermediate extracted from cfn-lint during sync
    // (into upstream_dir) and folded into getatt_attributes here; getatt_return_type_overrides
    // is a hand-maintained correction (CloudFormation stringifies some GetAtt
    // values) that has no cfn-lint equivalent.
    let getatt_additions = read_getatt_additions(upstream_dir)?;
    let getatt_return_overrides = read_getatt_return_type_overrides(handwritten_dir)?;
    fs::write(
        data_dir.join("getatt_attributes.json"),
        generate_getatt_data(&schemas, &getatt_additions, &getatt_return_overrides),
    )?;
    // Union the schema-derived types with the per-region known types. Some types
    // CloudFormation accepts (e.g. AWS::CDK::Metadata) have no provider schema but
    // appear only in the per-region type maps. The single `known_resource_types`
    // set is the source of truth
    let mut known_types: BTreeSet<String> = schemas.keys().cloned().collect();
    let region_types = read_region_resource_types_union(&data_dir)?;
    known_types.extend(region_types);
    let known_types_sorted: Vec<String> = known_types.into_iter().collect();
    fs::write(
        data_dir.join("known_resource_types.json"),
        serde_json::to_string_pretty(&serde_json::json!({"known_resource_types": known_types_sorted}))?,
    )?;
    fs::write(data_dir.join("primary_identifiers.json"), generate_primary_identifiers(&raw_schemas))?;
    fs::write(data_dir.join("resource_lifecycle.json"), generate_resource_lifecycle(&raw_schemas))?;
    stats.files_written += 5;
    info!(
        "Wrote schema_metadata, getatt_attributes, known_resource_types, primary_identifiers, resource_lifecycle -> data/"
    );

    info!("Schema processing complete: {} files written", stats.files_written);
    Ok(stats)
}

/// Reads `data_dir/region_resource_types.json` (produced by the sync phase from
/// the upstream per-region provider files) and returns the union of every
/// resource-type key across all regions.
///
/// The returned set is intentionally region-agnostic: callers (the
/// `known_resource_types` writer in this module, and downstream the engine
/// resource-type rule) only need to know whether a type is valid in *any*
/// region.
fn read_region_resource_types_union(data_dir: &Path) -> anyhow::Result<BTreeSet<String>> {
    let region_file = data_dir.join("region_resource_types.json");
    let content = fs::read_to_string(&region_file)
        .map_err(|source| anyhow::anyhow!("failed to read required {}: {}", region_file.display(), source))?;
    let parsed: serde_json::Value = serde_json::from_str(&content)?;
    let regions = parsed
        .get("region_resource_types")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow::anyhow!("{}: missing 'region_resource_types' object", region_file.display()))?;
    let mut union: BTreeSet<String> = BTreeSet::new();
    anyhow::ensure!(!regions.is_empty(), "{}: region_resource_types must not be empty", region_file.display());
    for (region, type_map) in regions {
        let type_obj = type_map.as_object().ok_or_else(|| {
            anyhow::anyhow!("{}: region '{}' resource types must be an object", region_file.display(), region)
        })?;
        anyhow::ensure!(
            !type_obj.is_empty(),
            "{}: region '{}' resource types must not be empty",
            region_file.display(),
            region
        );
        for type_name in type_obj.keys() {
            union.insert(type_name.clone());
        }
    }
    anyhow::ensure!(!union.is_empty(), "{} contains no resource types", region_file.display());
    info!("Collected {} unique resource types across regions for known_resource_types union", union.len());
    Ok(union)
}

/// Generates per-resource-type metadata: property names, types, required fields,
/// enums, scalar constraints, and inter-property dependencies (dependentRequired, etc.).
fn generate_schema_metadata(
    schemas: &HashMap<String, (String, SchemaTop)>,
    raw_schemas: &HashMap<String, serde_json::Value>,
) -> String {
    let mut meta: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (tn, (_, s)) in schemas {
        let raw = raw_schemas.get(tn);
        let obj = build_property_schema_obj(s.properties.as_ref(), s.required.as_ref(), s.definitions.as_ref(), raw);
        meta.insert(tn.clone(), obj);
    }
    serde_json::to_string_pretty(&serde_json::json!({"schema_metadata": meta})).unwrap()
}

/// Builds the metadata object for a resource type's top-level properties: the
/// sorted property names, the required list, each property's primary type and
/// allowed values, each property's own scalar constraints, and the schema-level
/// dependency groups.
///
/// Only the resource's top-level properties are described. The nested shape
/// (object sub-properties, array items) is enforced by the schema validator from
/// the compiled schemas, which keep shared definitions by reference; repeating it
/// here would inline every definition at every use site for no runtime reader.
fn build_property_schema_obj(
    properties: Option<&HashMap<String, serde_json::Value>>,
    required: Option<&Vec<String>>,
    defs: Option<&HashMap<String, serde_json::Value>>,
    raw: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut props: Vec<String> = properties.map(|p| p.keys().cloned().collect()).unwrap_or_default();
    props.sort();
    let req: Vec<String> = required.cloned().unwrap_or_default();
    let mut pt: BTreeMap<String, String> = BTreeMap::new();
    let mut pe: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    let mut pc: BTreeMap<String, serde_json::Value> = BTreeMap::new();

    if let Some(p) = properties {
        for (pn, ps) in p {
            let r = resolve_schema(ps, defs, &mut HashSet::new());
            if let Some(t) = r.get("type").and_then(extract_primary_type) {
                pt.insert(pn.clone(), t);
            }
            if let Some(e) = extract_property_enum(&r) {
                pe.insert(pn.clone(), e);
            }
            let constraints = extract_property_constraints(&r);
            if !constraints.is_null() {
                pc.insert(pn.clone(), constraints);
            }
        }
    }

    let mut obj = serde_json::json!({"properties": props, "required": req, "property_types": pt, "property_enums": pe});
    if !pc.is_empty() {
        obj["property_constraints"] = serde_json::json!(pc);
    }
    if let Some(r) = raw {
        if let Some(de) = r.get("dependentExcluded") {
            obj["dependent_excluded"] = de.clone();
        }
        if let Some(dr) = r.get("dependentRequired") {
            obj["dependent_required"] = dr.clone();
        }
        if let Some(ro) = r.get("requiredOr") {
            obj["required_or"] = ro.clone();
        }
        if let Some(rx) = r.get("requiredXor") {
            obj["required_xor"] = rx.clone();
        }
    }
    obj
}

/// The scalar constraints a resolved property definition states about its own
/// value: pattern, numeric bounds, length and item-count bounds, format, and
/// `uniqueItems` when set. Returns `Null` when the property states none.
fn extract_property_constraints(resolved: &serde_json::Value) -> serde_json::Value {
    let obj = match resolved.as_object() {
        Some(o) => o,
        None => return serde_json::Value::Null,
    };
    let mut c = serde_json::Map::new();

    for &key in &["pattern", "minLength", "maxLength", "minItems", "maxItems", "format"] {
        if let Some(v) = obj.get(key) {
            c.insert(key.to_string(), v.clone());
        }
    }
    for &key in &["minimum", "maximum"] {
        if let Some(v) = obj.get(key) {
            c.insert(key.to_string(), canonical_number(v));
        }
    }
    if obj.get("uniqueItems").and_then(|v| v.as_bool()) == Some(true) {
        c.insert("uniqueItems".to_string(), serde_json::Value::Bool(true));
    }

    if c.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(c) }
}

/// Generates GetAtt attribute names and types per resource type from readOnlyProperties.
fn generate_getatt_data(
    schemas: &HashMap<String, (String, SchemaTop)>,
    additions: &BTreeMap<String, Vec<String>>,
    return_type_overrides: &BTreeMap<String, BTreeMap<String, String>>,
) -> String {
    let mut attrs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut attr_types: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (tn, (_, s)) in schemas {
        let mut ta = Vec::new();
        if let Some(ref ro) = s.read_only_properties {
            for p in ro {
                if let Some(a) = p.strip_prefix("/properties/") {
                    ta.push(a.replace('/', "."));
                }
            }
        }
        // Return types for every top-level property, plus every nested readOnly
        // attribute path - both drive output string-type and property type-mismatch
        // checks. Attribute validity uses getatt_attributes (readOnly only), not
        // this map. Types are resolved the way the schema validator resolves
        // them: through `$ref` chains, and to the first declared member of a
        // union, so an attribute whose type lives in a shared definition is typed
        // exactly like one declared inline.
        let mut tt = BTreeMap::new();
        let defs = s.definitions.as_ref();
        if let Some(ps) = &s.properties {
            for (pn, pd) in ps {
                let resolved = resolve_schema(pd, defs, &mut HashSet::new());
                if let Some(t) = resolved.get("type").and_then(extract_primary_type) {
                    tt.insert(pn.clone(), t);
                }
            }
        }
        for attr in ta.iter().filter(|attr| attr.contains('.')) {
            if let Some(t) = resolve_attribute_path_type(s.properties.as_ref(), defs, attr) {
                tt.insert(attr.clone(), t);
            }
        }
        if !ta.is_empty() {
            ta.sort();
            attrs.insert(tn.clone(), ta);
        }
        if !tt.is_empty() {
            attr_types.insert(tn.clone(), tt);
        }
    }
    // Extend the schema-derived readOnly attributes with the broader set of
    // attributes CloudFormation actually exposes for Fn::GetAtt (writable
    // properties surfaced as attributes on older resource types), so attribute
    // validity matches what CloudFormation accepts.
    for (type_name, extra_attrs) in additions {
        let valid_attrs = attrs.entry(type_name.clone()).or_default();
        valid_attrs.extend(extra_attrs.iter().cloned());
        valid_attrs.sort();
        valid_attrs.dedup();
    }
    // Apply explicit GetAtt-return-type overrides for attributes whose GetAtt
    // value type differs from the declared property type.
    for (type_name, attr_overrides) in return_type_overrides {
        let type_map = attr_types.entry(type_name.clone()).or_default();
        for (attr, ret_type) in attr_overrides {
            type_map.insert(attr.clone(), ret_type.clone());
        }
    }
    serde_json::to_string_pretty(&serde_json::json!({"getatt_attributes": attrs, "getatt_attribute_types": attr_types}))
        .unwrap()
}

/// Reads the GetAtt attribute additions (extracted from cfn-lint during sync)
/// Removes `dependentExcluded` trigger properties that a dedicated engine rule
/// already enforces, so the schema validator's generic mutually-exclusive check
/// does not duplicate the rule's finding. Returns the number of trigger entries
/// removed. The reference tool strips the same entries from its loaded schema.
fn strip_superseded_dependent_excluded(
    raw_schemas: &mut HashMap<String, serde_json::Value>,
    handwritten_dir: &Path,
) -> anyhow::Result<usize> {
    #[derive(Deserialize)]
    struct Overrides {
        remove_dependent_excluded: BTreeMap<String, Vec<String>>,
    }
    let path = handwritten_dir.join("schema_dependent_excluded_overrides.json");
    let contents =
        fs::read_to_string(&path).map_err(|source| anyhow::anyhow!("failed to read {}: {}", path.display(), source))?;
    let parsed: Overrides = serde_json::from_str(&contents)
        .map_err(|source| anyhow::anyhow!("failed to parse {}: {}", path.display(), source))?;
    anyhow::ensure!(
        !parsed.remove_dependent_excluded.is_empty(),
        "{}: remove_dependent_excluded must not be empty",
        path.display()
    );

    let mut removed = 0;
    for (type_name, triggers) in &parsed.remove_dependent_excluded {
        let Some(schema) = raw_schemas.get_mut(type_name) else {
            continue;
        };
        for trigger in triggers {
            removed += remove_dependent_excluded_trigger(schema, trigger);
        }
    }
    Ok(removed)
}

/// Recursively removes `dependentExcluded.<trigger>` wherever it appears in a
/// schema value, returning the count removed.
fn remove_dependent_excluded_trigger(value: &mut serde_json::Value, trigger: &str) -> usize {
    let mut removed = 0;
    match value {
        serde_json::Value::Object(map) => {
            if let Some(de) = map.get_mut("dependentExcluded").and_then(|v| v.as_object_mut()) {
                if de.remove(trigger).is_some() {
                    removed += 1;
                }
            }
            for v in map.values_mut() {
                removed += remove_dependent_excluded_trigger(v, trigger);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                removed += remove_dependent_excluded_trigger(v, trigger);
            }
        }
        _ => {}
    }
    removed
}

/// Reads the raw GetAtt additions synced into `upstream_dir`. These extend the
/// schema-derived readOnly attributes with the full set CloudFormation exposes
/// for Fn::GetAtt on each resource type.
fn read_getatt_additions(upstream_dir: &Path) -> anyhow::Result<BTreeMap<String, Vec<String>>> {
    #[derive(Deserialize)]
    struct GetAttAdditions {
        getatt_additions: BTreeMap<String, Vec<String>>,
    }
    let path = upstream_dir.join(format!("{GETATT_ADDITIONS_NAME}.json"));
    let contents =
        fs::read_to_string(&path).map_err(|source| anyhow::anyhow!("failed to read {}: {}", path.display(), source))?;
    let parsed: GetAttAdditions = serde_json::from_str(&contents)
        .map_err(|source| anyhow::anyhow!("failed to parse {}: {}", path.display(), source))?;
    anyhow::ensure!(!parsed.getatt_additions.is_empty(), "{}: getatt_additions must not be empty", path.display());
    Ok(parsed.getatt_additions)
}

/// Reads overrides for the type CloudFormation returns from `Fn::GetAtt` on
/// specific attributes, where it differs from the raw schema property type
/// (CloudFormation stringifies many GetAtt return values).
fn read_getatt_return_type_overrides(
    handwritten_dir: &Path,
) -> anyhow::Result<BTreeMap<String, BTreeMap<String, String>>> {
    #[derive(Deserialize)]
    struct Overrides {
        getatt_return_type_overrides: BTreeMap<String, BTreeMap<String, String>>,
    }
    let path = handwritten_dir.join("getatt_return_type_overrides.json");
    let contents =
        fs::read_to_string(&path).map_err(|source| anyhow::anyhow!("failed to read {}: {}", path.display(), source))?;
    let parsed: Overrides = serde_json::from_str(&contents)
        .map_err(|source| anyhow::anyhow!("failed to parse {}: {}", path.display(), source))?;
    anyhow::ensure!(
        !parsed.getatt_return_type_overrides.is_empty(),
        "{}: getatt_return_type_overrides must not be empty",
        path.display()
    );
    Ok(parsed.getatt_return_type_overrides)
}

/// Generates user-settable primary identifier properties per resource type,
/// excluding service-generated (readOnly) identifiers.
fn generate_primary_identifiers(raw: &HashMap<String, serde_json::Value>) -> String {
    let mut ids: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (tn, schema) in raw {
        let primary = match schema.get("primaryIdentifier").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => continue,
        };
        let read_only: HashSet<&str> = schema
            .get("readOnlyProperties")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        // Skip if any primary ID is read-only (service-generated)
        if primary.iter().any(|p| p.as_str().map(|s| read_only.contains(s)).unwrap_or(false)) {
            continue;
        }
        let props: Vec<String> = primary
            .iter()
            .filter_map(|p| {
                let s = p.as_str()?;
                let name = s.strip_prefix("/properties/")?;
                // Skip nested paths - only root-level properties
                if name.contains('/') {
                    return None;
                }
                Some(name.to_string())
            })
            .collect();
        if props.is_empty() || props.len() != primary.len() {
            continue;
        }
        ids.insert(tn.clone(), props);
    }
    // Types whose schema identifier is service-generated but whose customer-set
    // name must still be unique; the runtime derivation applies the same table.
    for (type_name, id_props) in PRIMARY_IDENTIFIER_OVERRIDES {
        ids.insert((*type_name).to_string(), id_props.iter().map(|s| s.to_string()).collect());
    }
    serde_json::to_string_pretty(&serde_json::json!({"primary_identifiers": ids})).unwrap()
}

/// Extracts lifecycle metadata (shutdown/sunset/maintenance) from patched schemas.
fn generate_resource_lifecycle(raw_schemas: &HashMap<String, serde_json::Value>) -> String {
    let mut lifecycle_map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (type_name, schema) in raw_schemas {
        if let Some(lc) = schema.get("lifecycle").and_then(|v| v.as_object()) {
            if let Some(status) = lc.get("status").and_then(|s| s.as_str()) {
                let mut entry = serde_json::json!({"status": status});
                if let Some(date) = lc.get("date").and_then(|d| d.as_str()) {
                    entry["date"] = serde_json::Value::String(date.to_string());
                }
                lifecycle_map.insert(type_name.clone(), entry);
            }
        }
    }
    serde_json::to_string_pretty(&serde_json::json!({"resource_lifecycle": lifecycle_map})).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_schema_follows_ref() {
        let mut defs = HashMap::new();
        defs.insert("MyType".to_string(), json!({"type": "string", "maxLength": 128}));
        let schema = json!({"$ref": "#/definitions/MyType"});
        let resolved = resolve_schema(&schema, Some(&defs), &mut HashSet::new());
        assert_eq!(resolved["type"], "string");
        assert_eq!(resolved["maxLength"], 128);
    }

    #[test]
    fn resolve_schema_circular_ref_terminates() {
        // A references B, B references A - must not infinite-loop
        let mut defs = HashMap::new();
        defs.insert("A".to_string(), json!({"$ref": "#/definitions/B"}));
        defs.insert("B".to_string(), json!({"$ref": "#/definitions/A"}));
        let schema = json!({"$ref": "#/definitions/A"});
        let resolved = resolve_schema(&schema, Some(&defs), &mut HashSet::new());
        // Should return the unresolved $ref for the cycle-breaking point
        assert_ne!(resolved.get("$ref"), None, "resolved schema should contain $ref");
    }

    #[test]
    fn resolve_schema_self_referencing_terminates() {
        let mut defs = HashMap::new();
        defs.insert("Self".to_string(), json!({"$ref": "#/definitions/Self"}));
        let schema = json!({"$ref": "#/definitions/Self"});
        let resolved = resolve_schema(&schema, Some(&defs), &mut HashSet::new());
        assert_ne!(resolved.get("$ref"), None, "resolved schema should contain $ref");
    }

    #[test]
    fn resolve_schema_missing_def_returns_original() {
        let schema = json!({"$ref": "#/definitions/DoesNotExist"});
        let resolved = resolve_schema(&schema, None, &mut HashSet::new());
        assert_eq!(resolved, schema);
    }

    #[test]
    fn resolve_schema_no_ref_returns_original() {
        let schema = json!({"type": "integer", "minimum": 0});
        let resolved = resolve_schema(&schema, None, &mut HashSet::new());
        assert_eq!(resolved, schema);
    }

    #[test]
    fn extract_primary_type_simple_string() {
        assert_eq!(extract_primary_type(&json!("string")), Some("string".to_string()));
    }

    #[test]
    fn extract_primary_type_array_with_null() {
        assert_eq!(extract_primary_type(&json!(["integer", "null"])), Some("integer".to_string()));
    }

    #[test]
    fn extract_primary_type_array_multiple_non_null() {
        // A union names every accepted form; the first declared member is the
        // primary type, matching the runtime `PropType::primary` resolution.
        assert_eq!(extract_primary_type(&json!(["string", "integer"])), Some("string".to_string()));
        assert_eq!(extract_primary_type(&json!(["object", "string"])), Some("object".to_string()));
        assert_eq!(extract_primary_type(&json!(["null", "object", "string"])), Some("object".to_string()));
    }

    #[test]
    fn extract_primary_type_ignores_non_string_and_null_only_members() {
        assert_eq!(extract_primary_type(&json!(["null"])), None);
        assert_eq!(extract_primary_type(&json!([1, true])), None);
        assert_eq!(extract_primary_type(&json!({"not": "a type"})), None);
    }

    #[test]
    fn extract_property_enum_prefers_enum_then_case_insensitive() {
        assert_eq!(extract_property_enum(&json!({"enum": ["a", "b"]})), Some(vec![json!("a"), json!("b")]));
        assert_eq!(
            extract_property_enum(&json!({"enumCaseInsensitive": ["container", "multinode"]})),
            Some(vec![json!("container"), json!("multinode")])
        );
        assert_eq!(
            extract_property_enum(&json!({"enum": [], "enumCaseInsensitive": ["x"]})),
            Some(vec![json!("x")]),
            "an empty enum list defers to the case-insensitive values"
        );
        assert_eq!(extract_property_enum(&json!({"type": "string"})), None);
    }

    #[test]
    fn canonical_number_turns_whole_floats_into_integers_only() {
        assert_eq!(canonical_number(&json!(1.0)), json!(1));
        assert_eq!(canonical_number(&json!(-100.0)), json!(-100));
        assert_eq!(canonical_number(&json!(0.001)), json!(0.001));
        assert_eq!(canonical_number(&json!(99.999)), json!(99.999));
        assert_eq!(canonical_number(&json!(7)), json!(7));
        assert_eq!(canonical_number(&json!(9223372036854775807i64)), json!(9223372036854775807i64));
        assert_eq!(canonical_number(&json!("1.0")), json!("1.0"), "a non-number is left untouched");
    }

    #[test]
    fn build_property_schema_obj_describes_top_level_properties_only() {
        // A nested object property records its own type and constraints; the
        // shape of its sub-properties is the schema validator's concern and is
        // not repeated in the metadata.
        let mut properties = HashMap::new();
        properties.insert(
            "Config".to_string(),
            json!({
                "type": "object",
                "properties": {
                    "Name": {"type": "string", "maxLength": 64},
                    "Inner": {
                        "type": "object",
                        "properties": {
                            "Deep": {"type": "integer", "minimum": 0}
                        },
                        "required": ["Deep"]
                    }
                },
                "required": ["Name"],
                "dependentRequired": {"Name": ["Inner"]}
            }),
        );
        properties.insert(
            "Items".to_string(),
            json!({
                "type": "array",
                "minItems": 1,
                "uniqueItems": true,
                "items": {"type": "object", "properties": {"Key": {"type": "string"}}, "required": ["Key"]}
            }),
        );
        let required = vec!["Config".to_string()];
        let result = build_property_schema_obj(Some(&properties), Some(&required), None, None);

        assert_eq!(result["properties"], json!(["Config", "Items"]));
        assert_eq!(result["required"], json!(["Config"]));
        assert_eq!(result["property_types"], json!({"Config": "object", "Items": "array"}));
        assert_eq!(result["property_enums"], json!({}));
        assert_eq!(
            result["property_constraints"],
            json!({"Items": {"minItems": 1, "uniqueItems": true}}),
            "only the properties' own scalar constraints are recorded"
        );
        assert_eq!(result.get("dependent_required"), None, "a nested dependency group is not lifted to the resource");
    }

    #[test]
    fn build_property_schema_obj_records_union_types_case_insensitive_enums_and_canonical_bounds() {
        let mut properties = HashMap::new();
        properties.insert("PolicyDocument".to_string(), json!({"type": ["object", "string"]}));
        properties
            .insert("Kind".to_string(), json!({"type": "string", "enumCaseInsensitive": ["container", "multinode"]}));
        properties.insert("Order".to_string(), json!({"type": "number", "minimum": 1.0, "maximum": 1000.0}));
        properties.insert("Ratio".to_string(), json!({"type": "number", "minimum": 0.001}));
        let result = build_property_schema_obj(Some(&properties), None, None, None);

        assert_eq!(result["property_types"]["PolicyDocument"], json!("object"));
        assert_eq!(result["property_enums"]["Kind"], json!(["container", "multinode"]));
        assert_eq!(result["property_constraints"]["Order"], json!({"minimum": 1, "maximum": 1000}));
        assert_eq!(result["property_constraints"]["Ratio"], json!({"minimum": 0.001}));
    }

    #[test]
    fn build_property_schema_obj_resolves_refs_for_type_enum_and_constraints() {
        let mut defs = HashMap::new();
        defs.insert("Name".to_string(), json!({"type": "string", "pattern": "^[a-z]+$", "enum": ["alpha", "beta"]}));
        let mut properties = HashMap::new();
        properties.insert("Root".to_string(), json!({"$ref": "#/definitions/Name"}));
        let result = build_property_schema_obj(Some(&properties), None, Some(&defs), None);

        assert_eq!(result["property_types"]["Root"], json!("string"));
        assert_eq!(result["property_enums"]["Root"], json!(["alpha", "beta"]));
        assert_eq!(result["property_constraints"]["Root"], json!({"pattern": "^[a-z]+$"}));
    }

    #[test]
    fn build_property_schema_obj_circular_ref_terminates() {
        // Simulate a self-referencing definition (like AWS::Lex::Bot's recursive types)
        let mut defs = HashMap::new();
        defs.insert(
            "TreeNode".to_string(),
            json!({
                "type": "object",
                "properties": {
                    "Value": {"type": "string"},
                    "Children": {
                        "type": "array",
                        "items": {"$ref": "#/definitions/TreeNode"}
                    }
                }
            }),
        );
        let mut properties = HashMap::new();
        properties.insert("Root".to_string(), json!({"$ref": "#/definitions/TreeNode"}));
        // Must terminate without stack overflow
        let result = build_property_schema_obj(Some(&properties), None, Some(&defs), None);
        assert!(result["properties"].as_array().unwrap().contains(&json!("Root")));
        assert_eq!(result["property_types"]["Root"], json!("object"));
    }

    fn schema_top(raw: &serde_json::Value) -> SchemaTop {
        serde_json::from_value(raw.clone()).expect("schema parses")
    }

    #[test]
    fn resolve_attribute_path_type_follows_refs_at_every_hop() {
        let raw = json!({
            "typeName": "AWS::Test::Paths",
            "properties": {
                "Endpoint": {"$ref": "#/definitions/Endpoint"},
                "Inline": {"type": "object", "properties": {"Port": {"type": "integer"}}}
            },
            "definitions": {
                "Endpoint": {
                    "type": "object",
                    "properties": {"Address": {"$ref": "#/definitions/Address"}, "Zone": {"type": ["string", "null"]}}
                },
                "Address": {"type": "string"}
            }
        });
        let s = schema_top(&raw);
        let (props, defs) = (s.properties.as_ref(), s.definitions.as_ref());
        assert_eq!(resolve_attribute_path_type(props, defs, "Endpoint.Address"), Some("string".to_string()));
        assert_eq!(resolve_attribute_path_type(props, defs, "Endpoint.Zone"), Some("string".to_string()));
        assert_eq!(resolve_attribute_path_type(props, defs, "Inline.Port"), Some("integer".to_string()));
        assert_eq!(resolve_attribute_path_type(props, defs, "Endpoint"), Some("object".to_string()));
        assert_eq!(resolve_attribute_path_type(props, defs, "Endpoint.Missing"), None);
        assert_eq!(resolve_attribute_path_type(props, defs, "Inline.Port.Deeper"), None);
        assert_eq!(resolve_attribute_path_type(None, defs, "Endpoint"), None);
    }

    #[test]
    fn getatt_types_resolve_refs_unions_nested_paths_and_apply_overrides() {
        let raw = json!({
            "typeName": "AWS::Test::GetAtt",
            "properties": {
                // The definition is authoritative; the sibling `type` beside the
                // `$ref` is ignored, as the compiled schemas ignore it.
                "Mode": {"$ref": "#/definitions/Mode", "type": "object"},
                "Endpoint": {"$ref": "#/definitions/Endpoint"},
                "Document": {"type": ["object", "string"]},
                "Port": {"type": "integer"},
                "Untyped": {"$ref": "#/definitions/Missing"}
            },
            "definitions": {
                "Mode": {"type": "string", "enum": ["a", "b"]},
                "Endpoint": {"type": "object", "properties": {"Address": {"type": "string"}, "Port": {"type": "integer"}}}
            },
            "readOnlyProperties": ["/properties/Endpoint", "/properties/Endpoint/Address", "/properties/Endpoint/Port"]
        });
        let mut schemas = HashMap::new();
        schemas.insert("AWS::Test::GetAtt".to_string(), (String::new(), schema_top(&raw)));
        let additions = BTreeMap::from([("AWS::Test::GetAtt".to_string(), vec!["Mode".to_string()])]);
        let overrides = BTreeMap::from([(
            "AWS::Test::GetAtt".to_string(),
            BTreeMap::from([("Endpoint.Port".to_string(), "string".to_string())]),
        )]);

        let out: serde_json::Value =
            serde_json::from_str(&generate_getatt_data(&schemas, &additions, &overrides)).expect("valid JSON");

        assert_eq!(
            out["getatt_attributes"]["AWS::Test::GetAtt"],
            json!(["Endpoint", "Endpoint.Address", "Endpoint.Port", "Mode"]),
            "readOnly paths plus the additions, sorted"
        );
        assert_eq!(
            out["getatt_attribute_types"]["AWS::Test::GetAtt"],
            json!({
                "Mode": "string",
                "Endpoint": "object",
                "Endpoint.Address": "string",
                "Endpoint.Port": "string",
                "Document": "object",
                "Port": "integer"
            }),
            "every typed top-level property and nested readOnly path, with the override applied"
        );
    }

    /// End-to-end: process_schemas on the real generated data.
    /// Verifies the full pipeline doesn't panic and produces expected output files.
    #[test]
    fn process_schemas_on_real_data() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let upstream_dir = manifest.join("upstream");
        if !upstream_dir.join("schemas").exists() {
            // Skip if schemas haven't been downloaded
            eprintln!("Skipping process_schemas_on_real_data: no downloaded schemas");
            return;
        }
        let tmp = tempdir();
        let tmp_upstream = tempdir();
        // Copy schemas into temp upstream dir
        let tmp_schemas = tmp_upstream.join("schemas");
        copy_dir(&upstream_dir.join("schemas"), &tmp_schemas);
        copy_dir(&upstream_dir.join("extensions"), &tmp_upstream.join("extensions"));
        let getatt_additions = format!("{GETATT_ADDITIONS_NAME}.json");
        fs::copy(upstream_dir.join(&getatt_additions), tmp_upstream.join(&getatt_additions))
            .expect("required GetAtt additions fixture");
        let tmp_data = tmp.join("data");
        fs::create_dir_all(&tmp_data).unwrap();
        let generated_data = manifest.join("generated").join("data");
        fs::copy(generated_data.join("region_resource_types.json"), tmp_data.join("region_resource_types.json"))
            .expect("required region resource types fixture");

        let result = process_schemas(&tmp_upstream, &tmp, &manifest.join("handwritten"));
        let stats = result.expect("process_schemas should succeed");
        assert!(stats.files_written > 0, "expected files_written > 0, got {}", stats.files_written);

        // Verify output files exist
        let data_dir = tmp.join("data");
        assert!(data_dir.join("schema_metadata.json").exists());
        assert!(data_dir.join("getatt_attributes.json").exists());
        assert!(data_dir.join("known_resource_types.json").exists());
        assert!(data_dir.join("primary_identifiers.json").exists());
        assert!(tmp.join("patched_schemas").exists());

        // Verify schema_metadata is valid JSON with expected structure
        let meta_content = fs::read_to_string(data_dir.join("schema_metadata.json")).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&meta_content).unwrap();
        let meta_obj = meta["schema_metadata"].as_object().unwrap();
        assert!(meta_obj.len() > 100, "Expected 100+ resource types, got {}", meta_obj.len());

        // Spot-check a well-known resource type
        let s3 = &meta_obj["AWS::S3::Bucket"];
        assert!(
            s3["properties"].as_array().unwrap().len() > 5,
            "expected > 5 S3 properties, got {}",
            s3["properties"].as_array().unwrap().len()
        );

        // Every constraint object describes one top-level property's own value:
        // no nested sub-property or item trees are emitted anywhere.
        for (type_name, entry) in meta_obj {
            let Some(constraints) = entry.get("property_constraints").and_then(|v| v.as_object()) else {
                continue;
            };
            for (prop, constraint) in constraints {
                let keys: Vec<&str> =
                    constraint.as_object().expect("constraint object").keys().map(String::as_str).collect();
                for key in keys {
                    assert!(
                        matches!(
                            key,
                            "pattern"
                                | "minimum"
                                | "maximum"
                                | "minLength"
                                | "maxLength"
                                | "minItems"
                                | "maxItems"
                                | "format"
                                | "uniqueItems"
                        ),
                        "{type_name}.{prop}: unexpected constraint key '{key}'"
                    );
                }
            }
        }
    }

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("data_source_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn copy_dir(src: &Path, dst: &Path) {
        fs::create_dir_all(dst).unwrap();
        for entry in fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let dest_path = dst.join(entry.file_name());
            if entry.path().is_dir() {
                copy_dir(&entry.path(), &dest_path);
            } else {
                fs::copy(entry.path(), &dest_path).unwrap();
            }
        }
    }

    fn unique_tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("data_source_test_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn region_resource_types_union_errors_when_file_absent() {
        let directory = unique_tempdir("region_types_missing");

        let error = read_region_resource_types_union(&directory)
            .expect_err("missing required region_resource_types.json must fail");

        assert!(
            error.to_string().contains("failed to read required"),
            "error must identify the missing required file: {error}"
        );
    }

    #[test]
    fn region_resource_types_union_collects_types_across_regions() {
        let dir = unique_tempdir("region_types_union");
        let region_file = json!({
            "region_resource_types": {
                "us-east-1": {
                    "AWS::S3::Bucket": true,
                    "AWS::CDK::Metadata": true,
                },
                "cn-north-1": {
                    "AWS::S3::Bucket": true,
                    "AWS::CDK::Metadata": true,
                    "AWS::Special::ChinaOnlyType": true,
                },
            }
        });
        fs::write(dir.join("region_resource_types.json"), serde_json::to_string(&region_file).unwrap()).unwrap();

        let union = read_region_resource_types_union(&dir).expect("should parse valid file");

        assert_eq!(
            union,
            ["AWS::CDK::Metadata", "AWS::S3::Bucket", "AWS::Special::ChinaOnlyType"]
                .into_iter()
                .map(String::from)
                .collect::<BTreeSet<String>>(),
            "union should contain every type from every region exactly once"
        );
    }

    #[test]
    fn region_resource_types_union_errors_when_top_level_key_missing() {
        let dir = unique_tempdir("region_types_malformed");
        fs::write(dir.join("region_resource_types.json"), r#"{"wrong_key": {}}"#).unwrap();

        let result = read_region_resource_types_union(&dir);

        let err_msg = result.expect_err("should fail when top-level key is missing").to_string();
        assert!(
            err_msg.contains("missing 'region_resource_types' object"),
            "error must surface the missing top-level key, got: {}",
            err_msg
        );
    }

    #[test]
    fn region_resource_types_union_errors_on_invalid_json() {
        let dir = unique_tempdir("region_types_invalid_json");
        fs::write(dir.join("region_resource_types.json"), "not json at all {{{").unwrap();

        let result = read_region_resource_types_union(&dir);

        assert!(result.is_err(), "should fail on malformed JSON instead of silently returning empty");
    }
}
