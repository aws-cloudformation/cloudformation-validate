use crate::SyncStats;
use log::{info, warn};
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

/// Extracts the primary (non-null) type string from a JSON Schema "type" value.
/// Handles both `"type": "string"` and `"type": ["string", "null"]` forms.
fn extract_primary_type(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => {
            let non_null: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).filter(|s| *s != "null").collect();
            if non_null.len() == 1 { Some(non_null[0].to_string()) } else { None }
        }
        _ => None,
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
        // These are our own downloaded schema files — a parse failure means a
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
    let mut ext_count = 0;
    if extensions_dir.exists() {
        for (type_name, schema_json) in &mut raw_schemas {
            let ext_name = type_name.replace("::", "-").to_lowercase();
            let ext_file = extensions_dir.join(format!("{}.ext.json", ext_name));
            if !ext_file.exists() {
                continue;
            }
            let fragments: Vec<serde_json::Value> = serde_json::from_str(&fs::read_to_string(&ext_file)?)?;
            if fragments.is_empty() {
                continue;
            }
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
    // getatt_additions is extracted from cfn-lint during sync (into data_dir);
    // getatt_return_type_overrides is a hand-maintained correction (CloudFormation
    // stringifies some GetAtt values) that has no cfn-lint equivalent.
    let getatt_additions = read_getatt_additions(&data_dir)?;
    let getatt_return_overrides = read_getatt_return_type_overrides(handwritten_dir)?;
    fs::write(
        data_dir.join("getatt_attributes.json"),
        generate_getatt_data(&schemas, &raw_schemas, &getatt_additions, &getatt_return_overrides),
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
    if !region_file.exists() {
        warn!("{} not found — known_resource_types will not include per-region types", region_file.display());
        return Ok(BTreeSet::new());
    }
    let content = fs::read_to_string(&region_file)?;
    let parsed: serde_json::Value = serde_json::from_str(&content)?;
    let regions = parsed
        .get("region_resource_types")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow::anyhow!("{}: missing 'region_resource_types' object", region_file.display()))?;
    let mut union: BTreeSet<String> = BTreeSet::new();
    for type_map in regions.values() {
        let Some(type_obj) = type_map.as_object() else {
            continue;
        };
        for type_name in type_obj.keys() {
            union.insert(type_name.clone());
        }
    }
    info!("Collected {} unique resource types across regions for known_resource_types union", union.len());
    Ok(union)
}

/// Generates per-resource-type metadata: property names, types, required fields,
/// enums, constraints, and inter-property dependencies (dependentRequired, etc.).
fn generate_schema_metadata(
    schemas: &HashMap<String, (String, SchemaTop)>,
    raw_schemas: &HashMap<String, serde_json::Value>,
) -> String {
    let mut meta: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (tn, (_, s)) in schemas {
        let raw = raw_schemas.get(tn);
        let obj = build_property_schema_obj(
            s.properties.as_ref(),
            s.required.as_ref(),
            s.definitions.as_ref(),
            raw,
            &mut HashSet::new(),
        );
        meta.insert(tn.clone(), obj);
    }
    serde_json::to_string_pretty(&serde_json::json!({"schema_metadata": meta})).unwrap()
}

/// Recursively builds a metadata object for a set of properties, including
/// property types, enums, scalar constraints, and nested sub-property schemas.
fn build_property_schema_obj(
    properties: Option<&HashMap<String, serde_json::Value>>,
    required: Option<&Vec<String>>,
    defs: Option<&HashMap<String, serde_json::Value>>,
    raw: Option<&serde_json::Value>,
    visiting: &mut HashSet<String>,
) -> serde_json::Value {
    let mut props: Vec<String> = properties.map(|p| p.keys().cloned().collect()).unwrap_or_default();
    props.sort();
    let req: Vec<String> = required.cloned().unwrap_or_default();
    let mut pt: BTreeMap<String, String> = BTreeMap::new();
    let mut pe: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    let mut pc: BTreeMap<String, serde_json::Value> = BTreeMap::new();

    if let Some(p) = properties {
        for (pn, ps) in p {
            // Track which $ref definitions we're inside to prevent infinite recursion
            let ref_name = ps
                .get("$ref")
                .and_then(|v| v.as_str())
                .and_then(|s| s.strip_prefix("#/definitions/"))
                .map(String::from);
            if let Some(ref name) = ref_name {
                if visiting.contains(name) {
                    continue;
                }
                visiting.insert(name.clone());
            }
            let r = resolve_schema(ps, defs, &mut HashSet::new());
            if let Some(t) = r.get("type").and_then(|v| extract_primary_type(v)) {
                pt.insert(pn.clone(), t.clone());
            }
            if let Some(e) = r.get("enum").and_then(|v| v.as_array()) {
                pe.insert(pn.clone(), e.clone());
            }
            let constraints = extract_property_constraints(&r, defs, visiting);
            if !constraints.is_null() {
                pc.insert(pn.clone(), constraints);
            }
            if let Some(ref name) = ref_name {
                visiting.remove(name);
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

/// Extracts scalar constraints (pattern, min/max, format), nested sub-properties,
/// and array item schemas from a resolved property definition.
fn extract_property_constraints(
    resolved: &serde_json::Value,
    defs: Option<&HashMap<String, serde_json::Value>>,
    visiting: &mut HashSet<String>,
) -> serde_json::Value {
    let obj = match resolved.as_object() {
        Some(o) => o,
        None => return serde_json::Value::Null,
    };
    let mut c = serde_json::Map::new();

    for &key in &["pattern", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "format"] {
        if let Some(v) = obj.get(key) {
            c.insert(key.to_string(), v.clone());
        }
    }
    if obj.get("uniqueItems").and_then(|v| v.as_bool()) == Some(true) {
        c.insert("uniqueItems".to_string(), serde_json::Value::Bool(true));
    }

    if let Some(sub_props) = obj.get("properties").and_then(|v| v.as_object()) {
        let sub_req = obj
            .get("required")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>());
        let sub_map: HashMap<String, serde_json::Value> =
            sub_props.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let nested = build_property_schema_obj(Some(&sub_map), sub_req.as_ref(), defs, None, visiting);
        c.insert("sub_properties".to_string(), nested);
        if let Some(de) = obj.get("dependentExcluded") {
            c.insert("dependent_excluded".to_string(), de.clone());
        }
        if let Some(dr) = obj.get("dependentRequired") {
            c.insert("dependent_required".to_string(), dr.clone());
        }
    }

    if let Some(items) = obj.get("items") {
        let item_ref_name =
            items.get("$ref").and_then(|v| v.as_str()).and_then(|s| s.strip_prefix("#/definitions/")).map(String::from);
        let skip_items = item_ref_name.as_ref().map(|n| visiting.contains(n)).unwrap_or(false);
        if !skip_items {
            if let Some(ref name) = item_ref_name {
                visiting.insert(name.clone());
            }
            let resolved_items = resolve_schema(items, defs, &mut HashSet::new());
            if let Some(items_obj) = resolved_items.as_object() {
                let mut item_schema = serde_json::Map::new();
                if let Some(t) = items_obj.get("type").and_then(|v| extract_primary_type(v)) {
                    item_schema.insert("type".to_string(), serde_json::Value::String(t));
                }
                if let Some(item_props) = items_obj.get("properties").and_then(|v| v.as_object()) {
                    let item_req = items_obj
                        .get("required")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>());
                    let item_map: HashMap<String, serde_json::Value> =
                        item_props.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                    let nested = build_property_schema_obj(Some(&item_map), item_req.as_ref(), defs, None, visiting);
                    item_schema.insert("schema".to_string(), nested);
                }
                if let Some(de) = items_obj.get("dependentExcluded") {
                    item_schema.insert("dependent_excluded".to_string(), de.clone());
                }
                if let Some(dr) = items_obj.get("dependentRequired") {
                    item_schema.insert("dependent_required".to_string(), dr.clone());
                }
                if !item_schema.is_empty() {
                    c.insert("items".to_string(), serde_json::Value::Object(item_schema));
                }
            }
            if let Some(ref name) = item_ref_name {
                visiting.remove(name);
            }
        }
    }

    if c.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(c) }
}

/// Generates GetAtt attribute names and types per resource type from readOnlyProperties.
fn generate_getatt_data(
    schemas: &HashMap<String, (String, SchemaTop)>,
    raw: &HashMap<String, serde_json::Value>,
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
        // Include types for ALL properties — used by output type checking
        // and type mismatch detection. Attribute validity uses getatt_attributes
        // (readOnly only), not this map.
        let mut tt = BTreeMap::new();
        if let Some(r) = raw.get(tn) {
            if let Some(ps) = r.get("properties").and_then(|p| p.as_object()) {
                for (pn, pd) in ps {
                    if let Some(t) = pd.get("type").and_then(|v| v.as_str()) {
                        tt.insert(pn.clone(), t.to_string());
                    }
                }
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
    if !path.exists() {
        return Ok(0);
    }
    let contents =
        fs::read_to_string(&path).map_err(|source| anyhow::anyhow!("failed to read {}: {}", path.display(), source))?;
    let parsed: Overrides = serde_json::from_str(&contents)
        .map_err(|source| anyhow::anyhow!("failed to parse {}: {}", path.display(), source))?;

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

/// that extend the schema-derived readOnly attributes with the full set
/// CloudFormation exposes for Fn::GetAtt on each resource type.
fn read_getatt_additions(data_dir: &Path) -> anyhow::Result<BTreeMap<String, Vec<String>>> {
    #[derive(Deserialize)]
    struct GetAttAdditions {
        getatt_additions: BTreeMap<String, Vec<String>>,
    }
    let path = data_dir.join("getatt_additions.json");
    let contents =
        fs::read_to_string(&path).map_err(|source| anyhow::anyhow!("failed to read {}: {}", path.display(), source))?;
    let parsed: GetAttAdditions = serde_json::from_str(&contents)
        .map_err(|source| anyhow::anyhow!("failed to parse {}: {}", path.display(), source))?;
    Ok(parsed.getatt_additions)
}

/// Reads overrides for the type CloudFormation returns from `Fn::GetAtt` on
/// specific attributes, where it differs from the raw schema property type
/// (CloudFormation stringifies many GetAtt return values). Missing file yields
/// an empty map.
fn read_getatt_return_type_overrides(
    handwritten_dir: &Path,
) -> anyhow::Result<BTreeMap<String, BTreeMap<String, String>>> {
    #[derive(Deserialize)]
    struct Overrides {
        getatt_return_type_overrides: BTreeMap<String, BTreeMap<String, String>>,
    }
    let path = handwritten_dir.join("getatt_return_type_overrides.json");
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let contents =
        fs::read_to_string(&path).map_err(|source| anyhow::anyhow!("failed to read {}: {}", path.display(), source))?;
    let parsed: Overrides = serde_json::from_str(&contents)
        .map_err(|source| anyhow::anyhow!("failed to parse {}: {}", path.display(), source))?;
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
                // Skip nested paths — only root-level properties
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
        // A references B, B references A — must not infinite-loop
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
        // Ambiguous — should return None
        assert_eq!(extract_primary_type(&json!(["string", "integer"])), None);
    }

    #[test]
    fn build_property_schema_obj_nested_properties() {
        // Schema with nested object property containing sub-properties
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
                "required": ["Name"]
            }),
        );
        let required = vec!["Config".to_string()];
        let result = build_property_schema_obj(Some(&properties), Some(&required), None, None, &mut HashSet::new());

        // Top level
        assert_eq!(result["required"], json!(["Config"]));
        // Nested constraints should exist (no depth truncation)
        let config_constraints = &result["property_constraints"]["Config"];
        assert_ne!(config_constraints.get("sub_properties"), None, "Config should have sub_properties");
        let sub = &config_constraints["sub_properties"];
        assert!(sub["required"].as_array().unwrap().contains(&json!("Name")));
        // Deep nesting should also be present
        let inner_constraints = &sub["property_constraints"]["Inner"];
        assert_ne!(inner_constraints.get("sub_properties"), None, "Inner should have sub_properties");
        let deep_sub = &inner_constraints["sub_properties"];
        assert!(deep_sub["required"].as_array().unwrap().contains(&json!("Deep")));
    }

    #[test]
    fn build_property_schema_obj_deeply_nested_no_truncation() {
        // Build a 6-level deep schema — previously truncated at depth 4
        fn make_nested(depth: usize) -> serde_json::Value {
            if depth == 0 {
                return json!({"type": "string", "pattern": "^leaf$"});
            }
            json!({
                "type": "object",
                "properties": {
                    "child": make_nested(depth - 1)
                },
                "required": ["child"]
            })
        }
        let mut properties = HashMap::new();
        properties.insert("root".to_string(), make_nested(6));
        let result = build_property_schema_obj(Some(&properties), None, None, None, &mut HashSet::new());

        // Walk down all 6 levels — none should be truncated
        let mut current = &result["property_constraints"]["root"];
        for _ in 0..6 {
            assert!(current.get("sub_properties").is_some(), "Nested level was truncated");
            current = &current["sub_properties"]["property_constraints"]["child"];
        }
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
        let result = build_property_schema_obj(Some(&properties), None, Some(&defs), None, &mut HashSet::new());
        assert!(result["properties"].as_array().unwrap().contains(&json!("Root")));
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
        if upstream_dir.join("extensions").exists() {
            copy_dir(&upstream_dir.join("extensions"), &tmp_upstream.join("extensions"));
        }
        // getatt_additions is a sync output (extracted from cfn-lint) read from
        // the generated data dir; seed it from the real one if present.
        let tmp_data = tmp.join("data");
        fs::create_dir_all(&tmp_data).unwrap();
        let real_additions = manifest.join("generated").join("data").join("getatt_additions.json");
        if real_additions.exists() {
            fs::copy(&real_additions, tmp_data.join("getatt_additions.json")).unwrap();
        } else {
            fs::write(tmp_data.join("getatt_additions.json"), r#"{"getatt_additions":{}}"#).unwrap();
        }

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
    fn region_resource_types_union_returns_empty_when_file_absent() {
        let dir = unique_tempdir("region_types_missing");

        let union = read_region_resource_types_union(&dir).expect("should succeed when file absent");

        assert!(union.is_empty(), "expected empty set when region_resource_types.json is absent, got {:?}", union);
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
