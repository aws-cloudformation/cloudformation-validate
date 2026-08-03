use crate::compiled::CompiledSchema;
use crate::overlay::{self, SchemaOverlayError};
use data_source::embedded::*;
use std::collections::{BTreeSet, HashMap};
use template_model::regions::AWS_REGIONS;

/// What applying an overlay did to the store.
///
/// An overlay whose type name matches no bundled schema is registered as a new
/// resource type — the supported way to describe a type CloudFormation has not
/// published yet — but it is also what a misspelled type name produces, so the
/// distinction is reported rather than swallowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayOutcome {
    /// Merged into the bundled schema for an existing resource type.
    Merged,
    /// Registered as a resource type the bundled schemas do not contain.
    Inserted,
}

pub struct CompiledSchemaStore {
    schemas: HashMap<String, CompiledSchema>,
    region_types: HashMap<String, HashMap<String, bool>>,
    ref_types: RefTypeStore,
    lifecycle: LifecycleStore,
    extensions: ExtensionStore,
    region_enums: RegionEnumStore,
}

impl Default for CompiledSchemaStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CompiledSchemaStore {
    pub fn new() -> Self {
        let schemas: HashMap<String, CompiledSchema> =
            serde_json::from_slice(&COMPILED_SCHEMAS_BYTES).expect("Embedded compiled schemas must be valid JSON");
        let ref_types = RefTypeStore::load(&REF_TYPES_BYTES);
        let lifecycle = LifecycleStore::load(&RESOURCE_LIFECYCLE_BYTES, &LAMBDA_RUNTIMES_BYTES);
        let mut extensions = ExtensionStore::load(&EXTENSIONS_BYTES);
        extensions.remap_keys(&schemas);
        let region_enums = RegionEnumStore::load(&REGION_ENUMS_BYTES);
        let mut store = CompiledSchemaStore {
            schemas,
            region_types: HashMap::new(),
            ref_types,
            lifecycle,
            extensions,
            region_enums,
        };
        // Load the embedded per-region resource-type map so region-availability
        // (F3006) validates against the target region. Without this the region
        // check is dormant and unavailable types slip through.
        store.load_region_data(&REGION_RESOURCE_TYPES_BYTES);
        assert!(
            store.has_region_data(),
            "Embedded region-availability data (region_resource_types) is empty; the build is missing regional data"
        );
        assert!(
            store.region_enums.has_data(),
            "Embedded regional enum data (region_enums) is empty; the build is missing regional data"
        );
        store
    }

    pub fn load_region_data(&mut self, json_bytes: &[u8]) {
        if let Ok(wrapper) = serde_json::from_slice::<serde_json::Value>(json_bytes)
            && let Some(obj) = wrapper.get("region_resource_types").and_then(|v| v.as_object())
        {
            for (region, types) in obj {
                let mut type_map = HashMap::new();
                if let Some(tobj) = types.as_object() {
                    for (t, _) in tobj {
                        type_map.insert(t.clone(), true);
                    }
                }
                self.region_types.insert(region.clone(), type_map);
            }
        }
    }

    pub fn get(&self, type_name: &str) -> Option<&CompiledSchema> {
        self.schemas.get(type_name)
    }

    /// Merge an overlay CloudFormation resource provider schema (raw registry
    /// JSON) into the store under `type_name`.
    ///
    /// The raw schema is compiled with the same transformation used at build time
    /// and deep-merged into the bundled schema for that type; when no bundled
    /// schema exists, the compiled overlay is registered as a new type. The
    /// return value says which happened, so callers can report a `type_name` that
    /// matched nothing. See the [`crate::overlay`] module for the merge
    /// model and its scope limits.
    ///
    /// Input is validated before anything is committed — an empty type name,
    /// non-object JSON, nesting past [`MAX_OVERLAY_DEPTH`](crate::overlay::MAX_OVERLAY_DEPTH),
    /// a cyclic definition graph, or an overlay that would change nothing is an
    /// error and leaves the store untouched. The merge therefore runs on a copy
    /// of the bundled schema that is only installed once it validates; a partly
    /// merged schema is never observable.
    pub fn apply_overlay(
        &mut self,
        type_name: &str,
        raw: &serde_json::Value,
    ) -> Result<OverlayOutcome, SchemaOverlayError> {
        let overlay = overlay::compile(type_name, raw)?;
        overlay::validate_schema(&overlay)?;
        match self.schemas.get(type_name) {
            Some(existing) => {
                let mut merged = existing.clone();
                overlay::merge_into(&mut merged, overlay);
                overlay::validate_schema(&merged)?;
                overlay::warn_dangling_refs(&merged);
                self.ref_types.update_from_schema(&merged);
                self.schemas.insert(type_name.to_string(), merged);
                Ok(OverlayOutcome::Merged)
            }
            None => {
                overlay::warn_dangling_refs(&overlay);
                self.ref_types.update_from_schema(&overlay);
                self.schemas.insert(type_name.to_string(), overlay);
                Ok(OverlayOutcome::Inserted)
            }
        }
    }

    /// Registers a schema directly, bypassing the embedded artifacts — lets
    /// unit tests exercise validation against schema shapes the committed
    /// artifacts do not yet contain.
    #[cfg(test)]
    pub(crate) fn insert_schema(&mut self, schema: CompiledSchema) {
        self.schemas.insert(schema.type_name.clone(), schema);
    }

    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    pub fn is_available_in_region(&self, type_name: &str, region: &str) -> bool {
        self.region_types.get(region).map(|types| types.contains_key(type_name)).unwrap_or(true)
    }

    /// Whether the type appears in at least one region's availability map. Used
    /// to distinguish a genuine regional provider type (absent only in some
    /// regions) from a type that is region-agnostic or not a provider type at
    /// all (SAM/transform placeholders), which must not trigger the region check.
    pub fn is_known_in_any_region(&self, type_name: &str) -> bool {
        self.region_types.values().any(|types| types.contains_key(type_name))
    }

    pub fn has_region_data(&self) -> bool {
        !self.region_types.is_empty()
    }

    pub fn ref_types(&self) -> &RefTypeStore {
        &self.ref_types
    }

    pub fn lifecycle(&self) -> &LifecycleStore {
        &self.lifecycle
    }

    pub fn extensions(&self) -> &ExtensionStore {
        &self.extensions
    }

    pub fn region_enums(&self) -> &RegionEnumStore {
        &self.region_enums
    }
}

pub struct RefTypeStore {
    ref_returns: HashMap<String, String>,
    getatt_returns: HashMap<String, HashMap<String, String>>,
    format_compatible_types: HashMap<String, Vec<String>>,
}

impl RefTypeStore {
    fn load(bytes: &[u8]) -> Self {
        let json: serde_json::Value = serde_json::from_slice(bytes).expect("Embedded ref_types must be valid JSON");
        let ref_returns = json
            .get("ref_returns")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .expect("Embedded ref_types must contain ref_returns");
        let getatt_returns = json
            .get("getatt_returns")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .expect("Embedded ref_types must contain getatt_returns");
        let format_compatible_types = json
            .get("format_compatible_types")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .expect("Embedded ref_types must contain format_compatible_types");
        RefTypeStore { ref_returns, getatt_returns, format_compatible_types }
    }

    /// Update Ref/GetAtt return type data from a merged overlay schema so
    /// type-checking rules see overlay-introduced/changed sources immediately.
    ///
    /// Uses the same derivation semantics as the catalog: no ref entry when
    /// primaryIdentifier is empty; "string" when multiple, readOnly, or
    /// unresolvable; otherwise the resolved single property type. GetAtt types
    /// include ALL top-level properties plus full-path readOnly attributes.
    /// Stale entries for a type that an overlay changes are replaced.
    pub fn update_from_schema(&mut self, schema: &crate::compiled::CompiledSchema) {
        let type_name = &schema.type_name;
        let read_only_set: std::collections::HashSet<&str> =
            schema.read_only_properties.iter().map(|s| s.as_str()).collect();

        // Ref return type: match catalog derivation semantics.
        // Remove stale entry first in case an overlay removed or changed
        // the primary identifier.
        self.ref_returns.remove(type_name);
        if !schema.primary_identifier.is_empty() {
            let ref_type = if schema.primary_identifier.len() > 1 {
                "string".to_string()
            } else {
                let id_prop = &schema.primary_identifier[0];
                if read_only_set.contains(id_prop.as_str()) {
                    "string".to_string()
                } else {
                    crate::catalog::resolve_property_type(schema, id_prop).unwrap_or_else(|| "string".to_string())
                }
            };
            self.ref_returns.insert(type_name.clone(), ref_type);
        }

        // GetAtt return types: ALL top-level properties plus full-path readOnly
        // attributes. Replace the whole entry so stale attributes from a
        // previous overlay are removed.
        let mut attr_map: HashMap<String, String> = HashMap::new();
        for (name, prop) in &schema.properties {
            let resolved = prop.resolve(&schema.definitions);
            if let Some(pt) = resolved.prop_type.as_ref().and_then(|p| p.primary()) {
                attr_map.insert(name.clone(), pt.to_string());
            }
        }
        for attr in &schema.read_only_properties {
            if attr.contains('.')
                && let Some(prop_type) = crate::catalog::resolve_property_type(schema, attr)
            {
                attr_map.insert(attr.clone(), prop_type);
            }
        }
        if !attr_map.is_empty() {
            self.getatt_returns.insert(type_name.clone(), attr_map);
        } else {
            self.getatt_returns.remove(type_name);
        }
    }

    pub fn ref_type_for(&self, resource_type: &str) -> Option<&str> {
        self.ref_returns.get(resource_type).map(|s| s.as_str())
    }

    pub fn getatt_type_for(&self, resource_type: &str, attribute: &str) -> Option<&str> {
        self.getatt_returns.get(resource_type).and_then(|attrs| attrs.get(attribute)).map(|s| s.as_str())
    }

    pub fn format_compatible_types(&self, format: &str) -> &[String] {
        self.format_compatible_types.get(format).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

pub struct LifecycleEntry {
    pub status: String,
    pub date: Option<String>,
}

pub struct LifecycleStore {
    resource_lifecycle: HashMap<String, LifecycleEntry>,
    deprecated_runtimes: Vec<String>,
    create_blocked_runtimes: Vec<String>,
    eol_runtimes: Vec<String>,
    runtime_lifecycle: HashMap<String, RuntimeLifecycle>,
}

/// Per-runtime lifecycle dates used to reconstruct the dated runtime-deprecation
/// message.
#[derive(Clone)]
pub struct RuntimeLifecycle {
    pub deprecated: String,
    pub create_block: String,
    pub update_block: String,
    pub successor: Option<String>,
}

impl LifecycleStore {
    fn load(lifecycle_bytes: &[u8], runtimes_bytes: &[u8]) -> Self {
        let lc_json: serde_json::Value =
            serde_json::from_slice(lifecycle_bytes).expect("Embedded resource_lifecycle must be valid JSON");
        let mut resource_lifecycle = HashMap::new();
        if let Some(obj) = lc_json.get("resource_lifecycle").and_then(|v| v.as_object()) {
            for (type_name, entry) in obj {
                let status = entry.get("status").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let date = entry.get("date").and_then(|v| v.as_str()).map(String::from);
                if !status.is_empty() {
                    resource_lifecycle.insert(type_name.clone(), LifecycleEntry { status, date });
                }
            }
        }

        let rt_json: serde_json::Value =
            serde_json::from_slice(runtimes_bytes).expect("Embedded lambda_runtimes must be valid JSON");
        let deprecated_runtimes = rt_json
            .get("lambda_runtimes")
            .and_then(|v| v.get("deprecated"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let eol_runtimes = rt_json
            .get("lambda_runtimes")
            .and_then(|v| v.get("eol"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let create_blocked_runtimes = rt_json
            .get("lambda_runtimes")
            .and_then(|v| v.get("create_blocked"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let mut runtime_lifecycle = HashMap::new();
        if let Some(obj) = rt_json.get("lambda_runtimes").and_then(|v| v.get("lifecycle")).and_then(|v| v.as_object()) {
            for (runtime, dates) in obj {
                let get = |k: &str| dates.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                runtime_lifecycle.insert(
                    runtime.clone(),
                    RuntimeLifecycle {
                        deprecated: get("deprecated"),
                        create_block: get("create_block"),
                        update_block: get("update_block"),
                        successor: dates.get("successor").and_then(|v| v.as_str()).map(String::from),
                    },
                );
            }
        }

        LifecycleStore {
            resource_lifecycle,
            deprecated_runtimes,
            create_blocked_runtimes,
            eol_runtimes,
            runtime_lifecycle,
        }
    }

    pub fn runtime_lifecycle(&self, runtime: &str) -> Option<&RuntimeLifecycle> {
        self.runtime_lifecycle.get(runtime)
    }

    pub fn resource_lifecycle(&self, type_name: &str) -> Option<&LifecycleEntry> {
        self.resource_lifecycle.get(type_name)
    }

    pub fn is_runtime_deprecated(&self, runtime: &str) -> bool {
        self.deprecated_runtimes.iter().any(|r| r == runtime)
    }

    pub fn is_runtime_eol(&self, runtime: &str) -> bool {
        self.eol_runtimes.iter().any(|r| r == runtime)
    }

    pub fn is_runtime_create_blocked(&self, runtime: &str) -> bool {
        self.create_blocked_runtimes.iter().any(|r| r == runtime)
    }
}

pub struct ExtensionStore {
    extensions: HashMap<String, Vec<serde_json::Value>>,
}

impl ExtensionStore {
    fn load(bytes: &[u8]) -> Self {
        let json: HashMap<String, serde_json::Value> =
            serde_json::from_slice(bytes).expect("Embedded extensions must be valid JSON");
        let mut extensions = HashMap::new();
        for (type_name, val) in json {
            if let Some(arr) = val.as_array() {
                extensions.insert(type_name, arr.clone());
            }
        }
        ExtensionStore { extensions }
    }

    /// Remap extension keys to match canonical resource type names.
    /// Extension source files may produce keys like "Aws::Rds::Dbcluster"
    /// but the actual type names are "AWS::RDS::DBCluster".
    pub fn remap_keys(&mut self, known_types: &HashMap<String, CompiledSchema>) {
        let lowercase_to_canonical: HashMap<String, String> =
            known_types.keys().map(|k| (k.to_lowercase(), k.clone())).collect();
        let old_keys: Vec<String> = self.extensions.keys().cloned().collect();
        for key in old_keys {
            if known_types.contains_key(&key) {
                continue;
            }
            if let Some(canonical) = lowercase_to_canonical.get(&key.to_lowercase())
                && let Some(val) = self.extensions.remove(&key)
            {
                self.extensions.insert(canonical.clone(), val);
            }
        }
    }

    pub fn get(&self, type_name: &str) -> Option<&[serde_json::Value]> {
        self.extensions.get(type_name).map(|v| v.as_slice())
    }
}

pub struct RegionEnumStore {
    enums: HashMap<String, HashMap<String, Vec<String>>>,
}

impl RegionEnumStore {
    fn load(bytes: &[u8]) -> Self {
        let enums: HashMap<String, HashMap<String, Vec<String>>> =
            serde_json::from_slice(bytes).expect("Embedded region_enums must be valid JSON");
        RegionEnumStore { enums }
    }

    /// Key format: "AWS::EC2::Instance::InstanceType"
    pub fn get(&self, resource_type: &str, prop_name: &str, region: &str) -> Option<&[String]> {
        let key = format!("{}::{}", resource_type, prop_name);
        self.enums.get(&key).and_then(|regions| regions.get(region)).map(|v| v.as_slice())
    }

    /// Allowed values for a property in the effective scope: the single `region`
    /// when configured, or the union across all AWS regions when not (`None`) — so
    /// with no region a value is accepted when it is valid in any region. Returns
    /// `None` when the property has no regional override, or when a configured
    /// region has no entry, so the caller falls back to the region-agnostic enum.
    pub fn allowed_values(&self, resource_type: &str, prop_name: &str, region: Option<&str>) -> Option<Vec<&str>> {
        let key = format!("{}::{}", resource_type, prop_name);
        let regions = self.enums.get(&key)?;
        match region {
            Some(region) => regions.get(region).map(|v| v.iter().map(String::as_str).collect()),
            None => {
                let mut union: BTreeSet<&str> = BTreeSet::new();
                for region in AWS_REGIONS {
                    if let Some(values) = regions.get(*region) {
                        union.extend(values.iter().map(String::as_str));
                    }
                }
                (!union.is_empty()).then(|| union.into_iter().collect())
            }
        }
    }

    pub fn has_data(&self) -> bool {
        !self.enums.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn store_loads_nonempty() {
        let store = CompiledSchemaStore::new();
        assert!(store.len() > 0, "store should have schemas, got {}", store.len());
    }

    #[test]
    fn store_get_known_type() {
        let store = CompiledSchemaStore::new();
        let schema = store.get("AWS::S3::Bucket").expect("expected AWS::S3::Bucket schema");
        assert_eq!(schema.type_name, "AWS::S3::Bucket");
    }

    #[test]
    fn store_get_unknown_type_returns_none() {
        let store = CompiledSchemaStore::new();
        assert!(store.get("AWS::Fake::NonExistent").is_none(), "unknown type should return None");
    }

    #[test]
    fn store_new_always_has_region_data() {
        let store = CompiledSchemaStore::new();
        assert!(store.has_region_data(), "embedded region data must be present");
    }

    #[test]
    fn store_load_region_data_filters_types() {
        let mut store = CompiledSchemaStore::new();
        let region_json = json!({
            "region_resource_types": {
                "us-east-1": { "AWS::S3::Bucket": true, "AWS::EC2::Instance": true },
                "eu-west-1": { "AWS::S3::Bucket": true }
            }
        });
        store.load_region_data(serde_json::to_vec(&region_json).unwrap().as_slice());
        assert!(store.has_region_data());
        assert!(store.is_available_in_region("AWS::S3::Bucket", "us-east-1"));
        assert!(store.is_available_in_region("AWS::EC2::Instance", "us-east-1"));
        assert!(!store.is_available_in_region("AWS::EC2::Instance", "eu-west-1"));
    }

    #[test]
    fn store_unknown_region_defaults_to_available() {
        let mut store = CompiledSchemaStore::new();
        let region_json = json!({
            "region_resource_types": {
                "us-east-1": { "AWS::S3::Bucket": true }
            }
        });
        store.load_region_data(serde_json::to_vec(&region_json).unwrap().as_slice());
        assert!(store.is_available_in_region("AWS::S3::Bucket", "ap-southeast-99"));
    }

    #[test]
    fn store_load_region_data_invalid_json_no_panic() {
        // Start from an empty region map (new() preloads the embedded one) so the
        // test verifies that malformed input adds nothing rather than panicking.
        let mut store = CompiledSchemaStore::new();
        store.region_types.clear();
        store.load_region_data(b"not json");
        assert!(!store.has_region_data());
    }

    #[test]
    fn store_load_region_data_wrong_structure_no_panic() {
        let mut store = CompiledSchemaStore::new();
        store.region_types.clear();
        store.load_region_data(b"{}");
        assert!(!store.has_region_data());
    }

    #[test]
    fn ref_type_store_loads_from_embedded_data() {
        let store = CompiledSchemaStore::new();
        let rt = store.ref_types();
        let vpc_ref = rt.ref_type_for("AWS::EC2::VPC");
        assert_eq!(vpc_ref, Some("string"), "expected Ref to VPC to return string");
    }

    #[test]
    fn ref_type_unknown_resource_returns_none() {
        let store = CompiledSchemaStore::new();
        assert_eq!(store.ref_types().ref_type_for("AWS::Fake::Thing"), None, "unknown type should have no ref type");
    }

    #[test]
    fn getatt_type_for_known_attribute() {
        let store = CompiledSchemaStore::new();
        let rt = store.ref_types();
        let sg = rt.getatt_type_for("AWS::EC2::VPC", "DefaultSecurityGroup");
        assert!(sg.is_some(), "expected GetAtt type for VPC.DefaultSecurityGroup");
    }

    #[test]
    fn getatt_type_unknown_attribute_returns_none() {
        let store = CompiledSchemaStore::new();
        assert!(store.ref_types().getatt_type_for("AWS::EC2::VPC", "FakeAttr").is_none());
    }

    #[test]
    fn format_compatible_types_vpc_id() {
        let store = CompiledSchemaStore::new();
        let compatible = store.ref_types().format_compatible_types("AWS::EC2::VPC.Id");
        assert!(
            compatible.iter().any(|t| t == "AWS::EC2::VPC"),
            "expected AWS::EC2::VPC in format-compatible types for VPC.Id, got: {:?}",
            compatible
        );
    }

    #[test]
    fn format_compatible_types_unknown_format_empty() {
        let store = CompiledSchemaStore::new();
        assert!(store.ref_types().format_compatible_types("FakeFormat").is_empty());
    }

    #[test]
    fn lifecycle_store_loads() {
        let store = CompiledSchemaStore::new();
        let lc = store.lifecycle();
        let entry = lc.resource_lifecycle("AWS::CodeStar::GitHubRepository");
        assert!(entry.is_some(), "expected lifecycle entry for AWS::CodeStar::GitHubRepository");
        assert_eq!(entry.unwrap().status, "shutdown");
    }

    #[test]
    fn lifecycle_unknown_type_returns_none() {
        let store = CompiledSchemaStore::new();
        assert!(store.lifecycle().resource_lifecycle("AWS::S3::Bucket").is_none());
    }

    #[test]
    fn runtime_eol_detection() {
        let store = CompiledSchemaStore::new();
        let lc = store.lifecycle();
        assert!(lc.is_runtime_eol("python2.7"), "expected python2.7 to be EOL");
        assert!(!lc.is_runtime_eol("python3.12"), "python3.12 should not be EOL");
    }

    #[test]
    fn runtime_deprecated_detection() {
        let store = CompiledSchemaStore::new();
        let lc = store.lifecycle();
        assert!(!lc.is_runtime_deprecated("python3.12"), "python3.12 should not be deprecated");
    }

    #[test]
    fn extension_store_remap_keys() {
        let mut extensions = ExtensionStore { extensions: HashMap::new() };
        extensions.extensions.insert("Aws::S3::Bucket".into(), vec![json!({"test": true})]);

        let mut known = HashMap::new();
        known.insert(
            "AWS::S3::Bucket".into(),
            CompiledSchema { type_name: "AWS::S3::Bucket".into(), ..Default::default() },
        );

        extensions.remap_keys(&known);
        assert!(extensions.get("AWS::S3::Bucket").is_some(), "expected remapped key");
        assert!(extensions.get("Aws::S3::Bucket").is_none(), "old key should be removed");
    }

    #[test]
    fn extension_store_remap_preserves_canonical_keys() {
        let mut extensions = ExtensionStore { extensions: HashMap::new() };
        extensions.extensions.insert("AWS::S3::Bucket".into(), vec![json!({"test": true})]);

        let mut known = HashMap::new();
        known.insert(
            "AWS::S3::Bucket".into(),
            CompiledSchema { type_name: "AWS::S3::Bucket".into(), ..Default::default() },
        );

        extensions.remap_keys(&known);
        assert!(extensions.get("AWS::S3::Bucket").is_some(), "canonical key should be preserved");
    }

    #[test]
    fn region_enum_get_unknown_returns_none() {
        let store = CompiledSchemaStore::new();
        assert!(store.region_enums().get("AWS::Fake::Type", "FakeProp", "us-east-1").is_none());
    }

    #[test]
    fn region_enum_store_from_empty_bytes() {
        let re = RegionEnumStore::load(b"{}");
        assert!(!re.has_data());
        assert!(re.get("AWS::EC2::Instance", "InstanceType", "us-east-1").is_none());
    }

    #[test]
    fn region_enum_store_from_valid_data() {
        let data = json!({
            "AWS::EC2::Instance::InstanceType": {
                "us-east-1": ["t2.micro", "t3.micro"],
                "eu-west-1": ["t2.micro"]
            }
        });
        let re = RegionEnumStore::load(serde_json::to_vec(&data).unwrap().as_slice());
        assert!(re.has_data());
        let vals =
            re.get("AWS::EC2::Instance", "InstanceType", "us-east-1").expect("expected enum values for us-east-1");
        assert_eq!(vals, &["t2.micro", "t3.micro"]);
        assert_eq!(
            re.get("AWS::EC2::Instance", "InstanceType", "ap-south-1"),
            None,
            "ap-south-1 should have no enum values"
        );
    }

    fn region_enum_fixture() -> RegionEnumStore {
        // t3.micro is valid only in eu-west-1, not us-east-1; "description" is a
        // synthetic non-region key that must never contribute to the union.
        let data = json!({
            "AWS::EC2::Instance::InstanceType": {
                "us-east-1": ["t2.micro"],
                "eu-west-1": ["t2.micro", "t3.micro"],
                "description": ["should.be.ignored"]
            }
        });
        RegionEnumStore::load(serde_json::to_vec(&data).unwrap().as_slice())
    }

    #[test]
    fn allowed_values_with_region_is_that_region_only() {
        let re = region_enum_fixture();
        let vals = re.allowed_values("AWS::EC2::Instance", "InstanceType", Some("us-east-1")).expect("us-east-1 entry");
        assert!(vals.contains(&"t2.micro"));
        assert!(!vals.contains(&"t3.micro"), "t3.micro is not valid in us-east-1");
    }

    #[test]
    fn allowed_values_without_region_unions_all_regions() {
        let re = region_enum_fixture();
        let vals = re.allowed_values("AWS::EC2::Instance", "InstanceType", None).expect("union across regions");
        assert!(vals.contains(&"t2.micro"));
        assert!(vals.contains(&"t3.micro"), "t3.micro is valid in eu-west-1, so present in the union");
        assert!(!vals.contains(&"should.be.ignored"), "the synthetic 'description' key must not contribute");
    }

    #[test]
    fn allowed_values_unknown_configured_region_is_none() {
        let re = region_enum_fixture();
        assert!(re.allowed_values("AWS::EC2::Instance", "InstanceType", Some("ap-south-1")).is_none());
    }

    #[test]
    fn allowed_values_unknown_property_is_none() {
        let re = region_enum_fixture();
        assert!(re.allowed_values("AWS::Fake::Type", "FakeProp", None).is_none());
        assert!(re.allowed_values("AWS::Fake::Type", "FakeProp", Some("us-east-1")).is_none());
    }
}
