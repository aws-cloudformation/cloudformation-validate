use crate::compiled::CompiledSchema;
use data_source::embedded::*;
use std::collections::HashMap;

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
            serde_json::from_slice(&COMPILED_SCHEMAS_BYTES)
                .expect("Embedded compiled schemas must be valid JSON");
        let ref_types = RefTypeStore::load(&REF_TYPES_BYTES);
        let lifecycle = LifecycleStore::load(&RESOURCE_LIFECYCLE_BYTES, &LAMBDA_RUNTIMES_BYTES);
        let mut extensions = ExtensionStore::load(&EXTENSIONS_BYTES);
        extensions.remap_keys(&schemas);
        let region_enums = RegionEnumStore::load(&REGION_ENUMS_BYTES);
        CompiledSchemaStore {
            schemas,
            region_types: HashMap::new(),
            ref_types,
            lifecycle,
            extensions,
            region_enums,
        }
    }

    pub fn load_region_data(&mut self, json_bytes: &[u8]) {
        if let Ok(wrapper) = serde_json::from_slice::<serde_json::Value>(json_bytes)
            && let Some(obj) = wrapper
                .get("region_resource_types")
                .and_then(|v| v.as_object())
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

    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    pub fn is_available_in_region(&self, type_name: &str, region: &str) -> bool {
        if self.region_types.is_empty() {
            return true;
        }
        self.region_types
            .get(region)
            .map(|types| types.contains_key(type_name))
            .unwrap_or(true)
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
        let json: serde_json::Value =
            serde_json::from_slice(bytes).expect("Embedded ref_types must be valid JSON");
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
        RefTypeStore {
            ref_returns,
            getatt_returns,
            format_compatible_types,
        }
    }

    pub fn ref_type_for(&self, resource_type: &str) -> Option<&str> {
        self.ref_returns.get(resource_type).map(|s| s.as_str())
    }

    pub fn getatt_type_for(&self, resource_type: &str, attribute: &str) -> Option<&str> {
        self.getatt_returns
            .get(resource_type)
            .and_then(|attrs| attrs.get(attribute))
            .map(|s| s.as_str())
    }

    pub fn format_compatible_types(&self, format: &str) -> &[String] {
        self.format_compatible_types
            .get(format)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
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
}

impl LifecycleStore {
    fn load(lifecycle_bytes: &[u8], runtimes_bytes: &[u8]) -> Self {
        let lc_json: serde_json::Value = serde_json::from_slice(lifecycle_bytes)
            .expect("Embedded resource_lifecycle must be valid JSON");
        let mut resource_lifecycle = HashMap::new();
        if let Some(obj) = lc_json
            .get("resource_lifecycle")
            .and_then(|v| v.as_object())
        {
            for (type_name, entry) in obj {
                let status = entry
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let date = entry.get("date").and_then(|v| v.as_str()).map(String::from);
                if !status.is_empty() {
                    resource_lifecycle.insert(type_name.clone(), LifecycleEntry { status, date });
                }
            }
        }

        let rt_json: serde_json::Value = serde_json::from_slice(runtimes_bytes)
            .expect("Embedded lambda_runtimes must be valid JSON");
        let deprecated_runtimes = rt_json
            .get("lambda_runtimes")
            .and_then(|v| v.get("deprecated"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let eol_runtimes = rt_json
            .get("lambda_runtimes")
            .and_then(|v| v.get("eol"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let create_blocked_runtimes = rt_json
            .get("lambda_runtimes")
            .and_then(|v| v.get("create_blocked"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        LifecycleStore {
            resource_lifecycle,
            deprecated_runtimes,
            create_blocked_runtimes,
            eol_runtimes,
        }
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
        let lowercase_to_canonical: HashMap<String, String> = known_types
            .keys()
            .map(|k| (k.to_lowercase(), k.clone()))
            .collect();
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
        self.enums
            .get(&key)
            .and_then(|regions| regions.get(region))
            .map(|v| v.as_slice())
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
        assert!(
            store.len() > 0,
            "store should have schemas, got {}",
            store.len()
        );
    }

    #[test]
    fn store_get_known_type() {
        let store = CompiledSchemaStore::new();
        let schema = store
            .get("AWS::S3::Bucket")
            .expect("expected AWS::S3::Bucket schema");
        assert_eq!(schema.type_name, "AWS::S3::Bucket");
    }

    #[test]
    fn store_get_unknown_type_returns_none() {
        let store = CompiledSchemaStore::new();
        assert!(
            store.get("AWS::Fake::NonExistent").is_none(),
            "unknown type should return None"
        );
    }

    #[test]
    fn store_no_region_data_always_available() {
        let store = CompiledSchemaStore::new();
        assert!(!store.has_region_data());
        assert!(store.is_available_in_region("AWS::S3::Bucket", "us-east-1"));
        assert!(store.is_available_in_region("AWS::Fake::Type", "us-west-2"));
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
        let mut store = CompiledSchemaStore::new();
        store.load_region_data(b"not json");
        assert!(!store.has_region_data());
    }

    #[test]
    fn store_load_region_data_wrong_structure_no_panic() {
        let mut store = CompiledSchemaStore::new();
        store.load_region_data(b"{}");
        assert!(!store.has_region_data());
    }

    #[test]
    fn ref_type_store_loads_from_embedded_data() {
        let store = CompiledSchemaStore::new();
        let rt = store.ref_types();
        let vpc_ref = rt.ref_type_for("AWS::EC2::VPC");
        assert_eq!(
            vpc_ref,
            Some("string"),
            "expected Ref to VPC to return string"
        );
    }

    #[test]
    fn ref_type_unknown_resource_returns_none() {
        let store = CompiledSchemaStore::new();
        assert_eq!(
            store.ref_types().ref_type_for("AWS::Fake::Thing"),
            None,
            "unknown type should have no ref type"
        );
    }

    #[test]
    fn getatt_type_for_known_attribute() {
        let store = CompiledSchemaStore::new();
        let rt = store.ref_types();
        let sg = rt.getatt_type_for("AWS::EC2::VPC", "DefaultSecurityGroup");
        assert!(
            sg.is_some(),
            "expected GetAtt type for VPC.DefaultSecurityGroup"
        );
    }

    #[test]
    fn getatt_type_unknown_attribute_returns_none() {
        let store = CompiledSchemaStore::new();
        assert!(
            store
                .ref_types()
                .getatt_type_for("AWS::EC2::VPC", "FakeAttr")
                .is_none()
        );
    }

    #[test]
    fn format_compatible_types_vpc_id() {
        let store = CompiledSchemaStore::new();
        let compatible = store
            .ref_types()
            .format_compatible_types("AWS::EC2::VPC.Id");
        assert!(
            compatible.iter().any(|t| t == "AWS::EC2::VPC"),
            "expected AWS::EC2::VPC in format-compatible types for VPC.Id, got: {:?}",
            compatible
        );
    }

    #[test]
    fn format_compatible_types_unknown_format_empty() {
        let store = CompiledSchemaStore::new();
        assert!(
            store
                .ref_types()
                .format_compatible_types("FakeFormat")
                .is_empty()
        );
    }

    #[test]
    fn lifecycle_store_loads() {
        let store = CompiledSchemaStore::new();
        let lc = store.lifecycle();
        let entry = lc.resource_lifecycle("AWS::CodeStar::GitHubRepository");
        assert!(
            entry.is_some(),
            "expected lifecycle entry for AWS::CodeStar::GitHubRepository"
        );
        assert_eq!(entry.unwrap().status, "shutdown");
    }

    #[test]
    fn lifecycle_unknown_type_returns_none() {
        let store = CompiledSchemaStore::new();
        assert!(
            store
                .lifecycle()
                .resource_lifecycle("AWS::S3::Bucket")
                .is_none()
        );
    }

    #[test]
    fn runtime_eol_detection() {
        let store = CompiledSchemaStore::new();
        let lc = store.lifecycle();
        assert!(
            lc.is_runtime_eol("python2.7"),
            "expected python2.7 to be EOL"
        );
        assert!(
            !lc.is_runtime_eol("python3.12"),
            "python3.12 should not be EOL"
        );
    }

    #[test]
    fn runtime_deprecated_detection() {
        let store = CompiledSchemaStore::new();
        let lc = store.lifecycle();
        assert!(
            !lc.is_runtime_deprecated("python3.12"),
            "python3.12 should not be deprecated"
        );
    }

    #[test]
    fn extension_store_remap_keys() {
        let mut extensions = ExtensionStore {
            extensions: HashMap::new(),
        };
        extensions
            .extensions
            .insert("Aws::S3::Bucket".into(), vec![json!({"test": true})]);

        let mut known = HashMap::new();
        known.insert(
            "AWS::S3::Bucket".into(),
            CompiledSchema {
                type_name: "AWS::S3::Bucket".into(),
                ..Default::default()
            },
        );

        extensions.remap_keys(&known);
        assert!(
            extensions.get("AWS::S3::Bucket").is_some(),
            "expected remapped key"
        );
        assert!(
            extensions.get("Aws::S3::Bucket").is_none(),
            "old key should be removed"
        );
    }

    #[test]
    fn extension_store_remap_preserves_canonical_keys() {
        let mut extensions = ExtensionStore {
            extensions: HashMap::new(),
        };
        extensions
            .extensions
            .insert("AWS::S3::Bucket".into(), vec![json!({"test": true})]);

        let mut known = HashMap::new();
        known.insert(
            "AWS::S3::Bucket".into(),
            CompiledSchema {
                type_name: "AWS::S3::Bucket".into(),
                ..Default::default()
            },
        );

        extensions.remap_keys(&known);
        assert!(
            extensions.get("AWS::S3::Bucket").is_some(),
            "canonical key should be preserved"
        );
    }

    #[test]
    fn region_enum_get_unknown_returns_none() {
        let store = CompiledSchemaStore::new();
        assert!(
            store
                .region_enums()
                .get("AWS::Fake::Type", "FakeProp", "us-east-1")
                .is_none()
        );
    }

    #[test]
    fn region_enum_store_from_empty_bytes() {
        let re = RegionEnumStore::load(b"{}");
        assert!(!re.has_data());
        assert!(
            re.get("AWS::EC2::Instance", "InstanceType", "us-east-1")
                .is_none()
        );
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
        let vals = re
            .get("AWS::EC2::Instance", "InstanceType", "us-east-1")
            .expect("expected enum values for us-east-1");
        assert_eq!(vals, &["t2.micro", "t3.micro"]);
        assert_eq!(
            re.get("AWS::EC2::Instance", "InstanceType", "ap-south-1"),
            None,
            "ap-south-1 should have no enum values"
        );
    }
}
