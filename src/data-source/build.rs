#[path = "src/rule_data.rs"]
mod cfnlint_rule_data;
#[path = "src/source_versions.rs"]
mod source_versions;

use source_versions::{SOURCE_VERSIONS_FILE, SourceVersions};
use std::env;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

/// All data files are minified, zstd-compressed (level 9), and embedded as
/// `pub static NAME_BYTES: LazyLock<Vec<u8>>` - decompressed lazily on first access.
const GENERATED_JSON: &[(&str, &str)] = &[
    ("schema-validator/compiled_schemas.json", "COMPILED_SCHEMAS"),
    ("schema-validator/ref_types.json", "REF_TYPES"),
    ("schema-validator/extensions.json", "EXTENSIONS"),
    ("schema-validator/region_enums.json", "REGION_ENUMS"),
    ("data/resource_lifecycle.json", "RESOURCE_LIFECYCLE"),
    ("data/lambda_runtimes.json", "LAMBDA_RUNTIMES"),
    ("data/schema_metadata.json", "SCHEMA_METADATA"),
    ("data/iam_action_resource_patterns.json", "IAM_ACTION_RESOURCE_PATTERNS"),
    ("data/region_resource_types.json", "REGION_RESOURCE_TYPES"),
    ("data/primary_identifiers.json", "PRIMARY_IDENTIFIERS"),
    ("data/getatt_attributes.json", "GETATT_ATTRIBUTES"),
    ("data/known_resource_types.json", "KNOWN_RESOURCE_TYPES"),
    ("data/stateful_resource_types.json", "STATEFUL_RESOURCE_TYPES"),
    ("data/retention_period_requirements.json", "RETENTION_PERIOD_REQUIREMENTS"),
    ("data/codepipeline_action_artifact_counts.json", "CODEPIPELINE_ACTION_ARTIFACT_COUNTS"),
    ("data/aws_rds_dbinstance_dbinstanceclass_enum.json", "AWS_RDS_DBINSTANCE_DBINSTANCECLASS_ENUM"),
    ("data/aws_ec2_instance_instancetype_enum.json", "AWS_EC2_INSTANCE_INSTANCETYPE_ENUM"),
    (
        "data/aws_emr_cluster_instancetypeconfig_instancetype_enum.json",
        "AWS_EMR_CLUSTER_INSTANCETYPECONFIG_INSTANCETYPE_ENUM",
    ),
    ("data/aws_gamelift_fleet_ec2instancetype_enum.json", "AWS_GAMELIFT_FLEET_EC2INSTANCETYPE_ENUM"),
    ("data/aws_appstream_fleet_instancetype_enum.json", "AWS_APPSTREAM_FLEET_INSTANCETYPE_ENUM"),
    ("data/aws_dax_cluster_nodetype_enum.json", "AWS_DAX_CLUSTER_NODETYPE_ENUM"),
    ("data/aws_docdb_dbinstance_dbinstanceclass_enum.json", "AWS_DOCDB_DBINSTANCE_DBINSTANCECLASS_ENUM"),
    ("data/aws_elasticache_cachecluster_cachenodetype_enum.json", "AWS_ELASTICACHE_CACHECLUSTER_CACHENODETYPE_ENUM"),
    (
        "data/aws_managedblockchain_node_nodeconfiguration_instancetype_enum.json",
        "AWS_MANAGEDBLOCKCHAIN_NODE_NODECONFIGURATION_INSTANCETYPE_ENUM",
    ),
    ("data/aws_neptune_dbinstance_dbinstanceclass_enum.json", "AWS_NEPTUNE_DBINSTANCE_DBINSTANCECLASS_ENUM"),
    ("data/aws_rds_dbcluster_dbclusterinstanceclass_enum.json", "AWS_RDS_DBCLUSTER_DBCLUSTERINSTANCECLASS_ENUM"),
    ("data/aws_rds_dbinstance_db_instance_class.json", "AWS_RDS_DBINSTANCE_DB_INSTANCE_CLASS"),
    ("data/aws_redshift_cluster_nodetype_enum.json", "AWS_REDSHIFT_CLUSTER_NODETYPE_ENUM"),
    ("data/aws_amazonmq_broker_instancetype_enum.json", "AWS_AMAZONMQ_BROKER_INSTANCETYPE_ENUM"),
    ("data/aws_sagemaker_processing_instancetype_enum.json", "AWS_SAGEMAKER_PROCESSING_INSTANCETYPE_ENUM"),
    ("data/aws_sagemaker_hosting_instancetype_enum.json", "AWS_SAGEMAKER_HOSTING_INSTANCETYPE_ENUM"),
    ("data/aws_sagemaker_transform_instancetype_enum.json", "AWS_SAGEMAKER_TRANSFORM_INSTANCETYPE_ENUM"),
    ("data/aws_sagemaker_cluster_instancetype_enum.json", "AWS_SAGEMAKER_CLUSTER_INSTANCETYPE_ENUM"),
    (
        "data/aws_elasticsearch_domain_elasticsearchclusterconfig_instancetype_enum.json",
        "AWS_ELASTICSEARCH_DOMAIN_ELASTICSEARCHCLUSTERCONFIG_INSTANCETYPE_ENUM",
    ),
    (
        "data/aws_opensearchservice_domain_clusterconfig_instancetype_enum.json",
        "AWS_OPENSEARCHSERVICE_DOMAIN_CLUSTERCONFIG_INSTANCETYPE_ENUM",
    ),
];

/// Handwritten JSON data files (from data-source/handwritten/). These have no
/// faithful cfn-lint source: deprecated_resource_types and sensitive_ports are
/// engine-specific, getatt_return_type_overrides corrects CloudFormation's
/// GetAtt stringification (consumed at generate time, and embedded so runtime
/// overlay-derived GetAtt/Ref metadata preserves the same corrections).
const HANDWRITTEN_JSON: &[(&str, &str)] = &[
    ("deprecated_resource_types", "DEPRECATED_RESOURCE_TYPES"),
    ("sensitive_ports", "SENSITIVE_PORTS"),
    ("secretsmanager_arn_fields", "SECRETSMANAGER_ARN_FIELDS"),
    ("getatt_return_type_overrides", "GETATT_RETURN_TYPE_OVERRIDES"),
];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let generated_dir = manifest_dir.join("generated");
    let generated_data_dir = generated_dir.join("data");
    let generated_sv_dir = generated_dir.join("schema-validator");
    let generated_cel_dir = generated_dir.join("cel-rules");
    let handwritten_dir = manifest_dir.join("handwritten");
    let rego_hw_dir = manifest_dir.parent().unwrap().join("rego-engine").join("handwritten").join("rego");

    for dir in [&generated_data_dir, &generated_sv_dir, &generated_cel_dir, &handwritten_dir] {
        println!("cargo:rerun-if-changed={}", dir.display());
    }
    println!("cargo:rerun-if-changed={}", rego_hw_dir.display());

    let mut code = String::new();

    let source_versions_path = generated_data_dir.join(SOURCE_VERSIONS_FILE);
    println!("cargo:rerun-if-changed={}", source_versions_path.display());
    require_file(&source_versions_path, "data source provenance");
    let source_versions = SourceVersions::read(&source_versions_path)
        .and_then(|versions| SourceVersions::new(versions.cfn_lint_version, versions.resource_schema_version))
        .unwrap_or_else(|error| panic!("failed to load required data source versions: {error}"));
    emit_version("CFN_LINT_VERSION", &source_versions.cfn_lint_version, &mut code);
    emit_version("RESOURCE_SCHEMA_VERSION", &source_versions.resource_schema_version, &mut code);

    for (relative_path, const_name) in GENERATED_JSON {
        let path = generated_dir.join(relative_path);
        require_file(&path, "generated JSON data");
        embed_minified_json(&path, const_name, &out_dir, &mut code);
    }

    let extensions_path = generated_sv_dir.join("extensions.json");
    let extensions: serde_json::Value = serde_json::from_slice(&fs::read(&extensions_path).unwrap_or_else(|error| {
        panic!("failed to read synced extensions from {}: {error}", extensions_path.display())
    }))
    .unwrap_or_else(|error| panic!("failed to parse synced extensions from {}: {error}", extensions_path.display()));
    let rule_data = cfnlint_rule_data::derive_from_extensions(&extensions)
        .unwrap_or_else(|error| panic!("failed to derive rule data from synced extensions: {error}"));
    let rule_data_path = out_dir.join("rule_data.json");
    fs::write(&rule_data_path, serde_json::to_vec(&rule_data).expect("derived rule data should serialize"))
        .unwrap_or_else(|error| panic!("failed to write derived rule data to {}: {error}", rule_data_path.display()));
    embed_minified_json(&rule_data_path, "RULE_DATA", &out_dir, &mut code);

    // Validate the rule_tables document at build time (fail-fast on schema drift or invalid paths).
    // The generated rule-table artifact is mandatory — a missing file or empty `{}` stub is a build
    // error because downstream engines cannot function without this data.
    // Then normalize the outer key from source-specific naming to `rule_tables` for engine consumption.
    {
        let rule_tables_path = generated_data_dir.join("cfnlint_rule_tables.json");
        let rule_tables_bytes = fs::read(&rule_tables_path).unwrap_or_else(|error| {
            panic!(
                "required generated rule tables are missing from {}: {error}. Run the sync pipeline before building.",
                rule_tables_path.display()
            )
        });
        let trimmed = String::from_utf8_lossy(&rule_tables_bytes);
        if trimmed.trim() == "{}" {
            panic!(
                "cfnlint_rule_tables.json is an empty stub ({{}}). \
                 This artifact is mandatory — run the sync pipeline to populate it before building."
            );
        }
        let doc: cfnlint_rule_data::RuleTablesDocument = serde_json::from_slice(&rule_tables_bytes)
            .unwrap_or_else(|error| panic!("rule tables JSON failed typed deserialization: {error}"));
        cfnlint_rule_data::RuleTables::validate(doc.cfnlint_rule_tables)
            .unwrap_or_else(|error| panic!("rule tables validation failed: {error}"));
        // Normalize: re-key the outer wrapper from the source-specific name to `rule_tables`.
        let raw_value: serde_json::Value = serde_json::from_slice(&rule_tables_bytes)
            .unwrap_or_else(|error| panic!("rule tables JSON parse failed: {error}"));
        let inner = raw_value
            .get("cfnlint_rule_tables")
            .cloned()
            .unwrap_or_else(|| panic!("cfnlint_rule_tables.json missing required top-level key 'cfnlint_rule_tables'"));
        let normalized = serde_json::json!({ "rule_tables": inner });
        let normalized_path = out_dir.join("rule_tables.json");
        fs::write(&normalized_path, serde_json::to_vec(&normalized).expect("normalized rule tables should serialize"))
            .unwrap_or_else(|error| {
                panic!("failed to write normalized rule tables to {}: {error}", normalized_path.display())
            });
        embed_minified_json(&normalized_path, "RULE_TABLES", &out_dir, &mut code);
    }

    for (filename, const_name) in HANDWRITTEN_JSON {
        let path = handwritten_dir.join(format!("{filename}.json"));
        require_file(&path, "handwritten JSON data");
        embed_minified_json(&path, const_name, &out_dir, &mut code);
    }

    // The generated CEL rules document is required even when its rules array is empty.
    let cel_rules_path = generated_cel_dir.join("generated_rules.json");
    require_file(&cel_rules_path, "generated CEL rules");
    embed_minified_json(&cel_rules_path, "GENERATED_RULES", &out_dir, &mut code);

    if !rego_hw_dir.is_dir() {
        panic!("missing required handwritten Rego directory: {}", rego_hw_dir.display());
    }
    code.push_str("pub const HANDWRITTEN_REGO_POLICIES: &[(&str, &str)] = &[\n");
    let rego_file_count = collect_rego_files(&rego_hw_dir, &rego_hw_dir, &mut code);
    if rego_file_count == 0 {
        panic!("required handwritten Rego directory contains no .rego files: {}", rego_hw_dir.display());
    }
    code.push_str("];\n");

    code.push_str(
        "\n/// Force-decompress every embedded data LazyLock. Safe to call multiple times (no-op after first).\n",
    );
    code.push_str("pub fn warm_all() {\n");
    for (_filename, const_name) in GENERATED_JSON.iter().chain(HANDWRITTEN_JSON.iter()) {
        code.push_str(&format!("    let _ = &*{}_BYTES;\n", const_name));
    }
    code.push_str("    let _ = &*RULE_DATA_BYTES;\n");
    code.push_str("    let _ = &*RULE_TABLES_BYTES;\n");
    code.push_str("    let _ = &*GENERATED_RULES_BYTES;\n");
    code.push_str("}\n");

    fs::write(out_dir.join("embedded_data.rs"), code).unwrap();
}

fn emit_version(const_name: &str, version: &str, code: &mut String) {
    code.push_str(&format!("pub const {const_name}: &str = {version:?};\n"));
}

fn require_file(path: &Path, label: &str) {
    if !path.is_file() {
        panic!("missing required {label}: {}", path.display());
    }
}

/// Minify JSON, compress with zstd level 9, and embed as
/// `pub static NAME_BYTES: LazyLock<Vec<u8>>` that lazily decompresses on first access.
/// Uses `ruzstd` (pure-Rust decoder) at runtime to keep WASM builds portable.
fn embed_minified_json(path: &Path, const_name: &str, out_dir: &Path, code: &mut String) {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read required JSON document {}: {error}", path.display()));
    let value: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("failed to parse required JSON document {}: {error}", path.display()));
    let object =
        value.as_object().unwrap_or_else(|| panic!("required JSON document must be an object: {}", path.display()));
    if object.is_empty() {
        panic!("required JSON document must not be empty: {}", path.display());
    }
    let minified = serde_json::to_vec(&value).unwrap();
    let compressed = zstd::encode_all(Cursor::new(&minified), 9).unwrap();

    let bin_path = out_dir.join(format!("{}.json.zst", const_name.to_lowercase()));
    fs::write(&bin_path, &compressed).unwrap();

    code.push_str(&format!(
        "pub static {const_name}_BYTES: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {{\n    \
             const COMPRESSED: &[u8] = include_bytes!({:?});\n    \
             let mut decoder = ruzstd::decoding::StreamingDecoder::new(COMPRESSED)\n        \
                 .expect(\"zstd stream init {const_name}\");\n    \
             let mut out = Vec::new();\n    \
             std::io::Read::read_to_end(&mut decoder, &mut out).expect(\"zstd decode {const_name}\");\n    \
             out\n\
         }});\n",
        bin_path.display().to_string(),
    ));
}

fn collect_rego_files(base: &Path, dir: &Path, code: &mut String) -> usize {
    let mut entries: Vec<_> =
        fs::read_dir(dir).unwrap().map(|e| e.expect("failed to read rego directory entry")).collect();
    entries.sort_by_key(|e| e.path());
    let mut file_count = 0;
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            file_count += collect_rego_files(base, &path, code);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let rel = path.strip_prefix(base).unwrap().display().to_string();
            let content = fs::read_to_string(&path).unwrap();
            code.push_str(&format!("    ({rel:?}, {:?}),\n", content));
            file_count += 1;
        }
    }
    file_count
}
