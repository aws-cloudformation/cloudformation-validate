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
    // schema-validator
    ("compiled_schemas", "COMPILED_SCHEMAS"),
    ("ref_types", "REF_TYPES"),
    ("extensions", "EXTENSIONS"),
    ("region_enums", "REGION_ENUMS"),
    ("resource_lifecycle", "RESOURCE_LIFECYCLE"),
    ("lambda_runtimes", "LAMBDA_RUNTIMES"),
    // shared across all engines
    ("schema_metadata", "SCHEMA_METADATA"),
    ("iam_action_resource_patterns", "IAM_ACTION_RESOURCE_PATTERNS"),
    ("region_resource_types", "REGION_RESOURCE_TYPES"),
    ("primary_identifiers", "PRIMARY_IDENTIFIERS"),
    ("getatt_attributes", "GETATT_ATTRIBUTES"),
    ("known_resource_types", "KNOWN_RESOURCE_TYPES"),
    ("stateful_resource_types", "STATEFUL_RESOURCE_TYPES"),
    ("aws_api_operation_catalog", "AWS_API_OPERATION_CATALOG"),
    // Tables extracted from cfn-lint rule code during sync
    ("retention_period_requirements", "RETENTION_PERIOD_REQUIREMENTS"),
    ("codepipeline_action_artifact_counts", "CODEPIPELINE_ACTION_ARTIFACT_COUNTS"),
    ("aws_rds_dbinstance_dbinstanceclass_enum", "AWS_RDS_DBINSTANCE_DBINSTANCECLASS_ENUM"),
    ("aws_ec2_instance_instancetype_enum", "AWS_EC2_INSTANCE_INSTANCETYPE_ENUM"),
    ("aws_emr_cluster_instancetypeconfig_instancetype_enum", "AWS_EMR_CLUSTER_INSTANCETYPECONFIG_INSTANCETYPE_ENUM"),
    ("aws_gamelift_fleet_ec2instancetype_enum", "AWS_GAMELIFT_FLEET_EC2INSTANCETYPE_ENUM"),
    ("aws_appstream_fleet_instancetype_enum", "AWS_APPSTREAM_FLEET_INSTANCETYPE_ENUM"),
    ("aws_dax_cluster_nodetype_enum", "AWS_DAX_CLUSTER_NODETYPE_ENUM"),
    ("aws_docdb_dbinstance_dbinstanceclass_enum", "AWS_DOCDB_DBINSTANCE_DBINSTANCECLASS_ENUM"),
    ("aws_elasticache_cachecluster_cachenodetype_enum", "AWS_ELASTICACHE_CACHECLUSTER_CACHENODETYPE_ENUM"),
    (
        "aws_managedblockchain_node_nodeconfiguration_instancetype_enum",
        "AWS_MANAGEDBLOCKCHAIN_NODE_NODECONFIGURATION_INSTANCETYPE_ENUM",
    ),
    ("aws_neptune_dbinstance_dbinstanceclass_enum", "AWS_NEPTUNE_DBINSTANCE_DBINSTANCECLASS_ENUM"),
    ("aws_rds_dbcluster_dbclusterinstanceclass_enum", "AWS_RDS_DBCLUSTER_DBCLUSTERINSTANCECLASS_ENUM"),
    ("aws_rds_dbinstance_db_instance_class", "AWS_RDS_DBINSTANCE_DB_INSTANCE_CLASS"),
    ("aws_redshift_cluster_nodetype_enum", "AWS_REDSHIFT_CLUSTER_NODETYPE_ENUM"),
    ("aws_amazonmq_broker_instancetype_enum", "AWS_AMAZONMQ_BROKER_INSTANCETYPE_ENUM"),
    ("aws_sagemaker_processing_instancetype_enum", "AWS_SAGEMAKER_PROCESSING_INSTANCETYPE_ENUM"),
    ("aws_sagemaker_hosting_instancetype_enum", "AWS_SAGEMAKER_HOSTING_INSTANCETYPE_ENUM"),
    ("aws_sagemaker_transform_instancetype_enum", "AWS_SAGEMAKER_TRANSFORM_INSTANCETYPE_ENUM"),
    ("aws_sagemaker_cluster_instancetype_enum", "AWS_SAGEMAKER_CLUSTER_INSTANCETYPE_ENUM"),
    (
        "aws_elasticsearch_domain_elasticsearchclusterconfig_instancetype_enum",
        "AWS_ELASTICSEARCH_DOMAIN_ELASTICSEARCHCLUSTERCONFIG_INSTANCETYPE_ENUM",
    ),
    (
        "aws_opensearchservice_domain_clusterconfig_instancetype_enum",
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

    let generated_data_dir = manifest_dir.join("generated").join("data");
    let generated_sv_dir = manifest_dir.join("generated").join("schema-validator");
    let generated_cel_dir = manifest_dir.join("generated").join("cel-rules");
    let handwritten_dir = manifest_dir.join("handwritten");
    let rego_hw_dir = manifest_dir.parent().unwrap().join("rego-engine").join("handwritten").join("rego");

    for dir in [&generated_data_dir, &generated_sv_dir, &generated_cel_dir, &handwritten_dir] {
        println!("cargo:rerun-if-changed={}", dir.display());
    }
    println!("cargo:rerun-if-changed={}", rego_hw_dir.display());

    let mut code = String::new();

    let source_versions_path = generated_data_dir.join(SOURCE_VERSIONS_FILE);
    println!("cargo:rerun-if-changed={}", source_versions_path.display());
    let source_versions = if source_versions_path.exists() {
        let versions = SourceVersions::read(&source_versions_path)
            .and_then(|versions| SourceVersions::new(versions.cfn_lint_version, versions.resource_schema_version))
            .unwrap_or_else(|error| panic!("failed to load required data source versions: {error}"));
        Some(versions)
    } else {
        None
    };
    emit_optional_version(
        "CFN_LINT_VERSION",
        source_versions.as_ref().map(|versions| versions.cfn_lint_version.as_str()),
        &mut code,
    );
    emit_optional_version(
        "RESOURCE_SCHEMA_VERSION",
        source_versions.as_ref().map(|versions| versions.resource_schema_version.as_str()),
        &mut code,
    );

    for (filename, const_name) in GENERATED_JSON {
        let path = resolve_json_file(&generated_data_dir, &generated_sv_dir, filename);
        embed_minified_json(&path, const_name, &out_dir, &mut code);
    }

    for (filename, const_name) in HANDWRITTEN_JSON {
        let path = handwritten_dir.join(format!("{filename}.json"));
        assert_exists(&path, "handwritten");
        embed_minified_json(&path, const_name, &out_dir, &mut code);
    }

    // CEL generated rules
    let cel_rules_path = generated_cel_dir.join("generated_rules.json");
    if !cel_rules_path.exists() {
        fs::create_dir_all(&generated_cel_dir).ok();
        fs::write(&cel_rules_path, "[]").unwrap();
    }
    embed_minified_json(&cel_rules_path, "GENERATED_RULES", &out_dir, &mut code);

    code.push_str("pub const HANDWRITTEN_REGO_POLICIES: &[(&str, &str)] = &[\n");
    if rego_hw_dir.exists() {
        collect_rego_files(&rego_hw_dir, &rego_hw_dir, &mut code);
    }
    code.push_str("];\n");

    code.push_str(
        "\n/// Force-decompress every embedded data LazyLock. Safe to call multiple times (no-op after first).\n",
    );
    code.push_str("pub fn warm_all() {\n");
    for (_filename, const_name) in GENERATED_JSON.iter().chain(HANDWRITTEN_JSON.iter()) {
        code.push_str(&format!("    let _ = &*{}_BYTES;\n", const_name));
    }
    code.push_str("    let _ = &*GENERATED_RULES_BYTES;\n");
    code.push_str("}\n");

    fs::write(out_dir.join("embedded_data.rs"), code).unwrap();
}

fn emit_optional_version(const_name: &str, version: Option<&str>, code: &mut String) {
    match version {
        Some(version) => code.push_str(&format!("pub const {const_name}: Option<&str> = Some({version:?});\n")),
        None => code.push_str(&format!("pub const {const_name}: Option<&str> = None;\n")),
    }
}

/// Find a JSON file in either the generated data or schema-validator directory.
/// Creates an empty stub if missing so the crate compiles from a clean workspace.
fn resolve_json_file(data_dir: &Path, sv_dir: &Path, name: &str) -> PathBuf {
    let data_path = data_dir.join(format!("{name}.json"));
    if data_path.exists() {
        return data_path;
    }
    let sv_path = sv_dir.join(format!("{name}.json"));
    if sv_path.exists() {
        return sv_path;
    }
    // Stub so build.rs succeeds before sync/generate has run.
    fs::create_dir_all(data_dir).ok();
    fs::write(&data_path, "{}").unwrap();
    data_path
}

fn assert_exists(path: &Path, _label: &str) {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(path, "{}").unwrap();
    }
}

/// Minify JSON, compress with zstd level 9, and embed as
/// `pub static NAME_BYTES: LazyLock<Vec<u8>>` that lazily decompresses on first access.
/// Uses `ruzstd` (pure-Rust decoder) at runtime to keep WASM builds portable.
fn embed_minified_json(path: &Path, const_name: &str, out_dir: &Path, code: &mut String) {
    let raw = fs::read_to_string(path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
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

fn collect_rego_files(base: &Path, dir: &Path, code: &mut String) {
    let mut entries: Vec<_> =
        fs::read_dir(dir).unwrap().map(|e| e.expect("failed to read rego directory entry")).collect();
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_rego_files(base, &path, code);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rego") {
            let rel = path.strip_prefix(base).unwrap().display().to_string();
            let content = fs::read_to_string(&path).unwrap();
            code.push_str(&format!("    ({rel:?}, {:?}),\n", content));
        }
    }
}
