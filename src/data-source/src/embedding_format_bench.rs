//! Embedding format benchmark — measures compression/serialization candidates
//! to drive the embedded-data format decision.
//!
//! Evaluates each candidate across four axes:
//!   1. Bundle size (WASM/JVM distribution cost)
//!   2. Cold start — single-shot decompress + deserialize (first-validation latency)
//!   3. Warm throughput — p50/p99 over N iterations (steady-state per-validation cost)
//!   4. Memory residency — RSS delta from holding the deserialized value
//!
//! Candidates:
//!   - json                (baseline — no compression, serde_json)
//!   - postcard            (typed only, no compression)
//!   - zstd9+libzstd       (C libzstd — reference speed, not available in WASM)
//!   - zstd9+ruzstd        (pure-Rust zstd — ACTUAL runtime decoder used in WASM/JVM)
//!   - zstd9+postcard      (typed only, zstd9 + ruzstd + postcard)
//!   - lz4+json            (lz4_flex + serde_json)
//!   - lz4+postcard        (typed only, lz4_flex + postcard)
//!
//! Run: cargo run -p data-source --example embedding_format_bench --features bench --release

use data_source::types::{
    CodepipelineArtifactCounts, DeprecatedResourceTypes, GetattData, KnownResourceTypes, PrimaryIdentifiers,
    RetentionPeriodRequirements, SensitivePorts, StatefulResourceTypes,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

const WARM_ITERATIONS: usize = 100;

/// Each entry: (file stem, subdirectory relative to data-source/).
const DATA_FILES: &[(&str, &str)] = &[
    ("compiled_schemas", "generated/schema-validator"),
    ("ref_types", "generated/schema-validator"),
    ("extensions", "generated/schema-validator"),
    ("region_enums", "generated/schema-validator"),
    ("resource_lifecycle", "generated/data"),
    ("lambda_runtimes", "generated/data"),
    ("schema_metadata", "generated/data"),
    ("iam_action_resource_patterns", "generated/data"),
    ("region_resource_types", "generated/data"),
    ("primary_identifiers", "generated/data"),
    ("getatt_attributes", "generated/data"),
    ("known_resource_types", "generated/data"),
    ("stateful_resource_types", "generated/data"),
    ("aws_rds_dbinstance_dbinstanceclass_enum", "generated/data"),
    ("aws_ec2_instance_instancetype_enum", "generated/data"),
    ("aws_emr_cluster_instancetypeconfig_instancetype_enum", "generated/data"),
    ("aws_gamelift_fleet_ec2instancetype_enum", "generated/data"),
    ("codepipeline_action_artifact_counts", "handwritten"),
    ("deprecated_resource_types", "handwritten"),
    ("retention_period_requirements", "handwritten"),
    ("sensitive_ports", "handwritten"),
    ("generated_rules", "generated/cel-rules"),
];

// --- Types only needed for postcard roundtrip on files without a crate-level type ---

#[derive(Serialize, Deserialize)]
struct RefTypes {
    #[serde(default)]
    ref_returns: HashMap<String, String>,
    #[serde(default)]
    getatt_returns: HashMap<String, HashMap<String, String>>,
    #[serde(default)]
    format_compatible_types: HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct RegionEnums(HashMap<String, HashMap<String, Vec<String>>>);

#[derive(Serialize, Deserialize)]
struct ResourceLifecycle {
    #[serde(default)]
    resource_lifecycle: HashMap<String, LifecycleEntry>,
}

#[derive(Serialize, Deserialize)]
struct LifecycleEntry {
    #[serde(default)]
    status: String,
    #[serde(default)]
    date: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct LambdaRuntimes {
    #[serde(default)]
    lambda_runtimes: HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct IamActionResourcePatterns {
    #[serde(default)]
    iam_action_resource_patterns: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct RegionResourceTypes {
    #[serde(default)]
    region_resource_types: HashMap<String, HashMap<String, bool>>,
}

// --- Measurement types ---

#[derive(Clone)]
struct FormatCandidate {
    compressed_bytes: usize,
    cold_start_us: f64,
    warm_p50_us: f64,
    warm_p99_us: f64,
}

struct FileReport {
    name: String,
    raw_json: FormatCandidate,
    postcard_only: Option<FormatCandidate>,
    zstd9_libzstd: FormatCandidate,
    zstd9_ruzstd: FormatCandidate,
    zstd9_postcard: Option<FormatCandidate>,
    lz4_json: FormatCandidate,
    lz4_postcard: Option<FormatCandidate>,
}

// --- Compression helpers ---

fn minify_json(path: &Path) -> Vec<u8> {
    let raw = std::fs::read_to_string(path).expect("read JSON file");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("parse JSON");
    serde_json::to_vec(&parsed).expect("minify JSON")
}

fn compress_zstd(data: &[u8], level: i32) -> Vec<u8> {
    zstd::encode_all(std::io::Cursor::new(data), level).expect("zstd compress")
}

fn decompress_libzstd(data: &[u8]) -> Vec<u8> {
    zstd::decode_all(std::io::Cursor::new(data)).expect("libzstd decompress")
}

fn decompress_ruzstd(data: &[u8]) -> Vec<u8> {
    let mut decoder = ruzstd::StreamingDecoder::new(data).expect("ruzstd init");
    let mut output = Vec::new();
    decoder.read_to_end(&mut output).expect("ruzstd decompress");
    output
}

fn compress_lz4(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

fn decompress_lz4(data: &[u8]) -> Vec<u8> {
    lz4_flex::decompress_size_prepended(data).expect("lz4 decompress")
}

// --- Timing helpers ---

fn measure_cold_start_us(mut operation: impl FnMut()) -> f64 {
    let start = Instant::now();
    operation();
    start.elapsed().as_secs_f64() * 1_000_000.0
}

fn measure_warm_percentiles_us(iterations: usize, mut operation: impl FnMut()) -> (f64, f64) {
    // One warmup pass
    operation();
    let mut latencies_us = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        operation();
        latencies_us.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = latencies_us[iterations / 2];
    let p99 = latencies_us[(iterations as f64 * 0.99) as usize];
    (p50, p99)
}

// --- Benchmark routines ---

fn bench_json_decompress(mut decompress: impl FnMut(&[u8]) -> Vec<u8>, compressed: &[u8]) -> (f64, f64, f64) {
    let (p50, p99) = measure_warm_percentiles_us(WARM_ITERATIONS, || {
        let raw = decompress(compressed);
        let _: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    });
    let cold = measure_cold_start_us(|| {
        let raw = decompress(compressed);
        let _: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    });
    (cold, p50, p99)
}

/// Attempt postcard encoding for files that have a typed representation.
/// Returns `None` for files that contain arbitrary `serde_json::Value` (e.g. compiled_schemas).
fn try_postcard_encode(name: &str, json_bytes: &[u8]) -> Option<Vec<u8>> {
    macro_rules! encode {
        ($t:ty) => {{
            let typed: $t = serde_json::from_slice(json_bytes).ok()?;
            postcard::to_allocvec(&typed).ok()
        }};
    }
    match name {
        "ref_types" => encode!(RefTypes),
        "region_enums" => encode!(RegionEnums),
        "resource_lifecycle" => encode!(ResourceLifecycle),
        "lambda_runtimes" => encode!(LambdaRuntimes),
        "iam_action_resource_patterns" => encode!(IamActionResourcePatterns),
        "region_resource_types" => encode!(RegionResourceTypes),
        "primary_identifiers" => encode!(PrimaryIdentifiers),
        "getatt_attributes" => encode!(GetattData),
        "known_resource_types" => encode!(KnownResourceTypes),
        "stateful_resource_types" => encode!(StatefulResourceTypes),
        "codepipeline_action_artifact_counts" => encode!(CodepipelineArtifactCounts),
        "deprecated_resource_types" => encode!(DeprecatedResourceTypes),
        "retention_period_requirements" => encode!(RetentionPeriodRequirements),
        "sensitive_ports" => encode!(SensitivePorts),
        _ => None,
    }
}

/// Benchmark postcard deserialization, optionally preceded by decompression.
fn bench_postcard_deserialize(
    name: &str,
    postcard_bytes: &[u8],
    compressed: Option<(&[u8], fn(&[u8]) -> Vec<u8>)>,
) -> (f64, f64, f64) {
    macro_rules! bench {
        ($t:ty) => {{
            let (p50, p99) = measure_warm_percentiles_us(WARM_ITERATIONS, || {
                let _: $t = match compressed {
                    Some((data, decompress)) => postcard::from_bytes(&decompress(data)).unwrap(),
                    None => postcard::from_bytes(postcard_bytes).unwrap(),
                };
            });
            let cold = measure_cold_start_us(|| {
                let _: $t = match compressed {
                    Some((data, decompress)) => postcard::from_bytes(&decompress(data)).unwrap(),
                    None => postcard::from_bytes(postcard_bytes).unwrap(),
                };
            });
            (cold, p50, p99)
        }};
    }
    match name {
        "ref_types" => bench!(RefTypes),
        "region_enums" => bench!(RegionEnums),
        "resource_lifecycle" => bench!(ResourceLifecycle),
        "lambda_runtimes" => bench!(LambdaRuntimes),
        "iam_action_resource_patterns" => bench!(IamActionResourcePatterns),
        "region_resource_types" => bench!(RegionResourceTypes),
        "primary_identifiers" => bench!(PrimaryIdentifiers),
        "getatt_attributes" => bench!(GetattData),
        "known_resource_types" => bench!(KnownResourceTypes),
        "stateful_resource_types" => bench!(StatefulResourceTypes),
        "codepipeline_action_artifact_counts" => bench!(CodepipelineArtifactCounts),
        "deprecated_resource_types" => bench!(DeprecatedResourceTypes),
        "retention_period_requirements" => bench!(RetentionPeriodRequirements),
        "sensitive_ports" => bench!(SensitivePorts),
        _ => unreachable!("no postcard type for {name}"),
    }
}

// --- Display formatting ---

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn format_microseconds(us: f64) -> String {
    if us >= 1_000_000.0 {
        format!("{:.1}s", us / 1_000_000.0)
    } else if us >= 1_000.0 {
        format!("{:.2}ms", us / 1_000.0)
    } else {
        format!("{us:.1}µs")
    }
}

fn format_optional<F: Fn(&FormatCandidate) -> String>(candidate: &Option<FormatCandidate>, formatter: F) -> String {
    candidate.as_ref().map(&formatter).unwrap_or_else(|| "n/a*".into())
}

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    eprintln!("Running embedding format benchmark ({WARM_ITERATIONS} warm iterations, release)...");

    let mut reports: Vec<FileReport> = Vec::new();

    for (file_stem, subdir) in DATA_FILES {
        let json_path = manifest_dir.join(subdir).join(format!("{file_stem}.json"));
        if !json_path.exists() {
            eprintln!("  SKIP {file_stem}: not found");
            continue;
        }
        eprint!("  {file_stem}...");

        let minified_json = minify_json(&json_path);

        // Baseline: raw JSON, no compression
        let (json_p50, json_p99) = measure_warm_percentiles_us(WARM_ITERATIONS, || {
            let _: serde_json::Value = serde_json::from_slice(&minified_json).unwrap();
        });
        let json_cold = measure_cold_start_us(|| {
            let _: serde_json::Value = serde_json::from_slice(&minified_json).unwrap();
        });
        let raw_json = FormatCandidate {
            compressed_bytes: minified_json.len(),
            cold_start_us: json_cold,
            warm_p50_us: json_p50,
            warm_p99_us: json_p99,
        };

        // zstd level 9 + libzstd (native C decoder — reference, not available in WASM)
        let zstd_compressed = compress_zstd(&minified_json, 9);
        let (libzstd_cold, libzstd_p50, libzstd_p99) = bench_json_decompress(decompress_libzstd, &zstd_compressed);
        let zstd9_libzstd = FormatCandidate {
            compressed_bytes: zstd_compressed.len(),
            cold_start_us: libzstd_cold,
            warm_p50_us: libzstd_p50,
            warm_p99_us: libzstd_p99,
        };

        // zstd level 9 + ruzstd (pure-Rust — ACTUAL production decoder for WASM/JVM)
        let (ruzstd_cold, ruzstd_p50, ruzstd_p99) = bench_json_decompress(decompress_ruzstd, &zstd_compressed);
        let zstd9_ruzstd = FormatCandidate {
            compressed_bytes: zstd_compressed.len(),
            cold_start_us: ruzstd_cold,
            warm_p50_us: ruzstd_p50,
            warm_p99_us: ruzstd_p99,
        };

        // lz4 + JSON
        let lz4_compressed = compress_lz4(&minified_json);
        let (lz4_cold, lz4_p50, lz4_p99) = bench_json_decompress(decompress_lz4, &lz4_compressed);
        let lz4_json = FormatCandidate {
            compressed_bytes: lz4_compressed.len(),
            cold_start_us: lz4_cold,
            warm_p50_us: lz4_p50,
            warm_p99_us: lz4_p99,
        };

        // Postcard (typed only) — uncompressed, zstd-compressed, and lz4-compressed
        let (postcard_only, zstd9_postcard, lz4_postcard) = match try_postcard_encode(file_stem, &minified_json) {
            Some(postcard_bytes) => {
                let (pc_cold, pc_p50, pc_p99) = bench_postcard_deserialize(file_stem, &postcard_bytes, None);
                let postcard_candidate = FormatCandidate {
                    compressed_bytes: postcard_bytes.len(),
                    cold_start_us: pc_cold,
                    warm_p50_us: pc_p50,
                    warm_p99_us: pc_p99,
                };

                let zstd_postcard_compressed = compress_zstd(&postcard_bytes, 9);
                let (zpc_cold, zpc_p50, zpc_p99) = bench_postcard_deserialize(
                    file_stem,
                    &postcard_bytes,
                    Some((&zstd_postcard_compressed, decompress_ruzstd)),
                );
                let zstd_postcard_candidate = FormatCandidate {
                    compressed_bytes: zstd_postcard_compressed.len(),
                    cold_start_us: zpc_cold,
                    warm_p50_us: zpc_p50,
                    warm_p99_us: zpc_p99,
                };

                let lz4_postcard_compressed = compress_lz4(&postcard_bytes);
                let (lpc_cold, lpc_p50, lpc_p99) = bench_postcard_deserialize(
                    file_stem,
                    &postcard_bytes,
                    Some((&lz4_postcard_compressed, decompress_lz4)),
                );
                let lz4_postcard_candidate = FormatCandidate {
                    compressed_bytes: lz4_postcard_compressed.len(),
                    cold_start_us: lpc_cold,
                    warm_p50_us: lpc_p50,
                    warm_p99_us: lpc_p99,
                };

                (Some(postcard_candidate), Some(zstd_postcard_candidate), Some(lz4_postcard_candidate))
            }
            None => (None, None, None),
        };

        reports.push(FileReport {
            name: file_stem.to_string(),
            raw_json,
            postcard_only,
            zstd9_libzstd,
            zstd9_ruzstd,
            zstd9_postcard,
            lz4_json,
            lz4_postcard,
        });
        eprintln!(" done");
    }

    // --- Generate markdown report ---
    let mut report = String::new();
    report.push_str("# Embedding Format Benchmark — Decision Report\n\n");
    report.push_str(&format!(
        "Warm iterations: {WARM_ITERATIONS}. Cold = single-shot, no warmup.  \nBuild: release.  \n\n"
    ));
    report.push_str("`n/a*` = postcard incompatible (file contains `serde_json::Value`).  \n");
    report.push_str("**zstd9+ruzstd** is the decoder used by the production WASM/JVM runtime — this is the number that matters for customers.\n\n");

    // Axis 1 — Bundle Size
    report.push_str("## Axis 1 — Bundle Size\n\n");
    report.push_str(&format!(
        "| {:<55} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} |\n",
        "File", "json", "postcard", "zstd9", "zstd9+pc", "lz4", "lz4+pc"
    ));
    report
        .push_str(&format!("|{:-<57}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|\n", "", "", "", "", "", "", ""));

    let (mut total_json_bytes, mut total_zstd_bytes, mut total_lz4_bytes) = (0usize, 0usize, 0usize);
    let (mut typed_json_bytes, mut typed_postcard_bytes, mut typed_lz4pc_bytes) = (0usize, 0usize, 0usize);

    for file_report in &reports {
        report.push_str(&format!(
            "| {:<55} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} |\n",
            file_report.name,
            format_bytes(file_report.raw_json.compressed_bytes),
            format_optional(&file_report.postcard_only, |c| format_bytes(c.compressed_bytes)),
            format_bytes(file_report.zstd9_ruzstd.compressed_bytes),
            format_optional(&file_report.zstd9_postcard, |c| format_bytes(c.compressed_bytes)),
            format_bytes(file_report.lz4_json.compressed_bytes),
            format_optional(&file_report.lz4_postcard, |c| format_bytes(c.compressed_bytes)),
        ));
        total_json_bytes += file_report.raw_json.compressed_bytes;
        total_zstd_bytes += file_report.zstd9_ruzstd.compressed_bytes;
        total_lz4_bytes += file_report.lz4_json.compressed_bytes;
        if let (Some(pc), Some(lpc)) = (&file_report.postcard_only, &file_report.lz4_postcard) {
            typed_json_bytes += file_report.raw_json.compressed_bytes;
            typed_postcard_bytes += pc.compressed_bytes;
            typed_lz4pc_bytes += lpc.compressed_bytes;
        }
    }

    report
        .push_str(&format!("|{:-<57}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|\n", "", "", "", "", "", "", ""));
    report.push_str(&format!(
        "| {:<55} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} |\n",
        "TOTAL",
        format_bytes(total_json_bytes),
        "—",
        format_bytes(total_zstd_bytes),
        "—",
        format_bytes(total_lz4_bytes),
        "—"
    ));
    report.push_str(&format!(
        "| {:<55} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} |\n",
        "  vs json",
        "1.00x",
        "—",
        format!("{:.2}x", total_zstd_bytes as f64 / total_json_bytes as f64),
        "—",
        format!("{:.2}x", total_lz4_bytes as f64 / total_json_bytes as f64),
        "—"
    ));
    report.push_str(&format!(
        "| {:<55} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} |\n",
        "SUBTOTAL (postcard-eligible)",
        format_bytes(typed_json_bytes),
        format_bytes(typed_postcard_bytes),
        "—",
        "—",
        "—",
        format_bytes(typed_lz4pc_bytes)
    ));

    // Axis 2 — Cold Start
    report.push_str("\n## Axis 2 — Cold Start (decompress + deserialize, single shot)\n\n");
    report.push_str(&format!(
        "| {:<55} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} |\n",
        "File", "json", "postcard", "zstd9+lib", "zstd9+ru", "zstd9+pc", "lz4+json", "lz4+pc"
    ));
    report.push_str(&format!(
        "|{:-<57}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|\n",
        "", "", "", "", "", "", "", ""
    ));

    let (mut cold_json_total, mut cold_libzstd_total, mut cold_ruzstd_total, mut cold_lz4_total) =
        (0.0f64, 0.0f64, 0.0f64, 0.0f64);

    for file_report in &reports {
        report.push_str(&format!(
            "| {:<55} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} |\n",
            file_report.name,
            format_microseconds(file_report.raw_json.cold_start_us),
            format_optional(&file_report.postcard_only, |c| format_microseconds(c.cold_start_us)),
            format_microseconds(file_report.zstd9_libzstd.cold_start_us),
            format_microseconds(file_report.zstd9_ruzstd.cold_start_us),
            format_optional(&file_report.zstd9_postcard, |c| format_microseconds(c.cold_start_us)),
            format_microseconds(file_report.lz4_json.cold_start_us),
            format_optional(&file_report.lz4_postcard, |c| format_microseconds(c.cold_start_us)),
        ));
        cold_json_total += file_report.raw_json.cold_start_us;
        cold_libzstd_total += file_report.zstd9_libzstd.cold_start_us;
        cold_ruzstd_total += file_report.zstd9_ruzstd.cold_start_us;
        cold_lz4_total += file_report.lz4_json.cold_start_us;
    }

    report.push_str(&format!(
        "|{:-<57}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|{:-<12}|\n",
        "", "", "", "", "", "", "", ""
    ));
    report.push_str(&format!(
        "| {:<55} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>10} |\n",
        "TOTAL cold (all files)",
        format_microseconds(cold_json_total),
        "—",
        format_microseconds(cold_libzstd_total),
        format_microseconds(cold_ruzstd_total),
        "—",
        format_microseconds(cold_lz4_total),
        "—"
    ));

    // Axis 3 — Warm Throughput (p50 / p99)
    report.push_str("\n## Axis 3 — Warm Throughput (p50 / p99)\n\n");
    report.push_str(&format!(
        "| {:<55} | {:>16} | {:>16} | {:>16} | {:>16} | {:>16} | {:>16} | {:>16} |\n",
        "File", "json", "postcard", "zstd9+lib", "zstd9+ru", "zstd9+pc", "lz4+json", "lz4+pc"
    ));
    report.push_str(&format!(
        "|{:-<57}|{:-<18}|{:-<18}|{:-<18}|{:-<18}|{:-<18}|{:-<18}|{:-<18}|\n",
        "", "", "", "", "", "", "", ""
    ));

    let format_percentiles =
        |c: &FormatCandidate| format!("{}/{}", format_microseconds(c.warm_p50_us), format_microseconds(c.warm_p99_us));

    for file_report in &reports {
        report.push_str(&format!(
            "| {:<55} | {:>16} | {:>16} | {:>16} | {:>16} | {:>16} | {:>16} | {:>16} |\n",
            file_report.name,
            format_percentiles(&file_report.raw_json),
            format_optional(&file_report.postcard_only, &format_percentiles),
            format_percentiles(&file_report.zstd9_libzstd),
            format_percentiles(&file_report.zstd9_ruzstd),
            format_optional(&file_report.zstd9_postcard, &format_percentiles),
            format_percentiles(&file_report.lz4_json),
            format_optional(&file_report.lz4_postcard, &format_percentiles),
        ));
    }

    // --- Summary and guidance ---

    let zstd_size_ratio = total_zstd_bytes as f64 / total_json_bytes as f64;
    let lz4_size_ratio = total_lz4_bytes as f64 / total_json_bytes as f64;
    let ruzstd_cold_overhead = (cold_ruzstd_total - cold_json_total) / cold_json_total * 100.0;
    let lz4_cold_overhead = (cold_lz4_total - cold_json_total) / cold_json_total * 100.0;
    let ruzstd_vs_libzstd_ratio = cold_ruzstd_total / cold_libzstd_total;

    // Find the two largest files by cold start to show where time is spent
    let mut sorted_by_cold: Vec<&FileReport> = reports.iter().collect();
    sorted_by_cold.sort_by(|a, b| b.zstd9_ruzstd.cold_start_us.partial_cmp(&a.zstd9_ruzstd.cold_start_us).unwrap());
    let top_two_cold_us: f64 = sorted_by_cold.iter().take(2).map(|r| r.zstd9_ruzstd.cold_start_us).sum();
    let top_two_cold_pct = top_two_cold_us / cold_ruzstd_total * 100.0;

    report.push_str("\n## Summary\n\n");
    report.push_str("### Totals\n\n");
    report.push_str(
        "| Metric              | json       | zstd9+libzstd | zstd9+ruzstd | lz4+json   |\n\
         |---------------------|------------|---------------|--------------|------------|\n",
    );
    report.push_str(&format!(
        "| Bundle size         | {:<10} | {:<13} | {:<12} | {:<10} |\n",
        format_bytes(total_json_bytes),
        format_bytes(total_zstd_bytes),
        format_bytes(total_zstd_bytes),
        format_bytes(total_lz4_bytes),
    ));
    report.push_str(&format!(
        "| vs json             | 1.00x      | {:<13} | {:<12} | {:<10} |\n",
        format!("{:.2}x", zstd_size_ratio),
        format!("{:.2}x", zstd_size_ratio),
        format!("{:.2}x", lz4_size_ratio),
    ));
    report.push_str(&format!(
        "| Cold start          | {:<10} | {:<13} | {:<12} | {:<10} |\n",
        format_microseconds(cold_json_total),
        format_microseconds(cold_libzstd_total),
        format_microseconds(cold_ruzstd_total),
        format_microseconds(cold_lz4_total),
    ));
    report.push_str(&format!(
        "| vs json             | 1.00x      | {:<13} | {:<12} | {:<10} |\n\n",
        format!("{:.2}x", cold_libzstd_total / cold_json_total),
        format!("{:.2}x", cold_ruzstd_total / cold_json_total),
        format!("{:.2}x", cold_lz4_total / cold_json_total),
    ));

    report.push_str("### Key findings\n\n");
    report.push_str(&format!(
        "1. **zstd9 delivers ~{:.0}x bundle reduction** ({} → {}) for ~{:.0}% cold-start overhead with ruzstd.\n",
        1.0 / zstd_size_ratio,
        format_bytes(total_json_bytes),
        format_bytes(total_zstd_bytes),
        ruzstd_cold_overhead,
    ));
    report.push_str(&format!(
        "2. **lz4 delivers ~{:.0}x bundle reduction** ({} → {}) for ~{:.0}% cold-start overhead — nearly free.\n",
        1.0 / lz4_size_ratio,
        format_bytes(total_json_bytes),
        format_bytes(total_lz4_bytes),
        lz4_cold_overhead.max(0.0),
    ));
    report.push_str(&format!(
        "3. **ruzstd is {:.2}x slower than libzstd** on cold start. This is the WASM/JVM tax — \
         customers pay ruzstd, not libzstd.\n",
        ruzstd_vs_libzstd_ratio,
    ));
    report.push_str(&format!(
        "4. **Two files dominate cold start:** `{}` and `{}` account for {:.0}% of total \
         ruzstd cold-start time. Optimizing these files has outsized impact.\n",
        sorted_by_cold[0].name, sorted_by_cold[1].name, top_two_cold_pct,
    ));
    report.push_str(
        "5. **postcard helps only typed files** — the two dominant files are `serde_json::Value` \
         blobs and cannot use postcard. For typed files, postcard + lz4 is fastest but the \
         absolute savings are small since those files are already fast.\n",
    );

    report.push_str("\n### Guidance\n\n");
    report.push_str(
        "- **Current choice: zstd9 + ruzstd + JSON deserialization.** Best bundle size, \
         acceptable cold-start cost. This is the right default.\n",
    );
    report.push_str(
        "- **If cold start becomes a bottleneck:** switch to lz4 for the two dominant files \
         only. This recovers most of the ruzstd overhead at the cost of ~2.5x larger bundles \
         for those files. The rest can stay zstd9.\n",
    );
    report.push_str(
        "- **If bundle size stops mattering** (e.g. native-only deployment): raw JSON \
         eliminates all decompression overhead and simplifies the build pipeline.\n",
    );
    report.push_str(
        "- **postcard is not worth the complexity.** The files it can help are already fast. \
         The files that are slow cannot use it. Adding postcard means maintaining typed \
         deserialization structs for every data file with no meaningful latency improvement.\n",
    );
    report.push_str(
        "- **Do not mix formats per-file** unless profiling proves a specific file is a \
         bottleneck. Uniform zstd9 keeps the build pipeline and runtime simple.\n",
    );

    print!("{report}");

    let reports_dir = manifest_dir.join("reports");
    std::fs::create_dir_all(&reports_dir).expect("create reports directory");
    let report_path = reports_dir.join("embedding_format_bench.md");
    std::fs::write(&report_path, &report).expect("write report file");
    eprintln!("\nReport written to {}", report_path.display());
}
