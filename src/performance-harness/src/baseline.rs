use crate::worker::Measurement;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCHEMA_VERSION: u32 = 1;
const ENGINES: [&str; 2] = ["rego", "cel"];

#[derive(Debug, Clone)]
struct Workload {
    name: String,
    templates: Vec<PathBuf>,
    iterations: usize,
    gate_process_lifecycle: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Environment {
    context: String,
    system: String,
    architecture: String,
    machine_model: Option<String>,
    cpu_model: Option<String>,
    logical_cpu_count: Option<usize>,
    page_size_bytes: Option<u64>,
    enforce_machine_model: bool,
    #[serde(default)]
    enforce_cpu_model: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MeasurementConfig {
    sample_count: usize,
    confirmation_sample_count: usize,
    discarded_launch_count: usize,
    warmup_iterations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricThreshold {
    minimum_expected: f64,
    regression_factor: f64,
    improvement_factor: f64,
    aggregate_regression_factor: f64,
    aggregate_improvement_factor: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Thresholds {
    init_and_first_ms: MetricThreshold,
    warm_per_call_ms: MetricThreshold,
    peak_rss_bytes: MetricThreshold,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedCase {
    init_and_first_ms: f64,
    warm_per_call_ms: f64,
    peak_rss_bytes: f64,
    gated_metrics: Vec<String>,
    aggregate_metrics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Baseline {
    schema_version: u32,
    profile: String,
    environment: Environment,
    measurement: MeasurementConfig,
    thresholds: Thresholds,
    provenance: Value,
    cases: BTreeMap<String, ExpectedCase>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    init_and_first_ms: f64,
    warm_per_call_ms: f64,
    peak_rss_bytes: f64,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum EvaluationStatus {
    Info,
    Pass,
    Regression,
    Improvement,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MetricEvaluation {
    case: String,
    metric: String,
    expected: f64,
    actual: f64,
    raw_ratio: f64,
    normalized_ratio: f64,
    lower_ratio: f64,
    upper_ratio: f64,
    status: EvaluationStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AggregateEvaluation {
    metric: String,
    ratio: f64,
    lower_bound: f64,
    upper_bound: f64,
    case_count: usize,
    status: EvaluationStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Results<'a> {
    schema_version: u32,
    profile: &'a str,
    revision: String,
    expected_file: String,
    environment: &'a Environment,
    sample_counts: BTreeMap<String, usize>,
    summaries: &'a BTreeMap<String, Summary>,
    evaluations: &'a [MetricEvaluation],
    aggregate_evaluations: &'a [AggregateEvaluation],
    failures: &'a [String],
    measurements: &'a BTreeMap<String, Vec<Measurement>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Metric {
    InitAndFirst,
    WarmPerCall,
    PeakRss,
}

impl Metric {
    const ALL: [Self; 3] = [Self::InitAndFirst, Self::WarmPerCall, Self::PeakRss];

    fn key(self) -> &'static str {
        match self {
            Self::InitAndFirst => "initAndFirstMs",
            Self::WarmPerCall => "warmPerCallMs",
            Self::PeakRss => "peakRssBytes",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::InitAndFirst => "Init + first",
            Self::WarmPerCall => "Warm / call",
            Self::PeakRss => "Peak RSS",
        }
    }

    fn measurement_value(self, measurement: &Measurement) -> f64 {
        match self {
            Self::InitAndFirst => measurement.init_total_ms + measurement.first_validation.wall_ms,
            Self::WarmPerCall => measurement.warm.per_call_total_ms,
            Self::PeakRss => measurement.peak_rss_bytes as f64,
        }
    }

    fn summary_value(self, summary: &Summary) -> f64 {
        match self {
            Self::InitAndFirst => summary.init_and_first_ms,
            Self::WarmPerCall => summary.warm_per_call_ms,
            Self::PeakRss => summary.peak_rss_bytes,
        }
    }

    fn expected_value(self, expected: &ExpectedCase) -> f64 {
        match self {
            Self::InitAndFirst => expected.init_and_first_ms,
            Self::WarmPerCall => expected.warm_per_call_ms,
            Self::PeakRss => expected.peak_rss_bytes,
        }
    }

    fn threshold(self, thresholds: &Thresholds) -> &MetricThreshold {
        match self {
            Self::InitAndFirst => &thresholds.init_and_first_ms,
            Self::WarmPerCall => &thresholds.warm_per_call_ms,
            Self::PeakRss => &thresholds.peak_rss_bytes,
        }
    }

    fn format_value(self, value: f64) -> String {
        match self {
            Self::PeakRss => format!("{:.1} MiB", value / (1024.0 * 1024.0)),
            _ if value < 1.0 => format!("{value:.3} ms"),
            _ => format!("{value:.2} ms"),
        }
    }
}

#[derive(Debug)]
struct EvaluationOutcome {
    metrics: Vec<MetricEvaluation>,
    aggregates: Vec<AggregateEvaluation>,
    failures: Vec<String>,
    confirmation_cases: BTreeSet<String>,
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn expected_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("expected")
}

fn canonical_architecture(architecture: &str) -> String {
    match architecture.to_ascii_lowercase().as_str() {
        "amd64" | "x86_64" => "x86_64".into(),
        "aarch64" | "arm64" => "arm64".into(),
        other => other.into(),
    }
}

fn command_text(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn linux_cpu_model() -> Option<String> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").ok()?;
    cpuinfo.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim().eq_ignore_ascii_case("model name").then(|| value.trim().to_string())
    })
}

pub fn detect_environment() -> Environment {
    let system = match env::consts::OS {
        "macos" => "Darwin",
        "linux" => "Linux",
        other => other,
    }
    .to_string();
    let machine_model = (system == "Darwin").then(|| command_text("sysctl", &["-n", "hw.model"])).flatten();
    let cpu_model = if system == "Darwin" {
        command_text("sysctl", &["-n", "machdep.cpu.brand_string"]).or_else(|| machine_model.clone())
    } else {
        linux_cpu_model()
    };
    let page_size_bytes = if system == "Darwin" {
        command_text("sysctl", &["-n", "hw.pagesize"]).and_then(|value| value.parse().ok())
    } else {
        command_text("getconf", &["PAGESIZE"]).and_then(|value| value.parse().ok())
    };
    Environment {
        context: if env::var("GITHUB_ACTIONS").is_ok_and(|value| value.eq_ignore_ascii_case("true")) {
            "github-actions".into()
        } else {
            "local".into()
        },
        system,
        architecture: canonical_architecture(env::consts::ARCH),
        machine_model,
        cpu_model,
        logical_cpu_count: std::thread::available_parallelism().ok().map(usize::from),
        page_size_bytes,
        enforce_machine_model: false,
        enforce_cpu_model: false,
    }
}

fn github_expected_file(cpu_model: Option<&str>) -> Result<PathBuf, String> {
    let cpu_model = cpu_model.ok_or_else(|| "GitHub runner CPU model could not be detected".to_string())?;
    let file_name = if cpu_model.contains("AMD EPYC 7763") {
        "github-ubuntu-x64-amd-epyc-7763.json"
    } else if cpu_model.contains("AMD EPYC 9V74") {
        "github-ubuntu-x64-amd-epyc-9v74.json"
    } else {
        return Err(format!(
            "no checked-in GitHub performance profile for CPU model {cpu_model:?}; add a calibrated CPU-specific baseline"
        ));
    };
    Ok(expected_directory().join(file_name))
}

pub fn default_expected_file(environment: &Environment) -> Result<PathBuf, String> {
    if environment.context == "github-actions" {
        if environment.system != "Linux" || environment.architecture != "x86_64" {
            return Err("the checked-in GitHub baseline supports only Linux x86_64".into());
        }
        return github_expected_file(environment.cpu_model.as_deref());
    }
    if environment.system == "Darwin" && environment.architecture == "arm64" {
        return Ok(expected_directory().join("local-macos-arm64.json"));
    }
    Err("no default performance profile for this environment; pass --expected explicitly".into())
}

fn validate_environment(expected: &Environment, actual: &Environment) -> Result<(), String> {
    for (name, expected_value, actual_value) in [
        ("context", expected.context.as_str(), actual.context.as_str()),
        ("system", expected.system.as_str(), actual.system.as_str()),
        ("architecture", expected.architecture.as_str(), actual.architecture.as_str()),
    ] {
        if expected_value != actual_value {
            return Err(format!(
                "performance environment mismatch for {name}: expected={expected_value:?} actual={actual_value:?}"
            ));
        }
    }
    if expected.enforce_machine_model {
        let expected_model = expected
            .machine_model
            .as_deref()
            .ok_or_else(|| "baseline enforces machine model without recording one".to_string())?;
        if Some(expected_model) != actual.machine_model.as_deref() {
            return Err(format!(
                "local baseline is for machine model {expected_model:?}, not {:?}",
                actual.machine_model
            ));
        }
    }
    if expected.enforce_cpu_model {
        let expected_cpu = expected
            .cpu_model
            .as_deref()
            .ok_or_else(|| "baseline enforces CPU model without recording one".to_string())?;
        if Some(expected_cpu) != actual.cpu_model.as_deref() {
            return Err(format!("performance baseline is for CPU model {expected_cpu:?}, not {:?}", actual.cpu_model));
        }
    }
    Ok(())
}

fn validate_threshold(metric: Metric, threshold: &MetricThreshold) -> Result<(), String> {
    if !threshold.minimum_expected.is_finite() || threshold.minimum_expected < 0.0 {
        return Err(format!("{} minimumExpected must be finite and non-negative", metric.key()));
    }
    for (name, value) in [
        ("regressionFactor", threshold.regression_factor),
        ("aggregateRegressionFactor", threshold.aggregate_regression_factor),
    ] {
        if !value.is_finite() || value <= 1.0 {
            return Err(format!("{} {name} must be finite and greater than 1", metric.key()));
        }
    }
    for (name, value) in [
        ("improvementFactor", threshold.improvement_factor),
        ("aggregateImprovementFactor", threshold.aggregate_improvement_factor),
    ] {
        if !value.is_finite() || !(0.0..1.0).contains(&value) {
            return Err(format!("{} {name} must be finite and between 0 and 1", metric.key()));
        }
    }
    Ok(())
}

fn validated_metric_set<'a>(case: &str, scope: &str, metrics: &'a [String]) -> Result<BTreeSet<&'a str>, String> {
    let mut unique = BTreeSet::new();
    for metric_name in metrics {
        if !Metric::ALL.iter().any(|metric| metric.key() == metric_name) {
            return Err(format!("{case} {scope} includes unknown metric {metric_name}"));
        }
        if !unique.insert(metric_name.as_str()) {
            return Err(format!("{case} {scope} includes {metric_name} more than once"));
        }
    }
    Ok(unique)
}

fn validate_baseline(baseline: &Baseline) -> Result<(), String> {
    if baseline.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported baseline schemaVersion {}; expected {SCHEMA_VERSION}",
            baseline.schema_version
        ));
    }
    if baseline.profile.is_empty() || baseline.cases.is_empty() {
        return Err("baseline profile and cases must not be empty".into());
    }
    for (name, value) in [
        ("sampleCount", baseline.measurement.sample_count),
        ("confirmationSampleCount", baseline.measurement.confirmation_sample_count),
        ("discardedLaunchCount", baseline.measurement.discarded_launch_count),
        ("warmupIterations", baseline.measurement.warmup_iterations),
    ] {
        if value == 0 {
            return Err(format!("{name} must be positive"));
        }
    }
    for metric in Metric::ALL {
        validate_threshold(metric, metric.threshold(&baseline.thresholds))?;
    }
    for (case, expected) in &baseline.cases {
        let gated_metrics = validated_metric_set(case, "gatedMetrics", &expected.gated_metrics)?;
        let aggregate_metrics = validated_metric_set(case, "aggregateMetrics", &expected.aggregate_metrics)?;
        if !gated_metrics.is_subset(&aggregate_metrics) {
            return Err(format!("{case} gatedMetrics must be a subset of aggregateMetrics"));
        }
        for metric in Metric::ALL {
            let value = metric.expected_value(expected);
            if !value.is_finite() || value <= 0.0 {
                return Err(format!("{case} {} must be finite and positive", metric.key()));
            }
            if (gated_metrics.contains(metric.key()) || aggregate_metrics.contains(metric.key()))
                && value < metric.threshold(&baseline.thresholds).minimum_expected
            {
                return Err(format!("{case} includes {} below its stability floor", metric.key()));
            }
        }
    }
    Ok(())
}

pub fn load_baseline(path: &Path) -> Result<Baseline, String> {
    let bytes = fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let baseline: Baseline =
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid baseline {}: {error}", path.display()))?;
    validate_baseline(&baseline)?;
    Ok(baseline)
}

fn default_profile(profile: &str) -> Result<(MeasurementConfig, Thresholds), String> {
    let measurement = MeasurementConfig {
        sample_count: 5,
        confirmation_sample_count: 4,
        discarded_launch_count: 1,
        warmup_iterations: 2,
    };
    let thresholds = match profile {
        "github-ubuntu-x64-amd-epyc-7763" | "github-ubuntu-x64-amd-epyc-9v74" => Thresholds {
            init_and_first_ms: MetricThreshold {
                minimum_expected: 5.0,
                regression_factor: 1.15,
                improvement_factor: 0.85,
                aggregate_regression_factor: 1.10,
                aggregate_improvement_factor: 0.90,
            },
            warm_per_call_ms: MetricThreshold {
                minimum_expected: 0.30,
                regression_factor: 1.15,
                improvement_factor: 0.85,
                aggregate_regression_factor: 1.10,
                aggregate_improvement_factor: 0.90,
            },
            peak_rss_bytes: MetricThreshold {
                minimum_expected: 16.0 * 1024.0 * 1024.0,
                regression_factor: 1.03,
                improvement_factor: 0.97,
                aggregate_regression_factor: 1.01,
                aggregate_improvement_factor: 0.99,
            },
        },
        "local-macos-arm64" => Thresholds {
            init_and_first_ms: MetricThreshold {
                minimum_expected: 5.0,
                regression_factor: 1.08,
                improvement_factor: 0.92,
                aggregate_regression_factor: 1.07,
                aggregate_improvement_factor: 0.93,
            },
            warm_per_call_ms: MetricThreshold {
                minimum_expected: 0.30,
                regression_factor: 1.08,
                improvement_factor: 0.92,
                aggregate_regression_factor: 1.06,
                aggregate_improvement_factor: 0.94,
            },
            peak_rss_bytes: MetricThreshold {
                minimum_expected: 16.0 * 1024.0 * 1024.0,
                regression_factor: 1.02,
                improvement_factor: 0.98,
                aggregate_regression_factor: 1.01,
                aggregate_improvement_factor: 0.99,
            },
        },
        _ => return Err(format!("unknown performance profile {profile:?}")),
    };
    Ok((measurement, thresholds))
}

fn write_buckets(path: &Path, count: usize, duplicate: bool) -> Result<(), String> {
    let mut text = String::from("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n");
    for index in 0..count {
        let bucket_name =
            if duplicate { "shared-performance-id".to_string() } else { format!("unique-performance-id-{index}") };
        text.push_str(&format!(
            "  Bucket{index}:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: {bucket_name}\n"
        ));
    }
    fs::write(path, text).map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn generate_fixtures(directory: &Path) -> Result<BTreeMap<&'static str, PathBuf>, String> {
    fs::create_dir_all(directory).map_err(|error| format!("could not create {}: {error}", directory.display()))?;
    let tiny = directory.join("tiny.yaml");
    fs::write(
        &tiny,
        "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: performance-baseline-bucket\n",
    )
    .map_err(|error| format!("could not write {}: {error}", tiny.display()))?;
    let unique = directory.join("unique-500.yaml");
    let duplicate = directory.join("duplicate-500.yaml");
    write_buckets(&unique, 500, false)?;
    write_buckets(&duplicate, 500, true)?;

    let conditional = directory.join("conditional-100.yaml");
    let mut conditional_text = String::from(
        "AWSTemplateFormatVersion: '2010-09-09'\nParameters:\n  Environment:\n    Type: String\n    AllowedValues: [a, b]\nConditions:\n  IsA: !Equals [!Ref Environment, a]\n  IsB: !Equals [!Ref Environment, b]\nResources:\n",
    );
    for index in 0..100 {
        let condition = if index % 2 == 0 { "IsA" } else { "IsB" };
        conditional_text.push_str(&format!(
            "  Bucket{index}:\n    Type: AWS::S3::Bucket\n    Condition: {condition}\n    Properties:\n      BucketName: shared-conditional-id\n"
        ));
    }
    fs::write(&conditional, conditional_text)
        .map_err(|error| format!("could not write {}: {error}", conditional.display()))?;
    Ok(BTreeMap::from([("tiny", tiny), ("unique", unique), ("duplicate", duplicate), ("conditional", conditional)]))
}

fn collect_template_paths(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| format!("could not read {}: {error}", directory.display()))? {
        let entry = entry.map_err(|error| format!("could not read entry in {}: {error}", directory.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_template_paths(&path, output)?;
        } else if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension.to_ascii_lowercase().as_str(), "json" | "yaml" | "yml"))
        {
            output.push(path);
        }
    }
    Ok(())
}

fn security_workloads(directory: &Path) -> Result<Vec<Workload>, String> {
    let iteration_counts = BTreeMap::from([
        ("condition_fusion.yaml", 2),
        ("cross_reference_fanout.yaml", 1),
        ("cross_resource_scale.yaml", 3),
        ("deep_intrinsic_resolution.yaml", 2),
        ("deep_nesting.json", 1),
        ("deep_yaml_nesting.yaml", 1),
        ("many_resources.yaml", 5),
        ("pathological_conditions.yaml", 3),
        ("scenario_assignment_budget.yaml", 2),
    ]);
    let mut templates = Vec::new();
    collect_template_paths(directory, &mut templates)?;
    templates.sort();
    templates
        .into_iter()
        .map(|template| {
            let relative = template
                .strip_prefix(directory)
                .map_err(|error| format!("security path {} is invalid: {error}", template.display()))?;
            let mut parts: Vec<String> = relative
                .components()
                .map(|component| component.as_os_str().to_string_lossy().replace('_', "-"))
                .collect();
            let last = parts.last_mut().ok_or_else(|| "security template has no file name".to_string())?;
            if let Some((stem, _)) = last.rsplit_once('.') {
                *last = stem.to_string();
            }
            let file_name = template.file_name().and_then(|name| name.to_str()).unwrap_or_default().to_string();
            Ok(Workload {
                name: format!("security-{}", parts.join("-")),
                templates: vec![template],
                iterations: iteration_counts.get(file_name.as_str()).copied().unwrap_or(2),
                gate_process_lifecycle: !matches!(file_name.as_str(), "deep_nesting.json" | "deep_yaml_nesting.yaml"),
            })
        })
        .collect()
}

fn workload_matrix(fixtures: &BTreeMap<&str, PathBuf>) -> Result<Vec<Workload>, String> {
    let fixture =
        |name: &str| fixtures.get(name).cloned().ok_or_else(|| format!("generated fixture {name:?} is missing"));
    let root = project_root();
    let templates = root.join("src/resources/templates");
    let mut workloads = vec![
        Workload {
            name: "tiny".into(),
            templates: vec![fixture("tiny")?],
            iterations: 151,
            gate_process_lifecycle: true,
        },
        Workload {
            name: "unique-500".into(),
            templates: vec![fixture("unique")?],
            iterations: 9,
            gate_process_lifecycle: true,
        },
        Workload {
            name: "duplicate-500".into(),
            templates: vec![fixture("duplicate")?],
            iterations: 7,
            gate_process_lifecycle: true,
        },
        Workload {
            name: "conditional-100".into(),
            templates: vec![fixture("conditional")?],
            iterations: 15,
            gate_process_lifecycle: true,
        },
        Workload {
            name: "mixed-real".into(),
            templates: vec![
                templates.join("cdk/codepipeline-build-deploy--CodepipelineBuildDeployStack.template.json"),
                templates.join("quickstart/vpc.json"),
            ],
            iterations: 7,
            gate_process_lifecycle: true,
        },
    ];
    workloads.extend(security_workloads(&root.join("src/resources/security"))?);
    Ok(workloads)
}

fn time_arguments() -> Result<Vec<&'static str>, String> {
    if !Path::new("/usr/bin/time").exists() {
        return Err("/usr/bin/time is required for peak RSS measurement".into());
    }
    match env::consts::OS {
        "linux" => Ok(vec!["-v"]),
        "macos" => Ok(vec!["-l"]),
        other => Err(format!("performance measurement is not supported on {other}")),
    }
}

fn first_allowed_cpu() -> Option<String> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let value = status.lines().find_map(|line| line.strip_prefix("Cpus_allowed_list:"))?.trim();
    let first = value.split(',').next()?.split('-').next()?.trim();
    (!first.is_empty()).then(|| first.to_string())
}

fn taskset_prefix() -> Option<(PathBuf, String)> {
    let taskset = ["/usr/bin/taskset", "/bin/taskset"].into_iter().map(PathBuf::from).find(|path| path.exists())?;
    Some((taskset, first_allowed_cpu()?))
}

fn parse_peak_rss(stderr: &str) -> Result<u64, String> {
    for line in stderr.lines() {
        if let Some((_, value)) = line.split_once("Maximum resident set size (kbytes):") {
            return value
                .trim()
                .parse::<u64>()
                .map(|kilobytes| kilobytes * 1024)
                .map_err(|error| format!("invalid Linux peak RSS: {error}"));
        }
        if let Some(value) = line.trim().strip_suffix("maximum resident set size") {
            return value.trim().parse::<u64>().map_err(|error| format!("invalid macOS peak RSS: {error}"));
        }
    }
    Err("maximum resident set size was not present in /usr/bin/time output".into())
}

fn failed_output(command: &str, output: &Output) -> String {
    format!(
        "{command} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_measurement(
    executable: &Path,
    engine: &str,
    workload: &Workload,
    warmup_iterations: usize,
    sample: i32,
) -> Result<Measurement, String> {
    let mut command = Command::new("/usr/bin/time");
    command.args(time_arguments()?);
    if let Some((taskset, cpu)) = taskset_prefix() {
        command.arg(taskset).args(["-c", &cpu]);
    }
    command
        .arg(executable)
        .arg("measure")
        .arg(engine)
        .arg(workload.iterations.to_string())
        .arg(warmup_iterations.to_string())
        .arg(&workload.name)
        .args(&workload.templates);
    let output = command.output().map_err(|error| format!("could not run {}: {error}", workload.name))?;
    if !output.status.success() {
        return Err(failed_output(&format!("{engine}/{}", workload.name), &output));
    }
    let stdout =
        String::from_utf8(output.stdout).map_err(|error| format!("measurement output was not UTF-8: {error}"))?;
    let json_line = stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| format!("measurement emitted no JSON for {engine}/{}", workload.name))?;
    let mut measurement: Measurement = serde_json::from_str(json_line)
        .map_err(|error| format!("measurement JSON was invalid for {engine}/{}: {error}", workload.name))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    measurement.peak_rss_bytes = parse_peak_rss(&stderr)?;
    measurement.sample = sample;
    measurement.gate_process_lifecycle = workload.gate_process_lifecycle;
    Ok(measurement)
}

fn collect_measurements(
    executable: &Path,
    workloads: &[Workload],
    sample_count: usize,
    config: &MeasurementConfig,
    measurements: &mut BTreeMap<String, Vec<Measurement>>,
    selected_cases: Option<&BTreeSet<String>>,
) -> Result<(), String> {
    for engine in ENGINES {
        for workload in workloads {
            let case = format!("{engine}/{}", workload.name);
            if selected_cases.is_some_and(|selected| !selected.contains(&case)) {
                continue;
            }
            let samples = measurements.entry(case.clone()).or_default();
            if samples.is_empty() {
                for discarded in 0..config.discarded_launch_count {
                    eprintln!("Discarding launch {}/{} for {case}", discarded + 1, config.discarded_launch_count);
                    run_measurement(executable, engine, workload, config.warmup_iterations, -((discarded + 1) as i32))?;
                }
            }
            for _ in 0..sample_count {
                let sample = samples.len() as i32;
                eprintln!("Measuring {case} sample {}", sample + 1);
                samples.push(run_measurement(executable, engine, workload, config.warmup_iterations, sample)?);
            }
        }
    }
    Ok(())
}

fn median(mut values: Vec<f64>) -> Result<f64, String> {
    if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
        return Err("median requires finite samples".into());
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) { Ok((values[middle - 1] + values[middle]) / 2.0) } else { Ok(values[middle]) }
}

fn summarize_measurements(
    measurements: &BTreeMap<String, Vec<Measurement>>,
) -> Result<BTreeMap<String, Summary>, String> {
    measurements
        .iter()
        .map(|(case, samples)| {
            let summary = Summary {
                init_and_first_ms: median(
                    samples.iter().map(|sample| Metric::InitAndFirst.measurement_value(sample)).collect(),
                )?,
                warm_per_call_ms: median(
                    samples.iter().map(|sample| Metric::WarmPerCall.measurement_value(sample)).collect(),
                )?,
                peak_rss_bytes: median(
                    samples.iter().map(|sample| Metric::PeakRss.measurement_value(sample)).collect(),
                )?,
            };
            Ok((case.clone(), summary))
        })
        .collect()
}

fn diagnostic_signature(measurement: &Measurement) -> Result<String, String> {
    let fingerprints: Vec<_> = measurement
        .fingerprints
        .iter()
        .map(|item| {
            (
                Path::new(&item.path).file_name().and_then(|name| name.to_str()).unwrap_or_default(),
                item.fingerprint.as_str(),
                item.diagnostics,
                &item.status,
            )
        })
        .collect();
    serde_json::to_string(&(measurement.first_validation.fingerprint.as_str(), fingerprints))
        .map_err(|error| format!("diagnostic signature could not be serialized: {error}"))
}

fn diagnostic_failures(measurements: &BTreeMap<String, Vec<Measurement>>) -> Result<Vec<String>, String> {
    let mut failures = Vec::new();
    for (case, samples) in measurements {
        let Some(first) = samples.first() else {
            return Err(format!("no samples collected for {case}"));
        };
        let expected = diagnostic_signature(first)?;
        for sample in samples.iter().skip(1) {
            if diagnostic_signature(sample)? != expected {
                failures.push(format!("{case}: diagnostic fingerprints changed across performance samples"));
                break;
            }
        }
    }
    Ok(failures)
}

fn expected_case_names(workloads: &[Workload]) -> BTreeSet<String> {
    ENGINES
        .into_iter()
        .flat_map(|engine| workloads.iter().map(move |workload| format!("{engine}/{}", workload.name)))
        .collect()
}

fn validate_case_set(baseline: &Baseline, workloads: &[Workload]) -> Result<(), String> {
    let expected: BTreeSet<_> = baseline.cases.keys().cloned().collect();
    let actual = expected_case_names(workloads);
    if expected == actual {
        return Ok(());
    }
    let missing: Vec<_> = actual.difference(&expected).cloned().collect();
    let obsolete: Vec<_> = expected.difference(&actual).cloned().collect();
    Err(format!(
        "performance workload set differs from the baseline; update it intentionally. missing={missing:?} obsolete={obsolete:?}"
    ))
}

fn evaluation_status(ratio: f64, improvement_factor: f64, regression_factor: f64) -> EvaluationStatus {
    if ratio > regression_factor {
        EvaluationStatus::Regression
    } else if ratio < improvement_factor {
        EvaluationStatus::Improvement
    } else {
        EvaluationStatus::Pass
    }
}

fn geometric_mean(values: &[f64]) -> Result<f64, String> {
    if values.is_empty() || values.iter().any(|value| !value.is_finite() || *value <= 0.0) {
        return Err("geometric mean requires finite positive ratios".into());
    }
    Ok((values.iter().map(|value| value.ln()).sum::<f64>() / values.len() as f64).exp())
}

fn evaluate_performance(
    baseline: &Baseline,
    summaries: &BTreeMap<String, Summary>,
) -> Result<EvaluationOutcome, String> {
    let mut aggregate_ratios: BTreeMap<Metric, Vec<(String, f64)>> = BTreeMap::new();
    for (case, expected_case) in &baseline.cases {
        let summary = summaries.get(case).ok_or_else(|| format!("no measured summary for {case}"))?;
        let aggregate_metrics: BTreeSet<_> = expected_case.aggregate_metrics.iter().map(String::as_str).collect();
        for metric in Metric::ALL {
            if aggregate_metrics.contains(metric.key()) {
                let ratio = metric.summary_value(summary) / metric.expected_value(expected_case);
                aggregate_ratios.entry(metric).or_default().push((case.clone(), ratio));
            }
        }
    }

    let mut aggregates = Vec::new();
    let mut normalizers = BTreeMap::new();
    let mut failures = Vec::new();
    let mut confirmation_cases = BTreeSet::new();
    for metric in Metric::ALL {
        let ratios = aggregate_ratios.get(&metric).cloned().unwrap_or_default();
        if ratios.is_empty() {
            continue;
        }
        let ratio = geometric_mean(&ratios.iter().map(|(_, value)| *value).collect::<Vec<_>>())?;
        normalizers.insert(metric, ratio);
        let threshold = metric.threshold(&baseline.thresholds);
        let status =
            evaluation_status(ratio, threshold.aggregate_improvement_factor, threshold.aggregate_regression_factor);
        aggregates.push(AggregateEvaluation {
            metric: metric.key().into(),
            ratio,
            lower_bound: threshold.aggregate_improvement_factor,
            upper_bound: threshold.aggregate_regression_factor,
            case_count: ratios.len(),
            status,
        });
        match status {
            EvaluationStatus::Regression => {
                failures.push(format!(
                    "aggregate {} regressed to {ratio:.3}x expected across {} cases",
                    metric.label(),
                    ratios.len()
                ));
                confirmation_cases.extend(ratios.iter().map(|(case, _)| case.clone()));
            }
            EvaluationStatus::Improvement => {
                failures.push(format!(
                    "aggregate {} improved to {ratio:.3}x expected across {} cases; confirm it and update the expected file",
                    metric.label(),
                    ratios.len()
                ));
                confirmation_cases.extend(ratios.iter().map(|(case, _)| case.clone()));
            }
            EvaluationStatus::Info | EvaluationStatus::Pass => {}
        }
    }

    let mut metrics = Vec::new();
    for (case, expected_case) in &baseline.cases {
        let summary = summaries.get(case).ok_or_else(|| format!("no measured summary for {case}"))?;
        let gated_metrics: BTreeSet<_> = expected_case.gated_metrics.iter().map(String::as_str).collect();
        for metric in Metric::ALL {
            let expected = metric.expected_value(expected_case);
            let actual = metric.summary_value(summary);
            let raw_ratio = actual / expected;
            let normalized_ratio = raw_ratio / normalizers.get(&metric).copied().unwrap_or(1.0);
            let threshold = metric.threshold(&baseline.thresholds);
            let status = if gated_metrics.contains(metric.key()) {
                evaluation_status(normalized_ratio, threshold.improvement_factor, threshold.regression_factor)
            } else {
                EvaluationStatus::Info
            };
            metrics.push(MetricEvaluation {
                case: case.clone(),
                metric: metric.key().into(),
                expected,
                actual,
                raw_ratio,
                normalized_ratio,
                lower_ratio: threshold.improvement_factor,
                upper_ratio: threshold.regression_factor,
                status,
            });
            match status {
                EvaluationStatus::Regression => {
                    failures.push(format!(
                        "{case}: {} regressed to {normalized_ratio:.3}x normalized ({raw_ratio:.3}x raw; {} vs {} expected)",
                        metric.label(),
                        metric.format_value(actual),
                        metric.format_value(expected)
                    ));
                    confirmation_cases.insert(case.clone());
                }
                EvaluationStatus::Improvement => {
                    failures.push(format!(
                        "{case}: {} improved to {normalized_ratio:.3}x normalized ({raw_ratio:.3}x raw); confirm it and update the expected file",
                        metric.label()
                    ));
                    confirmation_cases.insert(case.clone());
                }
                EvaluationStatus::Info | EvaluationStatus::Pass => {}
            }
        }
    }
    Ok(EvaluationOutcome { metrics, aggregates, failures, confirmation_cases })
}

fn workload_gates(workload: &Workload, summary: &Summary, thresholds: &Thresholds) -> Vec<String> {
    workload_aggregate_metrics(workload, summary, thresholds)
        .into_iter()
        .filter(|metric| workload.name != "security-cross-reference-fanout" || metric == Metric::PeakRss.key())
        .collect()
}

fn workload_aggregate_metrics(workload: &Workload, summary: &Summary, thresholds: &Thresholds) -> Vec<String> {
    Metric::ALL
        .into_iter()
        .filter(|metric| metric.summary_value(summary) >= metric.threshold(thresholds).minimum_expected)
        .filter(|metric| workload.gate_process_lifecycle || !matches!(metric, Metric::InitAndFirst | Metric::PeakRss))
        .map(|metric| metric.key().to_string())
        .collect()
}

fn command_output(program: &str, arguments: &[&str], directory: &Path) -> Result<String, String> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(directory)
        .output()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if !output.status.success() {
        return Err(failed_output(program, &output));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|error| format!("{program} output was not UTF-8: {error}"))
}

fn provenance() -> Result<Value, String> {
    let root = project_root();
    Ok(json!({
        "gitSha": command_output("git", &["rev-parse", "HEAD"], &root)?,
        "rustVersion": command_output("rustc", &["--version"], &root.join("src"))?,
        "workingTreeDirty": !command_output("git", &["status", "--porcelain"], &root)?.is_empty(),
    }))
}

fn round_milliseconds(value: f64) -> f64 {
    (value * 1_000.0).round() / 1_000.0
}

fn build_candidate(
    profile: &str,
    environment: &Environment,
    measurement: &MeasurementConfig,
    thresholds: &Thresholds,
    summaries: &BTreeMap<String, Summary>,
    workloads: &[Workload],
) -> Result<Baseline, String> {
    let workload_by_name: BTreeMap<_, _> =
        workloads.iter().map(|workload| (workload.name.as_str(), workload)).collect();
    let cases = summaries
        .iter()
        .map(|(case, summary)| {
            let (_, workload_name) = case.split_once('/').ok_or_else(|| format!("invalid case name {case}"))?;
            let workload =
                workload_by_name.get(workload_name).ok_or_else(|| format!("missing workload {workload_name}"))?;
            Ok((
                case.clone(),
                ExpectedCase {
                    init_and_first_ms: round_milliseconds(summary.init_and_first_ms),
                    warm_per_call_ms: round_milliseconds(summary.warm_per_call_ms),
                    peak_rss_bytes: summary.peak_rss_bytes.round(),
                    gated_metrics: workload_gates(workload, summary, thresholds),
                    aggregate_metrics: workload_aggregate_metrics(workload, summary, thresholds),
                },
            ))
        })
        .collect::<Result<_, String>>()?;
    let mut expected_environment = environment.clone();
    expected_environment.enforce_machine_model = profile == "local-macos-arm64";
    expected_environment.enforce_cpu_model = profile.starts_with("github-ubuntu-x64-");
    let baseline = Baseline {
        schema_version: SCHEMA_VERSION,
        profile: profile.into(),
        environment: expected_environment,
        measurement: measurement.clone(),
        thresholds: thresholds.clone(),
        provenance: provenance()?,
        cases,
    };
    validate_baseline(&baseline)?;
    Ok(baseline)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| format!("JSON serialization failed: {error}"))?;
    fs::write(path, [bytes, b"\n".to_vec()].concat())
        .map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn render_markdown(
    baseline: &Baseline,
    revision: &str,
    outcome: &EvaluationOutcome,
    failures: &[String],
    sample_total: usize,
    expected_file: &Path,
) -> Result<String, String> {
    let mut by_case: BTreeMap<&str, BTreeMap<&str, &MetricEvaluation>> = BTreeMap::new();
    for evaluation in &outcome.metrics {
        by_case.entry(&evaluation.case).or_default().insert(&evaluation.metric, evaluation);
    }
    let mut lines = vec![
        "# Expected performance check".to_string(),
        String::new(),
        format!("Profile: `{}`  ", baseline.profile),
        format!("Revision: `{}`  ", &revision[..revision.len().min(12)]),
        format!("Samples per case: up to `{sample_total}`"),
        String::new(),
        "Per-case ratios remove the run-wide geometric-mean host-speed shift; aggregate ratios remain raw current/expected. `(info)` metrics are not gated."
            .to_string(),
        String::new(),
        "| Engine / workload | Init + first | Warm / call | Peak RSS | Status |".to_string(),
        "|---|---:|---:|---:|---|".to_string(),
    ];
    for (case, evaluations) in by_case {
        let mut cells = Vec::new();
        let mut failed = false;
        for metric in Metric::ALL {
            let evaluation = evaluations
                .get(metric.key())
                .ok_or_else(|| format!("missing {} evaluation for {case}", metric.key()))?;
            let suffix = if evaluation.status == EvaluationStatus::Info { " (info)" } else { "" };
            cells.push(format!("{:.3}x{suffix}", evaluation.normalized_ratio));
            failed |= matches!(evaluation.status, EvaluationStatus::Regression | EvaluationStatus::Improvement);
        }
        lines.push(format!("| {case} | {} | {} |", cells.join(" | "), if failed { "FAIL" } else { "pass" }));
    }
    lines.extend([
        String::new(),
        "## Aggregate ratios".into(),
        String::new(),
        "| Metric | Ratio | Allowed range | Cases | Status |".into(),
        "|---|---:|---:|---:|---|".into(),
    ]);
    for evaluation in &outcome.aggregates {
        let label = Metric::ALL
            .into_iter()
            .find(|metric| metric.key() == evaluation.metric)
            .map(Metric::label)
            .unwrap_or(&evaluation.metric);
        lines.push(format!(
            "| {label} | {:.3}x | {:.3}x–{:.3}x | {} | {:?} |",
            evaluation.ratio, evaluation.lower_bound, evaluation.upper_bound, evaluation.case_count, evaluation.status
        ));
    }
    lines.extend([String::new(), "## Result".into(), String::new()]);
    if failures.is_empty() {
        lines.push("✅ Performance is within the checked-in two-sided expectations.".into());
    } else {
        lines.extend(failures.iter().map(|failure| format!("* ❌ {failure}")));
        lines.extend([
            String::new(),
            "A ready-to-review `performance-candidate-baseline.json` is included in the artifact.".into(),
            "Regressions require a code fix. For a confirmed improvement, replace the expected file with the candidate."
                .into(),
            String::new(),
            "```bash".into(),
            format!(
                "cargo run --locked --release -p performance-harness -- update --expected {}",
                expected_file.display()
            ),
            "```".into(),
        ]);
    }
    Ok(lines.join("\n") + "\n")
}

fn prepare_run(output_dir: &Path) -> Result<(PathBuf, Vec<Workload>), String> {
    fs::create_dir_all(output_dir).map_err(|error| format!("could not create {}: {error}", output_dir.display()))?;
    let fixtures = generate_fixtures(&output_dir.join("fixtures"))?;
    let workloads = workload_matrix(&fixtures)?;
    let executable = env::current_exe().map_err(|error| format!("could not locate performance harness: {error}"))?;
    Ok((executable, workloads))
}

pub fn run_check(expected_file: &Path, output_dir: &Path) -> Result<bool, String> {
    let baseline = load_baseline(expected_file)?;
    let environment = detect_environment();
    validate_environment(&baseline.environment, &environment)?;
    let (executable, workloads) = prepare_run(output_dir)?;
    validate_case_set(&baseline, &workloads)?;
    let mut measurements = BTreeMap::new();
    collect_measurements(
        &executable,
        &workloads,
        baseline.measurement.sample_count,
        &baseline.measurement,
        &mut measurements,
        None,
    )?;
    let mut summaries = summarize_measurements(&measurements)?;
    let mut diagnostic_errors = diagnostic_failures(&measurements)?;
    let mut outcome = evaluate_performance(&baseline, &summaries)?;
    if diagnostic_errors.is_empty() && !outcome.failures.is_empty() {
        eprintln!(
            "Confirming apparent performance change in {} case(s) with {} additional samples",
            outcome.confirmation_cases.len(),
            baseline.measurement.confirmation_sample_count
        );
        collect_measurements(
            &executable,
            &workloads,
            baseline.measurement.confirmation_sample_count,
            &baseline.measurement,
            &mut measurements,
            Some(&outcome.confirmation_cases),
        )?;
        summaries = summarize_measurements(&measurements)?;
        diagnostic_errors = diagnostic_failures(&measurements)?;
        outcome = evaluate_performance(&baseline, &summaries)?;
    }
    let candidate = build_candidate(
        &baseline.profile,
        &environment,
        &baseline.measurement,
        &baseline.thresholds,
        &summaries,
        &workloads,
    )?;
    write_json(&output_dir.join("performance-candidate-baseline.json"), &candidate)?;
    let mut failures = diagnostic_errors;
    failures.extend(outcome.failures.clone());
    let revision = command_output("git", &["rev-parse", "HEAD"], &project_root())?;
    let sample_counts = measurements.iter().map(|(case, samples)| (case.clone(), samples.len())).collect();
    let results = Results {
        schema_version: SCHEMA_VERSION,
        profile: &baseline.profile,
        revision: revision.clone(),
        expected_file: expected_file.display().to_string(),
        environment: &environment,
        sample_counts,
        summaries: &summaries,
        evaluations: &outcome.metrics,
        aggregate_evaluations: &outcome.aggregates,
        failures: &failures,
        measurements: &measurements,
    };
    write_json(&output_dir.join("performance-results.json"), &results)?;
    let sample_total = measurements.values().map(Vec::len).max().unwrap_or(0);
    let markdown = render_markdown(&baseline, &revision, &outcome, &failures, sample_total, expected_file)?;
    fs::write(output_dir.join("performance-results.md"), &markdown)
        .map_err(|error| format!("could not write performance markdown: {error}"))?;
    print!("{markdown}");
    for failure in &failures {
        println!("::error::{failure}");
    }
    Ok(failures.is_empty())
}

pub fn run_update(expected_file: &Path, profile: Option<&str>, output_dir: &Path) -> Result<(), String> {
    let environment = detect_environment();
    let (profile, measurement, thresholds) = if expected_file.exists() {
        let baseline = load_baseline(expected_file)?;
        validate_environment(&baseline.environment, &environment)?;
        (baseline.profile, baseline.measurement, baseline.thresholds)
    } else {
        let profile = profile
            .map(str::to_string)
            .or_else(|| expected_file.file_stem().and_then(|value| value.to_str()).map(str::to_string))
            .ok_or_else(|| "--profile is required to create this baseline".to_string())?;
        let (measurement, thresholds) = default_profile(&profile)?;
        (profile, measurement, thresholds)
    };
    let (executable, workloads) = prepare_run(output_dir)?;
    let mut measurements = BTreeMap::new();
    collect_measurements(&executable, &workloads, measurement.sample_count, &measurement, &mut measurements, None)?;
    let diagnostic_errors = diagnostic_failures(&measurements)?;
    if !diagnostic_errors.is_empty() {
        return Err(diagnostic_errors.join("; "));
    }
    let summaries = summarize_measurements(&measurements)?;
    let candidate = build_candidate(&profile, &environment, &measurement, &thresholds, &summaries, &workloads)?;
    write_json(expected_file, &candidate)?;
    write_json(&output_dir.join("performance-candidate-baseline.json"), &candidate)?;
    println!("Updated expected performance: {}", expected_file.display());
    println!("Measured {} cases with {} samples each", summaries.len(), measurement.sample_count);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::{FirstValidation, WarmMeasurement};

    fn threshold(
        regression: f64,
        improvement: f64,
        aggregate_regression: f64,
        aggregate_improvement: f64,
    ) -> MetricThreshold {
        MetricThreshold {
            minimum_expected: 0.0,
            regression_factor: regression,
            improvement_factor: improvement,
            aggregate_regression_factor: aggregate_regression,
            aggregate_improvement_factor: aggregate_improvement,
        }
    }

    fn synthetic_baseline() -> Baseline {
        let thresholds = Thresholds {
            init_and_first_ms: threshold(1.15, 0.85, 1.10, 0.90),
            warm_per_call_ms: threshold(1.15, 0.85, 1.10, 0.90),
            peak_rss_bytes: threshold(1.03, 0.97, 1.01, 0.99),
        };
        let gated_metrics: Vec<String> = Metric::ALL.into_iter().map(|metric| metric.key().to_string()).collect();
        let expected = ExpectedCase {
            init_and_first_ms: 100.0,
            warm_per_call_ms: 10.0,
            peak_rss_bytes: 100_000_000.0,
            gated_metrics: gated_metrics.clone(),
            aggregate_metrics: gated_metrics,
        };
        Baseline {
            schema_version: SCHEMA_VERSION,
            profile: "test".into(),
            environment: Environment {
                context: "local".into(),
                system: "Test".into(),
                architecture: "test".into(),
                machine_model: None,
                cpu_model: None,
                logical_cpu_count: Some(1),
                page_size_bytes: Some(4096),
                enforce_machine_model: false,
                enforce_cpu_model: false,
            },
            measurement: MeasurementConfig {
                sample_count: 5,
                confirmation_sample_count: 4,
                discarded_launch_count: 1,
                warmup_iterations: 2,
            },
            thresholds,
            provenance: json!({}),
            cases: BTreeMap::from([("cel/one".into(), expected.clone()), ("rego/two".into(), expected)]),
        }
    }

    fn scaled_summaries(scale: f64) -> BTreeMap<String, Summary> {
        synthetic_baseline()
            .cases
            .into_iter()
            .map(|(case, expected)| {
                (
                    case,
                    Summary {
                        init_and_first_ms: expected.init_and_first_ms * scale,
                        warm_per_call_ms: expected.warm_per_call_ms * scale,
                        peak_rss_bytes: expected.peak_rss_bytes * scale,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn stable_performance_passes() {
        let outcome = evaluate_performance(&synthetic_baseline(), &scaled_summaries(1.005)).expect("evaluation");
        assert!(outcome.failures.is_empty());
        assert!(outcome.confirmation_cases.is_empty());
    }

    #[test]
    fn common_host_shift_is_normalized_and_broad_change_still_fails() {
        let baseline = synthetic_baseline();
        let mut within_aggregate_band = scaled_summaries(1.0);
        for summary in within_aggregate_band.values_mut() {
            summary.init_and_first_ms *= 1.09;
            summary.warm_per_call_ms *= 1.09;
        }
        let outcome = evaluate_performance(&baseline, &within_aggregate_band).expect("within aggregate band");
        assert!(outcome.failures.is_empty());
        assert!(
            outcome
                .metrics
                .iter()
                .filter(|evaluation| evaluation.metric != Metric::PeakRss.key())
                .all(|evaluation| (evaluation.normalized_ratio - 1.0).abs() < 1e-12)
        );

        let mut outside_aggregate_band = scaled_summaries(1.0);
        for summary in outside_aggregate_band.values_mut() {
            summary.init_and_first_ms *= 1.11;
            summary.warm_per_call_ms *= 1.11;
        }
        let outcome = evaluate_performance(&baseline, &outside_aggregate_band).expect("outside aggregate band");
        assert!(outcome.failures.iter().any(|failure| failure.starts_with("aggregate Init + first")));
        assert!(outcome.failures.iter().any(|failure| failure.starts_with("aggregate Warm / call")));
    }

    #[test]
    fn tightened_boundaries_are_two_sided_and_inclusive() {
        assert_eq!(evaluation_status(1.15, 0.85, 1.15), EvaluationStatus::Pass);
        assert_eq!(evaluation_status(0.85, 0.85, 1.15), EvaluationStatus::Pass);
        assert_eq!(evaluation_status(1.151, 0.85, 1.15), EvaluationStatus::Regression);
        assert_eq!(evaluation_status(0.849, 0.85, 1.15), EvaluationStatus::Improvement);
        assert_eq!(evaluation_status(1.031, 0.97, 1.03), EvaluationStatus::Regression);
        assert_eq!(evaluation_status(0.969, 0.97, 1.03), EvaluationStatus::Improvement);
    }

    #[test]
    fn expected_timing_precision_is_one_microsecond() {
        assert_eq!(round_milliseconds(123.456_789), 123.457);
    }

    #[test]
    fn per_case_regression_and_improvement_fail() {
        let baseline = synthetic_baseline();
        let mut regression = scaled_summaries(1.0);
        regression.get_mut("cel/one").expect("case").warm_per_call_ms = 15.0;
        let outcome = evaluate_performance(&baseline, &regression).expect("regression evaluation");
        assert!(outcome.failures.iter().any(|failure| failure.contains("regressed")));
        assert!(outcome.confirmation_cases.contains("cel/one"));

        let mut improvement = scaled_summaries(1.0);
        improvement.get_mut("rego/two").expect("case").init_and_first_ms = 60.0;
        let outcome = evaluate_performance(&baseline, &improvement).expect("improvement evaluation");
        assert!(outcome.failures.iter().any(|failure| failure.contains("improved")));
        assert!(outcome.confirmation_cases.contains("rego/two"));
    }

    #[test]
    fn aggregate_regression_and_improvement_fail() {
        let baseline = synthetic_baseline();
        let regression = evaluate_performance(&baseline, &scaled_summaries(1.30)).expect("regression");
        assert!(regression.aggregates.iter().any(|value| value.status == EvaluationStatus::Regression));
        assert_eq!(regression.confirmation_cases, baseline.cases.keys().cloned().collect());

        let improvement = evaluate_performance(&baseline, &scaled_summaries(0.75)).expect("improvement");
        assert!(improvement.aggregates.iter().any(|value| value.status == EvaluationStatus::Improvement));
        assert_eq!(improvement.confirmation_cases, baseline.cases.keys().cloned().collect());
    }

    #[test]
    fn median_rejects_an_outlier() {
        assert_eq!(median(vec![1.0, 100.0, 3.0, 4.0, 5.0]).expect("median"), 4.0);
    }

    #[test]
    fn peak_rss_parses_linux_and_macos_output() {
        assert_eq!(parse_peak_rss("Maximum resident set size (kbytes): 123").expect("linux"), 123 * 1024);
        assert_eq!(parse_peak_rss("456 maximum resident set size").expect("macOS"), 456);
    }

    #[test]
    fn environment_mismatch_fails() {
        let baseline = synthetic_baseline();
        let mut actual = baseline.environment.clone();
        actual.context = "github-actions".into();
        assert!(validate_environment(&baseline.environment, &actual).is_err());
    }

    #[test]
    fn measurement_summary_uses_process_medians() {
        fn measurement(value: f64) -> Measurement {
            Measurement {
                label: "one".into(),
                engine: "cel".into(),
                template_count: 1,
                iterations: 1,
                samples: 1,
                schema_init_ms: value / 2.0,
                engine_init_ms: value / 2.0,
                init_total_ms: value,
                first_validation: FirstValidation {
                    wall_ms: value,
                    internal_ms: value,
                    fingerprint: "same".into(),
                    status: json!("OK"),
                },
                warm: WarmMeasurement {
                    total_ms: value,
                    per_call_total_ms: value,
                    wall_median_ms: value,
                    wall_p95_ms: value,
                    internal_median_ms: value,
                    model_median_ms: value,
                    schema_median_ms: value,
                    rule_median_ms: value,
                    finalize_median_ms: value,
                },
                fingerprints: Vec::new(),
                peak_rss_bytes: value as u64,
                sample: 0,
                gate_process_lifecycle: true,
            }
        }
        let measurements = BTreeMap::from([(
            "cel/one".into(),
            vec![measurement(1.0), measurement(100.0), measurement(3.0), measurement(4.0), measurement(5.0)],
        )]);
        let summary = summarize_measurements(&measurements).expect("summary")["cel/one"];
        assert_eq!(summary.init_and_first_ms, 8.0);
        assert_eq!(summary.warm_per_call_ms, 4.0);
        assert_eq!(summary.peak_rss_bytes, 4.0);
    }

    #[test]
    fn checked_in_baselines_are_valid_and_cover_the_same_cases() {
        let github_7763 = load_baseline(&expected_directory().join("github-ubuntu-x64-amd-epyc-7763.json"))
            .expect("GitHub 7763 baseline");
        let github_9v74 = load_baseline(&expected_directory().join("github-ubuntu-x64-amd-epyc-9v74.json"))
            .expect("GitHub 9V74 baseline");
        let macos = load_baseline(&expected_directory().join("local-macos-arm64.json")).expect("macOS baseline");
        assert_eq!(github_7763.cases.keys().collect::<Vec<_>>(), github_9v74.cases.keys().collect::<Vec<_>>());
        assert_eq!(github_7763.cases.keys().collect::<Vec<_>>(), macos.cases.keys().collect::<Vec<_>>());
        assert_eq!(github_7763.cases.len(), 38);
        assert!(github_7763.environment.enforce_cpu_model);
        assert!(github_9v74.environment.enforce_cpu_model);
        assert_eq!(github_7763.environment.cpu_model.as_deref(), Some("AMD EPYC 7763 64-Core Processor"));
        assert_eq!(github_9v74.environment.cpu_model.as_deref(), Some("AMD EPYC 9V74 80-Core Processor"));
        for (case, expected_7763) in &github_7763.cases {
            let expected_9v74 = &github_9v74.cases[case];
            assert_eq!(expected_7763.gated_metrics, expected_9v74.gated_metrics, "{case} gated metrics");
            assert_eq!(expected_7763.aggregate_metrics, expected_9v74.aggregate_metrics, "{case} aggregate metrics");
        }
        fn assert_threshold(
            threshold: &MetricThreshold,
            regression: f64,
            improvement: f64,
            aggregate_regression: f64,
            aggregate_improvement: f64,
        ) {
            assert_eq!(threshold.regression_factor, regression);
            assert_eq!(threshold.improvement_factor, improvement);
            assert_eq!(threshold.aggregate_regression_factor, aggregate_regression);
            assert_eq!(threshold.aggregate_improvement_factor, aggregate_improvement);
        }
        for github in [&github_7763, &github_9v74] {
            assert_threshold(&github.thresholds.init_and_first_ms, 1.15, 0.85, 1.10, 0.90);
            assert_threshold(&github.thresholds.warm_per_call_ms, 1.15, 0.85, 1.10, 0.90);
            assert_threshold(&github.thresholds.peak_rss_bytes, 1.03, 0.97, 1.01, 0.99);
        }
        assert_threshold(&macos.thresholds.init_and_first_ms, 1.08, 0.92, 1.07, 0.93);
        assert_threshold(&macos.thresholds.warm_per_call_ms, 1.08, 0.92, 1.06, 0.94);
        assert_threshold(&macos.thresholds.peak_rss_bytes, 1.02, 0.98, 1.01, 0.99);
        let fanout = &github_7763.cases["cel/security-cross-reference-fanout"];
        assert_eq!(fanout.gated_metrics, vec![Metric::PeakRss.key()]);
        assert!(fanout.aggregate_metrics.contains(&Metric::InitAndFirst.key().to_string()));
        assert!(fanout.aggregate_metrics.contains(&Metric::WarmPerCall.key().to_string()));
    }

    #[test]
    fn github_cpu_profiles_are_selected_and_enforced() {
        let mut environment = synthetic_baseline().environment;
        environment.context = "github-actions".into();
        environment.system = "Linux".into();
        environment.architecture = "x86_64".into();
        environment.cpu_model = Some("AMD EPYC 7763 64-Core Processor".into());
        assert!(
            default_expected_file(&environment)
                .expect("7763 profile")
                .ends_with("github-ubuntu-x64-amd-epyc-7763.json")
        );
        let baseline = load_baseline(&default_expected_file(&environment).expect("7763 path")).expect("7763 baseline");
        validate_environment(&baseline.environment, &environment).expect("matching CPU");

        environment.cpu_model = Some("AMD EPYC 9V74 80-Core Processor".into());
        assert!(
            default_expected_file(&environment)
                .expect("9V74 profile")
                .ends_with("github-ubuntu-x64-amd-epyc-9v74.json")
        );
        assert!(validate_environment(&baseline.environment, &environment).is_err());

        environment.cpu_model = Some("Unexpected CPU".into());
        assert!(default_expected_file(&environment).is_err());
    }
}
