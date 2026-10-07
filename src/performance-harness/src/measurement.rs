use crate::worker::Measurement;
use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub(crate) const ENGINES: [&str; 3] = ["rego", "cel", "composite"];

/// One template set that every engine validates in a fresh process. `gate_process_lifecycle` is off for workloads
/// whose interesting cost is the deep-nesting parse itself, so only their warm per-call time is compared.
#[derive(Debug, Clone)]
pub(crate) struct Workload {
    pub(crate) name: String,
    templates: Vec<PathBuf>,
    iterations: usize,
    gate_process_lifecycle: bool,
}

impl Workload {
    /// Metrics that are lifecycle-appropriate for this workload and that `is_stable` accepts as measured above their
    /// stability floor; only these contribute to the run-wide aggregate.
    pub(crate) fn aggregate_metrics(&self, is_stable: impl Fn(Metric) -> bool) -> Vec<Metric> {
        Metric::ALL
            .into_iter()
            .filter(|metric| is_stable(*metric))
            .filter(|metric| self.gate_process_lifecycle || !matches!(metric, Metric::InitAndFirst | Metric::PeakRss))
            .collect()
    }

    /// Aggregate metrics that are also enforced per case. The long cross-reference-fanout timings vary per workload
    /// beyond the normal residual range on identical trees, so only its memory is gated individually.
    pub(crate) fn gated_metrics(&self, is_stable: impl Fn(Metric) -> bool) -> Vec<Metric> {
        self.aggregate_metrics(is_stable)
            .into_iter()
            .filter(|metric| self.name != "security-cross-reference-fanout" || *metric == Metric::PeakRss)
            .collect()
    }
}

/// The host a comparison ran on, recorded with the results so that noisy or surprising numbers can be traced back to
/// the hardware that produced them.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Environment {
    context: String,
    system: String,
    architecture: String,
    machine_model: Option<String>,
    cpu_model: Option<String>,
    logical_cpu_count: Option<usize>,
    page_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Metric {
    InitAndFirst,
    WarmPerCall,
    PeakRss,
}

impl Metric {
    pub(crate) const ALL: [Self; 3] = [Self::InitAndFirst, Self::WarmPerCall, Self::PeakRss];

    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::InitAndFirst => "initAndFirstMs",
            Self::WarmPerCall => "warmPerCallMs",
            Self::PeakRss => "peakRssBytes",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::InitAndFirst => "Init + first",
            Self::WarmPerCall => "Warm / call",
            Self::PeakRss => "Peak RSS",
        }
    }

    pub(crate) fn measurement_value(self, measurement: &Measurement) -> f64 {
        match self {
            Self::InitAndFirst => measurement.init_total_ms + measurement.first_validation.wall_ms,
            Self::WarmPerCall => measurement.warm.per_call_total_ms,
            Self::PeakRss => measurement.peak_rss_bytes as f64,
        }
    }

    pub(crate) fn format_value(self, value: f64) -> String {
        match self {
            Self::PeakRss => format!("{:.1} MiB", value / (1024.0 * 1024.0)),
            _ if value < 1.0 => format!("{value:.3} ms"),
            _ => format!("{value:.2} ms"),
        }
    }
}

pub(crate) fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
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

impl Environment {
    pub(crate) fn cpu_model(&self) -> Option<&str> {
        self.cpu_model.as_deref()
    }
}

pub(crate) fn detect_environment() -> Environment {
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
    }
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

pub(crate) fn run_measurement(
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

pub(crate) fn diagnostic_signature(measurement: &Measurement) -> Result<String, String> {
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

pub(crate) fn diagnostic_failures(measurements: &BTreeMap<String, Vec<Measurement>>) -> Result<Vec<String>, String> {
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

pub(crate) fn command_output(program: &str, arguments: &[&str], directory: &Path) -> Result<String, String> {
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

pub(crate) fn prepare_run(output_dir: &Path) -> Result<(PathBuf, Vec<Workload>), String> {
    fs::create_dir_all(output_dir).map_err(|error| format!("could not create {}: {error}", output_dir.display()))?;
    let fixtures = generate_fixtures(&output_dir.join("fixtures"))?;
    let workloads = workload_matrix(&fixtures)?;
    let executable = env::current_exe().map_err(|error| format!("could not locate performance harness: {error}"))?;
    Ok((executable, workloads))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peak_rss_parses_linux_and_macos_output() {
        assert_eq!(parse_peak_rss("Maximum resident set size (kbytes): 123").expect("linux"), 123 * 1024);
        assert_eq!(parse_peak_rss("456 maximum resident set size").expect("macOS"), 456);
        assert!(parse_peak_rss("no memory line").is_err());
    }

    #[test]
    fn workload_matrix_covers_every_engine_and_workload() {
        let fixtures =
            generate_fixtures(&project_root().join("tmp/performance-harness-unit-test/fixtures")).expect("fixtures");
        let workloads = workload_matrix(&fixtures).expect("workloads");
        let names: Vec<&str> = workloads.iter().map(|workload| workload.name.as_str()).collect();
        assert_eq!(workloads.len(), 19, "{names:?}");
        assert!(names.contains(&"tiny") && names.contains(&"mixed-real"), "{names:?}");
        assert!(names.contains(&"security-cross-reference-fanout"), "{names:?}");
        assert_eq!(ENGINES.len() * workloads.len(), 57);
    }

    fn workload(name: &str, gate_process_lifecycle: bool) -> Workload {
        Workload { name: name.into(), templates: Vec::new(), iterations: 1, gate_process_lifecycle }
    }

    #[test]
    fn gated_metrics_follow_lifecycle_and_stability() {
        let every = |_: Metric| true;
        assert_eq!(workload("unique-500", true).gated_metrics(every), Metric::ALL.to_vec());
        assert_eq!(workload("security-deep-nesting", false).gated_metrics(every), vec![Metric::WarmPerCall]);
        assert_eq!(workload("security-cross-reference-fanout", true).gated_metrics(every), vec![Metric::PeakRss]);
        assert_eq!(
            workload("security-cross-reference-fanout", true).aggregate_metrics(every),
            Metric::ALL.to_vec(),
            "fanout timings still contribute to the aggregate"
        );
        let only_memory = |metric: Metric| metric == Metric::PeakRss;
        assert_eq!(workload("tiny", true).gated_metrics(only_memory), vec![Metric::PeakRss]);
    }

    #[test]
    fn metric_values_format_by_magnitude() {
        assert_eq!(Metric::PeakRss.format_value(3.0 * 1024.0 * 1024.0), "3.0 MiB");
        assert_eq!(Metric::WarmPerCall.format_value(0.5), "0.500 ms");
        assert_eq!(Metric::InitAndFirst.format_value(12.345), "12.35 ms");
    }
}
