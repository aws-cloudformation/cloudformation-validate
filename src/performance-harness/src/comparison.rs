use crate::measurement::{self, ENGINES, Environment, Metric, Workload};
use crate::worker::Measurement;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u32 = 1;
const PAIR_COUNT: usize = 5;
const CONFIRMATION_PAIR_COUNT: usize = 4;
const DISCARDED_LAUNCH_COUNT: usize = 1;
const WARMUP_ITERATIONS: usize = 2;
pub(crate) const DEFAULT_TITLE: &str = "Performance comparison against base";

/// Head/base ratio limits. Both sides run on the same host, so the limits only absorb residual launch noise and the
/// natural growth of bundled schema data rather than differences between runner hardware.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegressionLimit {
    case_factor: f64,
    aggregate_factor: f64,
}

fn regression_limit(metric: Metric) -> RegressionLimit {
    match metric {
        Metric::InitAndFirst | Metric::WarmPerCall => RegressionLimit { case_factor: 1.20, aggregate_factor: 1.08 },
        Metric::PeakRss => RegressionLimit { case_factor: 1.10, aggregate_factor: 1.05 },
    }
}

/// Below these base values, process launch and allocator noise dominate the metric, so it is reported but not gated.
fn stability_floor(metric: Metric) -> f64 {
    match metric {
        Metric::InitAndFirst => 5.0,
        Metric::WarmPerCall => 0.30,
        Metric::PeakRss => 16.0 * 1024.0 * 1024.0,
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum EvaluationStatus {
    Info,
    Pass,
    Regression,
    Improvement,
}

fn median(mut values: Vec<f64>) -> Result<f64, String> {
    if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
        return Err("median requires finite samples".into());
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) { Ok((values[middle - 1] + values[middle]) / 2.0) } else { Ok(values[middle]) }
}

fn geometric_mean(values: &[f64]) -> Result<f64, String> {
    if values.is_empty() || values.iter().any(|value| !value.is_finite() || *value <= 0.0) {
        return Err("geometric mean requires finite positive ratios".into());
    }
    Ok((values.iter().map(|value| value.ln()).sum::<f64>() / values.len() as f64).exp())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| format!("JSON serialization failed: {error}"))?;
    fs::write(path, [bytes, b"\n".to_vec()].concat())
        .map_err(|error| format!("could not write {}: {error}", path.display()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Base,
    Head,
}

#[derive(Debug, Default, Serialize)]
struct PairedMeasurements {
    base: Vec<Measurement>,
    head: Vec<Measurement>,
}

impl PairedMeasurements {
    fn side_mut(&mut self, side: Side) -> &mut Vec<Measurement> {
        match side {
            Side::Base => &mut self.base,
            Side::Head => &mut self.head,
        }
    }

    fn launch_pairs(&self, metric: Metric) -> Vec<LaunchPair> {
        self.base
            .iter()
            .zip(&self.head)
            .map(|(base, head)| LaunchPair {
                base: metric.measurement_value(base),
                head: metric.measurement_value(head),
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct LaunchPair {
    base: f64,
    head: f64,
}

#[derive(Debug, Clone)]
struct CaseInput {
    pairs: BTreeMap<Metric, Vec<LaunchPair>>,
    aggregate_metrics: BTreeSet<Metric>,
    gated_metrics: BTreeSet<Metric>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseComparison {
    case: String,
    metric: &'static str,
    base_median: f64,
    head_median: f64,
    ratio: f64,
    limit: f64,
    pair_count: usize,
    status: EvaluationStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AggregateComparison {
    metric: &'static str,
    ratio: f64,
    limit: f64,
    case_count: usize,
    status: EvaluationStatus,
}

#[derive(Debug)]
struct ComparisonOutcome {
    cases: Vec<CaseComparison>,
    aggregates: Vec<AggregateComparison>,
    failures: Vec<String>,
    confirmation_cases: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ComparisonResults<'a> {
    schema_version: u32,
    base_revision: &'a str,
    head_revision: &'a str,
    environment: &'a Environment,
    limits: BTreeMap<&'static str, RegressionLimit>,
    case_comparisons: &'a [CaseComparison],
    aggregate_comparisons: &'a [AggregateComparison],
    diagnostic_changes: &'a [String],
    failures: &'a [String],
    measurements: &'a BTreeMap<String, PairedMeasurements>,
}

/// The ratio of one head launch to the base launch measured beside it; the median of these ratios cancels host speed
/// changes that affect both launches of a pair.
fn median_paired_ratio(pairs: &[LaunchPair]) -> Result<f64, String> {
    if pairs.iter().any(|pair| !(pair.base.is_finite() && pair.base > 0.0 && pair.head.is_finite() && pair.head > 0.0))
    {
        return Err("paired comparison requires finite positive measurements".into());
    }
    median(pairs.iter().map(|pair| pair.head / pair.base).collect())
}

fn classify(ratio: f64, limit: f64) -> EvaluationStatus {
    if ratio > limit {
        EvaluationStatus::Regression
    } else if ratio < 1.0 / limit {
        EvaluationStatus::Improvement
    } else {
        EvaluationStatus::Pass
    }
}

fn evaluate_comparison(inputs: &BTreeMap<String, CaseInput>) -> Result<ComparisonOutcome, String> {
    let mut cases = Vec::new();
    let mut failures = Vec::new();
    let mut confirmation_cases = BTreeSet::new();
    let mut aggregate_ratios: BTreeMap<Metric, Vec<(String, f64)>> = BTreeMap::new();
    for (case, input) in inputs {
        for metric in Metric::ALL {
            let pairs = input.pairs.get(&metric).ok_or_else(|| format!("{case} has no {} pairs", metric.key()))?;
            let ratio = median_paired_ratio(pairs)?;
            let limit = regression_limit(metric).case_factor;
            let status =
                if input.gated_metrics.contains(&metric) { classify(ratio, limit) } else { EvaluationStatus::Info };
            if input.aggregate_metrics.contains(&metric) {
                aggregate_ratios.entry(metric).or_default().push((case.clone(), ratio));
            }
            let base_median = median(pairs.iter().map(|pair| pair.base).collect())?;
            let head_median = median(pairs.iter().map(|pair| pair.head).collect())?;
            if status == EvaluationStatus::Regression {
                failures.push(format!(
                    "{case}: {} regressed to {ratio:.3}x base ({} vs {}; limit {limit:.2}x)",
                    metric.label(),
                    metric.format_value(head_median),
                    metric.format_value(base_median)
                ));
                confirmation_cases.insert(case.clone());
            }
            cases.push(CaseComparison {
                case: case.clone(),
                metric: metric.key(),
                base_median,
                head_median,
                ratio,
                limit,
                pair_count: pairs.len(),
                status,
            });
        }
    }

    let mut aggregates = Vec::new();
    for (metric, ratios) in aggregate_ratios {
        let ratio = geometric_mean(&ratios.iter().map(|(_, ratio)| *ratio).collect::<Vec<_>>())?;
        let limit = regression_limit(metric).aggregate_factor;
        let status = classify(ratio, limit);
        if status == EvaluationStatus::Regression {
            failures.push(format!(
                "aggregate {} regressed to {ratio:.3}x base across {} cases (limit {limit:.2}x)",
                metric.label(),
                ratios.len()
            ));
            confirmation_cases.extend(ratios.iter().map(|(case, _)| case.clone()));
        }
        aggregates.push(AggregateComparison { metric: metric.key(), ratio, limit, case_count: ratios.len(), status });
    }
    Ok(ComparisonOutcome { cases, aggregates, failures, confirmation_cases })
}

fn case_inputs(
    measurements: &BTreeMap<String, PairedMeasurements>,
    workloads: &[Workload],
) -> Result<BTreeMap<String, CaseInput>, String> {
    let workloads_by_name: BTreeMap<_, _> =
        workloads.iter().map(|workload| (workload.name.as_str(), workload)).collect();
    measurements
        .iter()
        .map(|(case, paired)| {
            let (_, workload_name) = case.split_once('/').ok_or_else(|| format!("invalid case name {case}"))?;
            let workload =
                workloads_by_name.get(workload_name).ok_or_else(|| format!("missing workload {workload_name}"))?;
            let pairs: BTreeMap<_, _> =
                Metric::ALL.into_iter().map(|metric| (metric, paired.launch_pairs(metric))).collect();
            let base_medians = pairs
                .iter()
                .map(|(metric, pairs)| Ok((*metric, median(pairs.iter().map(|pair| pair.base).collect())?)))
                .collect::<Result<BTreeMap<_, _>, String>>()?;
            let is_stable =
                |metric: Metric| base_medians.get(&metric).is_some_and(|median| *median >= stability_floor(metric));
            Ok((
                case.clone(),
                CaseInput {
                    aggregate_metrics: workload.aggregate_metrics(is_stable).into_iter().collect(),
                    gated_metrics: workload.gated_metrics(is_stable).into_iter().collect(),
                    pairs,
                },
            ))
        })
        .collect()
}

struct Executables<'a> {
    base: &'a Path,
    head: &'a Path,
}

impl Executables<'_> {
    fn path(&self, side: Side) -> &Path {
        match side {
            Side::Base => self.base,
            Side::Head => self.head,
        }
    }
}

/// Alternates which side launches first in successive pairs so that monotonic host drift during a pair penalizes base
/// and head equally.
fn launch_order(pair_index: usize) -> [Side; 2] {
    if pair_index.is_multiple_of(2) { [Side::Base, Side::Head] } else { [Side::Head, Side::Base] }
}

fn collect_pairs(
    executables: &Executables,
    workloads: &[Workload],
    pair_count: usize,
    measurements: &mut BTreeMap<String, PairedMeasurements>,
    selected_cases: Option<&BTreeSet<String>>,
) -> Result<(), String> {
    for engine in ENGINES {
        for workload in workloads {
            let case = format!("{engine}/{}", workload.name);
            if selected_cases.is_some_and(|selected| !selected.contains(&case)) {
                continue;
            }
            let paired = measurements.entry(case.clone()).or_default();
            if paired.base.is_empty() {
                for discarded in 0..DISCARDED_LAUNCH_COUNT {
                    eprintln!("Discarding launch {}/{DISCARDED_LAUNCH_COUNT} for {case}", discarded + 1);
                    for side in launch_order(discarded) {
                        let sample = -((discarded + 1) as i32);
                        measurement::run_measurement(
                            executables.path(side),
                            engine,
                            workload,
                            WARMUP_ITERATIONS,
                            sample,
                        )?;
                    }
                }
            }
            for _ in 0..pair_count {
                let pair_index = paired.base.len();
                eprintln!("Measuring {case} pair {}", pair_index + 1);
                for side in launch_order(pair_index) {
                    let measurement = measurement::run_measurement(
                        executables.path(side),
                        engine,
                        workload,
                        WARMUP_ITERATIONS,
                        pair_index as i32,
                    )
                    .map_err(|error| format!("{side:?} measurement failed: {error}"))?;
                    paired.side_mut(side).push(measurement);
                }
            }
        }
    }
    Ok(())
}

fn side_measurements(
    measurements: &BTreeMap<String, PairedMeasurements>,
    side: Side,
) -> BTreeMap<String, Vec<Measurement>> {
    measurements
        .iter()
        .map(|(case, paired)| {
            let samples = match side {
                Side::Base => &paired.base,
                Side::Head => &paired.head,
            };
            (case.clone(), samples.clone())
        })
        .collect()
}

fn diagnostic_stability_failures(measurements: &BTreeMap<String, PairedMeasurements>) -> Result<Vec<String>, String> {
    let mut failures = Vec::new();
    for side in [Side::Base, Side::Head] {
        let label = format!("{side:?}").to_ascii_lowercase();
        failures.extend(
            measurement::diagnostic_failures(&side_measurements(measurements, side))?
                .into_iter()
                .map(|failure| format!("{label} {failure}")),
        );
    }
    Ok(failures)
}

/// Cases whose diagnostics differ between base and head. A rule or schema-data change is expected to change them, so
/// this is reported for context and never fails the comparison.
fn diagnostic_changes(measurements: &BTreeMap<String, PairedMeasurements>) -> Result<Vec<String>, String> {
    let mut changes = Vec::new();
    for (case, paired) in measurements {
        let (Some(base), Some(head)) = (paired.base.first(), paired.head.first()) else {
            return Err(format!("no paired samples collected for {case}"));
        };
        if measurement::diagnostic_signature(base)? != measurement::diagnostic_signature(head)? {
            changes.push(case.clone());
        }
    }
    Ok(changes)
}

fn short_revision(revision: &str) -> &str {
    &revision[..revision.len().min(12)]
}

fn render_markdown(
    title: &str,
    base_revision: &str,
    head_revision: &str,
    environment: &Environment,
    outcome: &ComparisonOutcome,
    diagnostic_changes: &[String],
    failures: &[String],
) -> Result<String, String> {
    let mut by_case: BTreeMap<&str, BTreeMap<&str, &CaseComparison>> = BTreeMap::new();
    for comparison in &outcome.cases {
        by_case.entry(&comparison.case).or_default().insert(comparison.metric, comparison);
    }
    let pair_total = outcome.cases.iter().map(|comparison| comparison.pair_count).max().unwrap_or(0);
    let mut lines = vec![
        format!("# {title}"),
        String::new(),
        format!("Base: `{}`  ", short_revision(base_revision)),
        format!("Head: `{}`  ", short_revision(head_revision)),
        format!("CPU: `{}`  ", environment.cpu_model().unwrap_or("unknown")),
        format!("Interleaved launch pairs per case: up to `{pair_total}`"),
        String::new(),
        "Ratios are head / base: the median of per-pair ratios from base and head launches run back to back on the \
         same host (pinned to one CPU where `taskset` is available). Above 1 is slower or larger. `(info)` metrics are below their stability floor and are not \
         gated per case."
            .to_string(),
        String::new(),
        "| Engine / workload | Init + first | Warm / call | Peak RSS | Status |".to_string(),
        "|---|---:|---:|---:|---|".to_string(),
    ];
    for (case, comparisons) in by_case {
        let mut cells = Vec::new();
        let mut regressed = false;
        for metric in Metric::ALL {
            let comparison = comparisons
                .get(metric.key())
                .ok_or_else(|| format!("missing {} comparison for {case}", metric.key()))?;
            let suffix = if comparison.status == EvaluationStatus::Info { " (info)" } else { "" };
            cells.push(format!("{:.3}x{suffix}", comparison.ratio));
            regressed |= comparison.status == EvaluationStatus::Regression;
        }
        lines.push(format!("| {case} | {} | {} |", cells.join(" | "), if regressed { "FAIL" } else { "pass" }));
    }
    lines.extend([
        String::new(),
        "## Aggregate (geometric mean of per-case ratios)".into(),
        String::new(),
        "| Metric | Ratio | Limit | Cases | Status |".into(),
        "|---|---:|---:|---:|---|".into(),
    ]);
    for aggregate in &outcome.aggregates {
        let label = Metric::ALL
            .into_iter()
            .find(|metric| metric.key() == aggregate.metric)
            .map(Metric::label)
            .unwrap_or(aggregate.metric);
        lines.push(format!(
            "| {label} | {:.3}x | {:.2}x | {} | {:?} |",
            aggregate.ratio, aggregate.limit, aggregate.case_count, aggregate.status
        ));
    }
    if !diagnostic_changes.is_empty() {
        lines.extend([
            String::new(),
            format!(
                "Diagnostics differ from base in {} case(s); this is expected when rules or schema data change and \
                 is not gated.",
                diagnostic_changes.len()
            ),
        ]);
    }
    lines.extend([String::new(), "## Result".into(), String::new()]);
    if failures.is_empty() {
        lines.push("✅ No performance regression beyond the head/base limits.".into());
    } else {
        lines.extend(failures.iter().map(|failure| format!("* ❌ {failure}")));
        lines.extend([
            String::new(),
            "Each reported regression was confirmed with additional interleaved pairs. Fix the regression, or record \
             why it is intentional in the review; later changes are compared against the merged revision."
                .into(),
        ]);
    }
    Ok(lines.join("\n") + "\n")
}

pub fn run_compare(
    base_executable: &Path,
    base_revision: &str,
    title: &str,
    output_dir: &Path,
) -> Result<bool, String> {
    let (head_executable, workloads) = measurement::prepare_run(output_dir)?;
    let base_executable = canonical_executable(base_executable)?;
    if base_executable == canonical_executable(&head_executable)? {
        return Err("the base executable must be a separate build from the running head harness".into());
    }
    let executables = Executables { base: &base_executable, head: &head_executable };
    let mut measurements = BTreeMap::new();
    collect_pairs(&executables, &workloads, PAIR_COUNT, &mut measurements, None)?;
    let mut stability_failures = diagnostic_stability_failures(&measurements)?;
    let mut outcome = evaluate_comparison(&case_inputs(&measurements, &workloads)?)?;
    if stability_failures.is_empty() && !outcome.failures.is_empty() {
        eprintln!(
            "Confirming apparent regression in {} case(s) with {CONFIRMATION_PAIR_COUNT} additional pairs",
            outcome.confirmation_cases.len()
        );
        collect_pairs(
            &executables,
            &workloads,
            CONFIRMATION_PAIR_COUNT,
            &mut measurements,
            Some(&outcome.confirmation_cases),
        )?;
        stability_failures = diagnostic_stability_failures(&measurements)?;
        outcome = evaluate_comparison(&case_inputs(&measurements, &workloads)?)?;
    }
    let mut failures = stability_failures;
    failures.extend(outcome.failures.clone());
    let changes = diagnostic_changes(&measurements)?;
    let environment = measurement::detect_environment();
    let head_revision = measurement::command_output("git", &["rev-parse", "HEAD"], &measurement::project_root())?;
    let results = ComparisonResults {
        schema_version: SCHEMA_VERSION,
        base_revision,
        head_revision: &head_revision,
        environment: &environment,
        limits: Metric::ALL.into_iter().map(|metric| (metric.key(), regression_limit(metric))).collect(),
        case_comparisons: &outcome.cases,
        aggregate_comparisons: &outcome.aggregates,
        diagnostic_changes: &changes,
        failures: &failures,
        measurements: &measurements,
    };
    write_json(&output_dir.join("performance-comparison.json"), &results)?;
    let markdown = render_markdown(title, base_revision, &head_revision, &environment, &outcome, &changes, &failures)?;
    fs::write(output_dir.join("performance-comparison.md"), &markdown)
        .map_err(|error| format!("could not write performance comparison markdown: {error}"))?;
    print!("{markdown}");
    for failure in &failures {
        println!("::error::{failure}");
    }
    Ok(failures.is_empty())
}

fn canonical_executable(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path).map_err(|error| format!("executable {} is not accessible: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_metric() -> BTreeSet<Metric> {
        Metric::ALL.into_iter().collect()
    }

    fn case_input(base: [f64; 3], head_scale: [f64; 3], pair_count: usize) -> CaseInput {
        let pairs = Metric::ALL
            .into_iter()
            .zip(base.into_iter().zip(head_scale))
            .map(|(metric, (base, scale))| {
                let pairs = (0..pair_count)
                    .map(|index| {
                        let host_drift = 1.0 + index as f64 * 0.05;
                        LaunchPair { base: base * host_drift, head: base * scale * host_drift }
                    })
                    .collect();
                (metric, pairs)
            })
            .collect();
        CaseInput { pairs, aggregate_metrics: every_metric(), gated_metrics: every_metric() }
    }

    fn uniform_inputs(head_scale: [f64; 3]) -> BTreeMap<String, CaseInput> {
        ["cel/one", "rego/two", "composite/three"]
            .into_iter()
            .map(|case| (case.to_string(), case_input([100.0, 10.0, 100_000_000.0], head_scale, 5)))
            .collect()
    }

    #[test]
    fn identical_revisions_pass_despite_host_drift() {
        let outcome = evaluate_comparison(&uniform_inputs([1.0, 1.0, 1.0])).expect("evaluation");
        assert!(outcome.failures.is_empty());
        assert!(outcome.cases.iter().all(|comparison| (comparison.ratio - 1.0).abs() < 1e-12));
        assert!(outcome.aggregates.iter().all(|aggregate| aggregate.status == EvaluationStatus::Pass));
    }

    #[test]
    fn schema_data_growth_within_limits_passes() {
        let outcome = evaluate_comparison(&uniform_inputs([1.06, 1.05, 1.04])).expect("evaluation");
        assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    }

    #[test]
    fn broad_regression_fails_the_aggregate_and_confirms_every_case() {
        let inputs = uniform_inputs([1.10, 1.0, 1.0]);
        let outcome = evaluate_comparison(&inputs).expect("evaluation");
        assert!(outcome.failures.iter().any(|failure| failure.starts_with("aggregate Init + first regressed")));
        assert_eq!(outcome.confirmation_cases, inputs.keys().cloned().collect());
    }

    #[test]
    fn single_case_regression_fails_only_that_case() {
        let mut inputs: BTreeMap<String, CaseInput> = (0..20)
            .map(|index| (format!("cel/case-{index}"), case_input([100.0, 10.0, 100_000_000.0], [1.0, 1.0, 1.0], 5)))
            .collect();
        inputs.insert("cel/one".into(), case_input([100.0, 10.0, 100_000_000.0], [1.0, 1.30, 1.0], 5));
        let outcome = evaluate_comparison(&inputs).expect("evaluation");
        assert_eq!(outcome.confirmation_cases, BTreeSet::from(["cel/one".to_string()]));
        assert!(outcome.failures.iter().any(|failure| failure.starts_with("cel/one: Warm / call regressed")));
        assert!(!outcome.failures.iter().any(|failure| failure.starts_with("aggregate Warm")));
    }

    #[test]
    fn memory_limits_are_tighter_than_timing_limits() {
        let mut inputs = uniform_inputs([1.0, 1.0, 1.0]);
        inputs.insert("rego/two".into(), case_input([100.0, 10.0, 100_000_000.0], [1.0, 1.0, 1.12], 5));
        let outcome = evaluate_comparison(&inputs).expect("evaluation");
        assert!(outcome.failures.iter().any(|failure| failure.starts_with("rego/two: Peak RSS regressed")));
    }

    #[test]
    fn improvements_are_reported_but_never_fail() {
        let outcome = evaluate_comparison(&uniform_inputs([0.5, 0.5, 0.5])).expect("evaluation");
        assert!(outcome.failures.is_empty());
        assert!(outcome.aggregates.iter().all(|aggregate| aggregate.status == EvaluationStatus::Improvement));
    }

    #[test]
    fn ungated_metrics_are_informational_and_excluded_from_the_aggregate() {
        let mut inputs = uniform_inputs([1.0, 1.0, 1.0]);
        let mut noisy = case_input([100.0, 0.1, 100_000_000.0], [1.0, 3.0, 1.0], 5);
        noisy.gated_metrics.remove(&Metric::WarmPerCall);
        noisy.aggregate_metrics.remove(&Metric::WarmPerCall);
        inputs.insert("cel/tiny".into(), noisy);
        let outcome = evaluate_comparison(&inputs).expect("evaluation");
        assert!(outcome.failures.is_empty());
        let tiny_warm = outcome
            .cases
            .iter()
            .find(|comparison| comparison.case == "cel/tiny" && comparison.metric == Metric::WarmPerCall.key())
            .expect("tiny warm comparison");
        assert_eq!(tiny_warm.status, EvaluationStatus::Info);
        let warm_aggregate =
            outcome.aggregates.iter().find(|aggregate| aggregate.metric == Metric::WarmPerCall.key()).expect("warm");
        assert_eq!(warm_aggregate.case_count, 3);
    }

    #[test]
    fn a_single_outlier_pair_does_not_fail() {
        let mut input = case_input([100.0, 10.0, 100_000_000.0], [1.0, 1.0, 1.0], 5);
        let warm = input.pairs.get_mut(&Metric::WarmPerCall).expect("warm pairs");
        warm[2].head *= 2.0;
        let outcome = evaluate_comparison(&BTreeMap::from([("cel/one".to_string(), input)])).expect("evaluation");
        assert!(outcome.failures.is_empty());
    }

    #[test]
    fn non_positive_measurements_are_rejected() {
        let mut input = case_input([100.0, 10.0, 100_000_000.0], [1.0, 1.0, 1.0], 5);
        input.pairs.get_mut(&Metric::PeakRss).expect("rss pairs")[0].base = 0.0;
        assert!(evaluate_comparison(&BTreeMap::from([("cel/one".to_string(), input)])).is_err());
    }

    /// The workflow reads the whole file as the tag name and fetches `refs/tags/<anchor>`, so the file must contain
    /// nothing but one release tag in the form the release workflow creates.
    #[test]
    fn drift_anchor_is_one_release_tag() {
        let anchor = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("drift-anchor.txt"))
            .expect("drift anchor file");
        let tag = anchor.trim_end_matches('\n');
        assert!(!tag.contains(char::is_whitespace), "one tag and nothing else: {anchor:?}");
        let (version, prerelease) = tag.split_once('-').unwrap_or((tag, ""));
        assert!(prerelease.is_empty() || prerelease == "beta", "unexpected release kind in {tag}");
        let components: Vec<&str> = version.split('.').collect();
        assert_eq!(components.len(), 3, "release tags are MAJOR.MINOR.PATCH: {tag}");
        assert!(components.iter().all(|component| component.parse::<u32>().is_ok()), "{tag}");
    }

    #[test]
    fn median_rejects_an_outlier_and_averages_even_counts() {
        assert_eq!(median(vec![1.0, 100.0, 3.0, 4.0, 5.0]).expect("odd"), 4.0);
        assert_eq!(median(vec![1.0, 2.0, 3.0, 4.0]).expect("even"), 2.5);
        assert!(median(Vec::new()).is_err());
    }

    #[test]
    fn launch_order_alternates() {
        assert_eq!(launch_order(0), [Side::Base, Side::Head]);
        assert_eq!(launch_order(1), [Side::Head, Side::Base]);
        assert_eq!(launch_order(2), [Side::Base, Side::Head]);
    }
}
