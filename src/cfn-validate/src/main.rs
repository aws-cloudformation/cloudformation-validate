use std::{collections::HashMap, env, fs, path::Path, process};

use cel_engine::CelEngine;
use diagnostics::{DetailLevel, ValidationReport};
use log::{error, info};
use rego_engine::RegoEngine;
use rules::{FilterConfig, IdRange, RuleFilterConfig, Severity};
use schema_validator::SchemaValidator;
use template_model::PseudoParameterOverrides;
use validation_engine::{
    EngineConfig, EngineType, ExternalRuleSource, ValidateConfig, ValidationEngine, guard,
    validate_bytes_with_path, validate_catching_panics,
};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        process::exit(2);
    }

    let mut template_path = None;
    let mut include_ids = Vec::new();
    let mut exclude_ids = Vec::new();
    let mut include_categories = Vec::new();
    let mut exclude_categories = Vec::new();
    let mut exclude_ranges: Vec<IdRange> = Vec::new();
    let mut include_ranges: Vec<IdRange> = Vec::new();
    let mut custom_rules: Vec<ExternalRuleSource> = Vec::new();
    let mut guard_rule_source_paths: Vec<String> = Vec::new();
    let mut list_rules = false;
    let mut engine_type = EngineType::default();
    let mut validate_config = ValidateConfig::default();
    let mut parameter_overrides = HashMap::new();
    let mut pseudo_parameter_overrides = PseudoParameterOverrides::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--include-ids" => {
                i += 1;
                include_ids = args
                    .get(i)
                    .map(|s| s.split(',').map(String::from).collect())
                    .unwrap_or_default();
            }
            "--exclude-ids" => {
                i += 1;
                exclude_ids = args
                    .get(i)
                    .map(|s| s.split(',').map(String::from).collect())
                    .unwrap_or_default();
            }
            "--include-categories" => {
                i += 1;
                include_categories = args
                    .get(i)
                    .map(|s| s.split(',').map(String::from).collect())
                    .unwrap_or_default();
            }
            "--exclude-categories" => {
                i += 1;
                exclude_categories = args
                    .get(i)
                    .map(|s| s.split(',').map(String::from).collect())
                    .unwrap_or_default();
            }
            "--include-range" => {
                i += 1;
                if let Some(r) = args.get(i).and_then(|s| cfn_validate::parse_range(s)) {
                    include_ranges.push(r);
                }
            }
            "--exclude-range" => {
                i += 1;
                if let Some(r) = args.get(i).and_then(|s| cfn_validate::parse_range(s)) {
                    exclude_ranges.push(r);
                }
            }
            "--rule-source" => {
                i += 1;
                if let Some(path) = args.get(i) {
                    match fs::read_to_string(path) {
                        Ok(content) => custom_rules.push(ExternalRuleSource {
                            name: path.clone(),
                            content,
                        }),
                        Err(e) => {
                            error!("Failed to read rule source {}: {}", path, e);
                            process::exit(2);
                        }
                    }
                }
            }
            "--guard-rule-source" => {
                i += 1;
                if let Some(path) = args.get(i) {
                    guard_rule_source_paths.push(path.clone());
                } else {
                    error!("--guard-rule-source requires a file or directory path argument");
                    process::exit(2);
                }
            }
            "--list-rules" => list_rules = true,
            "--format" => {
                i += 1;
                validate_config.detail_level = match args.get(i).map(|s| s.as_str()) {
                    Some("standard") => DetailLevel::Standard,
                    Some("detailed") => DetailLevel::Detailed,
                    _ => {
                        error!("Invalid format, expected standard|detailed");
                        process::exit(2);
                    }
                };
            }
            "--level" => {
                i += 1;
                validate_config.severity_level = match args.get(i).map(|s| s.as_str()) {
                    Some("fatal") => Severity::Fatal,
                    Some("error") => Severity::Error,
                    Some("warning") => Severity::Warn,
                    Some("info") => Severity::Info,
                    Some("debug") => Severity::Debug,
                    _ => {
                        error!("Invalid level, expected error|warning|info|debug");
                        process::exit(2);
                    }
                };
            }
            "--no-strict" => validate_config.strict = false,
            "--strict" => validate_config.strict = true,
            "--no-engine-rules" => validate_config.include_engine_rules = false,
            "--engine" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    engine_type = EngineType::parse(val).unwrap_or_else(|e| {
                        error!("{}", e);
                        process::exit(2);
                    });
                }
            }
            "--region" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    pseudo_parameter_overrides.region = Some(val.clone());
                }
            }
            "--parameter" => {
                i += 1;
                if let Some(kv) = args.get(i) {
                    if let Some((k, v)) = kv.split_once('=') {
                        parameter_overrides.insert(k.to_string(), v.to_string());
                    }
                }
            }
            "--pseudo-parameter" => {
                i += 1;
                if let Some(kv) = args.get(i) {
                    if let Some((k, v)) = kv.split_once('=') {
                        match k {
                            "AWS::AccountId" => {
                                pseudo_parameter_overrides.account_id = Some(v.to_string())
                            }
                            "AWS::NotificationARNs" => {
                                pseudo_parameter_overrides.notification_arns = Some(v.to_string())
                            }
                            "AWS::Partition" => {
                                pseudo_parameter_overrides.partition = Some(v.to_string())
                            }
                            "AWS::Region" => {
                                pseudo_parameter_overrides.region = Some(v.to_string())
                            }
                            "AWS::StackId" => {
                                pseudo_parameter_overrides.stack_id = Some(v.to_string())
                            }
                            "AWS::StackName" => {
                                pseudo_parameter_overrides.stack_name = Some(v.to_string())
                            }
                            "AWS::URLSuffix" => {
                                pseudo_parameter_overrides.url_suffix = Some(v.to_string())
                            }
                            _ => {
                                error!("Unknown pseudo-parameter: {}", k);
                                process::exit(2);
                            }
                        }
                    }
                }
            }
            s if !s.starts_with('-') => template_path = Some(s.to_string()),
            other => {
                error!("Unknown option: {}", other);
                process::exit(2);
            }
        }
        i += 1;
    }

    let guard_rules = if !guard_rule_source_paths.is_empty() {
        match guard::resolve_guard_config(&guard_rule_source_paths) {
            Ok(entries) => entries,
            Err(e) => {
                error!("Failed to resolve guard rules: {}", e);
                process::exit(2);
            }
        }
    } else {
        Vec::new()
    };

    let engine_config = EngineConfig {
        custom_rules,
        guard_rules,
    };

    let schema_validator = SchemaValidator::new();

    let engine: Box<dyn ValidationEngine> = match engine_type {
        EngineType::Cel => Box::new(CelEngine::new(engine_config).unwrap_or_else(|e| {
            error!("CEL engine init failed: {}", e);
            process::exit(2);
        })),
        EngineType::Rego => Box::new(RegoEngine::new(engine_config).unwrap_or_else(|e| {
            error!("Rego engine init failed: {}", e);
            process::exit(2);
        })),
    };

    if list_rules {
        let mut rules = engine.list_rules();
        rules.extend(schema_validator.list_rules());
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        for r in &rules {
            println!(
                "{:<8} {:<12} {:<16} {}",
                r.id,
                format!("{:?}", r.severity),
                r.category.as_deref().unwrap_or(""),
                r.description
            );
        }
        println!("\n{} rules available", rules.len());
        process::exit(0);
    }

    let path = match template_path {
        Some(p) => p,
        None => {
            error!("No template file specified");
            process::exit(2);
        }
    };

    let files = cfn_validate::collect_files(Path::new(&path));
    if files.is_empty() {
        error!("No files found at {}", path);
        process::exit(2);
    }

    info!("Validating {} file(s) from {}", files.len(), path);

    validate_config.filters = FilterConfig::new(
        RuleFilterConfig {
            ids: include_ids,
            categories: include_categories,
            id_ranges: include_ranges,
            ..Default::default()
        },
        RuleFilterConfig {
            ids: exclude_ids,
            categories: exclude_categories,
            id_ranges: exclude_ranges,
            ..Default::default()
        },
    );
    validate_config.parameter_overrides = parameter_overrides;
    validate_config.pseudo_parameter_overrides = pseudo_parameter_overrides;

    let detail_level = validate_config.detail_level.clone();
    let mut has_errors = false;
    for file in &files {
        let file_str = file.display().to_string();
        let bytes = match fs::read(file) {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to read {}: {}", file_str, e);
                process::exit(2);
            }
        };

        let report = match validate_catching_panics(|| {
            validate_bytes_with_path(
                engine.as_ref(),
                &schema_validator,
                &bytes,
                validate_config.clone(),
                file_str.clone(),
            )
        }) {
            Ok(r) => r,
            Err(e) => {
                error!("Validation failed for {}: {}", file_str, e);
                has_errors = true;
                continue;
            }
        };

        info!(
            "{}: {} errors, {} warnings, {} informational",
            file_str,
            report.metadata.counts.errors,
            report.metadata.counts.warnings,
            report.metadata.counts.informational
        );
        print_report(&report, &detail_level);
        if report.metadata.counts.fatal > 0 || report.metadata.counts.errors > 0 {
            has_errors = true;
        }
    }

    if has_errors {
        process::exit(1);
    }
}

fn print_report(report: &ValidationReport, format: &DetailLevel) {
    match format {
        DetailLevel::Standard => println!(
            "{}",
            serde_json::to_string_pretty(&report.to_standard()).unwrap()
        ),
        DetailLevel::Detailed => println!(
            "{}",
            serde_json::to_string_pretty(&report.to_detailed()).unwrap()
        ),
    }
}

fn print_help() {
    eprintln!("Usage: cfn-validate <TEMPLATE|DIR> [OPTIONS]");
    eprintln!();
    eprintln!("Validate a CloudFormation template or all files in a directory.");
    eprintln!();
    eprintln!("Filter options:");
    eprintln!("  --include-ids ID,...          Only report these rule IDs");
    eprintln!("  --exclude-ids ID,...          Suppress these rule IDs");
    eprintln!("  --include-categories CAT,...  Only report these categories");
    eprintln!("  --exclude-categories CAT,...  Suppress these categories");
    eprintln!("  --include-range E3000-E3099   Only report rules in numeric range");
    eprintln!("  --exclude-range E3000-E3099   Suppress rules in numeric range");
    eprintln!();
    eprintln!("Output options:");
    eprintln!("  --format standard|detailed   Detail level (default: detailed)");
    eprintln!("  --level error|warning|info|debug  Minimum severity (default: info)");
    eprintln!();
    eprintln!("Other options:");
    eprintln!("  --engine rego|cel             Validation engine (default: rego)");
    eprintln!("  --rule-source <PATH>          Load custom rule from file");
    eprintln!("  --guard-rule-source <PATH>    Load Guard (.guard) rule file or directory");
    eprintln!("  --region REGION               Set AWS::Region pseudo-parameter");
    eprintln!("  --parameter Key=Value         Override a template parameter value (repeatable)");
    eprintln!("  --pseudo-parameter Key=Value  Override a pseudo-parameter value (repeatable)");
    eprintln!("  --strict                      Upgrade Warning-severity diagnostics to Error");
    eprintln!(
        "  --no-engine-rules             Suppress engine-native (RuleOrigin::Engine) diagnostics"
    );
    eprintln!("  --list-rules                  List all available rules and exit");
}
