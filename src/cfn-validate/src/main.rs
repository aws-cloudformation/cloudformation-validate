use std::{collections::HashMap, env, fs, path::Path, process};

use cel_engine::CelEngine;
use diagnostics::{DetailLevel, ValidationReport};
use log::{error, info};
use rego_engine::RegoEngine;
use rules::{
    EntityType, FilterConfig, IdRange, LogicalIdFilter, ResourceIdFilter, ResourceTypeFilter, RuleFilterConfig,
    ServiceFilter, Severity,
};
use schema_validator::SchemaValidator;
use template_model::PseudoParameterOverrides;
use validation_engine::{
    EngineConfig, EngineType, ExternalRuleSource, ValidateConfig, ValidationEngine, ValidationError, catch_panics,
    guard, validate_bytes_with_path, validate_catching_panics,
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
    let mut include_resource_ids: Vec<ResourceIdFilter> = Vec::new();
    let mut exclude_resource_ids: Vec<ResourceIdFilter> = Vec::new();
    let mut include_logical_ids: Vec<LogicalIdFilter> = Vec::new();
    let mut exclude_logical_ids: Vec<LogicalIdFilter> = Vec::new();
    let mut include_resource_types: Vec<ResourceTypeFilter> = Vec::new();
    let mut exclude_resource_types: Vec<ResourceTypeFilter> = Vec::new();
    let mut include_services: Vec<ServiceFilter> = Vec::new();
    let mut exclude_services: Vec<ServiceFilter> = Vec::new();
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
                include_ids = args.get(i).map(|s| s.split(',').map(String::from).collect()).unwrap_or_default();
            }
            "--exclude-ids" => {
                i += 1;
                exclude_ids = args.get(i).map(|s| s.split(',').map(String::from).collect()).unwrap_or_default();
            }
            "--include-categories" => {
                i += 1;
                include_categories = args.get(i).map(|s| s.split(',').map(String::from).collect()).unwrap_or_default();
            }
            "--exclude-categories" => {
                i += 1;
                exclude_categories = args.get(i).map(|s| s.split(',').map(String::from).collect()).unwrap_or_default();
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
            "--include-resource-id" => {
                i += 1;
                let (resource_id, rule_id) = parse_scoped_arg(args.get(i), "--include-resource-id");
                include_resource_ids.push(ResourceIdFilter { rule_id, resource_id });
            }
            "--exclude-resource-id" => {
                i += 1;
                let (resource_id, rule_id) = parse_scoped_arg(args.get(i), "--exclude-resource-id");
                exclude_resource_ids.push(ResourceIdFilter { rule_id, resource_id });
            }
            "--include-logical-id" => {
                i += 1;
                let (target, rule_id) = parse_scoped_arg(args.get(i), "--include-logical-id");
                let (logical_id, entity_type) = parse_logical_id_target(&target, "--include-logical-id");
                include_logical_ids.push(LogicalIdFilter { rule_id, logical_id, entity_type });
            }
            "--exclude-logical-id" => {
                i += 1;
                let (target, rule_id) = parse_scoped_arg(args.get(i), "--exclude-logical-id");
                let (logical_id, entity_type) = parse_logical_id_target(&target, "--exclude-logical-id");
                exclude_logical_ids.push(LogicalIdFilter { rule_id, logical_id, entity_type });
            }
            "--include-resource-type" => {
                i += 1;
                let (resource_type, rule_id) = parse_scoped_arg(args.get(i), "--include-resource-type");
                include_resource_types.push(ResourceTypeFilter { rule_id, resource_type });
            }
            "--exclude-resource-type" => {
                i += 1;
                let (resource_type, rule_id) = parse_scoped_arg(args.get(i), "--exclude-resource-type");
                exclude_resource_types.push(ResourceTypeFilter { rule_id, resource_type });
            }
            "--include-service" => {
                i += 1;
                let (service, rule_id) = parse_scoped_arg(args.get(i), "--include-service");
                include_services.push(ServiceFilter { rule_id, service });
            }
            "--exclude-service" => {
                i += 1;
                let (service, rule_id) = parse_scoped_arg(args.get(i), "--exclude-service");
                exclude_services.push(ServiceFilter { rule_id, service });
            }
            "--rule-source" => {
                i += 1;
                if let Some(path) = args.get(i) {
                    match fs::read_to_string(path) {
                        Ok(content) => custom_rules.push(ExternalRuleSource { name: path.clone(), content }),
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
                if let Some(val) = args.get(i) {
                    validate_config.severity_level = val.parse::<Severity>().unwrap_or_else(|e| {
                        error!("{}", e);
                        process::exit(2);
                    });
                }
            }
            "--strict" => validate_config.strict = true,
            "--disable-builtin-rules" => validate_config.disable_builtin_rules = true,
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
                if let Some(kv) = args.get(i)
                    && let Some((k, v)) = kv.split_once('=')
                {
                    parameter_overrides.insert(k.to_string(), v.to_string());
                }
            }
            "--pseudo-parameter" => {
                i += 1;
                if let Some(kv) = args.get(i)
                    && let Some((k, v)) = kv.split_once('=')
                {
                    match k {
                        "AWS::AccountId" => pseudo_parameter_overrides.account_id = Some(v.to_string()),
                        "AWS::NotificationARNs" => pseudo_parameter_overrides.notification_arns = Some(v.to_string()),
                        "AWS::Partition" => pseudo_parameter_overrides.partition = Some(v.to_string()),
                        "AWS::Region" => pseudo_parameter_overrides.region = Some(v.to_string()),
                        "AWS::StackId" => pseudo_parameter_overrides.stack_id = Some(v.to_string()),
                        "AWS::StackName" => pseudo_parameter_overrides.stack_name = Some(v.to_string()),
                        "AWS::URLSuffix" => pseudo_parameter_overrides.url_suffix = Some(v.to_string()),
                        _ => {
                            error!("Unknown pseudo-parameter: {}", k);
                            process::exit(2);
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

    let engine_config = EngineConfig { custom_rules, guard_rules };

    let schema_validator = SchemaValidator::new();

    // Engine construction compiles user-supplied custom and Guard rules, so an
    // internal invariant violation on adversarial rule input could panic. Catch it
    // here so it surfaces as a structured error and a clean exit code rather than an
    // uncaught abort — matching how the library bindings guard the same entry point.
    let engine_init: Result<Box<dyn ValidationEngine>, ValidationError> = catch_panics(
        || {
            let engine: Box<dyn ValidationEngine> = match engine_type {
                EngineType::Cel => Box::new(CelEngine::new(engine_config).map_err(|e| e.to_string())?),
                EngineType::Rego => Box::new(RegoEngine::new(engine_config).map_err(|e| e.to_string())?),
            };
            Ok(engine)
        },
        |message| {
            ValidationError::Engine(format!("Internal error while initializing the {engine_type} engine: {message}"))
        },
    );
    let engine: Box<dyn ValidationEngine> = engine_init.unwrap_or_else(|e| {
        error!("{} engine init failed: {}", engine_type, e);
        process::exit(2);
    });

    if list_rules {
        let mut rules = engine.list_rules();
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
            resource_ids: include_resource_ids,
            logical_ids: include_logical_ids,
            resource_types: include_resource_types,
            services: include_services,
            ..Default::default()
        },
        RuleFilterConfig {
            ids: exclude_ids,
            categories: exclude_categories,
            id_ranges: exclude_ranges,
            resource_ids: exclude_resource_ids,
            logical_ids: exclude_logical_ids,
            resource_types: exclude_resource_types,
            services: exclude_services,
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
        if let Err(e) = print_report(&report, &detail_level) {
            error!("Failed to render report for {}: {}", file_str, e);
            has_errors = true;
            continue;
        }
        if report.metadata.counts.fatal > 0 || report.metadata.counts.errors > 0 {
            has_errors = true;
        }
    }

    if has_errors {
        process::exit(1);
    }
}

/// Parses a resource-scoped filter argument (`TARGET` or `TARGET=RULE_ID`) for
/// `flag`, exiting with an error when the argument is missing or the target is
/// empty. Returns the target and its optional rule scope (`None` = every rule).
fn parse_scoped_arg(raw: Option<&String>, flag: &str) -> (String, Option<String>) {
    match raw.and_then(|s| cfn_validate::parse_scoped_target(s)) {
        Some(parsed) => parsed,
        None => {
            error!("{flag} requires a TARGET or TARGET=RULE_ID argument with a non-empty TARGET");
            process::exit(2);
        }
    }
}

/// Splits a logical-id filter target (`ID` or `ID:ENTITY_TYPE`) into the
/// logical ID and its optional entity-type scope, exiting with an error on an
/// unknown entity type. `None` = entities of every type.
fn parse_logical_id_target(target: &str, flag: &str) -> (String, Option<EntityType>) {
    match target.split_once(':') {
        None => (target.to_string(), None),
        Some((logical_id, entity_type)) => match entity_type.parse::<EntityType>() {
            Ok(parsed) => (logical_id.to_string(), Some(parsed)),
            Err(message) => {
                error!("{flag}: {message}");
                process::exit(2);
            }
        },
    }
}

fn print_report(report: &ValidationReport, format: &DetailLevel) -> Result<(), serde_json::Error> {
    let json = match format {
        DetailLevel::Standard => serde_json::to_string_pretty(&report.to_standard())?,
        DetailLevel::Detailed => serde_json::to_string_pretty(&report.to_detailed())?,
    };
    println!("{}", json);
    Ok(())
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
    eprintln!("Resource-scoped filters (TARGET, or TARGET=RULE_ID for one rule; repeatable):");
    eprintln!("  --include-resource-id ID[=RULE]      Only report rules on a logical resource ID");
    eprintln!("  --exclude-resource-id ID[=RULE]      Suppress rules on a logical resource ID");
    eprintln!("  --include-logical-id ID[:TYPE][=RULE]  Only report rules on a named template entity (resource,");
    eprintln!("                                       parameter, output, mapping, condition, or rule); an optional");
    eprintln!("                                       :TYPE (e.g. :Parameter) scopes it to one entity type");
    eprintln!("  --exclude-logical-id ID[:TYPE][=RULE]  Suppress rules on a named template entity");
    eprintln!("  --include-resource-type TYPE[=RULE]  Only report rules on a resource type");
    eprintln!("  --exclude-resource-type TYPE[=RULE]  Suppress rules on a resource type");
    eprintln!("  --include-service SERVICE[=RULE]     Only report rules on a service (e.g. AWS::AutoScaling)");
    eprintln!("  --exclude-service SERVICE[=RULE]     Suppress rules on a service (e.g. AWS::AutoScaling)");
    eprintln!();
    eprintln!("Output options:");
    eprintln!("  --format standard|detailed   Detail level (default: detailed)");
    eprintln!("  --level fatal|error|warn|info|debug  Minimum severity (default: info)");
    eprintln!();
    eprintln!("Other options:");
    eprintln!("  --engine rego|cel             Validation engine (default: rego)");
    eprintln!("  --rule-source <PATH>          Load custom rule from file");
    eprintln!("  --guard-rule-source <PATH>    Load Guard (.guard) rule file or directory");
    eprintln!("  --region REGION               Set AWS::Region pseudo-parameter");
    eprintln!("  --parameter Key=Value         Override a template parameter value (repeatable)");
    eprintln!("  --pseudo-parameter Key=Value  Override a pseudo-parameter value (repeatable)");
    eprintln!("  --strict                      Upgrade Warn-severity diagnostics to Error");
    eprintln!("  --disable-builtin-rules       Disable all built-in rules; only evaluate custom and guard rules");
    eprintln!("  --list-rules                  List all available rules and exit");
}
