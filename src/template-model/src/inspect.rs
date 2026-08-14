use log::error;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::{env, fs, process};
use template_model::ParseConfig;
use template_model::SemanticModel;
use template_model::conditions::format_condition_expr;
use template_model::consts::{EDGE_KIND_DEPENDS_ON, EDGE_KIND_REF, SAM_FUNCTION_TYPE};
use template_model::resolver::{RefKind, ResolvedValue};
use template_model::span_to_option;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    let path = args.iter().find(|a| !a.starts_with('-') && *a != &args[0]);
    let path = match path {
        Some(p) => p.clone(),
        None => {
            eprintln!("Usage: cargo run -p template-model --example inspect -- <template|dir>");
            eprintln!();
            eprintln!("Inspect a CloudFormation template or all files in a directory (recursive).");
            process::exit(2);
        }
    };

    let p = Path::new(&path);
    let files = if p.is_dir() {
        let mut out = Vec::new();
        collect_files(p, &mut out);
        out.sort();
        out
    } else {
        vec![p.to_path_buf()]
    };

    if files.is_empty() {
        error!("No files found at {}", path);
        process::exit(2);
    }

    for file in &files {
        inspect_file(&file.display().to_string());
    }
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_files(&p, out);
        } else if p.is_file() {
            out.push(p);
        }
    }
}

fn inspect_file(path: &str) {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to read {}: {}", path, e);
            return;
        }
    };

    let result = match SemanticModel::parse(&bytes, ParseConfig { ..Default::default() }) {
        Ok(r) => r,
        Err(e) => {
            error!("Parse error in {}: {}", path, e);
            return;
        }
    };
    let model = result.model;
    let model_build_ms = result.model_build_ms;

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  CloudFormation Template Model                             ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("File: {}", path);
    let file_kb = bytes.len() as f64 / 1024.0;
    println!("File size: {} bytes ({:.1} KB)", bytes.len(), file_kb);
    if let Some(v) = &model.format_version {
        println!("Format Version: {}", v);
    }
    if let Some(d) = &model.description {
        println!("Description: {}", d);
    }
    if !model.transforms.is_empty() {
        println!("Transforms: {}", model.transforms.join(", "));
    }
    if !model.raw_top_level_keys.is_empty() {
        println!("Top-level sections (as written): {}", model.raw_top_level_keys.join(", "));
    }
    if model.is_cdk {
        println!("CDK Template: yes");
    }
    println!("Model build time: {:.1}ms", model_build_ms);
    println!();

    if let Some(ref meta) = model.template_metadata {
        println!("── Template Metadata ──────────────────────────────────");
        println!("  {}", format_json_compact(meta));
        println!();
    }

    if !model.parameters.is_empty() {
        println!("── Parameters ({}) ─────────────────────────────────────", model.parameters.len());
        for (name, info) in &model.parameters {
            print!("  {} ({})", name, info.param_type);
            if let Some(ref d) = info.default {
                print!(" [default: {}]", d);
            }
            if let Some(ref av) = info.allowed_values {
                print!(" [allowed: {}]", av.join(", "));
            }
            if let Some(ref ap) = info.allowed_pattern {
                print!(" [pattern: {}]", ap);
            }
            if let Some(v) = info.min_length {
                print!(" [min_length: {}]", v);
            }
            if let Some(v) = info.max_length {
                print!(" [max_length: {}]", v);
            }
            if let Some(v) = info.min_value {
                print!(" [min_value: {}]", v);
            }
            if let Some(v) = info.max_value {
                print!(" [max_value: {}]", v);
            }
            if info.no_echo {
                print!(" [NoEcho]");
            }
            if let Some(ref av) = info.allowed_values {
                print!("  → Enum[{}]", av.iter().map(|v| format!("\"{}\"", v)).collect::<Vec<_>>().join(" | "));
            } else if let Some(ref d) = info.default {
                print!("  → \"{}\"", d);
            } else {
                print!("  → Dynamic (unknown at parse time)");
            }
            println!();
            if let Some(ref desc) = info.description {
                println!("    {}", desc);
            }
        }
        if !model.params_referenced_in_definitions.is_empty() {
            let mut referenced: Vec<&String> = model.params_referenced_in_definitions.iter().collect();
            referenced.sort();
            println!(
                "  Referenced from other parameter definitions: {}",
                referenced.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
        println!();
    }

    if !model.mappings.is_empty() {
        println!("── Mappings ({}) ───────────────────────────────────────", model.mappings.len());
        for (name, l1) in &model.mappings {
            println!("  {}:", name);
            for (k1, l2) in l1 {
                println!("    {}:", k1);
                for (k2, v) in l2 {
                    println!("      {}: {}", k2, format_json_compact(v));
                }
            }
        }
        if !model.find_in_map_names.is_empty() {
            let mut referenced: Vec<&String> = model.find_in_map_names.iter().collect();
            referenced.sort();
            println!(
                "  Referenced by Fn::FindInMap: {}",
                referenced.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
        if model.has_dynamic_findinmap_name {
            println!("  ⚠ Fn::FindInMap with a non-literal map name present (unused-mapping check disabled)");
        }
        println!();
    }

    if !model.sam_globals.is_empty() || !model.sam_implicit_resources.is_empty() || !model.globals_param_refs.is_empty()
    {
        println!("── SAM ────────────────────────────────────────────────");
        if !model.sam_globals.is_empty() {
            println!("  Globals:");
            for (type_name, props) in &model.sam_globals {
                let items: Vec<String> =
                    props.iter().map(|(k, v)| format!("{}: {}", k, format_json_compact(v))).collect();
                println!("    {} → {{{}}}", type_name, items.join(", "));
            }
        }
        if !model.sam_implicit_resources.is_empty() {
            let mut implicit: Vec<&String> = model.sam_implicit_resources.iter().collect();
            implicit.sort();
            println!("  Implicit resources: {}", implicit.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
        }
        if !model.globals_param_refs.is_empty() {
            println!("  Globals parameter refs: {}", model.globals_param_refs.join(", "));
        }
        println!();
    }

    if !model.conditions.conditions.is_empty() {
        println!("── Conditions ({}) ────────────────────────────────────", model.conditions.conditions.len());
        for name in model.conditions.names() {
            let expr = model.conditions.get(name).unwrap();
            println!("  {}: {}", name, format_condition_expr(expr));
        }
        if !model.conditions.mutex_groups.is_empty() {
            println!();
            println!("  Mutex groups:");
            for g in &model.conditions.mutex_groups {
                println!("    [{}] (param: {}, values: {})", g.conditions.join(", "), g.parameter, g.values.join(", "));
            }
        }
        if !model.conditions.implications.is_empty() {
            println!("  Implications:");
            for imp in &model.conditions.implications {
                println!("    {} → {}", imp.antecedent, imp.consequent);
            }
        }
        let ref_params = model.conditions.referenced_params();
        if !ref_params.is_empty() {
            println!("  Condition-driving parameters: [{}]", ref_params.join(", "));
        }
        if !model.fn_if_conditions.is_empty() {
            println!("  Referenced by Fn::If: [{}]", model.fn_if_conditions.join(", "));
        }
        for (cond_name, always_val) in model.conditions.tautological_equals() {
            println!("  ⚠ Tautological: {} always {}", cond_name, if always_val { "True" } else { "False" });
        }
        // Pairwise compatibility (SAT analysis) - cap at 20 conditions
        // Skip conditions that are tautologically always-false (already flagged above)
        let tautological: HashSet<String> =
            model.conditions.tautological_equals().into_iter().filter(|(_, v)| !v).map(|(n, _)| n).collect();
        let cond_names: Vec<&str> = model.conditions.names().filter(|n| !tautological.contains(*n)).collect();
        if cond_names.len() >= 2 && cond_names.len() <= 20 {
            let mut incompatible = Vec::new();
            for i in 0..cond_names.len() {
                for j in (i + 1)..cond_names.len() {
                    if !model.conditions.conditions_compatible(cond_names[i], cond_names[j]) {
                        incompatible.push((cond_names[i], cond_names[j]));
                    }
                }
            }
            if !incompatible.is_empty() {
                println!("  SAT incompatible pairs:");
                for (a, b) in &incompatible {
                    println!("    ✗ {} ↔ {}", a, b);
                }
            }
        }
        println!();
    }

    println!("── Resources ({}) ─────────────────────────────────────", model.resources.len());

    let mut types: Vec<&String> = model.resources_by_type.keys().collect();
    types.sort();
    println!();
    println!("  By type:");
    for t in &types {
        let ids = &model.resources_by_type[*t];
        println!("    {} ({}): {}", t, ids.len(), ids.join(", "));
    }
    println!();

    for (id, res) in &model.resources {
        let span_suffix = model
            .source_location(&format!("Resources/{}", id))
            .filter(|s| s.start_line > 0)
            .map(|s| format!(" @ L{}:C{}", s.start_line, s.start_column))
            .unwrap_or_default();
        println!("  ┌─ {} ({}){}", id, res.resource_type, span_suffix);
        if let Some(ref c) = res.condition {
            println!("  │  Condition: {}", c);
        }
        if !res.depends_on.is_empty() {
            println!("  │  DependsOn: {}", res.depends_on.join(", "));
        }
        if let Some(ref dp) = res.deletion_policy {
            println!("  │  DeletionPolicy: {}", format_resolved(dp));
        }
        if let Some(ref urp) = res.update_replace_policy {
            println!("  │  UpdateReplacePolicy: {}", format_resolved(urp));
        }
        if let Some(ref up) = res.update_policy {
            println!("  │  UpdatePolicy: {}", format_json_compact(up));
        }
        if let Some(ref cp) = res.creation_policy {
            println!("  │  CreationPolicy: {}", format_json_compact(cp));
        }
        if let Some(ref meta) = res.metadata {
            println!("  │  Metadata: {}", format_json_compact(meta));
        }

        if !res.properties.is_empty() {
            println!("  │  Properties:");
            let mut props: Vec<(&String, &ResolvedValue)> = res.properties.iter().collect();
            props.sort_by_key(|(k, _)| k.as_str());
            let is_lambda = res.resource_type == "AWS::Lambda::Function";
            let is_sam_fn = res.resource_type == SAM_FUNCTION_TYPE;
            for (key, val) in props {
                if (is_lambda && key.as_str() == "Code") || (is_sam_fn && key.as_str() == "InlineCode") {
                    println!("  │    {}: <inline code suppressed>", key);
                } else {
                    println!("  │    {}: {}", key, format_resolved(val));
                }
            }
        }
        if res.properties_dynamic {
            println!("  │  Properties: <dynamic - resolved at deploy time>");
        }

        if !res.diagnostics.find_in_map_refs.is_empty() {
            println!("  │  FindInMap refs: {}", res.diagnostics.find_in_map_refs.join(", "));
        }
        if !res.diagnostics.simple_subs.is_empty() {
            println!("  │  Simple Subs:");
            for s in &res.diagnostics.simple_subs {
                println!("  │    {} → ${{{}}}", s.path, s.value);
            }
        }
        if !res.diagnostics.redundant_subs.is_empty() {
            println!("  │  Redundant Subs (no variables):");
            for p in &res.diagnostics.redundant_subs {
                println!("  │    {}", p);
            }
        }
        if !res.diagnostics.empty_joins.is_empty() {
            println!("  │  Empty Joins (empty delimiter):");
            for p in &res.diagnostics.empty_joins {
                println!("  │    {}", p);
            }
        }
        if !res.diagnostics.condition_refs.is_empty() {
            println!("  │  Condition refs: {}", res.diagnostics.condition_refs.join(", "));
        }
        if !res.diagnostics.hardcoded_partition_arns.is_empty() {
            println!("  │  Hardcoded partition ARNs:");
            for p in &res.diagnostics.hardcoded_partition_arns {
                println!("  │    {}", p);
            }
        }
        if !res.diagnostics.conditionally_null_props.is_empty() {
            println!("  │  Conditionally null properties:");
            for s in &res.diagnostics.conditionally_null_props {
                let branch = if s.null_in_true_branch { "true" } else { "false" };
                println!("  │    {} → null when {} is {}", s.path, s.condition, branch);
            }
        }
        if !res.diagnostics.foreach_expansions.is_empty() {
            println!("  │  ForEach expansions:");
            for fe in &res.diagnostics.foreach_expansions {
                println!("  │    {} (id: {}, collection: {})", fe.property_path, fe.identifier, fe.collection_source);
            }
        }
        if !res.diagnostics.unsubstituted_variables.is_empty() {
            println!("  │  Unsubstituted variables:");
            for s in &res.diagnostics.unsubstituted_variables {
                println!("  │    {} → {}", s.path, s.value);
            }
        }
        if !res.diagnostics.invalid_refs.is_empty() {
            println!("  │  ⚠ Invalid refs:");
            for s in &res.diagnostics.invalid_refs {
                println!("  │    {} → {} (not found)", s.path, s.value);
            }
        }

        let outgoing = model.graph.outgoing(id);
        if !outgoing.is_empty() {
            println!("  │  References out:");
            for e in &outgoing {
                let cond_ctx = e.condition_context.as_ref().map(|c| format!(" [condition: {}]", c)).unwrap_or_default();
                println!("  │    → {} (via {} at {}){}", e.target, format_ref_kind(&e.kind), e.source_path, cond_ctx);
            }
        }

        let incoming = model.graph.incoming(id);
        if !incoming.is_empty() {
            println!("  │  Referenced by:");
            for e in &incoming {
                let cond_ctx = e.condition_context.as_ref().map(|c| format!(" [condition: {}]", c)).unwrap_or_default();
                println!(
                    "  │    ← {} (via {} at {}){}",
                    e.source_resource,
                    format_ref_kind(&e.kind),
                    e.source_path,
                    cond_ctx
                );
            }
        }

        println!("  └─");
    }
    println!();

    println!("── Reference Graph ({} edges) ────────────────────────", model.graph.edges.len());
    let cycles = model.graph.cycles();
    if cycles.is_empty() {
        println!("  No circular dependencies.");
    } else {
        println!("  ⚠ Circular dependencies detected:");
        for cycle in cycles {
            println!("    {}", cycle.join(" → "));
        }
    }
    println!();

    if !model.resolution_sources.is_empty() {
        println!("── Resolution Sources ({}) ───────────────────────────", model.resolution_sources.len());
        let mut sources: Vec<(&(String, String), &String)> = model.resolution_sources.iter().collect();
        sources.sort_by_key(|(key, _)| *key);
        for ((resource_id, path), source) in sources {
            println!("  {} @ {} ← {}", resource_id, path, source);
        }
        println!();
    }

    if !model.outputs.is_empty() {
        println!("── Outputs ({}) ──────────────────────────────────────", model.outputs.len());
        for (name, out) in &model.outputs {
            let span_suffix = model
                .source_location(&format!("Outputs/{}", name))
                .filter(|s| s.start_line > 0)
                .map(|s| format!(" @ L{}:C{}", s.start_line, s.start_column))
                .unwrap_or_default();
            print!("  {}: {}", name, format_resolved(&out.value));
            if let Some(ref c) = out.condition {
                print!(" [condition: {}]", c);
            }
            if let Some(ref e) = out.export_name {
                print!(" [export: {}]", format_resolved(e));
            }
            if let Some(ref d) = out.description {
                print!(" - {}", d);
            }
            println!("{}", span_suffix);
        }
        if !model.output_empty_joins.is_empty() {
            println!("  Empty Joins in outputs:");
            for p in &model.output_empty_joins {
                println!("    {}", p);
            }
        }
        println!();
    }

    if !model.parsed_rules.is_empty() {
        println!("── Rules ({}) ─────────────────────────────────────────", model.parsed_rules.len());
        for rule in &model.parsed_rules {
            println!("  {}:", rule.name);
            if let Some(ref cond) = rule.condition {
                println!("    RuleCondition: {}", format_json_compact(cond));
            }
            for (i, assertion) in rule.assertions.iter().enumerate() {
                let desc = assertion.description.as_deref().unwrap_or("");
                println!("    Assertion[{}]: {}", i, desc);
                println!("      Assert: {}", format_json_compact(&assertion.assert));
            }
        }
        println!();
    }

    if !model.diagnostics.is_empty() {
        println!("── Diagnostics ({}) ─────────────────────────────────", model.diagnostics.len());
        for d in &model.diagnostics {
            match span_to_option(d.span) {
                Some(loc) => println!("  [{}] L{}:C{} {}", d.rule_id, loc.start_line, loc.start_column, d.message),
                None => println!("  [{}] {}", d.rule_id, d.message),
            }
        }
        println!();
    }

    println!("── Performance ────────────────────────────────────────");
    println!("  Model build:  {:>8.2} ms", model_build_ms);
    println!();

    println!("── Summary ────────────────────────────────────────────");
    println!("  Parameters:   {}", model.parameters.len());
    println!("  Mappings:     {}", model.mappings.len());
    println!("  Conditions:   {}", model.conditions.conditions.len());
    println!("  Resources:    {}", model.resources.len());
    println!("  Outputs:      {}", model.outputs.len());
    println!("  Edges:        {}", model.graph.edges.len());
    println!("  Cycles:       {}", model.graph.cycles().len());
    println!("  Diagnostics:  {}", model.diagnostics.len());
    println!("  Rules:        {}", model.parsed_rules.len());
    println!("  Arena nodes:  {}", model.arena.len());
    println!("  Span entries: {}", model.span_index.len());
    if model.is_cdk {
        println!("  CDK template: yes");
    }
    if !model.resolution_sources.is_empty() {
        println!("  Resolution sources: {}", model.resolution_sources.len());
    }
    let total_empty_joins: usize = model.resources.values().map(|r| r.diagnostics.empty_joins.len()).sum::<usize>()
        + model.output_empty_joins.len();
    if total_empty_joins > 0 {
        println!("  Empty joins:  {}", total_empty_joins);
    }
    let total_invalid_refs: usize = model.resources.values().map(|r| r.diagnostics.invalid_refs.len()).sum();
    if total_invalid_refs > 0 {
        println!("  Invalid refs: {}", total_invalid_refs);
    }
    let total_hardcoded: usize = model.resources.values().map(|r| r.diagnostics.hardcoded_partition_arns.len()).sum();
    if total_hardcoded > 0 {
        println!("  Hardcoded ARNs: {}", total_hardcoded);
    }
    let total_foreach: usize = model.resources.values().map(|r| r.diagnostics.foreach_expansions.len()).sum();
    if total_foreach > 0 {
        println!("  ForEach expansions: {}", total_foreach);
    }
    if !model.sam_globals.is_empty() {
        println!("  SAM globals:  {}", model.sam_globals.len());
    }
    if !model.sam_implicit_resources.is_empty() {
        println!("  SAM implicit: {}", model.sam_implicit_resources.len());
    }
}

fn format_resolved(val: &ResolvedValue) -> String {
    match val {
        ResolvedValue::Concrete { value: v } => format_json_compact(v),
        ResolvedValue::List { items } => {
            let parts: Vec<String> = items.iter().map(format_resolved).collect();
            format!("[{}]", parts.join(", "))
        }
        ResolvedValue::Map { entries } => {
            let parts: Vec<String> =
                entries.iter().map(|entry| format!("{}: {}", entry.key, format_resolved(&entry.value))).collect();
            format!("{{{}}}", parts.join(", "))
        }
        ResolvedValue::Enum { variants: vals } => {
            let items: Vec<String> = vals.iter().map(format_resolved).collect();
            format!("Enum[{}]", items.join(" | "))
        }
        ResolvedValue::Conditional { condition: cond, if_true: t, if_false: f } => {
            format!("If({}) ? {} : {}", cond, format_resolved(t), format_resolved(f))
        }
        ResolvedValue::Reference { target, kind } => {
            format!("→{} ({})", target, format_ref_kind(kind))
        }
        ResolvedValue::Dynamic { reason } => format!("Dynamic({})", reason),
        ResolvedValue::TypedDynamic { reason, param_type } => {
            format!("Dynamic({}, type={})", reason, param_type)
        }
    }
}

fn format_json_compact(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => {
            if s.len() > 120 {
                // Find a char boundary at or before byte 120 to avoid panicking on non-ASCII
                let truncate_at = s.floor_char_boundary(120);
                format!("\"{}...\" ({} chars)", &s[..truncate_at], s.len())
            } else {
                format!("\"{}\"", s)
            }
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_json_compact).collect();
            format!("[{}]", items.join(", "))
        }
        serde_json::Value::Object(map) => {
            let items: Vec<String> = map.iter().map(|(k, v)| format!("{}: {}", k, format_json_compact(v))).collect();
            format!("{{{}}}", items.join(", "))
        }
        other => other.to_string(),
    }
}

fn format_ref_kind(kind: &RefKind) -> String {
    match kind {
        RefKind::Ref => EDGE_KIND_REF.into(),
        RefKind::GetAtt { attr } => format!("GetAtt.{}", attr),
        RefKind::Sub { var } => format!("Sub({})", var),
        RefKind::DependsOn => EDGE_KIND_DEPENDS_ON.into(),
    }
}
