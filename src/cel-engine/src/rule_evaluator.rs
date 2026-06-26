use diagnostics::{Diagnostic, RegisteredDiagnostic};
use rules::lookup_rule;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use template_model::SemanticModel;
use template_model::coercion::{cfn_coerce_to_number, cfn_coerce_to_string};
use template_model::resolver::ResolvedValue;
use template_model::{MARKER_CONDITIONAL, MARKER_DYNAMIC};

#[derive(serde::Deserialize)]
struct RuleFile {
    rules: Vec<RuleDescriptor>,
}

#[derive(serde::Deserialize, Clone)]
struct RuleDescriptor {
    rule_id: String,
    resource_type: String,
    expression: String,
    message: String,
    #[serde(default)]
    prop_path: Option<String>,
    #[serde(default)]
    suggested_fix: Option<String>,
}

pub struct GeneratedRuleRegistry {
    rules_by_type: HashMap<String, Vec<RuleDescriptor>>,
    global_rules: Vec<RuleDescriptor>,
}

impl GeneratedRuleRegistry {
    pub fn new() -> anyhow::Result<Self> {
        let mut rules_by_type: HashMap<String, Vec<RuleDescriptor>> = HashMap::new();
        let mut global_rules = Vec::new();
        let mut total = 0;

        let file: RuleFile = serde_json::from_slice(&data_source::embedded::GENERATED_RULES_BYTES)
            .map_err(|e| anyhow::anyhow!("Failed to parse generated rules: {}", e))?;
        for rule in file.rules {
            total += 1;
            if rule.resource_type.is_empty() {
                global_rules.push(rule);
            } else {
                rules_by_type.entry(rule.resource_type.clone()).or_default().push(rule);
            }
        }
        log::info!(
            "Loaded {} generated CEL rules ({} resource types, {} global)",
            total,
            rules_by_type.len(),
            global_rules.len()
        );
        Ok(GeneratedRuleRegistry { rules_by_type, global_rules })
    }

    pub fn evaluate(
        &self,
        model: &Arc<SemanticModel>,
        _serialized_model: &serde_json::Value,
        excluded_cats: &HashSet<&str>,
    ) -> Vec<Diagnostic> {
        let mut out = Vec::new();

        for (rtype, rules) in &self.rules_by_type {
            let rids = model.resources_of_type(rtype);
            if rids.is_empty() {
                continue;
            }
            let rules: Vec<&RuleDescriptor> =
                rules.iter().filter(|r| !is_excluded(&r.rule_id, excluded_cats)).collect();
            if rules.is_empty() {
                continue;
            }
            for rid in rids {
                for rule in &rules {
                    evaluate_rule(&mut out, model, rid, rtype, rule);
                }
            }
        }

        for rule in &self.global_rules {
            if is_excluded(&rule.rule_id, excluded_cats) {
                continue;
            }
            for (rid, res) in &model.resources {
                evaluate_rule(&mut out, model, rid, &res.resource_type, rule);
            }
        }

        out
    }
}

fn is_excluded(rule_id: &str, excluded_cats: &HashSet<&str>) -> bool {
    lookup_rule(rule_id).is_some_and(|r| excluded_cats.contains(r.category.as_str()))
}

fn make_diag(
    rule: &RuleDescriptor,
    model: &Arc<SemanticModel>,
    rid: &str,
    rtype: &str,
    conds: Option<HashMap<String, bool>>,
) -> Diagnostic {
    let prop_path = rule.prop_path.as_deref().unwrap_or("");
    let span = model.resource_span(rid, prop_path);
    let mut builder = RegisteredDiagnostic::new(rule.rule_id.clone(), rule.message.clone())
        .resource(rid, Some(rtype.to_string()))
        .location(span)
        .suggested_fix(rule.suggested_fix.clone())
        .condition_scenario(conds);
    if let Some(prop) = &rule.prop_path {
        builder = builder.property_path(prop.clone());
    }
    builder.build()
}

fn satisfiable(m: &SemanticModel, conds: &HashMap<String, bool>) -> bool {
    if conds.is_empty() {
        return true;
    }
    let pairs: Vec<(String, bool)> = conds.iter().map(|(k, v)| (k.clone(), *v)).collect();
    m.conditions.is_satisfiable(&pairs)
}

fn evaluate_rule(out: &mut Vec<Diagnostic>, m: &Arc<SemanticModel>, rid: &str, rtype: &str, rule: &RuleDescriptor) {
    let expr = &rule.expression;

    // Simple expression: "true" — always fires (e.g., deprecated resource type)
    if expr == "true" {
        out.push(make_diag(rule, m, rid, rtype, None));
        return;
    }

    // has_property / !has_property patterns (single property only, not compound &&)
    if !expr.contains(" && ")
        && let Some(rest) = expr.strip_prefix("!has_property(name, \"")
        && let Some(prop) = rest.strip_suffix("\")")
    {
        if !m.resources.get(rid).map(|r| r.properties.contains_key(prop)).unwrap_or(false) {
            out.push(make_diag(rule, m, rid, rtype, None));
        }
        return;
    }

    // Combined has_property && !has_property (dependentRequired)
    if expr.starts_with("has_property(name, \"") && expr.contains(" && !has_property(name, \"") {
        let parts: Vec<&str> = expr.split(" && ").collect();
        if parts.len() == 2
            && let (Some(trigger), Some(dep)) = (extract_has_prop(parts[0]), extract_not_has_prop(parts[1]))
        {
            let res = m.resources.get(rid);
            let has_trigger = res.map(|r| r.properties.contains_key(trigger)).unwrap_or(false);
            let has_dep = res.map(|r| r.properties.contains_key(dep)).unwrap_or(false);
            if has_trigger && !has_dep {
                out.push(make_diag(rule, m, rid, rtype, None));
            }
            return;
        }
    }

    // Combined has_property && has_property (dependentExcluded)
    if expr.starts_with("has_property(name, \"") && expr.contains(" && has_property(name, \"") {
        let parts: Vec<&str> = expr.split(" && ").collect();
        if parts.len() == 2
            && let (Some(a), Some(b)) = (extract_has_prop(parts[0]), extract_has_prop(parts[1]))
        {
            let res = m.resources.get(rid);
            if res.map(|r| r.properties.contains_key(a) && r.properties.contains_key(b)).unwrap_or(false) {
                out.push(make_diag(rule, m, rid, rtype, None));
            }
            return;
        }
    }

    // All !has_property combined (requiredOr/requiredXor)
    if expr.contains("!has_property(name, \"") && !expr.contains("scenario_") {
        let parts: Vec<&str> = expr.split(" && ").collect();
        if parts.iter().all(|p| p.starts_with("!has_property(name, \"")) {
            let props: Vec<&str> = parts.iter().filter_map(|p| extract_not_has_prop(p)).collect();
            if props.len() == parts.len() {
                let res = m.resources.get(rid);
                let all_missing = props.iter().all(|p| !res.map(|r| r.properties.contains_key(*p)).unwrap_or(false));
                if all_missing {
                    out.push(make_diag(rule, m, rid, rtype, None));
                }
                return;
            }
        }
    }

    // has_unknown_properties
    if let Some(rest) = expr.strip_prefix("has_unknown_properties(name, ")
        && let Some(json_str) = rest.strip_suffix(')')
        && let Ok(known) = serde_json::from_str::<Vec<String>>(json_str)
    {
        let known_set: HashSet<&str> = known.iter().map(|s| s.as_str()).collect();
        if let Some(res) = m.resources.get(rid) {
            for prop in res.properties.keys() {
                if !known_set.contains(prop.as_str()) {
                    let mut d = make_diag(rule, m, rid, rtype, None);
                    d.message = format!("Unknown property '{}' for {}", prop, rtype);
                    d.property_path = Some(format!("Properties.{}", prop));
                    d.suggested_fix = Some(format!("Remove the unknown property '{}'", prop));
                    out.push(d);
                }
            }
        }
        return;
    }

    // scenario_check(name, "path", |val| ...)
    if let Some(rest) = expr.strip_prefix("scenario_check(name, \"")
        && let Some(idx) = rest.find("\", |val| ")
    {
        let path = &rest[..idx];
        let check_expr = &rest[idx + 9..];
        let check_expr = check_expr.strip_suffix(')').unwrap_or(check_expr);

        if path.contains("{}") {
            let arr_path = path.split(".{}").next().unwrap_or(path);
            let first_wc = match path.find("{}") {
                Some(i) => i,
                None => return,
            };
            let suffix = &path[first_wc + 2..];
            let arr_len = match m.resolve_deep(rid, arr_path) {
                Some(ResolvedValue::List { items }) => items.len(),
                Some(ResolvedValue::Concrete { value: v }) if v.is_array() => v.as_array().unwrap().len(),
                _ => 0,
            };
            if arr_len > 0 {
                for i in 0..arr_len {
                    let idx_path = format!("{}.{}{}", arr_path, i, suffix);
                    let scenarios = m.resolve_scenarios_json(rid, &idx_path);
                    for (val, conds) in &scenarios {
                        if !satisfiable(m, conds) {
                            continue;
                        }
                        if eval_val_check(check_expr, val) {
                            let cond_map = if conds.is_empty() { None } else { Some(conds.clone()) };
                            let mut d = make_diag(rule, m, rid, rtype, cond_map);
                            d.property_path = Some(idx_path.clone());
                            out.push(d);
                        }
                    }
                }
            } else {
                let scenarios = m.resolve_scenarios_json(rid, path);
                for (val, conds) in &scenarios {
                    if !satisfiable(m, conds) {
                        continue;
                    }
                    if eval_val_check(check_expr, val) {
                        let cond_map = if conds.is_empty() { None } else { Some(conds.clone()) };
                        out.push(make_diag(rule, m, rid, rtype, cond_map));
                    }
                }
            }
            return;
        }

        let scenarios = m.resolve_scenarios_json(rid, path);
        if !scenarios.is_empty() {
            for (val, conds) in &scenarios {
                if !satisfiable(m, conds) {
                    continue;
                }
                if eval_val_check(check_expr, val) {
                    let cond_map = if conds.is_empty() { None } else { Some(conds.clone()) };
                    out.push(make_diag(rule, m, rid, rtype, cond_map));
                }
            }
        } else if check_expr.starts_with("is_object(val)") {
            // Fallback for structural checks: resolve_scenarios_json filters out objects
            // with dynamic/reference values, but structural checks (has_key) only need keys.
            // Use resolve_deep to get the ResolvedValue and build a stub JSON with keys only.
            if let Some(rv) = m.resolve_deep(rid, path) {
                let stub = resolved_value_to_key_stub(&rv);
                if eval_val_check(check_expr, &stub) {
                    out.push(make_diag(rule, m, rid, rtype, None));
                }
            }
        }
        return;
    }

    // scenario_enum_check(name, "path", [...])
    if let Some(rest) = expr.strip_prefix("scenario_enum_check(name, \"")
        && let Some(idx) = rest.find("\", ")
    {
        let path = &rest[..idx];
        let json_str = &rest[idx + 3..];
        let json_str = json_str.strip_suffix(')').unwrap_or(json_str);
        if let Ok(valid_vals) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
            let scenarios = m.resolve_scenarios_json(rid, path);
            for (val, conds) in &scenarios {
                if !satisfiable(m, conds) || val.is_null() {
                    continue;
                }
                let coerced = cfn_coerce_to_string(val);
                let matches = valid_vals.iter().any(|v| match v {
                    serde_json::Value::String(s) => coerced.as_deref() == Some(s.as_str()),
                    serde_json::Value::Number(n) => cfn_coerce_to_number(val)
                        .map(|nv| n.as_f64().map(|nf| (nv - nf).abs() < f64::EPSILON).unwrap_or(false))
                        .unwrap_or(false),
                    serde_json::Value::Bool(b) => val.as_bool() == Some(*b),
                    _ => val == v,
                });
                if !matches {
                    let cond_map = if conds.is_empty() { None } else { Some(conds.clone()) };
                    let mut d = make_diag(rule, m, rid, rtype, cond_map);
                    d.message = format!("{} got '{}'", rule.message, val);
                    out.push(d);
                }
            }
        }
        return;
    }

    // scenario_pattern_check(name, "path", "pattern")
    if let Some(rest) = expr.strip_prefix("scenario_pattern_check(name, \"")
        && let Some(idx) = rest.find("\", \"")
    {
        let path = &rest[..idx];
        let pat_raw = &rest[idx + 4..];
        let pat_raw = pat_raw.strip_suffix("\")").unwrap_or(pat_raw);
        let pat = pat_raw.replace("\\\\", "\\").replace("\\\"", "\"");
        if let Ok(re) = regex::Regex::new(&pat) {
            let scenarios = m.resolve_scenarios_json(rid, path);
            for (val, conds) in &scenarios {
                if !satisfiable(m, conds) {
                    continue;
                }
                if let Some(s) = cfn_coerce_to_string(val) {
                    if s.contains("{{resolve:") || s.contains("${") {
                        continue;
                    }
                    if !re.is_match(&s) {
                        let cond_map = if conds.is_empty() { None } else { Some(conds.clone()) };
                        out.push(make_diag(rule, m, rid, rtype, cond_map));
                    }
                }
            }
        }
        return;
    }

    // array_item_missing_key(name, "path", "key")
    if let Some(rest) = expr.strip_prefix("array_item_missing_key(name, \"")
        && let Some(idx) = rest.find("\", \"")
    {
        let path = &rest[..idx];
        let key = rest[idx + 4..].strip_suffix("\")").unwrap_or(&rest[idx + 4..]);
        let scenarios = m.resolve_scenarios_json(rid, path);
        for (val, conds) in &scenarios {
            if !satisfiable(m, conds) {
                continue;
            }
            if let Some(arr) = val.as_array() {
                for item in arr {
                    if let Some(obj) = item.as_object() {
                        if obj.contains_key(MARKER_CONDITIONAL) || obj.contains_key(MARKER_DYNAMIC) {
                            continue;
                        }
                        if !obj.contains_key(key) {
                            let cond_map = if conds.is_empty() { None } else { Some(conds.clone()) };
                            out.push(make_diag(rule, m, rid, rtype, cond_map));
                        }
                    }
                }
            }
        }
        return;
    }

    // array_item_dep_excluded(name, "path", "trigger", "dep")
    if let Some(rest) = expr.strip_prefix("array_item_dep_excluded(name, \"") {
        let parts: Vec<&str> = rest.splitn(3, "\", \"").collect();
        if parts.len() == 3 {
            let path = parts[0];
            let trigger = parts[1];
            let dep = parts[2].strip_suffix("\")").unwrap_or(parts[2]);
            if let Some(rv) = m.resolve_deep(rid, path) {
                check_array_dep(rv, trigger, dep, true, rule, m, rid, rtype, out);
            }
            return;
        }
    }

    // array_item_dep_required(name, "path", "trigger", "dep")
    if let Some(rest) = expr.strip_prefix("array_item_dep_required(name, \"") {
        let parts: Vec<&str> = rest.splitn(3, "\", \"").collect();
        if parts.len() == 3 {
            let path = parts[0];
            let trigger = parts[1];
            let dep = parts[2].strip_suffix("\")").unwrap_or(parts[2]);
            if let Some(rv) = m.resolve_deep(rid, path) {
                check_array_dep(rv, trigger, dep, false, rule, m, rid, rtype, out);
            }
            return;
        }
    }

    // resolve_val_in / resolve_val_eq (standalone or with && condition)
    if expr.contains("resolve_val_in(") || expr.contains("resolve_val_eq(") {
        let parts: Vec<&str> = expr.splitn(2, " && ").collect();
        if parts.len() == 2 {
            let cond_met = eval_resolve_condition(m, rid, parts[0]);
            if cond_met
                && let Some(prop) = extract_not_has_prop(parts[1])
                && !m.resources.get(rid).map(|r| r.properties.contains_key(prop)).unwrap_or(false)
            {
                out.push(make_diag(rule, m, rid, rtype, None));
            }
        } else if eval_resolve_condition(m, rid, expr) {
            out.push(make_diag(rule, m, rid, rtype, None));
        }
        return;
    }

    // runtime_in_list(name, [...]) — for lambda runtime checks
    if let Some(rest) = expr.strip_prefix("runtime_in_list(name, ") {
        let json_str = rest.strip_suffix(')').unwrap_or(rest);
        if let Ok(runtimes) = serde_json::from_str::<Vec<String>>(json_str) {
            let scenarios = m.resolve_scenarios_json(rid, "Properties.Runtime");
            for (val, conds) in &scenarios {
                if !satisfiable(m, conds) {
                    continue;
                }
                if let Some(s) = val.as_str()
                    && runtimes.iter().any(|r| r == s)
                {
                    let cond_map = if conds.is_empty() { None } else { Some(conds.clone()) };
                    let mut d = make_diag(rule, m, rid, rtype, cond_map);
                    d.message = format!(
                        "Lambda runtime '{}' {}",
                        s,
                        if rule.rule_id == "E2533" { "is end-of-life and cannot be updated" } else { "is deprecated" }
                    );
                    out.push(d);
                }
            }
        }
    }
}

fn extract_has_prop(s: &str) -> Option<&str> {
    s.strip_prefix("has_property(name, \"")?.strip_suffix("\")")
}

fn extract_not_has_prop(s: &str) -> Option<&str> {
    s.strip_prefix("!has_property(name, \"")?.strip_suffix("\")")
}

/// Convert a ResolvedValue to a JSON stub preserving only object keys.
/// Values are set to `true` so `has_key` checks work, but dynamic/reference
/// content doesn't cause filtering. Used as fallback for structural checks.
fn resolved_value_to_key_stub(rv: &ResolvedValue) -> serde_json::Value {
    match rv {
        ResolvedValue::Map { entries } => {
            let obj: serde_json::Map<String, serde_json::Value> =
                entries.iter().map(|e| (e.key.clone(), serde_json::Value::Bool(true))).collect();
            serde_json::Value::Object(obj)
        }
        ResolvedValue::Concrete { value: v } => v.0.clone(),
        _ => serde_json::Value::Null,
    }
}

fn eval_val_check(expr: &str, val: &serde_json::Value) -> bool {
    if expr.contains("!is_null(val)") && val.is_null() {
        return false;
    }

    if expr == "!is_string(val) && !is_null(val)" {
        return !val.is_string() && !val.is_null();
    }
    if expr == "!is_number(val) && !is_null(val)" {
        return !val.is_number() && !val.is_null();
    }
    if expr == "!is_boolean(val) && !is_null(val)" {
        return !val.is_boolean() && !val.is_null();
    }
    if expr == "!is_object(val) && !is_null(val)" {
        return !val.is_object() && !val.is_null();
    }
    if expr == "!is_array(val) && !is_null(val)" {
        return !val.is_array() && !val.is_null();
    }
    if expr == "!is_string(val) && !is_number(val) && !is_null(val)" {
        return !val.is_string() && !val.is_number() && !val.is_null();
    }

    if expr.starts_with("is_object(val) && !has_key(val, \"")
        && let Some(key) = expr.strip_prefix("is_object(val) && !has_key(val, \"").and_then(|r| r.strip_suffix("\")"))
    {
        return val.as_object().map(|obj| !obj.contains_key(key)).unwrap_or(false);
    }

    if expr.starts_with("is_object(val) && has_key(val, \"") && expr.contains("&& !has_key(val, \"") {
        let parts: Vec<&str> = expr.split(" && ").collect();
        if parts.len() == 3 {
            let trigger = parts[1].strip_prefix("has_key(val, \"").and_then(|r| r.strip_suffix("\")"));
            let dep = parts[2].strip_prefix("!has_key(val, \"").and_then(|r| r.strip_suffix("\")"));
            if let (Some(t), Some(d)) = (trigger, dep)
                && let Some(obj) = val.as_object()
            {
                return obj.contains_key(t) && !obj.contains_key(d);
            }
        }
        return false;
    }

    // Nested dependentExcluded: is_object(val) && has_key(val, "A") && has_key(val, "B")
    if expr.starts_with("is_object(val) && has_key(val, \"") && expr.matches("has_key(val, \"").count() == 2 {
        let parts: Vec<&str> = expr.split(" && ").collect();
        if parts.len() == 3 {
            let a = parts[1].strip_prefix("has_key(val, \"").and_then(|r| r.strip_suffix("\")"));
            let b = parts[2].strip_prefix("has_key(val, \"").and_then(|r| r.strip_suffix("\")"));
            if let (Some(ka), Some(kb)) = (a, b)
                && let Some(obj) = val.as_object()
            {
                return obj.contains_key(ka) && obj.contains_key(kb);
            }
        }
        return false;
    }

    // Numeric: coerce_to_number(val) > N or < N
    if let Some(rest) = expr.strip_prefix("coerce_to_number(val) > ")
        && let Ok(n) = rest.parse::<i64>()
    {
        return cfn_coerce_to_number(val).map(|v| v > n as f64).unwrap_or(false);
    }
    if let Some(rest) = expr.strip_prefix("coerce_to_number(val) < ")
        && let Ok(n) = rest.parse::<i64>()
    {
        return cfn_coerce_to_number(val).map(|v| v < n as f64).unwrap_or(false);
    }

    // String length: size(coerce_to_string(val)) > N or < N
    if let Some(rest) = expr.strip_prefix("size(coerce_to_string(val)) > ")
        && let Ok(n) = rest.parse::<u64>()
    {
        return cfn_coerce_to_string(val).map(|s| s.len() as u64 > n).unwrap_or(false);
    }
    if let Some(rest) = expr.strip_prefix("size(coerce_to_string(val)) < ")
        && let Ok(n) = rest.parse::<u64>()
    {
        return cfn_coerce_to_string(val).map(|s| (s.len() as u64) < n).unwrap_or(false);
    }

    // Array size: is_array(val) && size(val) > N or < N
    if let Some(rest) = expr.strip_prefix("is_array(val) && size(val) > ")
        && let Ok(n) = rest.parse::<u64>()
    {
        return val.as_array().map(|a| a.len() as u64 > n).unwrap_or(false);
    }
    if let Some(rest) = expr.strip_prefix("is_array(val) && size(val) < ")
        && let Ok(n) = rest.parse::<u64>()
    {
        return val.as_array().map(|a| (a.len() as u64) < n).unwrap_or(false);
    }

    // uniqueItems: is_array(val) && has_duplicates(val)
    if expr == "is_array(val) && has_duplicates(val)" {
        if let Some(arr) = val.as_array() {
            let strs: Vec<String> = arr.iter().map(|v| v.to_string()).collect();
            let unique: HashSet<&str> = strs.iter().map(|s| s.as_str()).collect();
            return strs.len() != unique.len();
        }
        return false;
    }

    false
}

fn eval_resolve_condition(m: &SemanticModel, rid: &str, expr: &str) -> bool {
    // resolve_val_in(name, "path", [...])
    if let Some(rest) = expr.strip_prefix("resolve_val_in(name, \"")
        && let Some(idx) = rest.find("\", ")
    {
        let path = &rest[..idx];
        let json_str = rest[idx + 3..].strip_suffix(')').unwrap_or(&rest[idx + 3..]);
        if let Ok(valid) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
            let scenarios = m.resolve_scenarios_json(rid, path);
            for (val, _) in &scenarios {
                if valid.iter().any(
                    |v| {
                        if let (Some(a), Some(b)) = (v.as_str(), val.as_str()) { a == b } else { v == val }
                    },
                ) {
                    return true;
                }
            }
        }
    }
    // resolve_val_eq(name, "path", val)
    if let Some(rest) = expr.strip_prefix("resolve_val_eq(name, \"")
        && let Some(idx) = rest.find("\", ")
    {
        let path = &rest[..idx];
        let json_str = rest[idx + 3..].strip_suffix(')').unwrap_or(&rest[idx + 3..]);
        if let Ok(expected) = serde_json::from_str::<serde_json::Value>(json_str) {
            let scenarios = m.resolve_scenarios_json(rid, path);
            for (val, _) in &scenarios {
                if *val == expected {
                    return true;
                }
            }
        }
    }
    false
}

fn check_array_dep(
    rv: ResolvedValue,
    trigger: &str,
    dep: &str,
    excluded: bool,
    rule: &RuleDescriptor,
    m: &Arc<SemanticModel>,
    rid: &str,
    rtype: &str,
    out: &mut Vec<Diagnostic>,
) {
    match rv {
        ResolvedValue::Concrete { value: v } => {
            if let Some(arr) = v.as_array() {
                for item in arr {
                    if let Some(obj) = item.as_object() {
                        let has_trigger = obj.contains_key(trigger);
                        let has_dep = obj.contains_key(dep);
                        let violates = if excluded { has_dep } else { !has_dep };
                        if has_trigger && violates {
                            out.push(make_diag(rule, m, rid, rtype, None));
                        }
                    }
                }
            }
        }
        ResolvedValue::Map { entries } => {
            let has_trigger = entries.iter().any(|e| e.key == trigger);
            let has_dep = entries.iter().any(|e| e.key == dep);
            let violates = if excluded { has_dep } else { !has_dep };
            if has_trigger && violates {
                out.push(make_diag(rule, m, rid, rtype, None));
            }
        }
        ResolvedValue::List { items } => {
            for item in items {
                check_array_dep(item, trigger, dep, excluded, rule, m, rid, rtype, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use template_model::resolver::{MapEntry, ResolvedValue};

    #[test]
    fn extract_has_prop_valid() {
        assert_eq!(extract_has_prop("has_property(name, \"BucketName\")"), Some("BucketName"));
    }

    #[test]
    fn extract_has_prop_invalid_prefix() {
        assert_eq!(extract_has_prop("!has_property(name, \"X\")"), None);
    }

    #[test]
    fn extract_has_prop_no_closing() {
        assert_eq!(extract_has_prop("has_property(name, \"X\""), None);
    }

    #[test]
    fn extract_not_has_prop_valid() {
        assert_eq!(extract_not_has_prop("!has_property(name, \"Encryption\")"), Some("Encryption"));
    }

    #[test]
    fn extract_not_has_prop_without_negation() {
        assert_eq!(extract_not_has_prop("has_property(name, \"X\")"), None);
    }

    #[test]
    fn key_stub_from_map_preserves_keys() {
        let rv = ResolvedValue::Map {
            entries: vec![
                MapEntry { key: "KeyA".into(), value: ResolvedValue::Dynamic { reason: "ref".into() } },
                MapEntry { key: "KeyB".into(), value: ResolvedValue::Concrete { value: json!(42).into() } },
            ],
        };
        let stub = resolved_value_to_key_stub(&rv);
        let obj = stub.as_object().unwrap();
        assert_eq!(obj.len(), 2);
        assert_eq!(obj["KeyA"], json!(true));
        assert_eq!(obj["KeyB"], json!(true));
    }

    #[test]
    fn key_stub_from_concrete_passes_through() {
        let rv = ResolvedValue::Concrete { value: json!({"x": 1}).into() };
        let stub = resolved_value_to_key_stub(&rv);
        assert_eq!(stub, json!({"x": 1}));
    }

    #[test]
    fn key_stub_from_other_returns_null() {
        let rv = ResolvedValue::Dynamic { reason: "something".into() };
        assert_eq!(resolved_value_to_key_stub(&rv), json!(null));
    }

    // Type checks
    #[test]
    fn eval_not_string_and_not_null_rejects_string() {
        assert!(!eval_val_check("!is_string(val) && !is_null(val)", &json!("hello")));
    }

    #[test]
    fn eval_not_string_and_not_null_rejects_null() {
        assert!(!eval_val_check("!is_string(val) && !is_null(val)", &json!(null)));
    }

    #[test]
    fn eval_not_string_and_not_null_accepts_number() {
        assert!(eval_val_check("!is_string(val) && !is_null(val)", &json!(42)));
    }

    #[test]
    fn eval_not_number_and_not_null() {
        assert!(eval_val_check("!is_number(val) && !is_null(val)", &json!("x")));
        assert!(!eval_val_check("!is_number(val) && !is_null(val)", &json!(1)));
    }

    #[test]
    fn eval_not_boolean_and_not_null() {
        assert!(eval_val_check("!is_boolean(val) && !is_null(val)", &json!(1)));
        assert!(!eval_val_check("!is_boolean(val) && !is_null(val)", &json!(true)));
    }

    #[test]
    fn eval_not_object_and_not_null() {
        assert!(eval_val_check("!is_object(val) && !is_null(val)", &json!("x")));
        assert!(!eval_val_check("!is_object(val) && !is_null(val)", &json!({"a": 1})));
    }

    #[test]
    fn eval_not_array_and_not_null() {
        assert!(eval_val_check("!is_array(val) && !is_null(val)", &json!("x")));
        assert!(!eval_val_check("!is_array(val) && !is_null(val)", &json!([1])));
    }

    #[test]
    fn eval_not_string_not_number_not_null() {
        assert!(eval_val_check("!is_string(val) && !is_number(val) && !is_null(val)", &json!(true)));
        assert!(!eval_val_check("!is_string(val) && !is_number(val) && !is_null(val)", &json!("x")));
        assert!(!eval_val_check("!is_string(val) && !is_number(val) && !is_null(val)", &json!(1)));
    }

    // Nested required: is_object && !has_key
    #[test]
    fn eval_object_missing_key() {
        assert!(eval_val_check("is_object(val) && !has_key(val, \"Required\")", &json!({"Other": 1})));
    }

    #[test]
    fn eval_object_has_key() {
        assert!(!eval_val_check("is_object(val) && !has_key(val, \"Required\")", &json!({"Required": 1})));
    }

    #[test]
    fn eval_object_missing_key_on_non_object() {
        assert!(!eval_val_check("is_object(val) && !has_key(val, \"X\")", &json!("string")));
    }

    // Nested dependentRequired: is_object && has_key(A) && !has_key(B)
    #[test]
    fn eval_dependent_required_fires() {
        assert!(eval_val_check(
            "is_object(val) && has_key(val, \"Trigger\") && !has_key(val, \"Dep\")",
            &json!({"Trigger": 1})
        ));
    }

    #[test]
    fn eval_dependent_required_satisfied() {
        assert!(!eval_val_check(
            "is_object(val) && has_key(val, \"Trigger\") && !has_key(val, \"Dep\")",
            &json!({"Trigger": 1, "Dep": 2})
        ));
    }

    // Nested dependentExcluded: is_object && has_key(A) && has_key(B)
    #[test]
    fn eval_dependent_excluded_fires() {
        assert!(eval_val_check(
            "is_object(val) && has_key(val, \"A\") && has_key(val, \"B\")",
            &json!({"A": 1, "B": 2})
        ));
    }

    #[test]
    fn eval_dependent_excluded_not_both() {
        assert!(!eval_val_check("is_object(val) && has_key(val, \"A\") && has_key(val, \"B\")", &json!({"A": 1})));
    }

    // Numeric checks
    #[test]
    fn eval_coerce_number_gt() {
        assert!(eval_val_check("coerce_to_number(val) > 100", &json!(200)));
        assert!(!eval_val_check("coerce_to_number(val) > 100", &json!(50)));
    }

    #[test]
    fn eval_coerce_number_lt() {
        assert!(eval_val_check("coerce_to_number(val) < 10", &json!(5)));
        assert!(!eval_val_check("coerce_to_number(val) < 10", &json!(20)));
    }

    #[test]
    fn eval_coerce_number_string_coercion() {
        assert!(eval_val_check("coerce_to_number(val) > 100", &json!("200")));
    }

    // String length checks
    #[test]
    fn eval_string_size_gt() {
        assert!(eval_val_check("size(coerce_to_string(val)) > 5", &json!("longstring")));
        assert!(!eval_val_check("size(coerce_to_string(val)) > 5", &json!("hi")));
    }

    #[test]
    fn eval_string_size_lt() {
        assert!(eval_val_check("size(coerce_to_string(val)) < 3", &json!("ab")));
        assert!(!eval_val_check("size(coerce_to_string(val)) < 3", &json!("abcdef")));
    }

    // Array size checks
    #[test]
    fn eval_array_size_gt() {
        assert!(eval_val_check("is_array(val) && size(val) > 2", &json!([1, 2, 3])));
        assert!(!eval_val_check("is_array(val) && size(val) > 2", &json!([1])));
    }

    #[test]
    fn eval_array_size_lt() {
        assert!(eval_val_check("is_array(val) && size(val) < 2", &json!([1])));
        assert!(!eval_val_check("is_array(val) && size(val) < 2", &json!([1, 2, 3])));
    }

    #[test]
    fn eval_array_size_on_non_array() {
        assert!(!eval_val_check("is_array(val) && size(val) > 0", &json!("x")));
    }

    // Duplicates
    #[test]
    fn eval_has_duplicates_true() {
        assert!(eval_val_check("is_array(val) && has_duplicates(val)", &json!([1, 2, 1])));
    }

    #[test]
    fn eval_has_duplicates_false() {
        assert!(!eval_val_check("is_array(val) && has_duplicates(val)", &json!([1, 2, 3])));
    }

    #[test]
    fn eval_has_duplicates_non_array() {
        assert!(!eval_val_check("is_array(val) && has_duplicates(val)", &json!("x")));
    }

    // Null guard
    #[test]
    fn eval_not_null_guard_blocks_null() {
        assert!(!eval_val_check("!is_null(val)", &json!(null)));
    }

    // Unknown expression returns false
    #[test]
    fn eval_unknown_expression_returns_false() {
        assert!(!eval_val_check("some_unknown_check(val)", &json!(42)));
    }
}
