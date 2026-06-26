use crate::SyncStats;
use log::{info, warn};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub fn sync_additional_specs(
    rule_source_dir: &Path,
    data_output_dir: &Path,
    upstream_dir: &Path,
) -> anyhow::Result<SyncStats> {
    let mut stats = SyncStats::default();
    let specs_dir = rule_source_dir.join("src/cfnlint/data/AdditionalSpecs");
    if !specs_dir.exists() {
        anyhow::bail!("Rule-source AdditionalSpecs not found at: {}", specs_dir.display());
    }
    fs::create_dir_all(data_output_dir)?;

    let lifecycle_file = specs_dir.join("LmbdRuntimeLifecycle.json");
    if lifecycle_file.exists() {
        let content = fs::read_to_string(&lifecycle_file)?;
        let lifecycle: BTreeMap<String, serde_json::Value> = serde_json::from_str(&content)?;
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();

        let mut current = Vec::new();
        let mut deprecated = Vec::new();
        let mut create_blocked = Vec::new();
        let mut eol = Vec::new();

        for (runtime, info) in &lifecycle {
            let create_block = info.get("create-block").and_then(|v| v.as_str()).unwrap_or("");
            let update_block = info.get("update-block").and_then(|v| v.as_str()).unwrap_or("");
            let deprecated_date = info.get("deprecated").and_then(|v| v.as_str()).unwrap_or("");

            if !update_block.is_empty() && update_block <= today.as_str() {
                eol.push(runtime.clone());
            } else if !create_block.is_empty() && create_block <= today.as_str() {
                create_blocked.push(runtime.clone());
            } else if !deprecated_date.is_empty() && deprecated_date <= today.as_str() {
                deprecated.push(runtime.clone());
            } else {
                current.push(runtime.clone());
            }
        }

        let out = serde_json::json!({
            "lambda_runtimes": { "current": current, "deprecated": deprecated, "create_blocked": create_blocked, "eol": eol }
        });
        fs::write(data_output_dir.join("lambda_runtimes.json"), serde_json::to_string_pretty(&out)?)?;
        stats.files_written += 1;
        info!(
            "Synced lambda runtimes: {} current, {} deprecated, {} create-blocked, {} eol -> lambda_runtimes.json",
            current.len(),
            deprecated.len(),
            create_blocked.len(),
            eol.len()
        );
    } else {
        warn!("LmbdRuntimeLifecycle.json not found, skipping lambda runtimes");
    }

    let policies_file = specs_dir.join("Policies.json");
    if policies_file.exists() {
        let content = fs::read_to_string(&policies_file)?;
        let policies: BTreeMap<String, serde_json::Value> = serde_json::from_str(&content)?;
        let mut patterns: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for (service, svc_val) in &policies {
            let resources = match svc_val.get("Resources").and_then(|v| v.as_object()) {
                Some(r) => r,
                None => continue,
            };
            let actions = match svc_val.get("Actions").and_then(|v| v.as_object()) {
                Some(a) => a,
                None => continue,
            };
            let mut res_last_arn: BTreeMap<String, String> = BTreeMap::new();
            for (res_name, res_val) in resources {
                if let Some(arns) = res_val.get("ARNFormats").and_then(|v| v.as_array()) {
                    if let Some(last) = arns.last().and_then(|v| v.as_str()) {
                        res_last_arn.insert(res_name.to_lowercase(), last.to_string());
                    }
                }
            }
            for (action_name, action_val) in actions {
                if let Some(action_resources) = action_val.get("Resources").and_then(|v| v.as_array()) {
                    let mut arn_formats = Vec::new();
                    for res_ref in action_resources {
                        if let Some(res_name) = res_ref.as_str() {
                            if let Some(arn) = res_last_arn.get(&res_name.to_lowercase()) {
                                arn_formats.push(arn.clone());
                            }
                        }
                    }
                    if !arn_formats.is_empty() {
                        let key = format!("{}:{}", service, action_name);
                        patterns.insert(key, arn_formats);
                    }
                }
            }
        }

        let out = serde_json::json!({ "iam_action_resource_patterns": patterns });
        fs::write(data_output_dir.join("iam_action_resource_patterns.json"), serde_json::to_string_pretty(&out)?)?;
        stats.files_written += 1;
        info!("Synced {} IAM action-resource patterns -> iam_action_resource_patterns.json", patterns.len());
    } else {
        warn!("Policies.json not found, skipping IAM patterns");
    }

    let stateful_file = specs_dir.join("StatefulResources.json");
    if stateful_file.exists() {
        let content = fs::read_to_string(&stateful_file)?;
        let val: serde_json::Value = serde_json::from_str(&content)?;
        if let Some(types) = val.get("ResourceTypes").and_then(|v| v.as_object()) {
            let mut list: Vec<String> = types.keys().cloned().collect();
            list.sort();
            let out = serde_json::json!({ "stateful_resource_types": list });
            fs::write(data_output_dir.join("stateful_resource_types.json"), serde_json::to_string_pretty(&out)?)?;
            stats.files_written += 1;
            info!("Synced {} stateful resource types -> stateful_resource_types.json", list.len());
        }
    } else {
        warn!("StatefulResources.json not found, skipping stateful types");
    }

    let sf_schema = rule_source_dir.join("src/cfnlint/data/schemas/other/step_functions/statemachine.json");
    if sf_schema.exists() {
        let content = fs::read_to_string(&sf_schema)?;
        let _: serde_json::Value = serde_json::from_str(&content)?;
        fs::write(upstream_dir.join("step_functions_statemachine.json"), &content)?;
        stats.files_written += 1;
        info!("Synced Step Functions state machine schema -> upstream/step_functions_statemachine.json");
    } else {
        warn!("Step Functions schema not found at {:?}, skipping", sf_schema);
    }

    info!("Additional specs: {} files written", stats.files_written);
    Ok(stats)
}
