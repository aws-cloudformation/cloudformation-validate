use crate::coercion::coerce_string_or_integer_to_string;
use serde_json::Value;

pub const CPU_UNIT_LABELS: &[&str] = &["256", "512", "1024", "2048", "4096", "8192", "16384", "32768"];

const VCPU_SIZES: &[(&str, i64)] =
    &[(".25", 256), (".5", 512), ("1", 1024), ("2", 2048), ("4", 4096), ("8", 8192), ("16", 16384), ("32", 32768)];
const MIB_PER_GIB: i64 = 1024;

/// Returns whether an authored string-or-integer Cpu value names a Fargate size.
/// Values of another JSON shape return `None` so schema type validation remains
/// the sole owner of those findings.
pub fn cpu_is_offered(value: &Value) -> Option<bool> {
    let authored = coerce_string_or_integer_to_string(value)?;
    Some(cpu_units(&authored).is_some())
}

/// Returns whether authored string-or-integer Cpu and Memory values form a size
/// Fargate offers. Unsupported JSON shapes return `None`; malformed scalar
/// spellings return `Some(false)`.
pub fn task_size_is_offered(cpu: &Value, memory: &Value) -> Option<bool> {
    let cpu_text = coerce_string_or_integer_to_string(cpu)?;
    let memory_text = coerce_string_or_integer_to_string(memory)?;
    Some(match (cpu_units(&cpu_text), memory_mib(&memory_text)) {
        (Some(cpu_units), Some(memory_mib)) => valid_size_pair(cpu_units, memory_mib),
        _ => false,
    })
}

fn cpu_units(authored: &str) -> Option<i64> {
    if authored.bytes().all(|byte| byte.is_ascii_digit()) && !authored.is_empty() {
        return CPU_UNIT_LABELS.iter().find(|offered| **offered == authored).and_then(|offered| offered.parse().ok());
    }

    let lower = authored.to_ascii_lowercase();
    let vcpu = lower.strip_suffix("vcpu")?.trim();
    VCPU_SIZES.iter().find(|(label, _)| *label == vcpu).map(|(_, units)| *units)
}

fn memory_mib(authored: &str) -> Option<i64> {
    if !authored.is_empty() && authored.bytes().all(|byte| byte.is_ascii_digit()) {
        return authored.parse().ok();
    }

    let lower = authored.to_ascii_lowercase();
    let gib = lower.strip_suffix("gb")?.trim();
    if gib == "0.5" {
        return Some(MIB_PER_GIB / 2);
    }
    if gib.is_empty() || !gib.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    gib.parse::<i64>().ok()?.checked_mul(MIB_PER_GIB)
}

fn valid_size_pair(cpu: i64, memory: i64) -> bool {
    let (minimum, maximum, step) = match cpu {
        256 => return [512, 1024, 2048].contains(&memory),
        512 => (1024, 4096, 1024),
        1024 => (2048, 8192, 1024),
        2048 => (4096, 16384, 1024),
        4096 => (8192, 30720, 1024),
        8192 => (16384, 61440, 4096),
        16384 => (32768, 122880, 8192),
        32768 => return [61440, 122880, 249856].contains(&memory),
        _ => return false,
    };
    (minimum..=maximum).contains(&memory) && memory % step == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cpu_accepts_offered_unit_and_vcpu_spellings() {
        for value in [json!(256), json!("256"), json!(".25 vCPU"), json!("16vcpu"), json!("32 VCPU")] {
            assert_eq!(cpu_is_offered(&value), Some(true), "{value} must name an offered Cpu size");
        }
    }

    #[test]
    fn cpu_rejects_unoffered_scalar_spellings_and_defers_other_shapes() {
        for value in [json!("0512"), json!("3 vCPU"), json!("bananas"), json!(128)] {
            assert_eq!(cpu_is_offered(&value), Some(false), "{value} must not name an offered Cpu size");
        }
        for value in [json!(256.0), json!(true), json!([256]), json!({"Cpu": 256}), json!(null)] {
            assert_eq!(cpu_is_offered(&value), None, "{value} must be left to schema type validation");
        }
    }

    #[test]
    fn task_sizes_accept_units_and_documented_unit_suffixes() {
        for (cpu, memory) in [
            (json!(256), json!(512)),
            (json!(".25 vCPU"), json!("0.5 GB")),
            (json!("8 vCPU"), json!("60GB")),
            (json!("16 vCPU"), json!("120 GB")),
            (json!(32768), json!("60 GB")),
            (json!("32 vCPU"), json!("120 GB")),
            (json!("32768"), json!("244 GB")),
        ] {
            assert_eq!(task_size_is_offered(&cpu, &memory), Some(true), "{cpu}/{memory} must be offered");
        }
    }

    #[test]
    fn task_sizes_enforce_ranges_steps_and_discrete_32_vcpu_values() {
        for (cpu, memory) in [
            (json!(8192), json!(17408)),
            (json!("8 vCPU"), json!("17 GB")),
            (json!(16384), json!(36864)),
            (json!(32768), json!(65536)),
            (json!(32768), json!(245760)),
            (json!("32 vCPU"), json!("240 GB")),
        ] {
            assert_eq!(task_size_is_offered(&cpu, &memory), Some(false), "{cpu}/{memory} must not be offered");
        }
    }

    #[test]
    fn task_size_conversion_rejects_overflow_without_panicking() {
        assert_eq!(task_size_is_offered(&json!(8192), &json!("9999999999999999GB")), Some(false));
        assert_eq!(task_size_is_offered(&json!(8192), &json!("9223372036854775807GB")), Some(false));
    }

    #[test]
    fn task_size_defers_non_string_non_integer_shapes() {
        assert_eq!(task_size_is_offered(&json!(256.0), &json!(512)), None);
        assert_eq!(task_size_is_offered(&json!(256), &json!([512])), None);
    }
}
