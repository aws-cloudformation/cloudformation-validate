use serde::{Deserialize, Serialize};
use web_time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm-bindings", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct PhaseMetric {
    pub duration_ms: f64,
}

/// Creates a `PhaseMetric` from the elapsed time since `start`.
pub fn phase_metric(start: Instant) -> PhaseMetric {
    PhaseMetric {
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn phase_metric_captures_nonzero_elapsed_time() {
        let start = Instant::now();
        thread::sleep(Duration::from_millis(10));
        let metric = phase_metric(start);
        assert!(
            metric.duration_ms >= 5.0,
            "Expected at least 5ms, got {}ms",
            metric.duration_ms
        );
    }

    #[test]
    fn phase_metric_serializes_camel_case_field_name() {
        let metric = PhaseMetric { duration_ms: 42.5 };
        let json = serde_json::to_string(&metric).unwrap();
        assert!(json.contains("durationMs"));
        assert!(json.contains("42.5"));
    }

    #[test]
    fn phase_metric_serde_round_trips() {
        let original = PhaseMetric {
            duration_ms: 123.456,
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: PhaseMetric = serde_json::from_str(&json).unwrap();
        assert!((deserialized.duration_ms - 123.456).abs() < f64::EPSILON);
    }
}
