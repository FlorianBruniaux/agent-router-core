//! Qualified local capture intervals. No wall clock or serializable Instant.
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureTiming {
    Known { duration_ms: u64 },
    Unknown { reason: TimingUnknownReason },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingUnknownReason {
    MissingRecord,
    ClockRegression,
    DurationOverflow,
}
impl CaptureTiming {
    pub(crate) fn between(start: Instant, end: Instant) -> Self {
        Self::from_duration(end.checked_duration_since(start))
    }
    fn from_duration(duration: Option<Duration>) -> Self {
        match duration {
            None => Self::Unknown {
                reason: TimingUnknownReason::ClockRegression,
            },
            Some(duration) => match u64::try_from(duration.as_millis()) {
                Ok(duration_ms) => Self::Known { duration_ms },
                Err(_) => Self::Unknown {
                    reason: TimingUnknownReason::DurationOverflow,
                },
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttemptTimingRecord {
    pub schema_version: u32,
    pub ordinal: u32,
    pub attempt_evidence_sha256: String,
    pub producer: String,
    pub scope: String,
    pub clock: String,
    pub start_boundary: String,
    pub end_boundary: String,
    pub precision: String,
    pub measurement: CaptureTiming,
}
impl AttemptTimingRecord {
    pub(crate) fn new(ordinal: u32, hash: String, measurement: CaptureTiming) -> Self {
        Self {
            schema_version: 1,
            ordinal,
            attempt_evidence_sha256: hash,
            producer: "capture_guarded_v1".into(),
            scope: "supervisor_capture".into(),
            clock: "monotonic_same_invocation".into(),
            start_boundary: "before_dispatch_validation".into(),
            end_boundary: "after_reap_and_both_output_drains".into(),
            precision: "milliseconds_truncated".into(),
            measurement,
        }
    }
    pub(crate) fn valid(&self, elapsed_ms: u64) -> bool {
        self.schema_version == 1
            && (1..=5).contains(&self.ordinal)
            && self.producer == "capture_guarded_v1"
            && self.scope == "supervisor_capture"
            && self.clock == "monotonic_same_invocation"
            && self.start_boundary == "before_dispatch_validation"
            && self.end_boundary == "after_reap_and_both_output_drains"
            && self.precision == "milliseconds_truncated"
            && match self.measurement {
                CaptureTiming::Known { duration_ms } => duration_ms == elapsed_ms,
                CaptureTiming::Unknown { reason } => reason != TimingUnknownReason::MissingRecord,
            }
    }
}

/// Redacted source-bound local interval. Native and aggregate durations remain unknown.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AttemptTimingObservation {
    pub ordinal: u32,
    pub attempt_key_sha256: String,
    pub timing_event_sha256: Option<String>,
    pub scope: &'static str,
    pub clock: &'static str,
    pub start_boundary: &'static str,
    pub end_boundary: &'static str,
    pub precision: &'static str,
    pub measurement: CaptureTiming,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_intervals_distinguish_zero_truncation_regression_and_overflow() {
        let start = Instant::now();
        assert_eq!(
            CaptureTiming::between(start, start),
            CaptureTiming::Known { duration_ms: 0 }
        );
        assert_eq!(
            CaptureTiming::between(start, start + Duration::from_micros(1999)),
            CaptureTiming::Known { duration_ms: 1 }
        );
        assert_eq!(
            CaptureTiming::between(start + Duration::from_millis(1), start),
            CaptureTiming::Unknown {
                reason: TimingUnknownReason::ClockRegression
            }
        );
        assert_eq!(
            CaptureTiming::from_duration(Some(Duration::MAX)),
            CaptureTiming::Unknown {
                reason: TimingUnknownReason::DurationOverflow
            }
        );
    }
}
