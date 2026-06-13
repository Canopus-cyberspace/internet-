use crate::event_bus::{PriorityLane, TopicName, OPERATIONAL_METRIC};
use crate::observability::diagnostics::{validate_privacy_safe_text, DiagnosticsValidationError};
use sentinel_contracts::{MetricKind, PrivacyClass, SchemaVersion, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use super::diagnostics::TraceLink;

pub const METRIC_SAMPLE_EVENT_TYPE: &str = "platform.metric.sample";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricDescriptor {
    pub metric_name: String,
    pub kind: MetricKind,
    pub unit: Option<String>,
    pub description_redacted: String,
    pub labels: Vec<String>,
    pub privacy_class: PrivacyClass,
    pub schema_version: SchemaVersion,
}

impl MetricDescriptor {
    pub fn new(
        metric_name: impl Into<String>,
        kind: MetricKind,
        description_redacted: impl Into<String>,
    ) -> Result<Self, MetricValidationError> {
        Ok(Self {
            metric_name: require_metric_text("metric_name", metric_name)?,
            kind,
            unit: None,
            description_redacted: require_metric_text(
                "description_redacted",
                description_redacted,
            )?,
            labels: Vec::new(),
            privacy_class: PrivacyClass::Internal,
            schema_version: SchemaVersion::new(1, 0, 0),
        })
    }

    pub fn with_labels(mut self, labels: Vec<String>) -> Result<Self, MetricValidationError> {
        for label in &labels {
            validate_metric_text("label", label)?;
        }
        self.labels = labels;
        Ok(self)
    }

    pub fn core_v1_catalog() -> Vec<Self> {
        vec![
            counter("plugin_throughput", "Plugin event throughput"),
            gauge_ms("plugin_latency", "Plugin processing latency"),
            gauge_ratio("plugin_error_rate", "Plugin error rate"),
            gauge("queue_lag", "Event queue lag"),
            gauge("queue_depth", "Event queue depth"),
            counter("dropped_events", "Dropped low priority events"),
            counter("schema_validation_failure", "Schema validation failures"),
            counter("finding_count", "Findings emitted"),
            counter("alert_count", "Alerts emitted"),
            counter("incident_count", "Incidents emitted"),
            gauge_ratio("risk_score_distribution", "Risk score distribution summary"),
            gauge("model_staleness", "Model staleness indicator"),
            gauge_ratio("replay_success_rate", "Replay success rate"),
            counter("response_success", "Successful response results"),
            counter("rollback_success", "Successful rollback results"),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram {
        buckets: Vec<MetricBucket>,
        count: u64,
        sum: f64,
    },
    Distribution {
        values: Vec<f64>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricBucket {
    pub upper_bound: f64,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricSample {
    pub metric_name: String,
    pub value: MetricValue,
    pub labels: BTreeMap<String, String>,
    pub observed_at: Timestamp,
    pub privacy_class: PrivacyClass,
    pub trace_link: Option<TraceLink>,
}

impl MetricSample {
    pub fn new(
        metric_name: impl Into<String>,
        value: MetricValue,
    ) -> Result<Self, MetricValidationError> {
        Ok(Self {
            metric_name: require_metric_text("metric_name", metric_name)?,
            value,
            labels: BTreeMap::new(),
            observed_at: Timestamp::now(),
            privacy_class: PrivacyClass::Internal,
            trace_link: None,
        })
    }

    pub fn topic_name() -> TopicName {
        TopicName::new(OPERATIONAL_METRIC).expect("operational metric topic is valid")
    }

    pub fn event_type() -> &'static str {
        METRIC_SAMPLE_EVENT_TYPE
    }

    pub fn priority_lane(&self) -> PriorityLane {
        PriorityLane::P3Low
    }

    pub fn validate(
        &self,
        descriptor: Option<&MetricDescriptor>,
    ) -> Result<(), MetricValidationError> {
        validate_metric_text("metric_name", &self.metric_name)?;
        for (key, value) in &self.labels {
            validate_metric_text("label_key", key)?;
            validate_metric_text("label_value", value)?;
        }

        if let Some(descriptor) = descriptor {
            if descriptor.metric_name != self.metric_name {
                return Err(MetricValidationError::DescriptorMismatch {
                    expected: descriptor.metric_name.clone(),
                    actual: self.metric_name.clone(),
                });
            }
        }

        Ok(())
    }
}

pub trait MetricsSink {
    fn record(&mut self, sample: MetricSample) -> Result<(), MetricSinkError>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryMetricsSink {
    samples: Vec<MetricSample>,
}

impl InMemoryMetricsSink {
    pub fn samples(&self) -> &[MetricSample] {
        &self.samples
    }
}

impl MetricsSink for InMemoryMetricsSink {
    fn record(&mut self, sample: MetricSample) -> Result<(), MetricSinkError> {
        sample.validate(None)?;
        self.samples.push(sample);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetricValidationError {
    Diagnostics(DiagnosticsValidationError),
    DescriptorMismatch { expected: String, actual: String },
}

impl fmt::Display for MetricValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Diagnostics(error) => write!(f, "{error}"),
            Self::DescriptorMismatch { expected, actual } => {
                write!(
                    f,
                    "metric descriptor mismatch: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for MetricValidationError {}

impl From<DiagnosticsValidationError> for MetricValidationError {
    fn from(value: DiagnosticsValidationError) -> Self {
        Self::Diagnostics(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetricSinkError {
    Validation(MetricValidationError),
}

impl fmt::Display for MetricSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for MetricSinkError {}

impl From<MetricValidationError> for MetricSinkError {
    fn from(value: MetricValidationError) -> Self {
        Self::Validation(value)
    }
}

fn counter(name: &str, description: &str) -> MetricDescriptor {
    MetricDescriptor::new(name, MetricKind::Counter, description).expect("core metric descriptor")
}

fn gauge(name: &str, description: &str) -> MetricDescriptor {
    MetricDescriptor::new(name, MetricKind::Gauge, description).expect("core metric descriptor")
}

fn gauge_ms(name: &str, description: &str) -> MetricDescriptor {
    let mut descriptor = gauge(name, description);
    descriptor.unit = Some("ms".to_string());
    descriptor
}

fn gauge_ratio(name: &str, description: &str) -> MetricDescriptor {
    let mut descriptor = gauge(name, description);
    descriptor.unit = Some("ratio".to_string());
    descriptor
}

fn require_metric_text(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, MetricValidationError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(MetricValidationError::Diagnostics(
            DiagnosticsValidationError::EmptyField(field),
        ));
    }
    validate_privacy_safe_text(field, &value)?;
    Ok(value)
}

fn validate_metric_text(field: &'static str, value: &str) -> Result<(), MetricValidationError> {
    validate_privacy_safe_text(field, value)?;
    Ok(())
}
