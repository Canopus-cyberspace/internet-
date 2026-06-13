//! Platform kernel foundations.
//!
//! This crate owns control-plane models before runtime behavior is attached.

pub mod component;
pub mod event_bus;
pub mod observability;
pub mod permissions;
pub mod pipeline;
pub mod plugin_runtime;
pub mod registry;
pub mod resolver;

pub use component::*;
pub use event_bus::*;
pub use observability::{
    AuditActionType, AuditCategory, AuditDecision, AuditEvent, AuditReceipt, AuditSink,
    AuditSinkError, DiagnosticsSummary, ExportAuditMetadata, HealthProbe, HealthSnapshot,
    HealthSubject, InMemoryAuditSink, InMemoryMetricsSink, MetricDescriptor, MetricSample,
    MetricSinkError, MetricValue, MetricsSink, ObservabilityHealthStatus, TraceLink,
};
pub use permissions::*;
pub use pipeline::*;
pub use plugin_runtime::*;
pub use registry::*;
pub use resolver::*;
