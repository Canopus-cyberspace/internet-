//! Internal capability implementations.
//!
//! Task 360 starts this crate with a `MOCK_ONLY` network pipeline slice. Task
//! 370 adds metadata-only flow, DNS, TLS, and optional plaintext HTTP
//! observation capabilities. Task 380 adds local asset exposure and service
//! inventory metadata. Task 390 adds evidence management services for bundles,
//! quality validation, explanations, and traceable finding lifecycle updates.
//! Task 400 adds a metadata-only C2 detection MVP that emits findings,
//! evidence, risk hints, and graph hints.
//! Task 410 adds a metadata-only exfiltration detection MVP with upload
//! behavior, destination context, related C2 context, evidence, risk hints, and
//! process-upload graph hints.
//! Task 420 adds a metadata-only lateral movement lite detector with internal
//! fanout, service probing, unknown process access, exposure-linked movement,
//! evidence, and graph hints.
//! Task 430 adds risk-based alerting with entity risk aggregation, suppression,
//! decay, alert promotion, and incident candidate story metadata.
//! Task 440 adds the graph stage owner for canonical graph validation,
//! identity normalization, deduplication, metadata-only canonical writes, and
//! compact graph update events.
//! Task 450 adds bounded graph analytics, graph path building, redacted
//! `GraphViewModel` generation, and export-safe graph snapshots.
//! Task 460 adds recommend-first response planning and isolation policy
//! decisions with audit, rollback, approval, TTL, and replay safety metadata.
//! Task 470 adds approval, active response, STUB_ONLY executor adapter, and
//! rollback scheduling surfaces for the response execution boundary.
//! Task 480 adds incident report generation, report redaction validation,
//! export gating, and Markdown/HTML/redacted-JSON renderers.
//! Task 490 adds export history records, policy violation records, file-hash
//! metadata, and export audit service helpers.
//! The crate does not implement real packet capture, TLS decryption, service
//! control, or response execution. Only `graph_stage` writes canonical graph
//! records.

pub mod asset_exposure;
pub mod c2_detection;
pub mod continuous_metadata_watch;
pub mod endpoint_threat_detection;
pub mod evidence_management;
pub mod exfiltration_detection;
pub mod export_history;
pub mod graph_analytics;
pub mod graph_stage;
pub mod lateral_movement_lite;
pub mod local_proxy_metadata_provider;
#[cfg(any(test, feature = "test-support"))]
pub mod mock_network_pipeline;
pub mod multi_layer_fusion;
pub mod native_network_fact;
pub mod native_sampler_runtime;
pub mod network_observations;
pub mod portable_capture_lite;
pub mod portable_network_web;
pub mod report_generation;
pub mod response_execution;
pub mod response_planning;
pub mod risk_alerting;
pub mod static_plugin_runtime;

#[cfg(test)]
mod runtime_boundary_tests;
#[cfg(test)]
mod runtime_test_support;

pub use asset_exposure::*;
pub use c2_detection::*;
pub use continuous_metadata_watch::*;
pub use endpoint_threat_detection::*;
pub use evidence_management::*;
pub use exfiltration_detection::*;
pub use export_history::*;
pub use graph_analytics::*;
pub use graph_stage::*;
pub use lateral_movement_lite::*;
pub use local_proxy_metadata_provider::*;
#[cfg(any(test, feature = "test-support"))]
pub use mock_network_pipeline::*;
pub use multi_layer_fusion::*;
pub use native_network_fact::*;
pub use native_sampler_runtime::*;
pub use network_observations::*;
pub use portable_capture_lite::*;
pub use portable_network_web::*;
pub use report_generation::*;
pub use response_execution::*;
pub use response_planning::*;
pub use risk_alerting::*;
pub use static_plugin_runtime::*;
