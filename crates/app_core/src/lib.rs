//! Rust Local Core API facade.
//!
//! This crate exposes Tauri-compatible read command handlers. The handlers are
//! intentionally macro-free until the desktop shell crate wires them into Tauri.

pub mod authorized_native_permissions;
pub mod baseline_read_models;
pub mod demo_story;
pub mod event_streams;
pub mod evidence_quality;
pub mod explicit_session_export;
pub mod investigation_drill_down;
pub mod llm_alert_story;
pub mod machine_local_capabilities;
pub mod mutation_commands;
pub mod native_sampler_readiness;
pub mod native_sampler_runtime;
pub mod native_scheduler;
pub mod native_scheduler_host;
pub mod portable_capture_import;
pub mod portable_proxy_metadata_provider;
pub mod portable_source_readers;
pub mod read_commands;
pub mod reference_navigation;
pub mod vertical_slices;

pub use authorized_native_permissions::*;
pub use baseline_read_models::*;
pub use demo_story::*;
pub use event_streams::*;
pub use evidence_quality::*;
pub use explicit_session_export::*;
pub use investigation_drill_down::*;
pub use llm_alert_story::*;
pub use machine_local_capabilities::*;
pub use mutation_commands::*;
pub use native_sampler_runtime::*;
pub use native_scheduler::*;
pub use native_scheduler_host::*;
pub use portable_capture_import::*;
pub use portable_proxy_metadata_provider::*;
pub use portable_source_readers::*;
pub use read_commands::*;
pub use reference_navigation::*;
pub use sentinel_capabilities::{
    ExportHistoryRecord, ExportPolicyViolation, LocalProxyMetadataProviderStateKind,
    LocalProxyMetadataProviderStatus, LocalProxyMetadataStartRequest, ReportExportHistoryQuery,
};
pub use vertical_slices::*;
