//! Shared Sentinel Guard data contracts.
//!
//! This crate is intentionally independent from platform, storage,
//! infrastructure, capability, frontend, and service implementation code.
#![allow(ambiguous_glob_reexports)]
// Root-level re-exports intentionally preserve the existing public contract
// surface across both report export models and explicit session export models.
// Call sites that need the overlapping export type names should import from
// `report` or `session_export` directly.

pub mod baseline;
pub mod common;
pub mod evidence_quality;
pub mod fusion;
pub mod graph;
pub mod identity;
pub mod intelligence;
pub mod investigation;
pub mod native_permission;
pub mod native_sampler;
pub mod native_scheduler;
pub mod navigation;
pub mod network;
pub mod plugin;
pub mod release;
pub mod report;
pub mod response;
pub mod security;
pub mod service;
pub mod session_export;
pub mod settings;
pub mod watch;

pub use baseline::*;
pub use common::*;
pub use evidence_quality::*;
pub use fusion::*;
pub use graph::*;
pub use identity::*;
pub use intelligence::*;
pub use investigation::*;
pub use native_permission::*;
pub use native_sampler::*;
pub use native_scheduler::*;
pub use navigation::*;
pub use network::*;
pub use plugin::*;
pub use release::*;
#[allow(ambiguous_glob_reexports)]
pub use report::*;
pub use response::*;
pub use security::*;
pub use service::*;
#[allow(ambiguous_glob_reexports)]
pub use session_export::*;
pub use settings::*;
pub use watch::*;
