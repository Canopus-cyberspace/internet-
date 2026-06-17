//! Windows infrastructure adapters.
//!
//! These modules contain provider implementations only. They do not own
//! Sentinel runtime state, schedulers, read models, EventBus, DAG, or plugins.

pub mod etw_network;
pub mod etw_probe;
pub mod etw_session;
pub mod event_log_auth_remote;
pub mod event_log_rdp_operational;
pub mod event_log_smb_operational;
pub mod event_log_ssh_operational;
pub mod ip_helper;
pub mod native_health;
pub mod native_service;

pub use etw_network::*;
pub use etw_probe::*;
pub use etw_session::*;
pub use event_log_auth_remote::*;
pub use event_log_rdp_operational::*;
pub use event_log_smb_operational::*;
pub use event_log_ssh_operational::*;
pub use ip_helper::*;
pub use native_health::*;
pub use native_service::*;
