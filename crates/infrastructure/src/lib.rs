//! Infrastructure adapter boundaries.
//!
//! Task 590 hardens the offline local intelligence provider into a pack-backed
//! local index. The crate does not call online reputation services, create
//! alerts/incidents, execute responses, or persist raw packets, payloads, HTTP
//! bodies, cookies, tokens, credentials, or API keys.

pub mod api_gateway_provider_client;
pub mod cdn_edge_provider_client;
pub mod intelligence;
pub mod object_storage_audit_client;
pub mod provider_adapter;
pub mod service_ipc;
pub mod windows;

pub use api_gateway_provider_client::*;
pub use cdn_edge_provider_client::*;
pub use intelligence::*;
pub use object_storage_audit_client::*;
pub use provider_adapter::*;
pub use service_ipc::*;
pub use windows::*;
