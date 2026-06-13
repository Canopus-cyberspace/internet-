//! Infrastructure adapter boundaries.
//!
//! Task 590 hardens the offline local intelligence provider into a pack-backed
//! local index. The crate does not call online reputation services, create
//! alerts/incidents, execute responses, or persist raw packets, payloads, HTTP
//! bodies, cookies, tokens, credentials, or API keys.

pub mod intelligence;
pub mod service_ipc;

pub use intelligence::*;
pub use service_ipc::*;
