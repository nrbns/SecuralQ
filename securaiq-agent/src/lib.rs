//! SecuraIQ endpoint agent — Rust core + platform adapters.
//!
//! Speaks Agent Protocol v1 against the existing FastAPI control plane.
//! See `docs/agent-protocol-v1.md`.

pub mod collectors;
pub mod controls;
pub mod core;
pub mod crypto;
pub mod evidence;
pub mod inventory;
pub mod platform;
pub mod response;
pub mod storage;
pub mod transport;
pub mod vulnerability;

pub use core::config::AgentConfig;
pub use core::agent::Agent;
