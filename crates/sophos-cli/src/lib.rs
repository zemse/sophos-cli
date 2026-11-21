//! Sophos SSL VPN configuration, local daemon control and TOTP reconnect.

pub mod config;
pub mod daemon;
pub mod ipc;
pub mod ovpn;
pub mod routes;
pub mod totp;

pub const USER_AGENT: &str = concat!("sophos-cli/", env!("CARGO_PKG_VERSION"));
