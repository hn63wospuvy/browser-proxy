//! Self-hosted web proxy library: a Rust Wisp backend that pairs with the Scramjet client.
//!
//! - [`config`]: runtime configuration.
//! - [`route`]: outbound routing (direct, SOCKS5/HTTP proxy, embedded WireGuard, or embedded Tor).
//! - [`wireguard`]: embedded WireGuard route + WARP registration.
//! - [`tor`]: embedded Tor route (in-process arti-client).
//! - [`wisp`]: the Wisp v1 server (multiplexed TCP-over-WebSocket relay).
//! - [`server`]: the axum HTTP router that serves the client assets and the `/wisp/` endpoint.

pub mod config;
pub mod dns;
pub mod metrics;
pub mod route;
pub mod server;
pub mod tor;
pub mod wireguard;
pub mod wisp;
