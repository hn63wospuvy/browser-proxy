//! Self-hosted web proxy library: a Rust Wisp backend that pairs with the Scramjet client.
//!
//! - [`config`]: runtime configuration.
//! - [`route`]: outbound routing (direct or SOCKS5 upstream).
//! - [`wisp`]: the Wisp v1 server (multiplexed TCP-over-WebSocket relay).
//! - [`server`]: the axum HTTP router that serves the client assets and the `/wisp/` endpoint.

pub mod config;
pub mod metrics;
pub mod route;
pub mod server;
pub mod wisp;
