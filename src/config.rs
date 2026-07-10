//! Runtime configuration, read from environment variables with sane defaults.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Wisp per-stream flow-control window, in packets. The client may have at most this many
/// unacked DATA packets in flight before it must wait for a CONTINUE. Bounds memory per
/// stream to roughly `BUFFER_SIZE * max_packet_size`.
pub const DEFAULT_BUFFER_SIZE: u32 = 128;

#[derive(Clone, Debug)]
pub struct Config {
    /// Address the HTTP/WebSocket server binds to.
    pub bind: SocketAddr,
    /// Directory that holds the frontend + vendored client assets.
    pub static_dir: String,
    /// Wisp flow-control window (packets).
    pub buffer_size: u32,
    /// Timeout for establishing an outbound TCP connection to a target.
    pub connect_timeout: Duration,
    /// If true, refuse targets that resolve to private / loopback / link-local addresses.
    /// Off by default (personal use); enable when exposing the proxy more widely.
    pub block_private: bool,
    /// Hostnames containing any of these substrings are refused.
    pub host_blacklist: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind: SocketAddr::from(([0, 0, 0, 0], 8080)),
            static_dir: "static".to_string(),
            buffer_size: DEFAULT_BUFFER_SIZE,
            connect_timeout: Duration::from_secs(15),
            block_private: false,
            host_blacklist: Vec::new(),
        }
    }
}

impl Config {
    /// Build a config from environment variables, falling back to defaults.
    ///
    /// - `BIND` / `PORT`: bind address (default `0.0.0.0:8080`; `PORT` overrides just the port).
    /// - `STATIC_DIR`: static asset directory (default `static`).
    /// - `WISP_BUFFER_SIZE`: flow-control window in packets (default 128).
    /// - `CONNECT_TIMEOUT_SECS`: outbound connect timeout (default 15).
    /// - `BLOCK_PRIVATE`: `1`/`true` to refuse private-range targets (default off).
    /// - `HOST_BLACKLIST`: comma-separated hostname substrings to refuse.
    pub fn from_env() -> Self {
        let mut cfg = Config::default();

        if let Ok(bind) = std::env::var("BIND") {
            if let Ok(addr) = bind.parse::<SocketAddr>() {
                cfg.bind = addr;
            } else {
                tracing::warn!("ignoring invalid BIND={bind:?}");
            }
        }
        if let Ok(port) = std::env::var("PORT") {
            match port.parse::<u16>() {
                Ok(p) => cfg.bind.set_port(p),
                Err(_) => tracing::warn!("ignoring invalid PORT={port:?}"),
            }
        }
        if let Ok(dir) = std::env::var("STATIC_DIR") {
            cfg.static_dir = dir;
        }
        if let Ok(bs) = std::env::var("WISP_BUFFER_SIZE") {
            if let Ok(v) = bs.parse::<u32>() {
                if v > 0 {
                    cfg.buffer_size = v;
                }
            }
        }
        if let Ok(t) = std::env::var("CONNECT_TIMEOUT_SECS") {
            if let Ok(v) = t.parse::<u64>() {
                if v > 0 {
                    cfg.connect_timeout = Duration::from_secs(v);
                }
            }
        }
        cfg.block_private = matches!(
            std::env::var("BLOCK_PRIVATE").ok().as_deref(),
            Some("1") | Some("true") | Some("TRUE") | Some("yes")
        );
        if let Ok(list) = std::env::var("HOST_BLACKLIST") {
            cfg.host_blacklist = list
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
        }

        cfg
    }

    /// Whether a hostname is refused by the blacklist (case-insensitive substring match).
    pub fn is_host_blacklisted(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.host_blacklist.iter().any(|b| host.contains(b))
    }
}

/// Whether an IP address is in a private / loopback / link-local / unspecified range that
/// the SSRF guard should refuse when `block_private` is enabled.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                // 100.64.0.0/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // unique local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped: check the embedded v4
                || v6.to_ipv4_mapped().map(|m| is_private_ip(&IpAddr::V4(m))).unwrap_or(false)
        }
    }
}
