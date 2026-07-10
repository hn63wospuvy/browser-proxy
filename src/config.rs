//! Runtime configuration, read from environment variables with sane defaults.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::route::{direct_routes, parse_routes, Route};

/// Wisp per-stream flow-control window, in packets. The client may have at most this many
/// unacked DATA packets in flight before it must wait for a CONTINUE. The per-stream intake
/// channel is bounded to this, so it also caps memory per stream.
pub const DEFAULT_BUFFER_SIZE: u32 = 128;

#[derive(Clone, Debug)]
pub struct Config {
    /// Address the HTTP/WebSocket server binds to.
    pub bind: SocketAddr,
    /// Directory that holds the frontend + vendored client assets.
    pub static_dir: String,
    /// Wisp flow-control window (packets); also the per-stream intake bound.
    pub buffer_size: u32,
    /// Timeout for establishing an outbound TCP connection to a target.
    pub connect_timeout: Duration,
    /// Reap a stream whose target has been silent this long. `None` disables the idle timer
    /// (default) so legitimately-idle streams — SSE, long-poll — are never cut.
    pub idle_timeout: Option<Duration>,
    /// Max concurrent WebSocket (Wisp) connections. Further upgrades get 503.
    pub max_connections: usize,
    /// Max concurrent streams per connection. Further CONNECTs get CLOSE(refused).
    pub max_streams: usize,
    /// If true, refuse targets that resolve to private / loopback / link-local addresses.
    pub block_private: bool,
    /// Hostnames containing any of these substrings are refused.
    pub host_blacklist: Vec<String>,
    /// Named outbound routes selectable via `?route=`. Always contains `direct`.
    pub routes: HashMap<String, Route>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            // Loopback-only by default: the intended use is http://localhost, and this
            // keeps the auth-free relay off every LAN interface. Set BIND to expose it.
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            static_dir: "static".to_string(),
            buffer_size: DEFAULT_BUFFER_SIZE,
            connect_timeout: Duration::from_secs(15),
            idle_timeout: None,
            max_connections: 128,
            max_streams: 256,
            block_private: false,
            host_blacklist: Vec::new(),
            routes: direct_routes(),
        }
    }
}

impl Config {
    /// Build a config from environment variables, falling back to defaults.
    ///
    /// - `BIND` / `PORT`: bind address (default `127.0.0.1:8080`; `PORT` overrides just the port).
    /// - `STATIC_DIR`: static asset directory (default `static`).
    /// - `WISP_BUFFER_SIZE`: flow-control window in packets (default 128).
    /// - `CONNECT_TIMEOUT_SECS`: outbound connect timeout (default 15).
    /// - `IDLE_TIMEOUT_SECS`: reap streams idle this long (default 0 = disabled).
    /// - `MAX_CONNECTIONS`: max concurrent Wisp connections (default 128).
    /// - `MAX_STREAMS`: max concurrent streams per connection (default 256).
    /// - `BLOCK_PRIVATE`: `1`/`true` to refuse private-range targets (default off).
    /// - `HOST_BLACKLIST`: comma-separated hostname substrings to refuse.
    /// - `ROUTES`: comma-separated `name=socks5://[user:pass@]host:port` upstream routes,
    ///   selectable via `?route=<name>`. `direct` is implicit and reserved. A malformed
    ///   spec is fatal (returns `Err`).
    pub fn from_env() -> Result<Self, String> {
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
        if let Some(v) = parse_env_u32("WISP_BUFFER_SIZE") {
            if v > 0 {
                cfg.buffer_size = v;
            }
        }
        if let Some(v) = parse_env_u64("CONNECT_TIMEOUT_SECS") {
            if v > 0 {
                cfg.connect_timeout = Duration::from_secs(v);
            }
        }
        if let Some(v) = parse_env_u64("IDLE_TIMEOUT_SECS") {
            cfg.idle_timeout = (v > 0).then(|| Duration::from_secs(v));
        }
        if let Some(v) = parse_env_usize("MAX_CONNECTIONS") {
            if v > 0 {
                cfg.max_connections = v;
            }
        }
        if let Some(v) = parse_env_usize("MAX_STREAMS") {
            if v > 0 {
                cfg.max_streams = v;
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
        if let Ok(spec) = std::env::var("ROUTES") {
            cfg.routes = parse_routes(&spec).map_err(|e| format!("invalid ROUTES: {e}"))?;
        }

        Ok(cfg)
    }

    /// Whether a hostname is refused by the blacklist (case-insensitive substring match).
    pub fn is_host_blacklisted(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.host_blacklist.iter().any(|b| host.contains(b))
    }
}

fn parse_env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok()?.parse().ok()
}
fn parse_env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok()?.parse().ok()
}
fn parse_env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok()?.parse().ok()
}

/// Whether an IP address is in a private / loopback / link-local / unspecified range that
/// the SSRF guard should refuse when `block_private` is enabled. Handles the IPv6 forms that
/// can embed an IPv4 address (mapped, compatible, NAT64, 6to4).
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
            if v6.is_loopback()
                || v6.is_unspecified()
                // unique local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
            {
                return true;
            }
            // Any embedded IPv4 (mapped ::ffff:0:0/96, compatible ::/96, NAT64 64:ff9b::/96,
            // 6to4 2002::/16) is classified by its inner v4.
            if let Some(v4) = embedded_ipv4(v6) {
                return is_private_ip(&IpAddr::V4(v4));
            }
            false
        }
    }
}

/// Extract an embedded IPv4 address from the IPv6 forms that carry one.
fn embedded_ipv4(v6: &std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let seg = v6.segments();
    let low32 = || std::net::Ipv4Addr::new(
        (seg[6] >> 8) as u8,
        (seg[6] & 0xff) as u8,
        (seg[7] >> 8) as u8,
        (seg[7] & 0xff) as u8,
    );

    // ::ffff:a.b.c.d (IPv4-mapped)
    if let Some(m) = v6.to_ipv4_mapped() {
        return Some(m);
    }
    // 2002:AABB:CCDD::/16 (6to4) — inner v4 is the two segments after 2002.
    if seg[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            (seg[1] & 0xff) as u8,
            (seg[2] >> 8) as u8,
            (seg[2] & 0xff) as u8,
        ));
    }
    // 64:ff9b::a.b.c.d (NAT64 well-known prefix).
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0 {
        return Some(low32());
    }
    // ::a.b.c.d (deprecated IPv4-compatible), excluding :: and ::1 already handled above.
    if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0 {
        return Some(low32());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn routes_default_has_direct_only() {
        let cfg = Config::default();
        assert!(cfg.routes.contains_key("direct"));
        assert_eq!(cfg.routes.len(), 1);
    }

    #[test]
    fn private_v4() {
        assert!(is_private_ip(&ip("127.0.0.1")));
        assert!(is_private_ip(&ip("10.1.2.3")));
        assert!(is_private_ip(&ip("192.168.0.1")));
        assert!(is_private_ip(&ip("169.254.169.254")));
        assert!(is_private_ip(&ip("100.64.0.1")));
        assert!(!is_private_ip(&ip("93.184.216.34")));
        assert!(!is_private_ip(&ip("8.8.8.8")));
    }

    #[test]
    fn private_v6_embedded() {
        assert!(is_private_ip(&ip("::1")));
        assert!(is_private_ip(&ip("fc00::1")));
        assert!(is_private_ip(&ip("fe80::1")));
        assert!(is_private_ip(&ip("::ffff:127.0.0.1"))); // mapped
        assert!(is_private_ip(&ip("64:ff9b::7f00:1"))); // NAT64 -> 127.0.0.1
        assert!(is_private_ip(&ip("2002:c0a8:0001::"))); // 6to4 -> 192.168.0.1
        assert!(!is_private_ip(&ip("2606:4700:4700::1111"))); // public v6
    }
}
