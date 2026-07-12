//! Runtime configuration, read from environment variables with sane defaults.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::dns::{self, DnsResolver, DEFAULT_DNS};
use crate::route::{direct_routes, Route};

/// Wisp per-stream flow-control window, in packets. The client may have at most this many
/// unacked DATA packets in flight before it must wait for a CONTINUE. The per-stream intake
/// channel is bounded to this, so it also caps memory per stream.
pub const DEFAULT_BUFFER_SIZE: u32 = 128;

#[derive(Clone, Debug)]
pub struct Config {
    /// Address the HTTP/WebSocket server binds to.
    pub bind: SocketAddr,
    /// Optional on-disk override for the frontend + vendored client assets. `None` (the
    /// default) serves the copy embedded in the binary; `Some(dir)` serves from that directory
    /// instead — useful for iterating on the frontend without a rebuild.
    pub static_dir: Option<String>,
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
    pub routes: HashMap<String, Arc<Route>>,
    /// Named DNS resolvers selectable via `?dns=` (applies to the `direct` route only). Always
    /// contains `system` (the OS resolver) plus the built-in DoH presets.
    pub dns: HashMap<String, Arc<DnsResolver>>,
    /// DNS name used when a connection sends no `?dns=`. Defaults to `system`.
    pub default_dns: String,
    /// TLS termination. `None` (default) serves plain HTTP. `Some(_)` serves HTTPS: with both
    /// `cert` and `key` paths it uses those PEM files; with neither it generates a self-signed
    /// cert at startup (localhost/dev only).
    pub tls: Option<TlsSettings>,
}

/// Enabled-TLS settings. Absence of a value (`Config::tls == None`) means TLS is off.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsSettings {
    /// Path to the PEM certificate chain. `None` (with `key` also `None`) → generate a
    /// self-signed cert at startup.
    pub cert: Option<String>,
    /// Path to the PEM private key. `None` (with `cert` also `None`) → generate a self-signed
    /// cert at startup.
    pub key: Option<String>,
    /// Extra SAN entries (IPs or domain names) for the self-signed cert generated when no
    /// `cert`/`key` is given. `localhost`, `127.0.0.1`, and `::1` are always included; add your
    /// public IP / hostname here so a browser reaching the server over it accepts the cert.
    /// Ignored when `cert`/`key` are supplied.
    pub hostnames: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            // Loopback-only by default: the intended use is http://localhost, and this
            // keeps the auth-free relay off every LAN interface. Set BIND to expose it.
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            static_dir: None,
            buffer_size: DEFAULT_BUFFER_SIZE,
            connect_timeout: Duration::from_secs(15),
            idle_timeout: None,
            max_connections: 128,
            max_streams: 256,
            block_private: false,
            host_blacklist: Vec::new(),
            routes: direct_routes(),
            // Minimal, infallible default: only the OS resolver. `from_env` replaces this with
            // the built-in DoH presets (+ any custom `dns:` entries).
            dns: {
                let mut m = HashMap::new();
                m.insert(DEFAULT_DNS.to_string(), Arc::new(DnsResolver::System));
                m
            },
            default_dns: DEFAULT_DNS.to_string(),
            tls: None,
        }
    }
}

impl Config {
    /// Build a config from environment variables, falling back to defaults.
    ///
    /// - `BIND` / `PORT`: bind address (default `127.0.0.1:8080`; `PORT` overrides just the port).
    /// - `STATIC_DIR`: serve the frontend from this directory instead of the embedded copy
    ///   (unset = serve the assets baked into the binary).
    /// - `WISP_BUFFER_SIZE`: flow-control window in packets (default 128).
    /// - `CONNECT_TIMEOUT_SECS`: outbound connect timeout (default 15).
    /// - `IDLE_TIMEOUT_SECS`: reap streams idle this long (default 0 = disabled).
    /// - `MAX_CONNECTIONS`: max concurrent Wisp connections (default 128).
    /// - `MAX_STREAMS`: max concurrent streams per connection (default 256).
    /// - `BLOCK_PRIVATE`: `1`/`true` to refuse private-range targets (default off).
    /// - `HOST_BLACKLIST`: comma-separated hostname substrings to refuse.
    /// - `TLS`: `1`/`true` to serve HTTPS (default off = HTTP).
    /// - `TLS_CERT` / `TLS_KEY`: PEM cert + key paths; set both, or neither to auto-generate.
    /// - `TLS_HOSTNAMES`: comma-separated extra SAN hosts for the auto-generated cert.
    /// - `CONFIG`: path to a YAML config (default `config.yaml` if present). See
    ///   `config.example.yaml`. Holds the `bind` address (`interface` + `port`) and the
    ///   `routes` list. `BIND`/`PORT` env vars override the file's `bind`. A malformed config
    ///   is fatal (returns `Err`).
    pub fn from_env() -> Result<Self, String> {
        let mut cfg = Config::default();

        // Load the YAML config file first (bind address + routes); the env vars below then
        // override whatever it set, so env always wins.
        let path = std::env::var("CONFIG").unwrap_or_else(|_| "config.yaml".to_string());
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => Some(b),
            // The default file being absent is fine; an explicitly-set CONFIG that is missing
            // is an error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if std::env::var("CONFIG").is_ok() {
                    return Err(format!("{path}: {e}"));
                }
                None
            }
            Err(e) => return Err(format!("{path}: {e}")),
        };
        if let Some(body) = &body {
            if let Some(bind) = parse_bind(body).map_err(|e| format!("{path}: {e}"))? {
                cfg.bind = bind;
            }
            cfg.routes =
                crate::route::routes_from_yaml(body).map_err(|e| format!("{path}: {e}"))?;
            let (dns, default_dns) = dns::dns_from_yaml(body).map_err(|e| format!("{path}: {e}"))?;
            cfg.dns = dns;
            cfg.default_dns = default_dns;
            cfg.tls = parse_tls(body).map_err(|e| format!("{path}: {e}"))?;
        } else {
            // No config file: still expose the built-in DoH presets alongside `system`.
            cfg.dns = dns::build_defaults()?;
            cfg.default_dns = DEFAULT_DNS.to_string();
        }

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
            cfg.static_dir = Some(dir);
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

        // TLS env overrides (env always wins over the file, like BIND/PORT). `TLS` toggles HTTPS;
        // `TLS_CERT` / `TLS_KEY` set the PEM paths (and imply enabled). Setting a path also
        // materializes an enabled `TlsSettings` if the file didn't.
        if let Ok(v) = std::env::var("TLS") {
            match v.as_str() {
                "1" | "true" | "TRUE" | "yes" => {
                    cfg.tls.get_or_insert_with(TlsSettings::default);
                }
                "0" | "false" | "FALSE" | "no" => cfg.tls = None,
                other => tracing::warn!("ignoring invalid TLS={other:?}"),
            }
        }
        if let Ok(cert) = std::env::var("TLS_CERT") {
            cfg.tls.get_or_insert_with(TlsSettings::default).cert = Some(cert);
        }
        if let Ok(key) = std::env::var("TLS_KEY") {
            cfg.tls.get_or_insert_with(TlsSettings::default).key = Some(key);
        }
        if let Ok(list) = std::env::var("TLS_HOSTNAMES") {
            cfg.tls.get_or_insert_with(TlsSettings::default).hostnames = list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Some(tls) = &cfg.tls {
            validate_tls(tls)?;
        }
        Ok(cfg)
    }

    /// Whether a hostname is refused by the blacklist (case-insensitive substring match).
    pub fn is_host_blacklisted(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.host_blacklist.iter().any(|b| host.contains(b))
    }
}

/// The optional `bind:` section of the config file.
#[derive(serde::Deserialize)]
struct BindFile {
    bind: Option<BindSpec>,
}
#[derive(serde::Deserialize)]
struct BindSpec {
    /// IP address to bind (e.g. `127.0.0.1`, `0.0.0.0`). Defaults to the default interface.
    interface: Option<String>,
    /// Port to bind. Defaults to the default port.
    port: Option<u16>,
}

/// Parse the `bind` address from the config file, if present. Starts from the default bind
/// and overrides the interface / port that the file specifies.
fn parse_bind(yaml: &str) -> Result<Option<SocketAddr>, String> {
    let f: BindFile =
        serde_yaml_ng::from_str(yaml).map_err(|e| format!("config parse error: {e}"))?;
    let Some(spec) = f.bind else {
        return Ok(None);
    };
    let mut addr = Config::default().bind;
    if let Some(iface) = spec.interface {
        let ip: IpAddr = iface
            .parse()
            .map_err(|_| format!("bind.interface must be an IP address, got {iface:?}"))?;
        addr.set_ip(ip);
    }
    if let Some(port) = spec.port {
        addr.set_port(port);
    }
    Ok(Some(addr))
}

/// The optional `tls:` section of the config file.
#[derive(serde::Deserialize)]
struct TlsFile {
    tls: Option<TlsSpec>,
}
#[derive(serde::Deserialize)]
struct TlsSpec {
    /// Serve HTTPS when true. Defaults to false (plain HTTP).
    enabled: Option<bool>,
    /// PEM certificate chain path. Omit (with `key`) to auto-generate a self-signed cert.
    cert: Option<String>,
    /// PEM private key path. Omit (with `cert`) to auto-generate a self-signed cert.
    key: Option<String>,
    /// Extra SAN hosts (IPs / domains) for the auto-generated self-signed cert.
    hostnames: Option<Vec<String>>,
}

/// Parse the `tls` section from the config file. Returns `None` when TLS is absent or disabled,
/// `Some(settings)` when enabled. A half-configured pair (only `cert` or only `key`) is fatal.
fn parse_tls(yaml: &str) -> Result<Option<TlsSettings>, String> {
    let f: TlsFile =
        serde_yaml_ng::from_str(yaml).map_err(|e| format!("config parse error: {e}"))?;
    let Some(spec) = f.tls else {
        return Ok(None);
    };
    // Disabled (or the field omitted) → plain HTTP.
    if !spec.enabled.unwrap_or(false) {
        return Ok(None);
    }
    let settings = TlsSettings {
        cert: spec.cert,
        key: spec.key,
        hostnames: spec.hostnames.unwrap_or_default(),
    };
    validate_tls(&settings)?;
    Ok(Some(settings))
}

/// Validate that `cert` and `key` are set together (both, so custom PEM files are used) or
/// neither (auto-generate a self-signed cert). A lone one is a configuration error.
fn validate_tls(s: &TlsSettings) -> Result<(), String> {
    if s.cert.is_some() != s.key.is_some() {
        return Err(
            "tls: set both `cert` and `key`, or neither (to auto-generate a self-signed cert)"
                .to_string(),
        );
    }
    Ok(())
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
    fn bind_parsed_from_config() {
        assert_eq!(parse_bind("routes: []").unwrap(), None);
        let both = parse_bind("bind:\n  interface: \"0.0.0.0\"\n  port: 9000\n")
            .unwrap()
            .unwrap();
        assert_eq!(both.to_string(), "0.0.0.0:9000");
        // Only a port: keep the default interface (127.0.0.1).
        let port_only = parse_bind("bind:\n  port: 9000\n").unwrap().unwrap();
        assert_eq!(port_only.to_string(), "127.0.0.1:9000");
        // Only an interface: keep the default port (8080).
        let iface_only = parse_bind("bind:\n  interface: \"0.0.0.0\"\n")
            .unwrap()
            .unwrap();
        assert_eq!(iface_only.to_string(), "0.0.0.0:8080");
        // Bad interface is fatal.
        assert!(parse_bind("bind:\n  interface: \"not-an-ip\"\n").is_err());
    }

    #[test]
    fn tls_absent_or_disabled_is_none() {
        // No tls section at all.
        assert_eq!(parse_tls("routes: []").unwrap(), None);
        // Present but disabled.
        assert_eq!(parse_tls("tls:\n  enabled: false\n").unwrap(), None);
        // enabled defaults to false when the field is omitted.
        assert_eq!(
            parse_tls("tls:\n  cert: \"c.pem\"\n  key: \"k.pem\"\n").unwrap(),
            None
        );
    }

    #[test]
    fn tls_enabled_without_paths_self_signs() {
        let s = parse_tls("tls:\n  enabled: true\n").unwrap().unwrap();
        assert_eq!(s.cert, None);
        assert_eq!(s.key, None);
        assert!(s.hostnames.is_empty());
    }

    #[test]
    fn tls_hostnames_parsed() {
        let s = parse_tls("tls:\n  enabled: true\n  hostnames: [\"10.0.0.5\", \"h.example\"]\n")
            .unwrap()
            .unwrap();
        assert_eq!(s.hostnames, vec!["10.0.0.5".to_string(), "h.example".to_string()]);
    }

    #[test]
    fn tls_enabled_with_both_paths() {
        let s = parse_tls("tls:\n  enabled: true\n  cert: \"c.pem\"\n  key: \"k.pem\"\n")
            .unwrap()
            .unwrap();
        assert_eq!(s.cert.as_deref(), Some("c.pem"));
        assert_eq!(s.key.as_deref(), Some("k.pem"));
    }

    #[test]
    fn tls_enabled_with_only_one_path_is_fatal() {
        assert!(parse_tls("tls:\n  enabled: true\n  cert: \"c.pem\"\n").is_err());
        assert!(parse_tls("tls:\n  enabled: true\n  key: \"k.pem\"\n").is_err());
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
