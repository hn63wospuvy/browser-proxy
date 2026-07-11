//! Server-side DNS resolution for the `direct` route.
//!
//! Name resolution in this proxy happens on the server: the `direct` route resolves the target
//! hostname here before dialing. (Proxied routes — socks5 / http / wireguard / tor — resolve at
//! their exit and never reach this code, so the DNS selection has no effect on them.) By default
//! resolution uses the OS resolver — `tokio::net::lookup_host` — exactly as before. A connection
//! may instead select a **DNS-over-HTTPS** resolver by name via `?dns=<name>`; each DoH resolver
//! is built once at startup and shared across connections.
//!
//! Fail-closed, matching the routing layer: a *selected* DoH resolver that fails to resolve
//! returns an error (the caller maps it to a stream close) — it never silently falls back to the
//! OS resolver, which would defeat the point of choosing a censorship-resistant DNS. An unknown
//! `?dns=` name is rejected before the WebSocket upgrade (see `server.rs`); a missing param uses
//! the default ([`DEFAULT_DNS`]).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hickory_resolver::config::{NameServerConfig, ResolverConfig, CLOUDFLARE, GOOGLE, QUAD9};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use serde::Deserialize;

/// DNS name used when a connection sends no `?dns=` — preserves the prior OS-resolver behavior.
pub const DEFAULT_DNS: &str = "system";

/// A per-connection DNS resolver for the `direct` route.
pub enum DnsResolver {
    /// The OS resolver (`getaddrinfo` via tokio). Today's behavior.
    System,
    /// A hickory-driven resolver: a DoH preset, a custom DoH entry, or a plain UDP/TCP resolver
    /// built on the fly for a user-typed server IP.
    Hickory(TokioResolver),
}

impl std::fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsResolver::System => write!(f, "System"),
            DnsResolver::Hickory(_) => write!(f, "Hickory"),
        }
    }
}

impl DnsResolver {
    /// Resolve `host` to socket addresses on `port`. An IP literal is returned as-is (no query),
    /// matching `lookup_host` and avoiding a needless DoH round-trip for IP targets.
    pub async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        match self {
            DnsResolver::System => Ok(tokio::net::lookup_host((host, port)).await?.collect()),
            DnsResolver::Hickory(resolver) => {
                let lookup = resolver
                    .lookup_ip(host)
                    .await
                    .map_err(io::Error::other)?;
                Ok(lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect())
            }
        }
    }
}

/// Build a DoH resolver from a hickory `ResolverConfig`. Construction is local (no network I/O);
/// the first query lazily opens the connection to the server.
fn build_resolver(config: ResolverConfig) -> Result<TokioResolver, String> {
    Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .map_err(|e| format!("build resolver: {e}"))
}

/// Build a plain UDP+TCP resolver targeting a specific DNS server IP (port 53). Used when the
/// DNS picker receives a bare IP instead of a preset name — e.g. a resolver that isn't subject
/// to the local ISP's DNS hijacking. Cheap enough to build per connection. The server IP is used
/// as given (no private-range guard): the operator may legitimately point at a LAN resolver.
pub fn build_ip_resolver(ip: IpAddr) -> Result<Arc<DnsResolver>, String> {
    let ns = NameServerConfig::udp_and_tcp(ip);
    let config = ResolverConfig::from_parts(None, Vec::new(), vec![ns]);
    Ok(Arc::new(DnsResolver::Hickory(build_resolver(config)?)))
}

/// The built-in resolver set, always present even with no config file: `system` (OS resolver,
/// the default) plus DoH to Cloudflare / Google / Quad9 using hickory's preset endpoints.
pub fn build_defaults() -> Result<HashMap<String, Arc<DnsResolver>>, String> {
    let mut m: HashMap<String, Arc<DnsResolver>> = HashMap::new();
    m.insert(DEFAULT_DNS.to_string(), Arc::new(DnsResolver::System));
    for (name, group) in [
        ("cloudflare", &CLOUDFLARE),
        ("google", &GOOGLE),
        ("quad9", &QUAD9),
    ] {
        let resolver = build_resolver(ResolverConfig::https(group))?;
        m.insert(name.to_string(), Arc::new(DnsResolver::Hickory(resolver)));
    }
    Ok(m)
}

/// The optional `dns:` section of the config file.
#[derive(Deserialize)]
struct DnsFile {
    dns: Option<DnsSection>,
}

#[derive(Deserialize)]
struct DnsSection {
    /// Name selected when the UI/connection doesn't specify one. Defaults to `system`.
    default: Option<String>,
    /// Extra custom DoH resolvers, in addition to the built-ins.
    #[serde(default)]
    resolvers: Vec<DohEntry>,
}

/// One custom DoH resolver as written in YAML.
#[derive(Deserialize)]
struct DohEntry {
    name: String,
    /// One or more IP literals of the DoH endpoint (used directly — no bootstrap DNS needed).
    addresses: Vec<String>,
    /// The DoH endpoint URL, e.g. `https://dns.adguard-dns.com/dns-query`.
    url: String,
    /// TLS server name (SNI). Defaults to the host in `url`.
    sni: Option<String>,
}

/// Split a DoH `https://host[:port]/path` URL into (server_name, path). The path keeps its
/// leading slash and defaults to `/dns-query` (the standard DoH path) when absent.
fn parse_doh_url(url: &str) -> Result<(String, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("DoH url must start with https:// : {url:?}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/dns-query".to_string()),
    };
    let host = authority.split(':').next().unwrap_or(authority);
    if host.is_empty() {
        return Err(format!("DoH url has no host: {url:?}"));
    }
    Ok((host.to_string(), path))
}

/// Build a custom DoH resolver from IP literals + a DoH URL (+ optional SNI override).
fn build_custom_doh(entry: &DohEntry) -> Result<TokioResolver, String> {
    let (host, path) = parse_doh_url(&entry.url)?;
    let server_name: Arc<str> = Arc::from(entry.sni.clone().unwrap_or(host).as_str());
    let path: Arc<str> = Arc::from(path.as_str());
    if entry.addresses.is_empty() {
        return Err(format!("dns resolver {:?}: no addresses", entry.name));
    }
    let mut servers = Vec::with_capacity(entry.addresses.len());
    for a in &entry.addresses {
        let ip: IpAddr = a
            .parse()
            .map_err(|_| format!("dns resolver {:?}: bad IP {a:?}", entry.name))?;
        servers.push(NameServerConfig::https(
            ip,
            server_name.clone(),
            Some(path.clone()),
        ));
    }
    build_resolver(ResolverConfig::from_parts(None, Vec::new(), servers))
}

/// Parse the resolver map + default name from a `config.yaml` body. Always includes the
/// built-ins; custom entries are merged on top. A custom name may not be empty, collide with a
/// built-in or another custom entry; the chosen `default:` must name a resolver that exists.
pub fn dns_from_yaml(yaml: &str) -> Result<(HashMap<String, Arc<DnsResolver>>, String), String> {
    let file: DnsFile =
        serde_yaml_ng::from_str(yaml).map_err(|e| format!("dns config parse error: {e}"))?;
    let mut map = build_defaults()?;
    let mut default = DEFAULT_DNS.to_string();

    if let Some(section) = file.dns {
        for entry in &section.resolvers {
            if entry.name.is_empty() {
                return Err("dns resolver with empty name".into());
            }
            let resolver = build_custom_doh(entry)?;
            if map
                .insert(entry.name.clone(), Arc::new(DnsResolver::Hickory(resolver)))
                .is_some()
            {
                return Err(format!("duplicate dns resolver name: {:?}", entry.name));
            }
        }
        if let Some(d) = section.default {
            if !map.contains_key(&d) {
                return Err(format!("dns default {d:?} is not a configured resolver"));
            }
            default = d;
        }
    }
    Ok((map, default))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_have_system_and_presets() {
        let m = build_defaults().unwrap();
        for name in ["system", "cloudflare", "google", "quad9"] {
            assert!(m.contains_key(name), "missing built-in {name}");
        }
        assert!(matches!(&**m.get("system").unwrap(), DnsResolver::System));
        assert!(matches!(&**m.get("cloudflare").unwrap(), DnsResolver::Hickory(_)));
    }

    #[test]
    fn empty_config_is_defaults_with_system_default() {
        let (m, def) = dns_from_yaml("routes: []").unwrap();
        assert_eq!(def, "system");
        assert!(m.contains_key("system") && m.contains_key("quad9"));
    }

    #[test]
    fn custom_resolver_is_added() {
        let y = "dns:\n  resolvers:\n    - name: adguard\n      addresses: [\"94.140.14.14\", \"94.140.15.15\"]\n      url: \"https://dns.adguard-dns.com/dns-query\"\n";
        let (m, def) = dns_from_yaml(y).unwrap();
        assert!(m.contains_key("adguard"));
        assert!(matches!(&**m.get("adguard").unwrap(), DnsResolver::Hickory(_)));
        assert_eq!(def, "system");
    }

    #[test]
    fn default_override_must_exist() {
        let ok = "dns:\n  default: cloudflare\n";
        assert_eq!(dns_from_yaml(ok).unwrap().1, "cloudflare");
        let bad = "dns:\n  default: nope\n";
        assert!(dns_from_yaml(bad).is_err());
    }

    #[test]
    fn duplicate_and_empty_names_rejected() {
        let dup = "dns:\n  resolvers:\n    - name: cloudflare\n      addresses: [\"1.1.1.1\"]\n      url: \"https://x/dns-query\"\n";
        assert!(dns_from_yaml(dup).is_err());
        let empty = "dns:\n  resolvers:\n    - name: \"\"\n      addresses: [\"1.1.1.1\"]\n      url: \"https://x/dns-query\"\n";
        assert!(dns_from_yaml(empty).is_err());
    }

    #[test]
    fn bad_address_rejected() {
        let y = "dns:\n  resolvers:\n    - name: x\n      addresses: [\"not-an-ip\"]\n      url: \"https://x/dns-query\"\n";
        assert!(dns_from_yaml(y).is_err());
    }

    #[test]
    fn doh_url_parsing() {
        assert_eq!(
            parse_doh_url("https://dns.adguard-dns.com/dns-query").unwrap(),
            ("dns.adguard-dns.com".to_string(), "/dns-query".to_string())
        );
        // No path → default DoH path.
        assert_eq!(
            parse_doh_url("https://example.net").unwrap(),
            ("example.net".to_string(), "/dns-query".to_string())
        );
        // Port stripped from the SNI host.
        assert_eq!(
            parse_doh_url("https://example.net:8443/resolve").unwrap(),
            ("example.net".to_string(), "/resolve".to_string())
        );
        assert!(parse_doh_url("http://insecure/dns-query").is_err());
    }

    #[test]
    fn ip_resolver_builds_for_v4_and_v6() {
        assert!(matches!(
            &*build_ip_resolver("1.1.1.1".parse().unwrap()).unwrap(),
            DnsResolver::Hickory(_)
        ));
        assert!(build_ip_resolver("2606:4700:4700::1111".parse().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn system_resolves_ip_literal_without_network() {
        let r = DnsResolver::System;
        let addrs = r.resolve("93.184.216.34", 443).await.unwrap();
        assert_eq!(addrs, vec!["93.184.216.34:443".parse().unwrap()]);
    }

    // Live DoH resolution. Ignored by default (needs network); mirrors the Tor smoke test.
    #[tokio::test]
    #[ignore = "hits the network (Cloudflare DoH)"]
    async fn cloudflare_doh_resolves_example_com() {
        let m = build_defaults().unwrap();
        let r = m.get("cloudflare").unwrap();
        let addrs = r.resolve("example.com", 443).await.unwrap();
        assert!(!addrs.is_empty(), "cloudflare DoH returned no addresses");
    }
}
