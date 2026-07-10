//! Outbound routing: send a stream's TCP either directly or through a SOCKS5 upstream (a VPN
//! exposed as a proxy — WARP `mode proxy`, Tor, …). One `Route` per Wisp connection.
//!
//! Fail closed: selection and dialing never silently fall back to `Direct`. An unknown route
//! is rejected before the WebSocket upgrade; a dead proxy closes the stream.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{is_private_ip, Config};
use crate::wisp::{R_BLOCKED, R_INVALID, R_REFUSED, R_TIMEOUT, R_UNREACHABLE};

/// The reserved route name that always maps to a direct connection.
pub const DIRECT: &str = "direct";

/// How a stream's outbound TCP is established.
#[derive(Clone, Debug)]
pub enum Route {
    /// Resolve locally and connect straight out (today's behavior).
    Direct,
    /// Dial through a SOCKS5 proxy (RFC 1928). `auth` is optional username/password (RFC 1929).
    Socks5 {
        addr: SocketAddr,
        auth: Option<(String, String)>,
    },
}

/// The route map used when `ROUTES` is unset: only `direct` exists.
pub fn direct_routes() -> HashMap<String, Route> {
    let mut m = HashMap::new();
    m.insert(DIRECT.to_string(), Route::Direct);
    m
}

/// Parse the `ROUTES` env spec: `name=socks5://[user:pass@]host:port`, comma-separated.
/// Returns a map that always includes the implicit `direct` route. Any malformed entry,
/// unknown scheme, duplicate name, or use of the reserved name `direct` is an error — the
/// caller treats that as fatal.
pub fn parse_routes(spec: &str) -> Result<HashMap<String, Route>, String> {
    let mut map = direct_routes();
    for entry in spec.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (name, url) = entry
            .split_once('=')
            .ok_or_else(|| format!("route entry missing '=': {entry:?}"))?;
        let name = name.trim();
        let url = url.trim();
        if name.is_empty() {
            return Err(format!("route entry has empty name: {entry:?}"));
        }
        if name == DIRECT {
            return Err(format!("route name {DIRECT:?} is reserved"));
        }
        let route = parse_socks5_url(url)?;
        if map.insert(name.to_string(), route).is_some() {
            return Err(format!("duplicate route name: {name:?}"));
        }
    }
    Ok(map)
}

/// Parse `socks5://[user:pass@]host:port` into a `Route::Socks5`.
fn parse_socks5_url(url: &str) -> Result<Route, String> {
    let rest = url
        .strip_prefix("socks5://")
        .ok_or_else(|| format!("unsupported route scheme (expected socks5://): {url:?}"))?;
    // Split optional `user:pass@` credentials from the `host:port` authority.
    let (auth, authority) = match rest.rsplit_once('@') {
        Some((creds, hostport)) => {
            let (u, p) = creds
                .split_once(':')
                .ok_or_else(|| format!("credentials must be user:pass in {url:?}"))?;
            (Some((u.to_string(), p.to_string())), hostport)
        }
        None => (None, rest),
    };
    let addr: SocketAddr = authority
        .parse()
        .map_err(|_| format!("route address must be ip:port, got {authority:?}"))?;
    Ok(Route::Socks5 { addr, auth })
}

impl Route {
    /// Open a connected TCP stream to `host:port` according to this route.
    /// On failure returns a Wisp close reason.
    pub async fn connect(&self, host: &str, port: u16, cfg: &Config) -> Result<TcpStream, u8> {
        match self {
            Route::Direct => connect_direct(host, port, cfg).await,
            Route::Socks5 { addr, auth } => {
                connect_socks5(*addr, auth.as_ref(), host, port, cfg).await
            }
        }
    }
}

/// Resolve locally, honor the SSRF guard + blacklist, and connect. This is the logic that
/// used to live in `wisp::connect_target`.
async fn connect_direct(host: &str, port: u16, cfg: &Config) -> Result<TcpStream, u8> {
    if cfg.is_host_blacklisted(host) {
        return Err(R_BLOCKED);
    }

    let mut addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host, port)).await {
        Ok(it) => it.collect(),
        Err(_) => return Err(R_UNREACHABLE),
    };
    if cfg.block_private {
        addrs.retain(|a| !is_private_ip(&a.ip()));
    }
    if addrs.is_empty() {
        return Err(if cfg.block_private {
            R_BLOCKED
        } else {
            R_UNREACHABLE
        });
    }

    let mut last = R_UNREACHABLE;
    for addr in addrs {
        match tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(e)) => {
                last = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => R_REFUSED,
                    _ => R_UNREACHABLE,
                };
            }
            Err(_) => last = R_TIMEOUT,
        }
    }
    Err(last)
}

/// Build the SOCKS5 CONNECT request for `host:port`. IP literals use ATYP 1/4; anything else
/// is sent as a domain name (ATYP 3) so the proxy resolves it — no DNS leaves this host.
fn socks5_request(host: &str, port: u16) -> Vec<u8> {
    let mut req = vec![0x05, 0x01, 0x00]; // VER, CMD=CONNECT, RSV
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            req.push(0x03);
            req.push(host.len() as u8); // caller guarantees host.len() <= 255 (MAX_HOST_LEN)
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes()); // SOCKS ports are big-endian
    req
}

/// Map a SOCKS5 reply code (REP field) to the closest Wisp close reason.
fn map_socks_reply(rep: u8) -> u8 {
    match rep {
        0x02 => R_BLOCKED,
        0x05 => R_REFUSED,
        0x06 => R_TIMEOUT,
        0x07 | 0x08 => R_INVALID,
        // 0x01 general failure, 0x03 net unreachable, 0x04 host unreachable, and anything else.
        _ => R_UNREACHABLE,
    }
}

/// Byte length of BND.ADDR for a given ATYP. `first` is the already-read first address byte,
/// which is the length prefix for the domain form. Returns None for an unknown ATYP.
fn bnd_addr_len(atyp: u8, first: u8) -> Option<usize> {
    match atyp {
        0x01 => Some(4),
        0x04 => Some(16),
        0x03 => Some(1 + first as usize), // 1 length byte already read as `first`
        _ => None,
    }
}

async fn connect_socks5(
    proxy: SocketAddr,
    auth: Option<&(String, String)>,
    host: &str,
    port: u16,
    cfg: &Config,
) -> Result<TcpStream, u8> {
    // The whole handshake — not just the TCP connect — is bounded, so a proxy that accepts
    // the socket and then stalls cannot hang the stream task forever.
    match tokio::time::timeout(cfg.connect_timeout, socks5_handshake(proxy, auth, host, port)).await
    {
        Ok(res) => res,
        Err(_) => Err(R_TIMEOUT),
    }
}

async fn socks5_handshake(
    proxy: SocketAddr,
    auth: Option<&(String, String)>,
    host: &str,
    port: u16,
) -> Result<TcpStream, u8> {
    let mut sock = TcpStream::connect(proxy).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::ConnectionRefused => R_REFUSED,
        _ => R_UNREACHABLE,
    })?;

    // Greeting: offer no-auth, and username/password if we have credentials.
    if auth.is_some() {
        sock.write_all(&[0x05, 0x02, 0x00, 0x02])
            .await
            .map_err(|_| R_UNREACHABLE)?;
    } else {
        sock.write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|_| R_UNREACHABLE)?;
    }

    let mut method = [0u8; 2];
    sock.read_exact(&mut method)
        .await
        .map_err(|_| R_UNREACHABLE)?;
    if method[0] != 0x05 {
        return Err(R_UNREACHABLE);
    }
    match method[1] {
        0x00 => {} // no auth required
        0x02 => {
            let (u, p) = auth.ok_or(R_BLOCKED)?; // proxy wants auth we don't have
            let mut neg = vec![0x01, u.len() as u8];
            neg.extend_from_slice(u.as_bytes());
            neg.push(p.len() as u8);
            neg.extend_from_slice(p.as_bytes());
            sock.write_all(&neg).await.map_err(|_| R_UNREACHABLE)?;
            let mut ok = [0u8; 2];
            sock.read_exact(&mut ok).await.map_err(|_| R_UNREACHABLE)?;
            if ok[1] != 0x00 {
                return Err(R_BLOCKED); // auth rejected
            }
        }
        _ => return Err(R_BLOCKED), // 0xFF or unsupported method
    }

    // CONNECT request.
    sock.write_all(&socks5_request(host, port))
        .await
        .map_err(|_| R_UNREACHABLE)?;

    // Reply: VER REP RSV ATYP ...
    let mut head = [0u8; 4];
    sock.read_exact(&mut head)
        .await
        .map_err(|_| R_UNREACHABLE)?;
    if head[0] != 0x05 {
        return Err(R_UNREACHABLE);
    }
    if head[1] != 0x00 {
        return Err(map_socks_reply(head[1]));
    }
    // Consume BND.ADDR + BND.PORT so no leftover bytes bleed into the stream payload.
    let mut first = [0u8; 1];
    if head[3] == 0x03 {
        sock.read_exact(&mut first)
            .await
            .map_err(|_| R_UNREACHABLE)?;
    }
    let addr_len = bnd_addr_len(head[3], first[0]).ok_or(R_INVALID)?;
    // For ATYP=3 the 1 length byte was already consumed into `first`; read the rest.
    let remaining = if head[3] == 0x03 {
        addr_len - 1
    } else {
        addr_len
    };
    let mut scratch = [0u8; 256];
    if remaining > 0 {
        sock.read_exact(&mut scratch[..remaining])
            .await
            .map_err(|_| R_UNREACHABLE)?;
    }
    let mut bnd_port = [0u8; 2];
    sock.read_exact(&mut bnd_port)
        .await
        .map_err(|_| R_UNREACHABLE)?;

    let _ = sock.set_nodelay(true);
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(r: &Route) -> String {
        match r {
            Route::Socks5 { addr, .. } => addr.to_string(),
            Route::Direct => "direct".into(),
        }
    }

    #[test]
    fn parses_single_socks5() {
        let m = parse_routes("warp=socks5://127.0.0.1:40000").unwrap();
        assert_eq!(m.len(), 2); // direct + warp
        assert_eq!(addr(&m["warp"]), "127.0.0.1:40000");
        assert!(matches!(&m["warp"], Route::Socks5 { auth: None, .. }));
    }

    #[test]
    fn parses_multiple_and_credentials() {
        let m = parse_routes("warp=socks5://127.0.0.1:40000,tor=socks5://u:p@127.0.0.1:9050")
            .unwrap();
        assert_eq!(m.len(), 3); // direct + warp + tor
        match &m["tor"] {
            Route::Socks5 {
                auth: Some((u, p)), ..
            } => {
                assert_eq!(u, "u");
                assert_eq!(p, "p");
            }
            _ => panic!("expected socks5 with auth"),
        }
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(parse_routes("x=http://127.0.0.1:8080").is_err());
    }

    #[test]
    fn rejects_duplicate_name() {
        assert!(parse_routes("a=socks5://127.0.0.1:1,a=socks5://127.0.0.1:2").is_err());
    }

    #[test]
    fn rejects_reserved_direct_name() {
        assert!(parse_routes("direct=socks5://127.0.0.1:1").is_err());
    }

    #[test]
    fn rejects_bad_port() {
        assert!(parse_routes("a=socks5://127.0.0.1:99999").is_err());
        assert!(parse_routes("a=socks5://127.0.0.1").is_err());
    }

    #[test]
    fn empty_spec_is_direct_only() {
        assert_eq!(parse_routes("").unwrap().len(), 1);
        assert_eq!(parse_routes("   ").unwrap().len(), 1);
        assert!(parse_routes("").unwrap().contains_key(DIRECT));
    }

    #[test]
    fn request_uses_domain_atyp_for_hostname() {
        let req = socks5_request("example.com", 443);
        assert_eq!(&req[0..3], &[0x05, 0x01, 0x00]); // VER, CONNECT, RSV
        assert_eq!(req[3], 0x03); // ATYP DOMAINNAME
        assert_eq!(req[4] as usize, "example.com".len());
        assert_eq!(&req[5..5 + 11], b"example.com");
        assert_eq!(&req[req.len() - 2..], &[0x01, 0xBB]); // port 443 big-endian
    }

    #[test]
    fn request_uses_v4_atyp_for_ip_literal() {
        let req = socks5_request("127.0.0.1", 80);
        assert_eq!(req[3], 0x01); // ATYP IPV4
        assert_eq!(&req[4..8], &[127, 0, 0, 1]);
        assert_eq!(&req[8..10], &[0x00, 0x50]); // port 80 big-endian
    }

    #[test]
    fn request_uses_v6_atyp_for_ipv6_literal() {
        let req = socks5_request("::1", 80);
        assert_eq!(req[3], 0x04); // ATYP IPV6
        assert_eq!(req.len(), 4 + 16 + 2);
    }

    #[test]
    fn reply_code_maps_to_wisp_reason() {
        assert_eq!(map_socks_reply(0x01), R_UNREACHABLE);
        assert_eq!(map_socks_reply(0x02), R_BLOCKED);
        assert_eq!(map_socks_reply(0x03), R_UNREACHABLE);
        assert_eq!(map_socks_reply(0x04), R_UNREACHABLE);
        assert_eq!(map_socks_reply(0x05), R_REFUSED);
        assert_eq!(map_socks_reply(0x06), R_TIMEOUT);
        assert_eq!(map_socks_reply(0x07), R_INVALID);
        assert_eq!(map_socks_reply(0x08), R_INVALID);
        assert_eq!(map_socks_reply(0x7f), R_UNREACHABLE); // unknown
    }

    #[test]
    fn bnd_addr_len_by_atyp() {
        assert_eq!(bnd_addr_len(0x01, 0), Some(4));
        assert_eq!(bnd_addr_len(0x04, 0), Some(16));
        assert_eq!(bnd_addr_len(0x03, 7), Some(8));
        assert_eq!(bnd_addr_len(0x09, 0), None);
    }
}
