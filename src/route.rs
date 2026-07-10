//! Outbound routing: send a stream's TCP either directly, through a SOCKS5 / HTTP proxy, or
//! (later) through an embedded WireGuard tunnel. One `Route` per Wisp connection.
//!
//! Fail closed: selection and dialing never silently fall back to `Direct`. An unknown route
//! is rejected before the WebSocket upgrade; a dead upstream closes the stream.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::config::{is_private_ip, Config};
use crate::wireguard::{WgStream, WgTunnel};
use crate::wisp::{R_BLOCKED, R_INVALID, R_REFUSED, R_TIMEOUT, R_UNREACHABLE};

/// The reserved route name that always maps to a direct connection.
pub const DIRECT: &str = "direct";

/// How a stream's outbound TCP is established.
pub enum Route {
    /// Resolve locally and connect straight out (today's behavior).
    Direct,
    /// Dial through a SOCKS5 proxy (RFC 1928). `auth` is optional username/password (RFC 1929).
    Socks5 {
        addr: SocketAddr,
        auth: Option<(String, String)>,
    },
    /// Dial through an HTTP proxy via the CONNECT method. `auth` is optional Basic credentials.
    Http {
        addr: SocketAddr,
        auth: Option<(String, String)>,
    },
    /// Dial through an embedded WireGuard tunnel (shared, one per route).
    Wireguard(Arc<WgTunnel>),
}

// Manual Debug: never render credentials. Only the variant + proxy address are shown.
impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Route::Direct => write!(f, "Direct"),
            Route::Socks5 { addr, .. } => write!(f, "Socks5({addr})"),
            Route::Http { addr, .. } => write!(f, "Http({addr})"),
            Route::Wireguard(_) => write!(f, "Wireguard"),
        }
    }
}

/// A connected upstream stream: a real TCP socket (direct/socks5/http) or a virtual stream
/// through a WireGuard tunnel. A delegating enum keeps the hot path free of `dyn`.
pub enum Conn {
    Tcp(TcpStream),
    Wg(WgStream),
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Conn::Wg(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Conn::Wg(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_flush(cx),
            Conn::Wg(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Conn::Wg(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// The route map used when no config file is present: only `direct` exists.
pub fn direct_routes() -> HashMap<String, Arc<Route>> {
    let mut m = HashMap::new();
    m.insert(DIRECT.to_string(), Arc::new(Route::Direct));
    m
}

/// A `config.yaml` body.
#[derive(Deserialize)]
struct ConfigFile {
    #[serde(default)]
    routes: Vec<RouteSpec>,
}

/// One route entry as written in YAML, tagged by `type`.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum RouteSpec {
    Socks5 {
        name: String,
        address: String,
        username: Option<String>,
        password: Option<String>,
    },
    Http {
        name: String,
        address: String,
        username: Option<String>,
        password: Option<String>,
    },
    Wireguard {
        name: String,
        private_key: String,
        peer_public_key: String,
        endpoint: String,
        address: String,
    },
    Warp {
        name: String,
    },
}

impl RouteSpec {
    fn name(&self) -> &str {
        match self {
            RouteSpec::Socks5 { name, .. }
            | RouteSpec::Http { name, .. }
            | RouteSpec::Wireguard { name, .. }
            | RouteSpec::Warp { name } => name,
        }
    }
}

fn auth_pair(u: Option<String>, p: Option<String>) -> Option<(String, String)> {
    match (u, p) {
        (Some(u), Some(p)) => Some((u, p)),
        _ => None,
    }
}

/// Parse a `config.yaml` body into the route map (always including the implicit `direct`).
/// Any malformed entry, unknown `type`, duplicate name, or use of the reserved name `direct`
/// is an error — the caller treats that as fatal. `wireguard`/`warp` specs build (and, for
/// `warp`, register) a tunnel eagerly, so this may block and must run inside the tokio runtime.
pub fn routes_from_yaml(yaml: &str) -> Result<HashMap<String, Arc<Route>>, String> {
    let cfg: ConfigFile =
        serde_yaml_ng::from_str(yaml).map_err(|e| format!("config parse error: {e}"))?;
    let mut map = direct_routes();
    for spec in cfg.routes {
        let name = spec.name().to_string();
        if name.is_empty() {
            return Err("route with empty name".into());
        }
        if name == DIRECT {
            return Err(format!("route name {DIRECT:?} is reserved"));
        }
        let route = build_route(spec, &name)?;
        if map.insert(name.clone(), Arc::new(route)).is_some() {
            return Err(format!("duplicate route name: {name:?}"));
        }
    }
    Ok(map)
}

fn build_route(spec: RouteSpec, name: &str) -> Result<Route, String> {
    match spec {
        RouteSpec::Socks5 {
            address,
            username,
            password,
            ..
        } => {
            let addr = address
                .parse()
                .map_err(|_| format!("socks5 route {name:?}: address must be ip:port"))?;
            Ok(Route::Socks5 {
                addr,
                auth: auth_pair(username, password),
            })
        }
        RouteSpec::Http {
            address,
            username,
            password,
            ..
        } => {
            let addr = address
                .parse()
                .map_err(|_| format!("http route {name:?}: address must be ip:port"))?;
            Ok(Route::Http {
                addr,
                auth: auth_pair(username, password),
            })
        }
        RouteSpec::Wireguard {
            private_key,
            peer_public_key,
            endpoint,
            address,
            ..
        } => {
            use std::net::ToSocketAddrs;
            let cfg = crate::wireguard::WgConfig {
                private_key: crate::wireguard::decode_key_b64(&private_key)
                    .map_err(|e| format!("wireguard route {name:?}: {e}"))?,
                peer_public_key: crate::wireguard::decode_key_b64(&peer_public_key)
                    .map_err(|e| format!("wireguard route {name:?}: {e}"))?,
                endpoint: endpoint
                    .to_socket_addrs()
                    .map_err(|_| format!("wireguard route {name:?}: bad endpoint"))?
                    .next()
                    .ok_or_else(|| format!("wireguard route {name:?}: endpoint unresolved"))?,
                address_v4: address
                    .split('/')
                    .next()
                    .unwrap_or(&address)
                    .parse()
                    .map_err(|_| format!("wireguard route {name:?}: bad address"))?,
            };
            Ok(Route::Wireguard(WgTunnel::spawn(cfg)))
        }
        RouteSpec::Warp { .. } => {
            let cache = std::path::PathBuf::from(format!("warp-{name}.json"));
            let cfg = crate::wireguard::register_warp(&cache)
                .map_err(|e| format!("warp route {name:?}: {e}"))?;
            Ok(Route::Wireguard(WgTunnel::spawn(cfg)))
        }
    }
}

impl Route {
    /// Open a connected stream to `host:port` according to this route.
    /// On failure returns a Wisp close reason.
    pub async fn connect(&self, host: &str, port: u16, cfg: &Config) -> Result<Conn, u8> {
        match self {
            Route::Direct => connect_direct(host, port, cfg).await.map(Conn::Tcp),
            Route::Socks5 { addr, auth } => connect_socks5(*addr, auth.as_ref(), host, port, cfg)
                .await
                .map(Conn::Tcp),
            Route::Http { addr, auth } => connect_http(*addr, auth.as_ref(), host, port, cfg)
                .await
                .map(Conn::Tcp),
            Route::Wireguard(tunnel) => tunnel
                .dial(host, port, cfg.connect_timeout)
                .await
                .map(Conn::Wg),
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

// --- HTTP proxy (CONNECT) ---

/// Minimal RFC 4648 base64 (standard alphabet, padded). Enough for Basic auth.
fn base64_encode(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(A[(n >> 18 & 63) as usize] as char);
        out.push(A[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Build the HTTP CONNECT request bytes for `host:port`, with optional Basic credentials.
fn http_connect_request(host: &str, port: u16, auth: Option<&(String, String)>) -> Vec<u8> {
    let mut s = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some((u, p)) = auth {
        let token = base64_encode(format!("{u}:{p}").as_bytes());
        s.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    s.push_str("\r\n");
    s.into_bytes()
}

/// Map an HTTP CONNECT status code to a Wisp close reason. `None` means success (2xx).
fn map_http_status(code: u16) -> Option<u8> {
    match code {
        200..=299 => None,
        407 | 403 => Some(R_BLOCKED),
        _ => Some(R_UNREACHABLE),
    }
}

async fn connect_http(
    proxy: SocketAddr,
    auth: Option<&(String, String)>,
    host: &str,
    port: u16,
    cfg: &Config,
) -> Result<TcpStream, u8> {
    match tokio::time::timeout(cfg.connect_timeout, http_handshake(proxy, auth, host, port)).await {
        Ok(res) => res,
        Err(_) => Err(R_TIMEOUT),
    }
}

async fn http_handshake(
    proxy: SocketAddr,
    auth: Option<&(String, String)>,
    host: &str,
    port: u16,
) -> Result<TcpStream, u8> {
    let mut sock = TcpStream::connect(proxy).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::ConnectionRefused => R_REFUSED,
        _ => R_UNREACHABLE,
    })?;
    sock.write_all(&http_connect_request(host, port, auth))
        .await
        .map_err(|_| R_UNREACHABLE)?;

    // Read the response head one byte at a time until CRLFCRLF, bounded so a hostile proxy
    // cannot make us read forever.
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = sock.read(&mut byte).await.map_err(|_| R_UNREACHABLE)?;
        if n == 0 {
            return Err(R_UNREACHABLE);
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(R_UNREACHABLE); // header block too large
        }
    }
    // Status line: "HTTP/1.1 200 Connection established".
    let head = std::str::from_utf8(&buf).map_err(|_| R_UNREACHABLE)?;
    let code = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or(R_UNREACHABLE)?;
    if let Some(reason) = map_http_status(code) {
        return Err(reason);
    }
    let _ = sock.set_nodelay(true);
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(r: &Route) -> String {
        match r {
            Route::Socks5 { addr, .. } | Route::Http { addr, .. } => addr.to_string(),
            Route::Direct => "direct".into(),
            Route::Wireguard(_) => "wireguard".into(),
        }
    }

    #[test]
    fn yaml_parses_socks5_and_http() {
        let y = r#"
routes:
  - name: tor
    type: socks5
    address: "127.0.0.1:9050"
  - name: corp
    type: http
    address: "127.0.0.1:8080"
    username: u
    password: p
"#;
        let m = routes_from_yaml(y).unwrap();
        assert_eq!(addr(&m["tor"]), "127.0.0.1:9050");
        assert!(matches!(&*m["tor"], Route::Socks5 { auth: None, .. }));
        assert!(matches!(&*m["corp"], Route::Http { auth: Some(_), .. }));
        assert!(m.contains_key(DIRECT));
    }

    #[test]
    fn yaml_rejects_reserved_direct() {
        let y = "routes:\n  - name: direct\n    type: socks5\n    address: \"127.0.0.1:1\"\n";
        assert!(routes_from_yaml(y).is_err());
    }

    #[test]
    fn yaml_rejects_unknown_type() {
        let y = "routes:\n  - name: x\n    type: ftp\n    address: \"127.0.0.1:1\"\n";
        assert!(routes_from_yaml(y).is_err());
    }

    #[test]
    fn yaml_rejects_duplicate_name() {
        let y = "routes:\n  - name: a\n    type: socks5\n    address: \"127.0.0.1:1\"\n  - name: a\n    type: socks5\n    address: \"127.0.0.1:2\"\n";
        assert!(routes_from_yaml(y).is_err());
    }

    #[test]
    fn yaml_rejects_bad_address() {
        let y = "routes:\n  - name: a\n    type: socks5\n    address: \"not-an-addr\"\n";
        assert!(routes_from_yaml(y).is_err());
    }

    #[test]
    fn yaml_empty_is_direct_only() {
        assert_eq!(routes_from_yaml("routes: []").unwrap().len(), 1);
        assert!(routes_from_yaml("routes: []").unwrap().contains_key(DIRECT));
    }

    #[test]
    fn http_request_has_connect_line_and_host() {
        let req = http_connect_request("example.com", 443, None);
        let s = String::from_utf8(req).unwrap();
        assert!(s.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com:443\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
        assert!(!s.contains("Proxy-Authorization"));
    }

    #[test]
    fn http_request_includes_basic_auth() {
        let auth = ("u".to_string(), "p".to_string());
        let req = http_connect_request("h", 80, Some(&auth));
        let s = String::from_utf8(req).unwrap();
        // base64("u:p") = "dTpw"
        assert!(s.contains("Proxy-Authorization: Basic dTpw\r\n"));
    }

    #[test]
    fn http_status_maps() {
        assert_eq!(map_http_status(200), None);
        assert_eq!(map_http_status(407), Some(R_BLOCKED));
        assert_eq!(map_http_status(403), Some(R_BLOCKED));
        assert_eq!(map_http_status(502), Some(R_UNREACHABLE));
        assert_eq!(map_http_status(504), Some(R_UNREACHABLE));
        assert_eq!(map_http_status(500), Some(R_UNREACHABLE));
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b"u:p"), "dTpw");
        assert_eq!(base64_encode(b"Aladdin:open sesame"), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        assert_eq!(base64_encode(b""), "");
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
