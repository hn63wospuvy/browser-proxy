# VPN Routes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the frontend pick whether outbound TCP leaves the server directly or through a VPN exposed as a SOCKS5 proxy (WARP, Tor, …), selected per Wisp connection via `?route=<name>`.

**Architecture:** A new `enum Route { Direct, Socks5 { addr, auth } }` owns "open a TCP stream to host:port". Today's `connect_target` becomes the `Direct` arm; a hand-written RFC 1928 SOCKS5 client is the `Socks5` arm. `Config` parses a `ROUTES` env var into a `HashMap<String, Route>`; the axum `ws_handler` maps `?route=` to a `Route` and passes it down the Wisp stack. The frontend fetches `/routes.json` and shows a dropdown. Fail closed: an unknown route is a 400, a dead proxy is a stream CLOSE — never a silent direct connection.

**Tech Stack:** Rust (axum 0.7, tokio 1), no new crates. Vanilla JS/CSS frontend.

## Global Constraints

- **No new dependencies.** `Cargo.toml` stays at its current crate set; the SOCKS5 client is hand-written on `tokio::net::TcpStream`.
- **Rust edition 2021**, existing style: `tracing` for logs, `metrics::inc` counters, errors modeled as Wisp close-reason `u8`.
- **Wisp close reasons** (from `src/wisp.rs`): `R_VOLUNTARY=0x02`, `R_NETWORK=0x03`, `R_INVALID=0x41`, `R_UNREACHABLE=0x42`, `R_TIMEOUT=0x43`, `R_REFUSED=0x44`, `R_BLOCKED=0x48`. These are `pub(crate)`-visible to `route.rs` (see Task 1).
- **Fail closed.** Unknown `?route` → HTTP 400, no upgrade. Dead/misbehaving proxy → stream CLOSE. Never fall back to `Direct`.
- **`ROUTES` misconfiguration is fatal** — the server refuses to boot. Every other env var keeps warn-and-default behavior.
- **`direct` is a reserved, always-present route name** and cannot be overridden by `ROUTES`.
- **Credentials from `ROUTES` are never logged.**
- **Ports:** SOCKS5 wire is big-endian; Wisp wire is little-endian.
- **DNS:** on a SOCKS5 route, domain hosts are sent as `ATYP=03` (proxy resolves — no DNS leaves this host); only IP-literal hosts use `ATYP=01`/`04`.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/route.rs` | **new** — `Route` enum, `Route::connect`, SOCKS5 client, `parse_routes`, unit tests |
| `src/wisp.rs` | share close-reason consts with `route.rs`; `connect_target` → `Route::Direct`; thread `Arc<Route>` through `handle_connection`/`run_stream` |
| `src/config.rs` | `routes` field; `from_env` → `Result`; call `route::parse_routes` |
| `src/lib.rs` | `pub mod route;` |
| `src/main.rs` | handle `Config::from_env()` returning `Result` |
| `src/server.rs` | `handle_connection` signature; `?route=` extraction + 400; `GET /routes.json` |
| `static/index.html` | `<select id="route">` in the bar |
| `static/index.js` | populate dropdown from `/routes.json`; `wispUrl()` appends `?route=`; re-navigate on change |
| `static/style.css` | dropdown styling |
| `README.md` | `ROUTES` row + "Routing through a VPN" section + limitations |
| `tests/socks_routing.rs` | **new** — fake SOCKS5 server integration tests |

---

## Task 1: Extract Wisp close-reason constants so `route.rs` can share them

**Files:**
- Modify: `src/wisp.rs:44-52` (the close-reason consts) and their references

**Interfaces:**
- Produces: close-reason constants visible to `route.rs`. Chosen approach: make them `pub(crate)` in `wisp.rs` and `use crate::wisp::{R_UNREACHABLE, …}` from `route.rs`. This keeps one definition.

- [ ] **Step 1: Make the close-reason constants crate-visible**

In `src/wisp.rs`, change the close-reason block (lines ~45-52) from `const` to `pub(crate) const`:

```rust
// Close reasons.
pub(crate) const R_VOLUNTARY: u8 = 0x02;
pub(crate) const R_NETWORK: u8 = 0x03;
pub(crate) const R_INVALID: u8 = 0x41;
pub(crate) const R_UNREACHABLE: u8 = 0x42;
pub(crate) const R_TIMEOUT: u8 = 0x43;
pub(crate) const R_REFUSED: u8 = 0x44;
pub(crate) const R_BLOCKED: u8 = 0x48;
```

Leave `T_*`, `ST_TCP`, and `R_*` usages elsewhere unchanged.

- [ ] **Step 2: Verify it still builds**

Run: `cargo build`
Expected: compiles (warnings about unused `pub(crate)` are fine until Task 2 lands).

- [ ] **Step 3: Commit**

```bash
git add src/wisp.rs
git commit -m "refactor: make Wisp close-reason consts crate-visible"
```

---

## Task 2: `Route` enum + `parse_routes`, with the `Direct` arm only

Build the module skeleton and configuration parsing first; the SOCKS5 client lands in Task 3. The `Direct` arm reuses today's connect logic, moved verbatim.

**Files:**
- Create: `src/route.rs`
- Modify: `src/lib.rs` (add `pub mod route;`)
- Modify: `src/wisp.rs` (remove the moved `connect_target`; see Task 4 for call-site rewiring — for now keep `connect_target` too so the crate builds)

**Interfaces:**
- Consumes: `crate::wisp::{R_UNREACHABLE, R_REFUSED, R_TIMEOUT, R_BLOCKED, R_INVALID}`, `crate::config::{Config, is_private_ip}`.
- Produces:
  - `pub enum Route { Direct, Socks5 { addr: std::net::SocketAddr, auth: Option<(String, String)> } }`
  - `pub async fn Route::connect(&self, host: &str, port: u16, cfg: &Config) -> Result<tokio::net::TcpStream, u8>`
  - `pub fn parse_routes(spec: &str) -> Result<std::collections::HashMap<String, Route>, String>`
  - `pub fn direct_routes() -> HashMap<String, Route>` returning just `{"direct": Route::Direct}` (used when `ROUTES` is unset).

- [ ] **Step 1: Write failing tests for `parse_routes`**

Create `src/route.rs` with only the tests + minimal type stubs so it compiles to a failing state. Put this at the bottom of the file:

```rust
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
        assert_eq!(m.len(), 1);
        assert_eq!(addr(&m["warp"]), "127.0.0.1:40000");
        assert!(matches!(&m["warp"], Route::Socks5 { auth: None, .. }));
    }

    #[test]
    fn parses_multiple_and_credentials() {
        let m = parse_routes("warp=socks5://127.0.0.1:40000,tor=socks5://u:p@127.0.0.1:9050")
            .unwrap();
        assert_eq!(m.len(), 2);
        match &m["tor"] {
            Route::Socks5 { auth: Some((u, p)), .. } => {
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
    fn empty_spec_is_empty_map() {
        assert!(parse_routes("").unwrap().is_empty());
        assert!(parse_routes("   ").unwrap().is_empty());
    }
}
```

- [ ] **Step 2: Write the module body (types + `parse_routes` + `Direct` connect)**

Above the tests in `src/route.rs`:

```rust
//! Outbound routing: send a stream's TCP either directly or through a SOCKS5 upstream (a VPN
//! exposed as a proxy — WARP `mode proxy`, Tor, …). One `Route` per Wisp connection.
//!
//! Fail closed: selection and dialing never silently fall back to `Direct`. An unknown route
//! is rejected before the WebSocket upgrade; a dead proxy closes the stream.

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::config::{is_private_ip, Config};
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
        return Err(if cfg.block_private { R_BLOCKED } else { R_UNREACHABLE });
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

/// SOCKS5 arm — implemented in Task 3.
async fn connect_socks5(
    _proxy: SocketAddr,
    _auth: Option<&(String, String)>,
    _host: &str,
    _port: u16,
    _cfg: &Config,
) -> Result<TcpStream, u8> {
    // Placeholder replaced in Task 3. Kept compiling so Task 2 tests (parse_routes) run.
    Err(R_UNREACHABLE)
}
```

Note the imports `R_TIMEOUT`, `R_INVALID` may be unused until Task 3 — add `#[allow(unused_imports)]` on the `use crate::wisp::…` line if the build warns, and remove it in Task 3.

- [ ] **Step 3: Register the module**

In `src/lib.rs`, add under the other `pub mod` lines:

```rust
pub mod route;
```

Add a doc line too:

```rust
//! - [`route`]: outbound routing (direct or SOCKS5 upstream).
```

- [ ] **Step 4: Run the tests — expect PASS for parse, module compiles**

Run: `cargo test --lib route::`
Expected: the seven `parse_routes` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/route.rs src/lib.rs
git commit -m "feat: Route enum + ROUTES parser, Direct arm"
```

---

## Task 3: SOCKS5 client (the `Socks5` arm)

Replace the `connect_socks5` placeholder with a real RFC 1928 handshake. Unit-test the wire encoding/decoding as pure functions so they don't need a live proxy; the end-to-end path is covered by Task 7.

**Files:**
- Modify: `src/route.rs`

**Interfaces:**
- Consumes: close-reason consts from Task 1; `Config` (for `connect_timeout`).
- Produces: a working `connect_socks5`, plus pure helpers `socks5_request(host, port) -> Vec<u8>` and `map_socks_reply(rep: u8) -> u8` used by unit tests.

- [ ] **Step 1: Write failing unit tests for the wire helpers**

Add to the `tests` module in `src/route.rs`:

```rust
#[test]
fn request_uses_domain_atyp_for_hostname() {
    let req = socks5_request("example.com", 443);
    assert_eq!(&req[0..3], &[0x05, 0x01, 0x00]); // VER, CONNECT, RSV
    assert_eq!(req[3], 0x03); // ATYP DOMAINNAME
    assert_eq!(req[4] as usize, "example.com".len());
    assert_eq!(&req[5..5 + 11], b"example.com");
    // big-endian port 443 = 0x01BB
    assert_eq!(&req[req.len() - 2..], &[0x01, 0xBB]);
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
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test --lib route::`
Expected: FAIL — `socks5_request` / `map_socks_reply` not found.

- [ ] **Step 3: Implement the SOCKS5 client**

Replace the `connect_socks5` placeholder in `src/route.rs` with:

```rust
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/// Number of bytes occupied by BND.ADDR for a given ATYP, given the first address byte
/// (needed only for the domain form, whose length is that byte). Returns None for unknown ATYP.
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
    let deadline = cfg.connect_timeout;
    match tokio::time::timeout(deadline, socks5_handshake(proxy, auth, host, port)).await {
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
        sock.write_all(&[0x05, 0x02, 0x00, 0x02]).await.map_err(|_| R_UNREACHABLE)?;
    } else {
        sock.write_all(&[0x05, 0x01, 0x00]).await.map_err(|_| R_UNREACHABLE)?;
    }

    let mut method = [0u8; 2];
    sock.read_exact(&mut method).await.map_err(|_| R_UNREACHABLE)?;
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
    sock.write_all(&socks5_request(host, port)).await.map_err(|_| R_UNREACHABLE)?;

    // Reply: VER REP RSV ATYP ...
    let mut head = [0u8; 4];
    sock.read_exact(&mut head).await.map_err(|_| R_UNREACHABLE)?;
    if head[0] != 0x05 {
        return Err(R_UNREACHABLE);
    }
    if head[1] != 0x00 {
        return Err(map_socks_reply(head[1]));
    }
    // Consume BND.ADDR + BND.PORT so no leftover bytes bleed into the stream payload.
    let mut first = [0u8; 1];
    if head[3] == 0x03 {
        sock.read_exact(&mut first).await.map_err(|_| R_UNREACHABLE)?;
    }
    let addr_len = bnd_addr_len(head[3], first[0]).ok_or(R_INVALID)?;
    // For ATYP=3 we already consumed the 1 length byte into `first`; read the remaining
    // `addr_len - 1`. For 1/4 read the full length.
    let remaining = if head[3] == 0x03 { addr_len - 1 } else { addr_len };
    let mut scratch = [0u8; 256];
    if remaining > 0 {
        sock.read_exact(&mut scratch[..remaining]).await.map_err(|_| R_UNREACHABLE)?;
    }
    let mut bnd_port = [0u8; 2];
    sock.read_exact(&mut bnd_port).await.map_err(|_| R_UNREACHABLE)?;

    let _ = sock.set_nodelay(true);
    Ok(sock)
}
```

Remove any `#[allow(unused_imports)]` added in Task 2 — all close-reason consts are used now.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib route::`
Expected: all `parse_routes` + wire-helper tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/route.rs
git commit -m "feat: hand-written SOCKS5 client for the Socks5 route"
```

---

## Task 4: Wire `Route` through the Wisp relay

Make `handle_connection` / `run_stream` take an `Arc<Route>` and dial via it; delete the now-duplicated `connect_target` from `wisp.rs`.

**Files:**
- Modify: `src/wisp.rs`

**Interfaces:**
- Consumes: `crate::route::Route`.
- Produces: `pub async fn handle_connection(socket: WebSocket, cfg: Arc<Config>, route: Arc<Route>)` — the new signature `server.rs` (Task 6) must call.

- [ ] **Step 1: Change `handle_connection` signature and pass the route down**

In `src/wisp.rs`:

Add near the top with the other `use`s:

```rust
use crate::route::Route;
```

Change the function signature (line ~143):

```rust
pub async fn handle_connection(socket: WebSocket, cfg: Arc<Config>, route: Arc<Route>) {
```

At the `run_stream` spawn (line ~226), pass `route.clone()`:

```rust
let jh = tokio::spawn(run_stream(
    stream_id,
    host,
    port,
    data_rx,
    ws_tx.clone(),
    done_tx.clone(),
    cfg.clone(),
    route.clone(),
    outstanding.clone(),
));
```

- [ ] **Step 2: Change `run_stream` to accept and use the route**

Change `run_stream`'s signature (line ~342) to add `route: Arc<Route>` (place it after `cfg`):

```rust
async fn run_stream(
    stream_id: u32,
    host: String,
    port: u16,
    mut data_rx: mpsc::Receiver<Bytes>,
    ws_tx: mpsc::Sender<Message>,
    done_tx: mpsc::UnboundedSender<u32>,
    cfg: Arc<Config>,
    route: Arc<Route>,
    outstanding: Arc<AtomicU32>,
) {
```

Change the connect call at the top of `run_stream` (line ~352) from `connect_target(&host, port, &cfg)` to:

```rust
    let tcp = match route.connect(&host, port, &cfg).await {
```

- [ ] **Step 3: Delete the old `connect_target`**

Remove the whole `connect_target` function from `src/wisp.rs` (lines ~302-338). Its logic now lives in `route::connect_direct`. Remove the now-unused `use crate::config::{is_private_ip, Config};` import if `is_private_ip` is no longer referenced in `wisp.rs` (keep `Config`).

- [ ] **Step 4: Build — expect one error at the `server.rs` call site**

Run: `cargo build`
Expected: `wisp.rs` compiles; the only error is `handle_connection` called with 2 args in `server.rs`. That is fixed in Task 6. (If you want a green build now, temporarily pass `Arc::new(Route::Direct)` at the `server.rs` call site; Task 6 replaces it.)

- [ ] **Step 5: Commit**

```bash
git add src/wisp.rs
git commit -m "refactor: dial through Route in the Wisp relay"
```

---

## Task 5: `Config.routes` + fatal parse on bad `ROUTES`

**Files:**
- Modify: `src/config.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `crate::route::{parse_routes, direct_routes, Route}`.
- Produces:
  - `Config` gains `pub routes: std::collections::HashMap<String, crate::route::Route>`.
  - `pub fn Config::from_env() -> Result<Config, String>` (signature change).

- [ ] **Step 1: Add the field and switch `from_env` to `Result`**

In `src/config.rs`:

Add imports:

```rust
use std::collections::HashMap;
use crate::route::{direct_routes, parse_routes, Route};
```

Add to the struct (after `host_blacklist`):

```rust
    /// Named outbound routes selectable via `?route=`. Always contains `direct`.
    pub routes: HashMap<String, Route>,
```

`Route` has no `Debug`/`Clone`; the struct derives `#[derive(Clone, Debug)]`. Two options — pick the first:
- **Add `#[derive(Clone, Debug)]` to `enum Route` in `route.rs`.** `SocketAddr` and `Option<(String,String)>` are both `Clone + Debug`, so this just works. Do this now (edit `route.rs`: `#[derive(Clone, Debug)] pub enum Route`).

In `Default for Config`, initialize:

```rust
            routes: direct_routes(),
```

Change the signature and body of `from_env`:

```rust
    pub fn from_env() -> Result<Self, String> {
        let mut cfg = Config::default();
        // ... all existing env parsing unchanged ...

        if let Ok(spec) = std::env::var("ROUTES") {
            cfg.routes = parse_routes(&spec).map_err(|e| format!("invalid ROUTES: {e}"))?;
        }

        Ok(cfg)
    }
```

Keep every other env parse exactly as-is; only wrap the return in `Ok(...)` and add the `ROUTES` block before it.

Update the doc comment above `from_env` to mention `ROUTES`:

```rust
    /// - `ROUTES`: comma-separated `name=socks5://[user:pass@]host:port` upstream routes,
    ///   selectable via `?route=<name>`. `direct` is implicit and reserved. A malformed
    ///   spec is fatal (returns `Err`).
```

- [ ] **Step 2: Handle the `Result` in `main.rs`**

In `src/main.rs`, change line 17 from `let cfg = Arc::new(Config::from_env());` to:

```rust
    let cfg = match Config::from_env() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!("configuration error: {e}");
            std::process::exit(1);
        }
    };
```

- [ ] **Step 3: Fix the test/other callers of `from_env`**

Search for other `from_env()` callers: `grep -rn "from_env" src tests`. The integration test uses `Config::default()`, not `from_env`, so only `main.rs` should need changes. If any exist, unwrap or `.expect(...)` them.

- [ ] **Step 4: Add a unit test for the fatal path**

Add to `src/config.rs` tests module (create one if absent — mirror the style already there):

```rust
    #[test]
    fn routes_default_has_direct_only() {
        let cfg = Config::default();
        assert!(cfg.routes.contains_key("direct"));
        assert_eq!(cfg.routes.len(), 1);
    }
```

(The fatal-on-bad-ROUTES behavior itself is covered by `parse_routes` unit tests in Task 2; `from_env` reads a process-global env var, so don't test it by mutating env in parallel test threads.)

- [ ] **Step 5: Build + test**

Run: `cargo build && cargo test --lib`
Expected: compiles; `config` and `route` unit tests PASS. (`server.rs` call site still 2-arg — Task 6. If you added the temporary `Route::Direct` in Task 4 Step 4, the build is green; otherwise expect the same single call-site error.)

- [ ] **Step 6: Commit**

```bash
git add src/config.rs src/main.rs src/route.rs
git commit -m "feat: parse ROUTES into Config; fatal on misconfiguration"
```

---

## Task 6: Route selection in the axum layer + `/routes.json`

**Files:**
- Modify: `src/server.rs`

**Interfaces:**
- Consumes: `crate::route::{Route, DIRECT}`, `Config.routes`, `wisp::handle_connection(socket, cfg, route)`.
- Produces: `GET /routes.json` → `{"routes":[…]}`; `?route=` handling with 400 on unknown.

- [ ] **Step 1: Extract `?route=` and select the Route in `ws_handler`**

In `src/server.rs`:

Add imports:

```rust
use std::collections::HashMap;
use axum::extract::Query;
use crate::route::{Route, DIRECT};
```

Change `ws_handler` to read the query and resolve the route. Replace the function (lines ~72-90):

```rust
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    // Resolve the requested route BEFORE acquiring a connection permit, so a bad request
    // doesn't consume a slot. Unknown route → 400, never a silent direct fallback.
    let route_name = params.get("route").map(String::as_str).unwrap_or(DIRECT);
    let route = match state.cfg.routes.get(route_name) {
        Some(_) => route_name.to_string(),
        None => {
            return (StatusCode::BAD_REQUEST, format!("unknown route: {route_name}"))
                .into_response();
        }
    };

    let permit = match state.conn_sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            metrics::inc(&metrics::connections_rejected_maxconn);
            return (StatusCode::SERVICE_UNAVAILABLE, "too many connections").into_response();
        }
    };

    let cfg = state.cfg.clone();
    ws.max_message_size(MAX_WS_MESSAGE)
        .max_frame_size(MAX_WS_MESSAGE)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            // Look the route up again inside the task to get an owned Arc<Route>.
            let route = build_route(&cfg, &route);
            wisp::handle_connection(socket, cfg.clone(), route).await;
        })
}
```

Because `Route` isn't `Clone`-cheap to pull out of the map by value, add a small helper that clones the selected route into an `Arc`:

```rust
/// Clone the named route out of the config into an owned Arc. The name is guaranteed present
/// (validated in `ws_handler` before upgrade); fall back to Direct defensively.
fn build_route(cfg: &Config, name: &str) -> Arc<Route> {
    Arc::new(cfg.routes.get(name).cloned().unwrap_or(Route::Direct))
}
```

(`Route` derives `Clone` from Task 5 Step 1, so `.cloned()` works.)

- [ ] **Step 2: Add the `/routes.json` endpoint**

Add the route in `build_router` (after `/debug/stats`):

```rust
        .route("/routes.json", get(routes_handler))
```

Add the handler:

```rust
async fn routes_handler(State(state): State<AppState>) -> Response {
    // Sorted for stable output, with `direct` first so the UI shows it as the default.
    let mut names: Vec<&String> = state.cfg.routes.keys().collect();
    names.sort_by(|a, b| {
        (a.as_str() != DIRECT, a.as_str()).cmp(&(b.as_str() != DIRECT, b.as_str()))
    });
    let items = names
        .iter()
        .map(|n| format!("{n:?}"))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!("{{\"routes\":[{items}]}}");
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}
```

- [ ] **Step 3: Build**

Run: `cargo build`
Expected: compiles cleanly (this resolves the Task 4 call-site error). Remove any temporary `Route::Direct` shim from Task 4 Step 4.

- [ ] **Step 4: Smoke-test the endpoints**

Run:
```bash
cargo run --release &
sleep 2
curl -s localhost:8080/routes.json
curl -s -o /dev/null -w "%{http_code}\n" "localhost:8080/wisp/?route=nope"   # expect 400
kill %1
```
Expected: `{"routes":["direct"]}` and `400`.

- [ ] **Step 5: Commit**

```bash
git add src/server.rs
git commit -m "feat: select route from ?route=, expose /routes.json, fail closed on unknown"
```

---

## Task 7: Integration tests with a fake SOCKS5 server

**Files:**
- Create: `tests/socks_routing.rs`

**Interfaces:**
- Consumes: `build_router`, `Config` with a `routes` map pointing at the fake proxy. Since `Config.routes` is built by `parse_routes`, construct the test config via `Config { routes: parse_routes(&spec)?, ..Default::default() }`.

- [ ] **Step 1: Write the fake SOCKS5 server + happy-path test**

Create `tests/socks_routing.rs`:

```rust
//! Integration tests for SOCKS5 routing: a fake in-process SOCKS5 proxy relays to a TCP echo
//! server, driven end-to-end through the real axum router over a Wisp WebSocket.

use std::sync::Arc;
use std::time::Duration;

use browser_proxy::config::Config;
use browser_proxy::route::parse_routes;
use browser_proxy::server::build_router;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

fn connect_pkt(id: u32, port: u16, host: &str) -> Vec<u8> {
    let mut p = vec![0x01];
    p.extend_from_slice(&id.to_le_bytes());
    p.push(0x01);
    p.extend_from_slice(&port.to_le_bytes());
    p.extend_from_slice(host.as_bytes());
    p
}
fn data_pkt(id: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x02];
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(payload);
    p
}
fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn expect_binary(msg: Message) -> Vec<u8> {
    match msg {
        Message::Binary(b) => b,
        other => panic!("expected binary frame, got {other:?}"),
    }
}

async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Minimal SOCKS5 proxy: no-auth, CONNECT only, ATYP 1/3/4. `reply_override`, when set,
/// makes it answer every CONNECT with that REP code and close (for failure tests).
async fn spawn_fake_socks(reply_override: Option<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = listener.accept().await {
            tokio::spawn(async move {
                // Greeting.
                let mut g = [0u8; 2];
                if c.read_exact(&mut g).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; g[1] as usize];
                let _ = c.read_exact(&mut methods).await;
                let _ = c.write_all(&[0x05, 0x00]).await; // choose no-auth

                // Request: VER CMD RSV ATYP ...
                let mut h = [0u8; 4];
                if c.read_exact(&mut h).await.is_err() {
                    return;
                }
                let dst_host = match h[3] {
                    0x01 => {
                        let mut a = [0u8; 4];
                        let _ = c.read_exact(&mut a).await;
                        std::net::IpAddr::from(a).to_string()
                    }
                    0x04 => {
                        let mut a = [0u8; 16];
                        let _ = c.read_exact(&mut a).await;
                        std::net::IpAddr::from(a).to_string()
                    }
                    0x03 => {
                        let mut l = [0u8; 1];
                        let _ = c.read_exact(&mut l).await;
                        let mut d = vec![0u8; l[0] as usize];
                        let _ = c.read_exact(&mut d).await;
                        String::from_utf8_lossy(&d).into_owned()
                    }
                    _ => return,
                };
                let mut p = [0u8; 2];
                let _ = c.read_exact(&mut p).await;
                let dst_port = u16::from_be_bytes(p);

                if let Some(rep) = reply_override {
                    // Reply with the forced error and a dummy BND (ATYP=1, 0.0.0.0:0).
                    let _ = c
                        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return;
                }

                // Success path: connect to the real target, reply OK, then splice both ways.
                let upstream = match TcpStream::connect((dst_host.as_str(), dst_port)).await {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = c
                            .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                        return;
                    }
                };
                let _ = c
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let (mut cr, mut cw) = c.into_split();
                let (mut ur, mut uw) = upstream.into_split();
                let a = tokio::io::copy(&mut cr, &mut uw);
                let b = tokio::io::copy(&mut ur, &mut cw);
                let _ = tokio::join!(a, b);
            });
        }
    });
    port
}

async fn spawn_proxy_with_routes(spec: &str) -> u16 {
    let mut cfg = Config::default();
    cfg.routes = parse_routes(spec).unwrap();
    let app = build_router(Arc::new(cfg), "static");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

#[tokio::test]
async fn routes_through_socks_to_echo() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let echo = spawn_echo().await;
        let socks = spawn_fake_socks(None).await;
        let spec = format!("test=socks5://127.0.0.1:{socks}");
        let proxy = spawn_proxy_with_routes(&spec).await;

        let url = format!("ws://127.0.0.1:{proxy}/wisp/?route=test");
        let (mut ws, _) = connect_async(url.as_str()).await.expect("ws connect");
        let _ = expect_binary(ws.next().await.unwrap().unwrap()); // handshake CONTINUE

        ws.send(Message::Binary(connect_pkt(1, echo, "127.0.0.1"))).await.unwrap();
        ws.send(Message::Binary(data_pkt(1, b"hello socks"))).await.unwrap();

        let mut got = Vec::new();
        while got.len() < b"hello socks".len() {
            let f = expect_binary(ws.next().await.unwrap().unwrap());
            match f[0] {
                0x02 => {
                    assert_eq!(u32_le(&f[1..5]), 1);
                    got.extend_from_slice(&f[5..]);
                }
                0x03 => {}
                0x04 => panic!("unexpected CLOSE"),
                t => panic!("unexpected packet {t:#x}"),
            }
        }
        assert_eq!(got, b"hello socks");
    })
    .await
    .expect("timed out");
}
```

- [ ] **Step 2: Run the happy-path test**

Run: `cargo test --test socks_routing routes_through_socks_to_echo`
Expected: PASS.

- [ ] **Step 3: Add the unknown-route (400) test**

Append to `tests/socks_routing.rs`:

```rust
#[tokio::test]
async fn unknown_route_is_rejected() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let proxy = spawn_proxy_with_routes("test=socks5://127.0.0.1:1").await;
        let url = format!("ws://127.0.0.1:{proxy}/wisp/?route=nope");
        // tungstenite surfaces a non-101 upgrade as an Http error; just assert it fails.
        assert!(connect_async(url.as_str()).await.is_err(), "expected upgrade to be refused");
    })
    .await
    .expect("timed out");
}
```

- [ ] **Step 4: Add the forced-refuse (REP=05) test**

Append:

```rust
#[tokio::test]
async fn socks_refused_closes_stream() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socks = spawn_fake_socks(Some(0x05)).await; // connection refused
        let spec = format!("test=socks5://127.0.0.1:{socks}");
        let proxy = spawn_proxy_with_routes(&spec).await;

        let url = format!("ws://127.0.0.1:{proxy}/wisp/?route=test");
        let (mut ws, _) = connect_async(url.as_str()).await.expect("ws connect");
        let _ = expect_binary(ws.next().await.unwrap().unwrap());

        ws.send(Message::Binary(connect_pkt(3, 80, "example.com"))).await.unwrap();
        loop {
            let f = expect_binary(ws.next().await.unwrap().unwrap());
            if f[0] == 0x04 {
                assert_eq!(u32_le(&f[1..5]), 3);
                assert_eq!(f[5], 0x44, "REP=05 should map to R_REFUSED"); // R_REFUSED
                break;
            }
        }
    })
    .await
    .expect("timed out");
}
```

- [ ] **Step 5: Add the silent-proxy timeout test**

This proves the handshake timeout wraps the whole exchange, not just the TCP connect. Use a proxy that accepts then never replies, and a short `connect_timeout`.

Append:

```rust
async fn spawn_silent_socks() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((c, _)) = listener.accept().await {
            // Hold the socket open and never speak SOCKS.
            tokio::spawn(async move {
                let _c = c;
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn silent_proxy_times_out() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socks = spawn_silent_socks().await;
        let spec = format!("test=socks5://127.0.0.1:{socks}");
        let mut cfg = Config::default();
        cfg.routes = parse_routes(&spec).unwrap();
        cfg.connect_timeout = Duration::from_secs(1); // short, so the test is fast
        let app = build_router(Arc::new(cfg), "static");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });

        let url = format!("ws://127.0.0.1:{proxy}/wisp/?route=test");
        let (mut ws, _) = connect_async(url.as_str()).await.expect("ws connect");
        let _ = expect_binary(ws.next().await.unwrap().unwrap());

        ws.send(Message::Binary(connect_pkt(5, 80, "example.com"))).await.unwrap();
        loop {
            let f = expect_binary(ws.next().await.unwrap().unwrap());
            if f[0] == 0x04 {
                assert_eq!(u32_le(&f[1..5]), 5);
                assert_eq!(f[5], 0x43, "silent proxy should map to R_TIMEOUT"); // R_TIMEOUT
                break;
            }
        }
    })
    .await
    .expect("timed out");
}
```

- [ ] **Step 6: Run the full suite**

Run: `cargo test`
Expected: all tests PASS (existing `wisp_integration` + new `socks_routing`).

- [ ] **Step 7: Commit**

```bash
git add tests/socks_routing.rs
git commit -m "test: SOCKS5 routing integration (echo, unknown route, refused, timeout)"
```

---

## Task 8: Frontend route dropdown

**Files:**
- Modify: `static/index.html`, `static/index.js`, `static/style.css`

**Interfaces:**
- Consumes: `GET /routes.json` → `{"routes":[...]}`; existing `wispUrl()`, `ensureTransport()`, `connection.setTransport`.

- [ ] **Step 1: Add the `<select>` to the bar**

In `static/index.html`, inside `#proxy-form`, before the `<button>` (so tab order is input → route → Go):

```html
        <select id="proxy-route" aria-label="Route" hidden></select>
```

- [ ] **Step 2: Populate it from `/routes.json`, keep the selection**

In `static/index.js`, add after the `const frameHost = …` line:

```javascript
const routeSelect = document.getElementById("proxy-route");
const ROUTE_KEY = "proxy-route";

// Populate the route dropdown from the server. Hidden entirely when only `direct` exists,
// so users without any VPN configured see no extra control.
async function loadRoutes() {
  let routes = ["direct"];
  try {
    const res = await fetch("/routes.json");
    if (res.ok) {
      const json = await res.json();
      if (Array.isArray(json.routes) && json.routes.length) routes = json.routes;
    }
  } catch (_) {
    /* fall back to direct-only */
  }
  if (routes.length <= 1) return; // only `direct`: leave the select hidden

  routeSelect.innerHTML = "";
  for (const name of routes) {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    routeSelect.appendChild(opt);
  }
  const saved = localStorage.getItem(ROUTE_KEY);
  if (saved && routes.includes(saved)) routeSelect.value = saved;
  routeSelect.hidden = false;
}

function currentRoute() {
  return routeSelect && !routeSelect.hidden ? routeSelect.value : "direct";
}

loadRoutes();
```

- [ ] **Step 3: Append `?route=` in `wispUrl()`**

Replace `wispUrl()` (lines ~103-106) with:

```javascript
function wispUrl() {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  const route = currentRoute();
  const q = route && route !== "direct" ? `?route=${encodeURIComponent(route)}` : "";
  return `${scheme}://${location.host}/wisp/${q}`;
}
```

- [ ] **Step 4: Force the transport to rebuild on route change**

`ensureTransport()` is idempotent and won't switch when only the URL changes. Add an explicit setter and call it when the dropdown changes. Replace `ensureTransport` (lines ~108-113) with:

```javascript
/** Point bare-mux at our Wisp backend for the CURRENT route (idempotent per URL). */
let activeWispUrl = null;
async function ensureTransport() {
  const url = wispUrl();
  if ((await connection.getTransport()) !== "/libcurl/index.mjs" || activeWispUrl !== url) {
    await connection.setTransport("/libcurl/index.mjs", [{ websocket: url }]);
    activeWispUrl = url;
  }
}
```

Add the change handler (after `loadRoutes();`):

```javascript
// Changing the route rebuilds the transport, which tears down the live WebSocket and every
// stream on it. Re-navigate the frame to the current URL so the page reloads over the new
// route instead of dying half-loaded.
routeSelect.addEventListener("change", async () => {
  localStorage.setItem(ROUTE_KEY, routeSelect.value);
  if (!frame || !document.body.classList.contains("browsing")) return;
  try {
    await ensureTransport();
    const url = frame.frame.src;
    if (url) frame.go(frame.url || url);
  } catch (err) {
    console.error("route switch failed", err);
  }
});
```

Note: `frame.url` may not exist on the Scramjet frame object; the fallback `frame.frame.src` is the rendered (rewritten) URL. Re-navigating via `frame.go(...)` expects the *original* URL. To keep the original, store it on submit — in the `form` submit handler, after `frame.go(target);` add `frame.__lastTarget = target;`, and in the change handler use `frame.__lastTarget` first:

```javascript
    const target = frame.__lastTarget;
    if (target) frame.go(target);
```

- [ ] **Step 5: Style the dropdown to match the input/button**

In `static/style.css`, after the `input:focus` block (~line 74), add:

```css
#proxy-route {
  padding: 0.55rem 0.6rem;
  font-size: 0.9rem;
  color: var(--fg);
  background: var(--field);
  border: 1px solid var(--border);
  border-radius: 8px;
  outline: none;
  cursor: pointer;
}
#proxy-route:focus {
  border-color: var(--accent);
}
```

- [ ] **Step 6: Manual verification**

Run:
```bash
ROUTES="warp=socks5://127.0.0.1:40000" cargo run --release
```
Open http://localhost:8080/. Expected: a route dropdown appears next to the URL box showing `direct` and `warp`. With no `ROUTES` set, the dropdown is hidden. (Switching to `warp` only relays if a SOCKS5 proxy actually listens on `127.0.0.1:40000`.)

- [ ] **Step 7: Commit**

```bash
git add static/index.html static/index.js static/style.css
git commit -m "feat(ui): route dropdown, persisted, reloads frame on change"
```

---

## Task 9: Documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add the `ROUTES` row to the config table**

In `README.md`, in the config table (after the `HOST_BLACKLIST` row, ~line 60):

```markdown
| `ROUTES` | *(empty)* | Comma-separated `name=socks5://[user:pass@]host:port` upstream routes, selectable in the UI via `?route=`. `direct` is always available. A malformed value aborts startup. |
```

- [ ] **Step 2: Add a "Routing through a VPN" section**

After the "Configuration" table (before "## How it works"), add:

````markdown
## Routing through a VPN

Outbound connections can be sent through any VPN or proxy that exposes a **SOCKS5**
endpoint, chosen per-navigation from a dropdown in the UI. Target sites then see the VPN's
IP, not the server's.

Define named routes in `ROUTES` and pick one in the UI. `direct` (no proxy) is always
present; the dropdown is hidden when no other route is configured.

**Cloudflare WARP** (`1.1.1.1`): run WARP in proxy mode, which exposes a local SOCKS5
listener without capturing the host routing table:

```bash
warp-cli mode proxy          # SOCKS5 on 127.0.0.1:40000 by default
warp-cli connect
ROUTES="warp=socks5://127.0.0.1:40000" cargo run --release
```

**Tor**: `ROUTES="tor=socks5://127.0.0.1:9050"` (with the Tor daemon running).

You can define several at once:

```bash
ROUTES="warp=socks5://127.0.0.1:40000,tor=socks5://127.0.0.1:9050" cargo run --release
```

**Fail closed.** If the selected route doesn't exist the WebSocket upgrade is rejected
(HTTP 400); if the proxy is down the stream closes. Traffic is *never* silently sent
directly when a VPN route was requested.

**DNS.** On a SOCKS5 route the target hostname is handed to the proxy to resolve, so no DNS
query for the destination leaves this machine.

**Two caveats within the "personal use" scope:**

- `BLOCK_PRIVATE` cannot filter a *hostname* on a SOCKS5 route (the name is resolved by the
  proxy, not here). IP-literal targets are still checked. The SSRF exposure is smaller on a
  VPN route anyway, since connections originate from the VPN's network, not this host.
- The client transport is a **SharedWorker shared across all tabs** of the origin. Selecting
  a route affects every open tab, not just the current one — switching in one tab switches
  all of them. Use one tab at a time if you rely on per-tab routes.
````

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document ROUTES and VPN routing"
```

---

## Task 10: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Full build + test + lint**

Run:
```bash
cargo test
cargo clippy --all-targets -- -D warnings
```
Expected: all tests PASS; clippy clean. Fix any warnings inline (common ones: unused imports left from Task 2/3, `format!` in `routes_handler`).

- [ ] **Step 2: End-to-end with a real SOCKS proxy (optional, needs WARP or Tor)**

If WARP or Tor is available locally, start it, run `ROUTES="warp=socks5://127.0.0.1:40000" cargo run --release`, open the UI, select the route, browse to a "what is my IP" site, and confirm the IP is the VPN's. Document the observed IP in the PR description.

- [ ] **Step 3: Final commit / branch is ready**

The feature is complete. Hand off to `superpowers:finishing-a-development-branch`.

---

## Self-Review Notes

- **Spec coverage:** `enum Route` (T2), SOCKS5 client incl. the three wire traps (T3), `ROUTES` parse + fatal (T2/T5), reserved `direct` (T2), `?route=` + 400 + `/routes.json` (T6), `block_private` behavior preserved on Direct and IP-literal SOCKS (T2/T3 — hostname-on-SOCKS is intentionally unchecked per spec), proxy-addr exemption (proxy addr comes from config, never routed through `is_private_ip`), dropdown + hidden-when-direct-only + persistence + reload-on-change (T8), README incl. both caveats (T9), all four integration tests (T7). Credentials-never-logged holds because no code logs the `auth` field.
- **Types:** `Route::connect(&self, host, port, cfg) -> Result<TcpStream, u8>`, `parse_routes(&str) -> Result<HashMap<String,Route>,String>`, `handle_connection(socket, cfg, Arc<Route>)`, `run_stream(..., route, ...)`, `from_env() -> Result<Config,String>` — consistent across tasks.
- **Fatal path:** only `ROUTES` is fatal; all other env vars keep warn-and-default (T5 Step 1 preserves them verbatim).
