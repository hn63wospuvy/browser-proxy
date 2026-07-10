# VPN Routes v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the SOCKS5 route foundation with a YAML config file, an HTTP-proxy route, an embedded WireGuard route (in-process WARP registration), and a center-of-page route dropdown.

**Architecture:** `enum Route` gains `Http` and `Wireguard(Arc<WgTunnel>)` arms; `Route::connect` returns a new `enum Conn { Tcp, Wg }` (both `AsyncRead+AsyncWrite`) so the Wisp relay handles real and virtual streams uniformly. Routes are defined in `config.yaml` (serde). The WireGuard route reimplements the onetun/wireproxy core — `boringtun` (Noise) + `smoltcp` (userspace TCP/IP) + a UDP socket — as one shared long-lived tunnel task per route, with WARP credentials registered once via the unofficial Cloudflare API and cached to disk.

**Tech Stack:** Rust (axum 0.7, tokio 1); new: `serde`/`serde_yaml_ng`/`serde_json`, `boringtun` 0.7, `smoltcp`, `ureq`, `x25519-dalek`, `base64`, `rand`. Vanilla JS/CSS frontend.

## Global Constraints

- **Fail closed** (from v1): unknown `?route` → HTTP 400; a dead upstream/tunnel → stream CLOSE; never a silent `direct` fallback. Config parse failure is **fatal** (server refuses to boot).
- **`direct` is reserved, always-present, non-overridable.**
- **No secrets in logs** — SOCKS/HTTP credentials, WireGuard private keys, WARP registration keys.
- **DNS never leaks**: SOCKS/HTTP hosts are proxy-resolved; WireGuard hosts are resolved via 1.1.1.1 *inside* the tunnel; only `direct` uses the OS resolver.
- **Wisp close reasons** (crate-visible in `src/wisp.rs`): `R_VOLUNTARY=0x02`, `R_NETWORK=0x03`, `R_INVALID=0x41`, `R_UNREACHABLE=0x42`, `R_TIMEOUT=0x43`, `R_REFUSED=0x44`, `R_BLOCKED=0x48`.
- **WARP MTU is 1280.**
- **Ports:** SOCKS5 wire is big-endian; Wisp wire is little-endian.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/route.rs` | `Route` (+`Http`,`Wireguard`); `enum Conn`; SOCKS5 + HTTP clients; `Route::connect -> Result<Conn,u8>` |
| `src/config.rs` | load+parse `config.yaml`; `RouteSpec` serde types → `HashMap<String,Route>`; drop `ROUTES` env |
| `src/wireguard.rs` | **new** — WARP registration client, `WgTunnel` driver, `WgStream`, DNS-over-tunnel |
| `src/wisp.rs` | `run_stream` splits `Conn` via `tokio::io::split` |
| `src/server.rs` | unchanged (route selection + `/routes.json` already generic) |
| `src/lib.rs` | `pub mod wireguard;` |
| `Cargo.toml` | new dependencies |
| `static/index.html`,`index.js`,`style.css` | center landing dropdown + synced top-bar select |
| `README.md` | YAML config, route types, embedded WARP, cache file, dependency note |
| `tests/http_routing.rs` | **new** — fake HTTP CONNECT proxy integration |
| `tests/wireguard.rs` | **new** — registration-parse + DNS-encode units; `#[ignore]` real-WARP e2e |
| `config.example.yaml` | **new** — documented sample config |

---

## Phase 1 — YAML config

### Task 1: Add serde deps and parse `config.yaml` into route specs

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/config.rs`
- Modify: `src/route.rs` (a `from_spec` constructor; `Http` arm type only — impl in Phase 2)
- Create: `config.example.yaml`

**Interfaces:**
- Produces:
  - `Config` loads routes from YAML; `from_env() -> Result<Config,String>` now also reads `CONFIG`/`./config.yaml`.
  - `pub fn route::routes_from_yaml(yaml: &str) -> Result<HashMap<String, Route>, String>`.
  - `RouteSpec` serde enum (internal to `route.rs`).

- [ ] **Step 1: Add dependencies**

In `Cargo.toml` `[dependencies]`, add:

```toml
serde = { version = "1", features = ["derive"] }
serde_yaml_ng = "0.10"
```

(The heavier WireGuard deps are added in Phase 4 so Phases 1–3 build fast.)

- [ ] **Step 2: Write failing tests for YAML parsing**

Add to the `tests` module in `src/route.rs`:

```rust
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
    assert!(matches!(&m["tor"], Route::Socks5 { auth: None, .. }));
    assert!(matches!(&m["corp"], Route::Http { auth: Some(_), .. }));
    assert!(m.contains_key("direct"));
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
fn yaml_empty_is_direct_only() {
    assert_eq!(routes_from_yaml("routes: []").unwrap().len(), 1);
}
```

- [ ] **Step 3: Implement `RouteSpec` + `routes_from_yaml`**

Add to `src/route.rs` (keep the existing `parse_routes`/`parse_socks5_url` for now; they are removed in Step 6):

```rust
use serde::Deserialize;

#[derive(Deserialize)]
struct ConfigFile {
    #[serde(default)]
    routes: Vec<RouteSpec>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum RouteSpec {
    Socks5 { name: String, address: String, username: Option<String>, password: Option<String> },
    Http   { name: String, address: String, username: Option<String>, password: Option<String> },
    Wireguard {
        name: String,
        private_key: String,
        peer_public_key: String,
        endpoint: String,
        address: String,
    },
    Warp { name: String },
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

/// Parse a `config.yaml` body into the route map (always including `direct`).
/// WireGuard/Warp specs are validated here but the tunnel is built later (Phase 4 replaces
/// the `todo!` with `wireguard::build`).
pub fn routes_from_yaml(yaml: &str) -> Result<HashMap<String, Route>, String> {
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
        let route = match spec {
            RouteSpec::Socks5 { address, username, password, .. } => {
                let addr = address
                    .parse()
                    .map_err(|_| format!("socks5 route {name:?}: address must be ip:port"))?;
                Route::Socks5 { addr, auth: auth_pair(username, password) }
            }
            RouteSpec::Http { address, username, password, .. } => {
                let addr = address
                    .parse()
                    .map_err(|_| format!("http route {name:?}: address must be ip:port"))?;
                Route::Http { addr, auth: auth_pair(username, password) }
            }
            RouteSpec::Wireguard { .. } | RouteSpec::Warp { .. } => {
                // Phase 4 replaces this with a constructed Route::Wireguard(tunnel).
                return Err(format!(
                    "wireguard route {name:?} not supported yet (Phase 4)"
                ));
            }
        };
        if map.insert(name.clone(), route).is_some() {
            return Err(format!("duplicate route name: {name:?}"));
        }
    }
    Ok(map)
}
```

Add the `Http` variant to `enum Route` now so this compiles (impl in Phase 2):

```rust
pub enum Route {
    Direct,
    Socks5 { addr: SocketAddr, auth: Option<(String, String)> },
    Http { addr: SocketAddr, auth: Option<(String, String)> },
}
```

- [ ] **Step 4: Run the YAML tests**

Run: `cargo test --lib route::yaml`
Expected: `yaml_parses_socks5_and_http` fails to build only if `Route::Http` connect is missing — but since `routes_from_yaml` only constructs the variant (no connect yet), it compiles. All four tests PASS except any needing `Http::connect` (none do). Expected: PASS.

- [ ] **Step 5: Load the file in `Config::from_env`**

In `src/config.rs`, replace the `ROUTES` env block:

```rust
        // Routes come from a YAML config file (env ROUTES was removed).
        let path = std::env::var("CONFIG").unwrap_or_else(|_| "config.yaml".to_string());
        match std::fs::read_to_string(&path) {
            Ok(body) => {
                cfg.routes = crate::route::routes_from_yaml(&body)
                    .map_err(|e| format!("{path}: {e}"))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No config file: direct only. Only warn if CONFIG was explicitly set.
                if std::env::var("CONFIG").is_ok() {
                    return Err(format!("{path}: {e}"));
                }
            }
            Err(e) => return Err(format!("{path}: {e}")),
        }
```

Update the `from_env` doc comment: remove the `ROUTES` line, add:

```rust
    /// - `CONFIG`: path to a YAML route config (default `config.yaml` if present). See
    ///   `config.example.yaml`. A malformed config is fatal.
```

- [ ] **Step 6: Remove the dead `ROUTES` parser**

Delete `parse_routes` and `parse_socks5_url` from `src/route.rs` and their unit tests
(`parses_single_socks5`, `parses_multiple_and_credentials`, `rejects_unknown_scheme`,
`rejects_duplicate_name`, `rejects_reserved_direct_name`, `rejects_bad_port`,
`empty_spec_is_direct_only`) — they are superseded by `routes_from_yaml` and its tests. Keep
`direct_routes`, `Route`, `Route::connect`, the SOCKS5 client, and the wire-helper tests.

- [ ] **Step 7: Write `config.example.yaml`**

Create `config.example.yaml`:

```yaml
# Routes selectable from the UI. `direct` (no proxy) always exists implicitly.
# Point the server at this file with CONFIG=config.yaml (the default path).
routes:
  # Cloudflare WARP, registered in-process (one binary, no warp-cli):
  - name: warp
    type: warp

  # A generic WireGuard peer you configure yourself (e.g. wgcf-generated):
  # - name: myvpn
  #   type: wireguard
  #   private_key: "<base64 private key>"
  #   peer_public_key: "<base64 peer public key>"
  #   endpoint: "engage.cloudflareclient.com:2408"
  #   address: "172.16.0.2/32"

  # A SOCKS5 upstream (Tor, etc.):
  - name: tor
    type: socks5
    address: "127.0.0.1:9050"

  # An HTTP CONNECT proxy (optional credentials):
  - name: corp
    type: http
    address: "127.0.0.1:8080"
    # username: "u"
    # password: "p"
```

- [ ] **Step 8: Build + test + commit**

Run: `cargo test --lib`
Expected: PASS (route + config unit tests).

```bash
git add Cargo.toml Cargo.lock src/route.rs src/config.rs config.example.yaml
git commit -m "feat: YAML route config; drop ROUTES env var"
```

---

## Phase 2 — HTTP proxy route + `Conn`

### Task 2: `enum Conn` and generalize the relay to non-TCP streams

**Files:**
- Modify: `src/route.rs` (add `Conn`, change `Route::connect` return type)
- Modify: `src/wisp.rs` (`run_stream` splits `Conn`)

**Interfaces:**
- Produces: `pub enum Conn { Tcp(TcpStream), Wg(WgStream) }` implementing `AsyncRead+AsyncWrite`; `Route::connect(&self, host, port, cfg) -> Result<Conn, u8>`.
- Note: `WgStream` does not exist until Phase 4. Define `Conn` with only the `Tcp` variant now and add `Wg` in Phase 4 (a one-line variant + two match arms). This keeps Phase 2 shippable.

- [ ] **Step 1: Add `Conn` (Tcp-only for now)**

In `src/route.rs`:

```rust
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A connected upstream stream: a real TCP socket (direct/socks5/http) or, later, a virtual
/// stream through a WireGuard tunnel. Delegating enum avoids `dyn` on the hot path.
pub enum Conn {
    Tcp(TcpStream),
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>)
        -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8])
        -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
```

- [ ] **Step 2: Change `Route::connect` and the Direct/SOCKS5 arms to return `Conn`**

`Route::connect` signature → `Result<Conn, u8>`. Wrap the existing return values:

```rust
    pub async fn connect(&self, host: &str, port: u16, cfg: &Config) -> Result<Conn, u8> {
        match self {
            Route::Direct => connect_direct(host, port, cfg).await.map(Conn::Tcp),
            Route::Socks5 { addr, auth } => {
                connect_socks5(*addr, auth.as_ref(), host, port, cfg).await.map(Conn::Tcp)
            }
            Route::Http { addr, auth } => {
                connect_http(*addr, auth.as_ref(), host, port, cfg).await.map(Conn::Tcp)
            }
        }
    }
```

`connect_direct`/`connect_socks5` keep returning `Result<TcpStream, u8>` (the `.map(Conn::Tcp)` wraps them). Add a `connect_http` stub returning `Err(R_UNREACHABLE)` for now (real impl in Task 3) so this compiles.

- [ ] **Step 3: Split `Conn` in `run_stream`**

In `src/wisp.rs`, change the connect + split:

```rust
    let conn = match route.connect(&host, port, &cfg).await {
        Ok(c) => { /* metrics + log as today */ c }
        Err(reason) => { /* unchanged failure path */ return; }
    };
    let (mut tcp_read, mut tcp_write) = tokio::io::split(conn);
```

Add `use tokio::io::{AsyncReadExt, AsyncWriteExt};` is already present. `tokio::io::split` yields `ReadHalf<Conn>`/`WriteHalf<Conn>`, both `AsyncRead`/`AsyncWrite`; the existing `read`/`write_all`/`shutdown` calls work unchanged. Remove the old `tcp.into_split()` line.

- [ ] **Step 4: Build**

Run: `cargo build`
Expected: compiles. `connect_http` is a stub; the existing integration tests still pass over `direct`/`socks5`.

- [ ] **Step 5: Run tests + commit**

Run: `cargo test`
Expected: existing suites PASS.

```bash
git add src/route.rs src/wisp.rs
git commit -m "refactor: Conn enum so the relay handles non-TCP upstreams"
```

### Task 3: HTTP CONNECT client (the `Http` arm)

**Files:**
- Modify: `src/route.rs`
- Create: `tests/http_routing.rs`

**Interfaces:**
- Consumes: close-reason consts; `Config.connect_timeout`.
- Produces: working `connect_http`; pure helpers `http_connect_request(host, port, auth) -> Vec<u8>` and `map_http_status(code: u16) -> Option<u8>` (None = success).

- [ ] **Step 1: Write failing unit tests**

Add to the `tests` module in `src/route.rs`:

```rust
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
```

- [ ] **Step 2: Run to confirm failure**

Run: `cargo test --lib route::http`
Expected: FAIL — helpers not defined.

- [ ] **Step 3: Implement the HTTP CONNECT client**

Add to `src/route.rs`. Base64 without a new dep in Phase 2: implement a tiny standard-alphabet encoder (12 lines) — replaced by the `base64` crate in Phase 4 is unnecessary; keep the small encoder.

```rust
/// Minimal RFC 4648 base64 (standard alphabet, padded). Enough for Basic auth.
fn base64_encode(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(A[(n >> 18 & 63) as usize] as char);
        out.push(A[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { A[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn http_connect_request(host: &str, port: u16, auth: Option<&(String, String)>) -> Vec<u8> {
    let mut s = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some((u, p)) = auth {
        let token = base64_encode(format!("{u}:{p}").as_bytes());
        s.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    s.push_str("\r\n");
    s.into_bytes()
}

/// Map an HTTP CONNECT status to a Wisp close reason. None means success (2xx).
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

    // Read headers until CRLFCRLF (bounded to avoid an unbounded read from a hostile proxy).
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
    // Status line: "HTTP/1.1 200 Connection established"
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
```

Replace the Task 2 `connect_http` stub with this.

- [ ] **Step 4: Run unit tests**

Run: `cargo test --lib route::http`
Expected: PASS.

- [ ] **Step 5: Write the HTTP CONNECT integration test**

Create `tests/http_routing.rs` mirroring `tests/socks_routing.rs`, with a fake CONNECT proxy:

```rust
//! Integration test: an HTTP-CONNECT proxy relays to an echo server, driven through the real
//! router over a Wisp WebSocket.

use std::sync::Arc;
use std::time::Duration;

use browser_proxy::config::Config;
use browser_proxy::route::routes_from_yaml;
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
fn u32_le(b: &[u8]) -> u32 { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
fn expect_binary(m: Message) -> Vec<u8> {
    match m { Message::Binary(b) => b, o => panic!("want binary, got {o:?}") }
}

async fn spawn_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                loop {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => { if s.write_all(&b[..n]).await.is_err() { break; } }
                    }
                }
            });
        }
    });
    port
}

/// Fake HTTP CONNECT proxy: reads the CONNECT request headers, dials the target, replies 200,
/// then splices.
async fn spawn_fake_http() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match c.read(&mut byte).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => head.push(byte[0]),
                    }
                    if head.ends_with(b"\r\n\r\n") { break; }
                }
                let line = String::from_utf8_lossy(&head);
                let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let up = match TcpStream::connect(&target).await {
                    Ok(s) => s,
                    Err(_) => { let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await; return; }
                };
                let _ = c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                let (mut cr, mut cw) = c.into_split();
                let (mut ur, mut uw) = up.into_split();
                let _ = tokio::join!(tokio::io::copy(&mut cr, &mut uw), tokio::io::copy(&mut ur, &mut cw));
            });
        }
    });
    port
}

async fn spawn_proxy(yaml: &str) -> u16 {
    let cfg = Config { routes: routes_from_yaml(yaml).unwrap(), ..Default::default() };
    let app = build_router(Arc::new(cfg), "static");
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });
    port
}

#[tokio::test]
async fn routes_through_http_connect_to_echo() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let echo = spawn_echo().await;
        let http = spawn_fake_http().await;
        let yaml = format!("routes:\n  - name: web\n    type: http\n    address: \"127.0.0.1:{http}\"\n");
        let proxy = spawn_proxy(&yaml).await;

        let url = format!("ws://127.0.0.1:{proxy}/wisp/?route=web");
        let (mut ws, _) = connect_async(url.as_str()).await.expect("ws");
        let _ = expect_binary(ws.next().await.unwrap().unwrap());

        ws.send(Message::Binary(connect_pkt(1, echo, "127.0.0.1"))).await.unwrap();
        ws.send(Message::Binary(data_pkt(1, b"hi http"))).await.unwrap();

        let mut got = Vec::new();
        while got.len() < b"hi http".len() {
            let f = expect_binary(ws.next().await.unwrap().unwrap());
            match f[0] {
                0x02 => { assert_eq!(u32_le(&f[1..5]), 1); got.extend_from_slice(&f[5..]); }
                0x03 => {}
                0x04 => panic!("unexpected CLOSE"),
                t => panic!("packet {t:#x}"),
            }
        }
        assert_eq!(got, b"hi http");
    })
    .await
    .expect("timed out");
}
```

- [ ] **Step 6: Run + commit**

Run: `cargo test --test http_routing`
Expected: PASS.

```bash
git add src/route.rs tests/http_routing.rs
git commit -m "feat: HTTP CONNECT route type"
```

---

## Phase 3 — Frontend center dropdown

### Task 4: Center landing dropdown synced with the top-bar select

**Files:**
- Modify: `static/index.html`, `static/index.js`, `static/style.css`

**Interfaces:**
- Consumes: `/routes.json`; existing `wispUrl()`, `ensureTransport()`, `currentRoute()`, `routeSelect`.

- [ ] **Step 1: Add the landing dropdown to HTML**

In `static/index.html`, inside `#landing` after the `<p>Type any URL…</p>`:

```html
      <label id="route-picker" hidden>
        Route:
        <select id="proxy-route-landing" aria-label="Route"></select>
      </label>
```

- [ ] **Step 2: Sync both selects in JS**

In `static/index.js`, replace the route block so both selects share state. Change `loadRoutes` to fill both, and factor the change handling:

```javascript
const routeSelect = document.getElementById("proxy-route");
const routeSelectLanding = document.getElementById("proxy-route-landing");
const routePicker = document.getElementById("route-picker");
const ROUTE_KEY = "proxy-route";

function fillSelect(sel, routes, value) {
  sel.replaceChildren();
  for (const name of routes) {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    sel.appendChild(opt);
  }
  sel.value = value;
}

async function loadRoutes() {
  let routes = ["direct"];
  try {
    const res = await fetch("/routes.json");
    if (res.ok) {
      const json = await res.json();
      if (Array.isArray(json.routes) && json.routes.length) routes = json.routes;
    }
  } catch (_) { /* direct only */ }
  if (routes.length <= 1) return;

  const saved = localStorage.getItem(ROUTE_KEY);
  const value = saved && routes.includes(saved) ? saved : routes[0];
  fillSelect(routeSelect, routes, value);
  fillSelect(routeSelectLanding, routes, value);
  routeSelect.hidden = false;
  routePicker.hidden = false;
}

function currentRoute() {
  return !routeSelect.hidden ? routeSelect.value : "direct";
}

// Apply a route change coming from either select: mirror to the other, persist, and (while
// browsing) rebuild the transport + reload the frame.
async function onRouteChange(value) {
  routeSelect.value = value;
  routeSelectLanding.value = value;
  localStorage.setItem(ROUTE_KEY, value);
  if (!frame || !document.body.classList.contains("browsing")) return;
  try {
    await ensureTransport();
    if (frame.__lastTarget) frame.go(frame.__lastTarget);
  } catch (err) {
    console.error("route switch failed", err);
  }
}

routeSelect.addEventListener("change", () => onRouteChange(routeSelect.value));
routeSelectLanding.addEventListener("change", () => onRouteChange(routeSelectLanding.value));

loadRoutes();
```

(Remove the old single-select `routeSelect` block and its `change` listener that this replaces.)

- [ ] **Step 3: Style the landing picker**

In `static/style.css`, add:

```css
#route-picker {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 1.25rem;
  font-size: 1rem;
  color: var(--muted, #9aa4b2);
}
#route-picker select {
  padding: 0.5rem 0.75rem;
  font-size: 1rem;
  color: var(--fg);
  background: var(--field);
  border: 1px solid var(--border);
  border-radius: 8px;
  cursor: pointer;
}
#route-picker select:focus { border-color: var(--accent); }
```

- [ ] **Step 4: Verify**

Run: `node --check static/index.js` → syntax OK.
Then manual/browser: start with a config that has routes, load the page, confirm the landing shows a "Route:" dropdown and the top bar shows one, both change together, and both are hidden when only `direct` exists.

- [ ] **Step 5: Commit**

```bash
git add static/index.html static/index.js static/style.css
git commit -m "feat(ui): center landing route dropdown, synced with top bar"
```

---

## Phase 4 — Embedded WireGuard

> Highest-risk phase. `boringtun`+`smoltcp` is version-sensitive; expect to iterate the tunnel driver against the compiler. Ship Phases 1–3 first.

### Task 5: Dependencies + WARP registration client

**Files:**
- Modify: `Cargo.toml`, `src/lib.rs`
- Create: `src/wireguard.rs`
- Create: `tests/wireguard.rs`

**Interfaces:**
- Produces:
  - `pub struct WgConfig { pub private_key: [u8;32], pub peer_public_key: [u8;32], pub endpoint: SocketAddr, pub address_v4: Ipv4Addr }`
  - `pub fn parse_registration(json: &str) -> Result<PartialWgConfig, String>` where `PartialWgConfig` holds peer_public_key(base64), endpoint host:port, address v4.
  - `pub fn register_warp(cache_path: &Path) -> Result<WgConfig, String>` (blocking; caches).

- [ ] **Step 1: Add WireGuard dependencies**

In `Cargo.toml`:

```toml
boringtun = "0.7"
smoltcp = { version = "0.11", default-features = false, features = ["std", "medium-ip", "proto-ipv4", "socket-tcp", "socket-udp"] }
ureq = { version = "2", features = ["json"] }
x25519-dalek = { version = "2", features = ["static_secrets"] }
base64 = "0.22"
rand = "0.8"
serde_json = "1"
```

Run: `cargo build` (downloads/compiles the trees; expect a few minutes). Expected: compiles (nothing uses them yet).

- [ ] **Step 2: Register the module**

`src/lib.rs`: add `pub mod wireguard;` and a doc line `//! - [\`wireguard\`]: embedded WireGuard route + WARP registration.`

- [ ] **Step 3: Write failing tests for the registration parser + key decode**

Create `tests/wireguard.rs`:

```rust
use browser_proxy::wireguard::parse_registration;

// A trimmed real-shape WARP /reg response.
const SAMPLE: &str = r#"{
  "config": {
    "interface": { "addresses": { "v4": "172.16.0.2", "v6": "2606:4700:110::2" } },
    "peers": [ { "public_key": "bm90YXJlYWxrZXlfMzJieXRlc19wYWRkaW5nISE=",
                 "endpoint": { "host": "engage.cloudflareclient.com:2408",
                               "v4": "162.159.192.1:2408" } } ]
  }
}"#;

#[test]
fn parses_peer_endpoint_and_address() {
    let p = parse_registration(SAMPLE).unwrap();
    assert_eq!(p.address_v4.to_string(), "172.16.0.2");
    assert_eq!(p.endpoint_hostport, "engage.cloudflareclient.com:2408");
    assert_eq!(p.peer_public_key_b64, "bm90YXJlYWxrZXlfMzJieXRlc19wYWRkaW5nISE=");
}

#[test]
fn rejects_garbage() {
    assert!(parse_registration("{}").is_err());
}
```

- [ ] **Step 4: Run to confirm failure**

Run: `cargo test --test wireguard`
Expected: FAIL — `parse_registration` not found.

- [ ] **Step 5: Implement registration parsing + `register_warp`**

Create `src/wireguard.rs` with the registration piece (tunnel added in Task 6–7):

```rust
//! Embedded WireGuard route: WARP registration + a userspace tunnel (boringtun + smoltcp) that
//! dials arbitrary TCP through the tunnel. The registration API is Cloudflare's unofficial
//! endpoint (same shape wgcf uses) and may change.

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;

use base64::Engine;
use serde::Deserialize;

/// The subset of the WARP registration response we need.
pub struct PartialWgConfig {
    pub peer_public_key_b64: String,
    pub endpoint_hostport: String,
    pub address_v4: Ipv4Addr,
}

#[derive(Deserialize)]
struct RegResp { config: RegConfig }
#[derive(Deserialize)]
struct RegConfig { interface: RegIface, peers: Vec<RegPeer> }
#[derive(Deserialize)]
struct RegIface { addresses: RegAddrs }
#[derive(Deserialize)]
struct RegAddrs { v4: String }
#[derive(Deserialize)]
struct RegPeer { public_key: String, endpoint: RegEndpoint }
#[derive(Deserialize)]
struct RegEndpoint { host: String }

/// Parse the WARP `/reg` JSON body into the fields we need.
pub fn parse_registration(json: &str) -> Result<PartialWgConfig, String> {
    let r: RegResp = serde_json::from_str(json).map_err(|e| format!("reg parse: {e}"))?;
    let peer = r.config.peers.into_iter().next().ok_or("reg: no peers")?;
    let address_v4 = r
        .config
        .interface
        .addresses
        .v4
        .parse()
        .map_err(|_| "reg: bad v4 address".to_string())?;
    Ok(PartialWgConfig {
        peer_public_key_b64: peer.public_key,
        endpoint_hostport: peer.endpoint.host,
        address_v4,
    })
}

/// Fully-resolved WireGuard parameters for a tunnel.
#[derive(Clone)]
pub struct WgConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub endpoint: SocketAddr,
    pub address_v4: Ipv4Addr,
}

pub fn decode_key_b64(s: &str) -> Result<[u8; 32], String> {
    let v = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| "invalid base64 key".to_string())?;
    v.try_into().map_err(|_| "key must be 32 bytes".to_string())
}

/// Register a new WARP account (or load a cached one) and return full WG parameters.
/// Blocking: called once at startup.
pub fn register_warp(cache_path: &Path) -> Result<WgConfig, String> {
    if let Ok(body) = std::fs::read_to_string(cache_path) {
        if let Ok(cfg) = load_cached(&body) {
            return Ok(cfg);
        }
    }
    // Generate our keypair.
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(public.as_bytes());

    let body = serde_json::json!({
        "key": pub_b64,
        "install_id": "",
        "fcm_token": "",
        "tos": "2020-01-01T00:00:00.000Z",
        "model": "PC",
        "type": "Android",
        "locale": "en_US"
    })
    .to_string();

    let resp = ureq::post("https://api.cloudflareclient.com/v0a2158/reg")
        .set("User-Agent", "okhttp/3.12.1")
        .set("CF-Client-Version", "a-6.11-2223")
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| format!("WARP registration failed: {e}"))?;
    let text = resp
        .into_string()
        .map_err(|e| format!("WARP registration read: {e}"))?;

    let partial = parse_registration(&text)?;
    let endpoint = partial
        .endpoint_hostport
        .to_socket_addrs()
        .map_err(|e| format!("endpoint resolve: {e}"))?
        .next()
        .ok_or("endpoint did not resolve")?;
    let cfg = WgConfig {
        private_key: secret.to_bytes(),
        peer_public_key: decode_key_b64(&partial.peer_public_key_b64)?,
        endpoint,
        address_v4: partial.address_v4,
    };
    // Cache (best-effort). Store keys base64 + endpoint + address.
    let cached = serde_json::json!({
        "private_key": base64::engine::general_purpose::STANDARD.encode(cfg.private_key),
        "peer_public_key": partial.peer_public_key_b64,
        "endpoint": cfg.endpoint.to_string(),
        "address_v4": cfg.address_v4.to_string(),
    })
    .to_string();
    write_cache(cache_path, &cached);
    Ok(cfg)
}

fn load_cached(body: &str) -> Result<WgConfig, String> {
    #[derive(Deserialize)]
    struct Cached { private_key: String, peer_public_key: String, endpoint: String, address_v4: String }
    let c: Cached = serde_json::from_str(body).map_err(|e| e.to_string())?;
    Ok(WgConfig {
        private_key: decode_key_b64(&c.private_key)?,
        peer_public_key: decode_key_b64(&c.peer_public_key)?,
        endpoint: c.endpoint.parse().map_err(|_| "cached endpoint".to_string())?,
        address_v4: c.address_v4.parse().map_err(|_| "cached v4".to_string())?,
    })
}

#[cfg(unix)]
fn write_cache(path: &Path, body: &str) {
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true).mode(0o600).open(path)
    {
        use std::io::Write;
        let _ = f.write_all(body.as_bytes());
    }
}
#[cfg(not(unix))]
fn write_cache(path: &Path, body: &str) {
    let _ = std::fs::write(path, body);
}
```

- [ ] **Step 6: Run + commit**

Run: `cargo test --test wireguard`
Expected: `parses_peer_endpoint_and_address` + `rejects_garbage` PASS.

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/wireguard.rs tests/wireguard.rs
git commit -m "feat(wg): WARP registration client + response parsing"
```

### Task 6: WireGuard tunnel driver + `WgStream`

**Files:**
- Modify: `src/wireguard.rs`

**Interfaces:**
- Produces:
  - `pub struct WgTunnel` with `pub async fn dial(&self, host: &str, port: u16) -> Result<WgStream, u8>`.
  - `pub struct WgStream` implementing `AsyncRead + AsyncWrite + Unpin + Send`.
  - `pub fn WgTunnel::spawn(cfg: WgConfig) -> Arc<WgTunnel>` — builds the tunnel and starts its driver task.

> This task is a cohesive low-level unit; its steps are coarser than elsewhere. Build against
> the verified boringtun 0.7 API: `Tunn::new(StaticSecret, PublicKey, None, Some(keepalive), index, None)`,
> `encapsulate(src,dst)`/`decapsulate(Option<IpAddr>,datagram,dst)`/`update_timers(dst)` →
> `TunnResult::{Done, Err, WriteToNetwork(buf), WriteToTunnelV4(buf,ip), WriteToTunnelV6(buf,ip)}`.

- [ ] **Step 1: Model the driver and channels**

Add to `src/wireguard.rs`. The driver owns the UDP socket, `Tunn`, and a `smoltcp` `Interface` +
`SocketSet`. Streams talk to it via commands. Sketch the types:

```rust
use std::collections::HashMap;
use std::sync::Arc;
use std::net::IpAddr;

use boringtun::noise::{Tunn, TunnResult};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

const WG_MTU: usize = 1280;

/// A command sent from a stream/dialer to the tunnel driver.
enum Cmd {
    Dial { ip: IpAddr, port: u16, reply: oneshot::Sender<Result<WgStream, u8>> },
}

pub struct WgTunnel {
    cmd_tx: mpsc::Sender<Cmd>,
    /// DNS resolver over the tunnel (1.1.1.1). Set once the tunnel is up.
    address_v4: std::net::Ipv4Addr,
}
```

- [ ] **Step 2: Implement `spawn` + the driver loop**

The driver runs three concurrent concerns in a `tokio::select!`:
1. **UDP → tunnel:** `recv` an encrypted datagram, `tunn.decapsulate(None, &pkt, &mut buf)`,
   feed the resulting IP packet into smoltcp's device RX queue; then `iface.poll(...)`.
2. **smoltcp → UDP:** drain smoltcp's device TX queue, `tunn.encapsulate(&ip_pkt, &mut buf)`,
   and on `WriteToNetwork` `udp.send(...)` to the endpoint.
3. **Timers:** a 250 ms interval calling `tunn.update_timers(&mut buf)` and sending any
   `WriteToNetwork` output (handshake init / keepalive).
4. **Commands:** on `Cmd::Dial`, allocate a smoltcp `tcp::Socket`, `connect(dst, ephemeral)`,
   register it in the `SocketSet`, and hand back a `WgStream` bound to that socket handle.

Use smoltcp's in-memory device: a custom `Device` whose RX/TX are `VecDeque<Vec<u8>>`, so the
driver moves packets between boringtun and smoltcp without a real OS interface. `WgStream`
read/write are channels to the driver, which copies between the channel and the smoltcp socket
buffers on each `poll`.

Concretely define `WgStream` as two channels + a handle:

```rust
pub struct WgStream {
    to_tunnel: mpsc::Sender<Vec<u8>>,    // bytes we write → smoltcp socket tx
    from_tunnel: mpsc::Receiver<Vec<u8>>, // smoltcp socket rx → we read
    read_buf: Vec<u8>,
}
```

Implement `AsyncRead`/`AsyncWrite` for `WgStream` over those channels (same delegating pattern
as `Conn`, but backed by `mpsc`). The driver, whenever a smoltcp socket `can_recv`, reads into
a `Vec` and sends on that socket's `from_tunnel`; whenever `to_tunnel` has bytes and the socket
`can_send`, it writes them into the socket.

> Implementation note for the executor: this is the part to iterate on with the compiler and
> a real endpoint. Keep each smoltcp poll driven by (a) inbound UDP, (b) outbound data, and
> (c) the timer tick, and re-poll after every state change. Reference onetun's
> `wg.rs`/`tunnel.rs` structure for the boringtun↔smoltcp packet shuttle if stuck.

- [ ] **Step 3: Implement `dial` with DNS-over-tunnel**

```rust
impl WgTunnel {
    pub async fn dial(&self, host: &str, port: u16) -> Result<WgStream, u8> {
        let ip = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => self.resolve(host).await?, // DNS via 1.1.1.1 inside the tunnel
        };
        let (reply, rx) = oneshot::channel();
        self.cmd_tx.send(Cmd::Dial { ip, port, reply })
            .await.map_err(|_| crate::wisp::R_UNREACHABLE)?;
        rx.await.map_err(|_| crate::wisp::R_UNREACHABLE)?
    }

    /// Resolve a hostname by sending a DNS A query to 1.1.1.1 through the tunnel.
    async fn resolve(&self, host: &str) -> Result<IpAddr, u8> {
        // Open a UDP-like flow to 1.1.1.1:53 through the tunnel, send a minimal A query,
        // parse the first A record. (Encode/decode covered by unit tests.)
        // Returns R_UNREACHABLE on any failure.
        resolve_via_tunnel(&self.cmd_tx, host).await
    }
}
```

Add `dns_query(host) -> Vec<u8>` and `dns_first_a(resp) -> Option<Ipv4Addr>` as pure helpers
(unit-tested in Task 7).

- [ ] **Step 4: Build**

Run: `cargo build`
Expected: compiles. (Behavior is exercised by the ignored e2e test in Task 7.)

- [ ] **Step 5: Commit**

```bash
git add src/wireguard.rs
git commit -m "feat(wg): boringtun+smoltcp tunnel driver, dial, WgStream"
```

### Task 7: Wire `Route::Wireguard`, DNS unit tests, and the ignored e2e

**Files:**
- Modify: `src/route.rs` (add `Wireguard` arm + `Conn::Wg`), `src/config.rs`/`src/route.rs` (build tunnels from specs), `tests/wireguard.rs`

**Interfaces:**
- Consumes: `WgTunnel::spawn`, `WgTunnel::dial`, `register_warp`, `decode_key_b64`.

- [ ] **Step 1: Add `Conn::Wg` and the `Wireguard` route arm**

In `src/route.rs`:

```rust
pub enum Route {
    Direct,
    Socks5 { addr: SocketAddr, auth: Option<(String, String)> },
    Http { addr: SocketAddr, auth: Option<(String, String)> },
    Wireguard(std::sync::Arc<crate::wireguard::WgTunnel>),
}
```

Add the `Conn::Wg` variant and its match arms in all four `AsyncRead`/`AsyncWrite` methods:

```rust
pub enum Conn {
    Tcp(TcpStream),
    Wg(crate::wireguard::WgStream),
}
// ... add `Conn::Wg(s) => Pin::new(s).poll_read(cx, buf),` etc. to each method.
```

Add the connect arm:

```rust
            Route::Wireguard(tunnel) => tunnel.dial(host, port).await.map(Conn::Wg),
```

`Route` no longer derives `Clone` (WgTunnel is shared by `Arc`, and the whole `Route` is looked
up and `Arc`-wrapped in `server.rs`). Change `server.rs`'s `Arc::new(r.clone())` to clone via a
match, OR wrap routes in `Arc` at construction. Simplest: store `HashMap<String, Arc<Route>>` in
`Config`. Update `Config.routes` type to `HashMap<String, Arc<Route>>`, `direct_routes` and
`routes_from_yaml` to insert `Arc::new(...)`, and `server.rs` to `state.cfg.routes.get(name).cloned()`
(cloning the `Arc`, not the `Route`). Remove `#[derive(Clone, Debug)]` from `Route`.

- [ ] **Step 2: Build tunnels from WireGuard/Warp specs**

In `routes_from_yaml`, replace the Phase-1 error arm:

```rust
            RouteSpec::Wireguard { private_key, peer_public_key, endpoint, address, name } => {
                let cfg = crate::wireguard::WgConfig {
                    private_key: crate::wireguard::decode_key_b64(&private_key)
                        .map_err(|e| format!("wireguard route {name:?}: {e}"))?,
                    peer_public_key: crate::wireguard::decode_key_b64(&peer_public_key)
                        .map_err(|e| format!("wireguard route {name:?}: {e}"))?,
                    endpoint: endpoint.to_socket_addrs()
                        .map_err(|_| format!("wireguard route {name:?}: bad endpoint"))?
                        .next().ok_or(format!("wireguard route {name:?}: endpoint unresolved"))?,
                    address_v4: address.split('/').next().unwrap_or(&address)
                        .parse().map_err(|_| format!("wireguard route {name:?}: bad address"))?,
                };
                Route::Wireguard(crate::wireguard::WgTunnel::spawn(cfg))
            }
            RouteSpec::Warp { name } => {
                let cache = std::path::Path::new(&format!("warp-{name}.json")).to_path_buf();
                let cfg = crate::wireguard::register_warp(&cache)
                    .map_err(|e| format!("warp route {name:?}: {e}"))?;
                Route::Wireguard(crate::wireguard::WgTunnel::spawn(cfg))
            }
```

Add `use std::net::ToSocketAddrs;` to `route.rs`. Note: `routes_from_yaml` becomes effectively
blocking (registration + tunnel spawn). Since it runs once at startup inside `from_env` before
the server loop, that is acceptable; `WgTunnel::spawn` starts its own tokio task via
`tokio::spawn`, so it must be called from within the tokio runtime (it is — `main` is
`#[tokio::main]` and `from_env` runs inside it). Confirm `from_env` is called after the runtime
starts (it is, in `main`).

- [ ] **Step 3: DNS helper unit tests**

Add to `tests/wireguard.rs` (helpers must be `pub` in `wireguard.rs`):

```rust
use browser_proxy::wireguard::{dns_query, dns_first_a};

#[test]
fn dns_query_is_well_formed() {
    let q = dns_query("example.com");
    assert_eq!(&q[2..4], &[0x01, 0x00]); // standard query, RD=1
    assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT=1
    // QNAME ends with a zero label; QTYPE=A(1), QCLASS=IN(1)
    assert_eq!(&q[q.len() - 4..], &[0x00, 0x01, 0x00, 0x01]);
}

#[test]
fn dns_parses_an_a_record() {
    // Minimal response: echo the query header with 1 answer of type A → 93.184.216.34.
    let q = dns_query("example.com");
    let mut resp = q.clone();
    resp[2] = 0x81; resp[3] = 0x80; // QR=1, RA
    resp[6] = 0x00; resp[7] = 0x01; // ANCOUNT=1
    resp.extend_from_slice(&[0xc0, 0x0c]); // name ptr
    resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL
    resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
    resp.extend_from_slice(&[93, 184, 216, 34]);
    assert_eq!(dns_first_a(&resp).unwrap().to_string(), "93.184.216.34");
}
```

Implement `dns_query`/`dns_first_a` in `wireguard.rs` (standard DNS wire format; ~40 lines) and
make them `pub`.

- [ ] **Step 4: Ignored real-WARP end-to-end test**

Add to `tests/wireguard.rs`:

```rust
// Registers with the real Cloudflare WARP API and fetches a page through the tunnel. Needs
// internet and may hit rate limits. Run with: cargo test --test wireguard -- --ignored
#[tokio::test]
#[ignore]
async fn warp_end_to_end() {
    use browser_proxy::config::Config;
    use browser_proxy::route::routes_from_yaml;
    use browser_proxy::server::build_router;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::Arc;
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    let yaml = "routes:\n  - name: warp\n    type: warp\n";
    let cfg = Config { routes: routes_from_yaml(yaml).unwrap(), ..Default::default() };
    let app = build_router(Arc::new(cfg), "static");
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap(); });

    let url = format!("ws://127.0.0.1:{port}/wisp/?route=warp");
    let (mut ws, _) = connect_async(url.as_str()).await.unwrap();
    let _ = ws.next().await.unwrap().unwrap(); // handshake CONTINUE

    // CONNECT example.com:80 and send a GET; expect an HTTP status line back.
    let mut cp = vec![0x01u8]; cp.extend_from_slice(&1u32.to_le_bytes()); cp.push(0x01);
    cp.extend_from_slice(&80u16.to_le_bytes()); cp.extend_from_slice(b"example.com");
    ws.send(Message::Binary(cp)).await.unwrap();
    let req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let mut dp = vec![0x02u8]; dp.extend_from_slice(&1u32.to_le_bytes()); dp.extend_from_slice(req.as_bytes());
    ws.send(Message::Binary(dp)).await.unwrap();

    let mut body = Vec::new();
    while let Some(Ok(Message::Binary(f))) = ws.next().await {
        if f[0] == 0x02 { body.extend_from_slice(&f[5..]); }
        if f[0] == 0x04 { break; }
        if body.windows(8).any(|w| w == b"HTTP/1.1") { break; }
    }
    assert!(String::from_utf8_lossy(&body).contains("HTTP/1.1"));
}
```

- [ ] **Step 5: Build + unit tests + commit**

Run: `cargo test` (runs unit + non-ignored integration; the WARP e2e stays ignored).
Expected: PASS. Then, if network is available: `cargo test --test wireguard -- --ignored` to
exercise the real tunnel; record the observed result.

```bash
git add src/route.rs src/config.rs tests/wireguard.rs
git commit -m "feat(wg): Route::Wireguard + Conn::Wg; DNS-over-tunnel; ignored e2e"
```

---

## Phase 5 — Docs + verification

### Task 8: README + final verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the `ROUTES` row and rewrite the VPN section**

In `README.md` config table, replace the `ROUTES` row with:

```markdown
| `CONFIG` | `config.yaml` | Path to the YAML route config (see below). Absent default file → `direct` only; a malformed config aborts startup. |
```

Replace the "Routing through a VPN" section with one documenting the YAML file, the four route
types (`socks5`, `http`, `wireguard`, `warp`), the `warp-<name>.json` credential cache, the
in-process-registration caveat (unofficial API), and the dependency-growth note. Reuse the
fail-closed and DNS paragraphs from v1. Point at `config.example.yaml`.

- [ ] **Step 2: Full verification**

Run:
```bash
cargo test
cargo clippy --all-targets -- -D warnings
node --check static/index.js
```
Expected: tests PASS, clippy clean, JS OK. Fix warnings inline.

- [ ] **Step 3: Browser check**

With a config that defines `warp`, `tor`, `corp`, start the server, open the UI, confirm: the
center landing dropdown and the top-bar select both list the routes and stay in sync; both
hide when the config is direct-only.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: YAML config, route types, embedded WARP"
```

---

## Self-Review Notes

- **Spec coverage:** YAML config + drop ROUTES (Task 1); HTTP proxy + Conn (Tasks 2–3);
  center dropdown synced (Task 4); deps + WARP registration + cache (Task 5); tunnel driver +
  dial + DNS-over-tunnel (Task 6); `Route::Wireguard`/`Conn::Wg` + DNS units + ignored e2e
  (Task 7); README incl. cache file + dependency note + registration caveat (Task 8).
  Security: `0600` cache perms (Task 5), no-secrets-in-logs preserved (no code logs keys),
  block_private semantics unchanged (documented, v1).
- **Types:** `Route::connect -> Result<Conn, u8>`; `Conn { Tcp, Wg }`; `WgTunnel::spawn(WgConfig)
  -> Arc<WgTunnel>`, `WgTunnel::dial -> Result<WgStream, u8>`; `register_warp(&Path) ->
  Result<WgConfig, String>`; `routes_from_yaml(&str) -> Result<HashMap<String, Arc<Route>>, String>`
  (Arc introduced in Task 7 — Tasks 1–6 use `HashMap<String, Route>` and Task 7 migrates it;
  the migration is called out in Task 7 Step 1).
- **Known iteration risk:** Task 6 (boringtun+smoltcp shuttle) is the one place exact code will
  need compiler/endpoint iteration; its interfaces are fixed so surrounding tasks are stable.
- **Ordering:** Phases 1–3 are independently shippable and verifiable without any WireGuard
  code; Phase 4 is additive.
```
