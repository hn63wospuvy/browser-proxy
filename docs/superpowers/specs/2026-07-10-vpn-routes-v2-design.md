# VPN Routes v2 — Design Spec

Date: 2026-07-10

Builds on [2026-07-10-vpn-routes-design.md](2026-07-10-vpn-routes-design.md) (the SOCKS5
`enum Route` foundation, already implemented). This spec extends it with a YAML config file,
an HTTP-proxy route type, an **embedded WireGuard route** (with in-process WARP registration),
and a center-of-page route dropdown.

## Goal

- Configure routes from a **YAML file** instead of the `ROUTES` env var.
- Add an **HTTP proxy** route type (HTTP CONNECT).
- Add an **embedded WireGuard** route type so a route can tunnel through WARP with the server
  as a single binary — no `warp-cli`/`wireproxy` sidecar. `type: warp` registers a WARP
  account in-process; `type: wireguard` uses a config the operator supplies.
- Move the route **dropdown to the center of the page** (on the landing), keeping a small
  top-bar selector for switching mid-browse.

## Key decisions (from brainstorming)

- **onetun does not fit and is not used.** onetun forwards statically-configured `local:remote`
  pairs; it has no dynamic per-connection destination (its README suggests chaining a separate
  SOCKS server for that), and it has no WARP support. So "embed onetun" cannot give a proxy
  that reaches arbitrary sites through WARP. There is also no ready-made Rust crate exposing
  "dial arbitrary TCP through a WireGuard tunnel" — `boringtun` implements only the WireGuard
  Noise protocol (no network stack), and onetun/wireproxy implement the pattern internally as
  binaries. The embedded route therefore reimplements that core: `boringtun` + `smoltcp`.

- **In-process WARP registration** (`type: warp`), accepted with its risk: the Cloudflare
  registration API is unofficial and can change. Credentials are cached to disk so we register
  once, not every boot.

- **YAML via `serde_yaml_ng`.** The original `serde_yaml` is archived; `serde_yaml_ng` is the
  maintained community fork.

- **`enum Conn { Tcp, Wg }`** as the connection type, not `Box<dyn AsyncRead+AsyncWrite>` —
  keeps the hot path free of dynamic dispatch. Only WireGuard yields `Wg`.

- **Dependency growth is real and inherent** to embedded WARP: ~8 → ~15+ direct crates
  (`serde`, `serde_yaml_ng`, `serde_json`, `boringtun`, `smoltcp`, `ureq`, `x25519-dalek`,
  `base64`, `rand`). Documented, not hidden.

## Architecture

```
config.yaml ──serde──▶ Vec<RouteSpec> ──▶ HashMap<String, Route>
                                              │
   Route::Direct / Socks5 / Http  ───────────┤ connect() → Conn::Tcp(TcpStream)
   Route::Wireguard(Arc<WgTunnel>) ──────────┘ connect() → Conn::Wg(WgStream)
                                              │
                              wisp::run_stream splits Conn and relays both ways
```

`Route::connect` return type changes from `Result<TcpStream, u8>` to `Result<Conn, u8>`.

## Configuration

`Config` loads routes from a YAML file:

- Path from env `CONFIG`; if unset, try `./config.yaml`; if absent, routes = `{direct}` only.
- Parse failure (missing field, unknown `type`, bad key, duplicate/`direct` name) is **fatal**
  (`from_env` already returns `Result`, extended to load+parse the file).
- The `ROUTES` env var is **removed** (same-day, unreleased; replaced cleanly by the file).
  All other env vars are unchanged.

Schema:

```yaml
routes:
  - name: warp
    type: warp                 # WireGuard + in-process WARP registration
  - name: myvpn
    type: wireguard            # generic WireGuard, operator-supplied config
    private_key: "<base64>"
    peer_public_key: "<base64>"
    endpoint: "engage.cloudflareclient.com:2408"
    address: "172.16.0.2/32"   # assigned client address; /32 or with a v6 too
  - name: tor
    type: socks5
    address: "127.0.0.1:9050"
  - name: corp
    type: http
    address: "127.0.0.1:8080"
    username: "u"              # optional
    password: "p"             # optional
```

Deserialized with `#[serde(tag = "type", rename_all = "lowercase")]` into a `RouteSpec` enum,
then converted to the runtime `Route`. `direct` is implicit, reserved, non-overridable.
Credentials / keys are never logged.

## Components

### `enum Route` (extended, `src/route.rs`)

```rust
pub enum Route {
    Direct,
    Socks5 { addr: SocketAddr, auth: Option<(String, String)> },
    Http   { addr: SocketAddr, auth: Option<(String, String)> },
    Wireguard(Arc<WgTunnel>),
}
```

`Wireguard` holds an `Arc` to a shared, long-lived tunnel (one per WireGuard route, not per
stream). `Route` can no longer derive `Clone` cheaply for the tunnel — it holds `Arc<WgTunnel>`,
which is `Clone`, so the derive still holds.

### `enum Conn` (new, `src/route.rs`)

```rust
pub enum Conn { Tcp(tokio::net::TcpStream), Wg(WgStream) }
```

Implements `AsyncRead + AsyncWrite` by delegating to the active variant. `run_stream` uses
`tokio::io::split(conn)` instead of `TcpStream::into_split()`.

### HTTP proxy arm (`src/route.rs`)

HTTP CONNECT, ~60 lines, no new dependency:

```
CONNECT host:port HTTP/1.1
Host: host:port
Proxy-Authorization: Basic <base64(user:pass)>   (when auth present)
<blank line>
```

Read the status line; `200` → the socket is now a tunnel, return `Conn::Tcp`. Status → Wisp
close reason: `407`/`403` → `R_BLOCKED`, `502`/`504` → `R_UNREACHABLE`, other `4xx`/`5xx` →
`R_UNREACHABLE`. The whole handshake is wrapped in `connect_timeout` (same lesson as SOCKS).
The hostname is sent verbatim so the proxy resolves it — no DNS leaves this host.

### Embedded WireGuard (`src/wireguard.rs`, new)

Three sub-parts.

**1. WARP registration client.** On startup, for a `type: warp` route with no cached
credentials: generate an x25519 keypair, `POST https://api.cloudflareclient.com/v0a2158/reg`
with the public key, a generated install id, and the `User-Agent` / `CF-Client-Version`
headers wgcf uses. Parse the response for the peer public key, endpoint
(`engage.cloudflareclient.com:2408`), and assigned client addresses (v4/v6). HTTP via `ureq`
(light, blocking, rustls) — this is a one-shot startup call. **Cache** the resulting WireGuard
config to disk next to `config.yaml` (e.g. `warp-<name>.json`) and load from cache on
subsequent boots; Cloudflare rate-limits registration.

**2. Tunnel driver.** One background task per WireGuard route owns, with no locks (single
owner):
- a tokio UDP socket to the WG endpoint,
- a `boringtun` `Tunn` (handshake, encrypt/decrypt, keepalive/timers),
- a `smoltcp` `Interface` + `SocketSet`.

Loop: UDP datagram in → `Tunn::decapsulate` → feed smoltcp; smoltcp egress → `Tunn::encapsulate`
→ UDP out; drive boringtun's timers for keepalive/rekey. MTU is pinned to WARP's **1280**.

**3. Dynamic dial + DNS.** `WgTunnel::dial(host, port)` creates a smoltcp TCP socket to the
target and returns a `WgStream` (a duplex handle over channels to the driver). Hostname targets
are resolved via **1.1.1.1 inside the tunnel** (a minimal DNS-over-UDP query through smoltcp),
never the OS resolver — no DNS leak, correct routing.

`Route::Wireguard(tunnel).connect(host, port)` → `tunnel.dial(host, port)` → `Conn::Wg(stream)`.

### Route selection / server

Unchanged from v1: `?route=<name>` maps to a `Route`, unknown → 400, `/routes.json` lists
names. `handle_connection`/`run_stream` already take `Arc<Route>`; only the connection type
(`Conn`) and the split call change.

## Frontend

- A prominent route `<select>` in the center **landing** section (below the subtitle),
  populated from `/routes.json`, shown only when a non-`direct` route exists.
- The existing small top-bar `<select>` stays, for switching mid-browse (landing is hidden
  while browsing).
- Both bind one state: changing either updates the other + `localStorage`, and while browsing
  triggers the transport rebuild + frame reload (the v1 logic). `wispUrl()` appends
  `?route=`, unchanged.

## Security

- `block_private`: unchanged for `direct`; on `socks5`/`http` the hostname is proxy-resolved
  and not checked here (documented in v1); on `wireguard` the target is resolved *inside the
  tunnel* and connections originate from the tunnel, so the local SSRF surface does not apply.
- Cached WARP credentials contain a private key — written with `0600` perms where the OS
  supports it; the cache path is documented.
- Registration and config keys are never logged.

## Testing

- **Config:** parse each `type`; missing field / unknown type / `direct` reserved / duplicate
  name → error; env `CONFIG` override; absent file → direct only.
- **HTTP proxy:** unit-test the CONNECT request bytes (request line, `Host`, optional
  `Proxy-Authorization`) and status parsing; integration test with a fake HTTP-CONNECT proxy
  relaying to the echo server (mirrors `tests/socks_routing.rs`).
- **WireGuard:** unit-test the registration-response parser against a captured/mocked JSON
  body; unit-test the DNS query encoder. A full tunnel needs a real peer, so an end-to-end
  test that registers with real WARP and fetches a page is `#[ignore]` (network, like
  `wisp_relays_real_http`).
- **Frontend:** `node --check`; browser check that both dropdowns stay in sync.

## Files touched

| File | Change |
|---|---|
| `src/route.rs` | `Http` + `Wireguard` arms; `enum Conn`; `Route::connect -> Result<Conn, u8>` |
| `src/wireguard.rs` | **new** — WARP registration, tunnel driver, dial, DNS-over-tunnel |
| `src/config.rs` | load + parse `config.yaml`; drop `ROUTES` env; `RouteSpec` serde types |
| `src/wisp.rs` | `run_stream` splits `Conn` instead of `TcpStream` |
| `src/server.rs` | unchanged logic; `/routes.json` as-is |
| `Cargo.toml` | add `serde`, `serde_yaml_ng`, `serde_json`, `boringtun`, `smoltcp`, `ureq`, `x25519-dalek`, `base64`, `rand` |
| `static/index.html`, `index.js`, `style.css` | center landing dropdown + synced top-bar select |
| `README.md` | YAML config, route types, embedded WARP, cache file, dependency note |
| `tests/http_routing.rs` | **new** — fake HTTP-CONNECT proxy integration |
| `tests/wireguard.rs` | **new** — registration parse + DNS encode units; `#[ignore]` real-WARP e2e |

## Out of scope

- Per-domain split tunneling; per-tab route isolation (bare-mux SharedWorker limitation, v1).
- UDP/QUIC (Wisp server refuses it).
- `type: tcp` "TCP proxy" — dropped in brainstorming (a plain TCP proxy carries no destination).

## Risk note

The embedded WireGuard route is the highest-risk part: the WARP registration API is unofficial,
and boringtun+smoltcp is low-level network code with easy mistakes (MTU 1280, handshake,
timers). It is isolated in `src/wireguard.rs` and is the last thing implemented, so the rest of
the spec ships and is verifiable independently even though this is a single combined spec.
