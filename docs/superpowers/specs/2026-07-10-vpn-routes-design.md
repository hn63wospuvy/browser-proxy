# VPN Routes — Design Spec

Date: 2026-07-10

## Goal

Let the user choose, from the frontend, whether outbound TCP streams leave the server
**directly** or through a **VPN** (initially Cloudflare WARP), so target sites see the VPN's
IP instead of the server's. The mechanism must generalize to other VPNs (Tor, OpenVPN,
commercial providers) without a rewrite.

## Key decisions (from brainstorming)

- **Upstream SOCKS5, not an embedded tunnel.** Every VPN can expose a SOCKS5 endpoint; not
  every VPN can be embedded. WARP does it with `warp-cli mode proxy` (listens on
  `127.0.0.1:40000` by default and, crucially, does *not* touch the host routing table).
  Tor does it natively on `127.0.0.1:9050`. OpenVPN does not expose SOCKS itself — the
  standard pattern is to run it in a network namespace with a SOCKS server inside (what
  `gluetun` does) — but the result our server consumes is still just a SOCKS5 address.

  Embedding WireGuard in-process (`boringtun` + `smoltcp` + the unofficial WARP registration
  API, à la `onetun`/`wgcf`) was rejected as the *first* implementation: it speaks only
  WireGuard, so it does nothing for the stated OpenVPN goal, and it would add a userspace
  TCP/IP stack plus several dependencies to a `Cargo.toml` that currently has eight.

  Binding the socket to the WARP interface was rejected outright: WARP's default full-tunnel
  mode captures the routing table, so the `direct` branch would *also* go through WARP,
  defeating the toggle.

- **`enum Route`, not `trait Dialer`.** A trait object needs `dyn`, and `async fn` in traits
  is not `dyn`-compatible, so it would pull in `async-trait` or hand-boxed futures. There
  will only ever be two or three dial strategies and all live in this source tree, so
  dynamic dispatch buys nothing. The extension point is preserved either way.

- **Per-connection selection via query param.** `wss://host/wisp/?route=warp`. No new Wisp
  packet type, no protocol change. Matches the fact that bare-mux holds exactly one
  WebSocket.

- **Fail closed, never fall back to `direct`.** A user who believes they are on a VPN while
  their traffic goes out directly is the worst failure this feature can produce.

## Architecture

```
UI <select>  →  /wisp/?route=warp
                     │
                     ▼
              server.rs: ws_handler
                cfg.routes.get("warp")  ──miss──▶ 400, no upgrade
                     │ hit
                     ▼
              wisp.rs: handle_connection(socket, cfg, Arc<Route>)
                     │
                     ▼
              wisp.rs: run_stream  →  route.connect(host, port, &cfg)
                     │
       ┌─────────────┴──────────────┐
       ▼                            ▼
  Route::Direct               Route::Socks5
  lookup_host +               TcpStream::connect(proxy)
  TcpStream::connect          + RFC 1928 handshake
  (today's connect_target)    (hostname passed through → remote DNS)
```

Future `Route::Wireguard(Arc<WgTunnel>)` slots in as another variant; nothing else changes.

## Components

### `src/route.rs` (new, ~200 lines)

```rust
pub enum Route {
    Direct,
    Socks5 { addr: SocketAddr, auth: Option<(String, String)> },
}

impl Route {
    pub async fn connect(&self, host: &str, port: u16, cfg: &Config)
        -> Result<TcpStream, u8>;   // Err = Wisp close reason
}

pub fn parse_routes(spec: &str) -> Result<HashMap<String, Route>, String>;
```

Holds the `enum`, the SOCKS5 client, the `ROUTES` parser, and their unit tests. Kept out of
`wisp.rs` (already 522 lines) and out of `config.rs` (which stays about configuration).

### Configuration

New env var, parsed by `parse_routes`:

```
ROUTES=warp=socks5://127.0.0.1:40000,tor=socks5://127.0.0.1:9050
```

Grammar: `name=socks5://[user:pass@]host:port`, comma-separated. `Config` gains
`routes: HashMap<String, Route>`.

- `direct` always exists implicitly and **cannot be overridden**.
- Invalid syntax, unknown scheme, duplicate name, or a bad port is a **startup error** — the
  server refuses to boot. A misconfigured VPN that still serves traffic is the failure mode
  we are specifically avoiding.

  Concretely: `Config::from_env()` changes signature to `Result<Config, String>`, and
  `main.rs` prints the error and exits non-zero. Every other env var keeps today's
  warn-and-use-default behavior; only `ROUTES` is fatal, because it is the only one whose
  silent fallback has a security consequence.
- Credentials are never logged.

### Route selection (`src/server.rs`)

`ws_handler` reads `?route=<name>`:

| Case | Behavior |
|---|---|
| absent | `direct` |
| present, known | that route |
| present, unknown | **400, no WebSocket upgrade** |

A dead proxy surfaces as `CLOSE(R_UNREACHABLE)` on the stream. Under no circumstances does a
`warp` request silently traverse `direct`.

New endpoint `GET /routes.json` → `{"routes":["direct","warp","tor"]}`. Required because
`static/` is served verbatim by `ServeDir` and cannot be templated.

### SOCKS5 client (RFC 1928)

1. TCP connect to the proxy.
2. Greeting `05 | nmethods | methods` — `05 01 00` with no auth, `05 02 00 02` with
   credentials.
3. Method reply `05 METHOD`. `00` done; `02` → RFC 1929 sub-negotiation
   (`01 | ulen | user | plen | pass`); `FF` → `R_BLOCKED`.
4. Request `05 01 00 | ATYP | DST.ADDR | DST.PORT`.
5. Reply `05 | REP | 00 | ATYP | BND.ADDR | BND.PORT`.

Three details that are easy to get wrong and are called out here deliberately:

- **`BND.ADDR` is variable length** (4, 16, or `1+len` bytes) and must be fully consumed.
  Leftover bytes would bleed into the stream's payload and corrupt the first response — a
  silent, hard-to-trace failure. The reply is at most 262 bytes; use a fixed small buffer.
- **SOCKS ports are big-endian**, whereas Wisp is little-endian
  (`src/wisp.rs`, `parse_packet`). Both byte orders appear in the same file.
- **If `host` parses as an IP literal, use `ATYP=01`/`04`**, not `ATYP=03`. Sending
  `"1.2.3.4"` as a domain name makes the proxy resolve a numeric "hostname".

When `host` *is* a domain, it is passed through as `ATYP=03` so the **proxy resolves it**.
No DNS query leaves this machine on a SOCKS route.

The **entire handshake** is wrapped in one `tokio::time::timeout(cfg.connect_timeout, …)`,
not just the TCP connect. A proxy that accepts the connection and then goes silent would
otherwise hang the stream task forever.

`REP` → Wisp close reason:

| REP | Meaning | Wisp |
|---|---|---|
| `00` | succeeded | — |
| `01` | general SOCKS server failure | `R_UNREACHABLE` |
| `02` | connection not allowed by ruleset | `R_BLOCKED` |
| `03` | network unreachable | `R_UNREACHABLE` |
| `04` | host unreachable | `R_UNREACHABLE` |
| `05` | connection refused | `R_REFUSED` |
| `06` | TTL expired | `R_TIMEOUT` |
| `07` | command not supported | `R_INVALID` |
| `08` | address type not supported | `R_INVALID` |

`set_nodelay(true)` after the handshake, matching the direct path.

## Security

`host_blacklist` is unchanged: it matches on the hostname before dialing, on every route.

`block_private` behaves differently per route, by design:

| Route | `host` | Behavior |
|---|---|---|
| `direct` | any | unchanged — resolve, then filter private IPs |
| `socks5` | IP literal | `is_private_ip` checked directly |
| `socks5` | domain | **not checked** |

Resolving a domain purely to check it would destroy the DNS-leak resistance above, and the
check would not bind anything anyway: our lookup and the proxy's lookup are two separate
resolutions (TOCTOU). The residual exposure is narrow — the connection originates from the
VPN's network, not ours, so it cannot reach our `192.168.0.0/16` or `169.254.169.254`. The
IP-literal check remains as defense in depth, not as the primary barrier.

This trade-off is documented in the README, not buried in code.

The proxy's own address (e.g. `127.0.0.1:40000`) is **exempt** from `block_private`: it
comes from operator configuration, not from an attacker-controlled CONNECT.

## Frontend

`static/index.html` gains a `<select id="route">` beside the URL box, populated from
`/routes.json`, hidden entirely when only `direct` exists. The selection persists in
`localStorage`. `wispUrl()` (`static/index.js`) appends `?route=<name>`.

Changing the route calls `connection.setTransport("/libcurl/index.mjs", [{ websocket: wispUrl() }])`,
which **rebuilds the transport inside the bare-mux SharedWorker**, killing the live
WebSocket and every stream on it. The handler therefore re-navigates the frame to the current
URL. This is required behavior, not incidental.

### Known limitation: SharedWorker is per-origin, not per-tab

bare-mux runs its transport in a SharedWorker shared by all tabs of the origin. With two
tabs open, the last `setTransport` wins for *both* — tab A on `warp` and tab B on `direct`
end up on whichever route was selected last, silently. This is pre-existing bare-mux
behavior that the dropdown merely exposes.

Within the "personal / small internal use" scope the README already declares, this is
**documented rather than engineered around**. Coordinating routes across tabs would require
per-tab transports and is out of scope.

## Testing

Unit (`src/route.rs`):

- `parse_routes`: valid spec; with credentials; unknown scheme; duplicate name; `direct`
  reserved; malformed port.
- Request encoding: `ATYP=03` for domains, `01`/`04` for IP literals, big-endian port.
- Reply parsing: consumes `BND.ADDR` correctly for all three `ATYP` values; full `REP` →
  close-reason table.

Integration (`tests/`, following the existing `wisp_integration.rs` shape, which already
stands up a local TCP echo server):

- Fake SOCKS5 server in-test → handshake → connects to the echo server. A Wisp CONNECT over
  `?route=test` round-trips bytes intact.
- `?route=nonexistent` → 400, no upgrade.
- Fake proxy replies `REP=05` → client observes `CLOSE(R_REFUSED)`.
- Fake proxy accepts TCP then goes silent → the stream closes within `connect_timeout`.
  This is the regression test for the "timeout wraps only the connect" trap above.

## Files touched

| File | Change |
|---|---|
| `src/route.rs` | **new** — `Route`, SOCKS5 client, `parse_routes`, unit tests |
| `src/config.rs` | `routes` field; delegates to `route::parse_routes` |
| `src/wisp.rs` | `connect_target` becomes the `Route::Direct` arm; `handle_connection`/`run_stream` take `Arc<Route>` |
| `src/server.rs` | `?route=` extraction, 400 on unknown, `GET /routes.json` |
| `static/index.html`, `index.js`, `style.css` | route dropdown |
| `README.md` | `ROUTES` row; "Routing through a VPN" section; both limitations above |
| `tests/` | integration tests listed above |

## Out of scope

- Embedded WireGuard (`Route::Wireguard`). Adds as a variant later without disturbing this
  design; deferred because it does not advance the multi-VPN goal.
- Per-domain split tunneling (a rule engine choosing a route at CONNECT time).
- Per-tab route isolation (see the SharedWorker limitation).
- UDP / QUIC, which the Wisp server already refuses.
