# Built-in Tor Route — Design Spec

Date: 2026-07-11

Builds on [2026-07-10-vpn-routes-v2-design.md](2026-07-10-vpn-routes-v2-design.md) (the
`enum Route` / `enum Conn` foundation with embedded WireGuard/WARP, already implemented). This
spec adds an **embedded Tor route** (`type: tor`): an in-process [`arti-client`](https://crates.io/crates/arti-client)
`TorClient` that dials arbitrary TCP (and `.onion`) through the Tor network — no external
`tor` daemon, no `arti` sidecar, no bundled per-OS binary. One self-contained binary, exactly
like `type: warp`.

## Goal

- A route type `type: tor` that reaches clearnet **and** `.onion` addresses through Tor,
  fully in-process.
- Mirror the existing embedded-tunnel shape: one shared `TorClient` per route (like one
  `Arc<WgTunnel>` per WireGuard route), selected fail-closed via `?route=`.
- Non-blocking startup: a slow or failing Tor bootstrap must never stop the server or the
  other routes.

## Key decisions (from brainstorming)

- **Embed the `arti-client` crate, not a bundled/spawned `arti` binary.** The project's
  identity is "one binary, no sidecar" (embedded WARP registers in-process, no `warp-cli`).
  `arti-client` gives the exact primitive we need — `TorClient::connect((host, port))` returns
  a `DataStream` implementing async read/write — which drops onto the existing `Conn`/`Route`
  enums the same way `WgStream` did. The linked `zydou/arti` repo is a source mirror of upstream
  arti and currently publishes **no release binaries**, so "bundle the binary" would mean
  building them ourselves anyway; rejected.

- **`.onion` support is enabled** (`onion-service-client` feature). Reaching hidden services is
  a primary reason to run Tor in a browser proxy. It adds dependencies but no config surface.

- **Trait bridge required.** arti's `DataStream` implements the **`futures::io`** async traits;
  our `enum Conn` delegates the **`tokio::io`** traits. `tokio_util::compat`'s `.compat()`
  wraps a `DataStream` into a `tokio`-trait stream — one call per stream. New variant is
  `Conn::Tor(Compat<DataStream>)`.

- **Non-blocking construction + background bootstrap.** `build_route` is sync and runs inside
  the tokio runtime (same as the WARP path). We build the client with
  `create_unbootstrapped()` (no network I/O — just spawns arti's daemon tasks, like
  `WgTunnel::spawn`) and `BootstrapBehavior::OnDemand`, then `tokio::spawn` a warmup
  `client.bootstrap()`. Startup returns immediately; the route is present even before Tor is
  ready, and the first real request triggers bootstrap on demand if warmup hasn't finished.

- **rustls, not native-tls.** Pure-Rust TLS keeps the "one self-contained binary" property
  (no OpenSSL/schannel link dependency).

- **State cached project-local.** arti's consensus/descriptor cache + guard/identity keys live
  in a project-local `arti-data/` directory (gitignored), consistent with the `warp-<name>.json`
  cache sitting in cwd — not scattered into OS dirs (`~/.local/share/arti`). Overridable per
  route via an optional `data_dir` field.

- **MSRV rises to 1.91.** arti requires Rust 1.91; the whole workspace's minimum toolchain
  rises with it. Build time and binary size grow (~200 transitive crates). Accepted as
  inherent to embedding Tor.

## Architecture

```
config.yaml ──serde──▶ Vec<RouteSpec> ──▶ HashMap<String, Route>
                                              │
   Route::Direct / Socks5 / Http  ───────────┤ connect() → Conn::Tcp(TcpStream)
   Route::Wireguard(Arc<WgTunnel>) ──────────┤ connect() → Conn::Wg(WgStream)
   Route::Tor(Arc<TorClient>) ───────────────┘ connect() → Conn::Tor(Compat<DataStream>)
                                              │
                              wisp::run_stream splits Conn and relays both ways
```

`Route::connect` keeps its `Result<Conn, u8>` signature; only a new arm is added.

## Configuration

Schema — minimal, like `warp`, plus one optional override:

```yaml
routes:
  - name: tor
    type: tor
    # data_dir: "arti-data"   # optional; arti's cache + key state (default: "arti-data")
```

- `RouteSpec::Tor { name, data_dir: Option<String> }`, tagged `type: tor` via the existing
  `#[serde(tag = "type", rename_all = "lowercase")]`.
- `direct` remains implicit/reserved; duplicate and empty names still error, unchanged.
- The prior `tor` example (a `type: socks5` route → `127.0.0.1:9050`, requiring an external
  Tor daemon) is replaced by this built-in form in `config.example.yaml` and `config.yaml`.

## Components

### `enum Route` (new arm, `src/route.rs`)

```rust
pub enum Route {
    Direct,
    Socks5 { addr: SocketAddr, auth: Option<(String, String)> },
    Http   { addr: SocketAddr, auth: Option<(String, String)> },
    Wireguard(Arc<WgTunnel>),
    Tor(Arc<TorClient<PreferredRuntime>>),
}
```

`Tor` holds an `Arc` to a shared, long-lived client (one per Tor route, not per stream), like
`Wireguard`. The manual `Debug` impl gains a `Tor => "Tor"` arm (no secrets to render).

### `enum Conn` (new arm, `src/route.rs`)

```rust
pub enum Conn {
    Tcp(TcpStream),
    Wg(WgStream),
    Tor(tokio_util::compat::Compat<arti_client::DataStream>),
}
```

Adds the `Tor` arm to the four `poll_*` delegations — mechanical, mirrors the `Wg` arms.
`run_stream`'s `tokio::io::split(conn)` is unchanged.

### Tor client construction (`src/tor.rs`, new)

A small module that isolates arti, parallel to `src/wireguard.rs`:

```rust
pub fn build_client(data_dir: &Path) -> Result<Arc<TorClient<PreferredRuntime>>, String>
```

- `PreferredRuntime::current()` grabs the ambient tokio runtime (we're inside `#[tokio::main]`).
- `TorClientConfig` built with `state_dir` and `cache_dir` under `data_dir`.
- `TorClient::with_runtime(rt).config(cfg).bootstrap_behavior(BootstrapBehavior::OnDemand)
  .create_unbootstrapped()` → `Arc<TorClient>`; spawns arti daemon tasks, no network I/O.
- Spawn a warmup task: `client.clone().bootstrap()`, `tracing::warn!` on error.
- Returns an error string on config/build failure (fatal at startup, like other route specs).

`build_route`'s `RouteSpec::Tor` arm calls `tor::build_client(...)` and wraps it in
`Route::Tor`.

### Connect + error mapping (`src/route.rs`)

`Route::connect` gains:

```rust
Route::Tor(client) => connect_tor(client, host, port, cfg).await.map(Conn::Tor),
```

`connect_tor`:
- Enforce the host blacklist first: `if cfg.is_host_blacklisted(host) { return Err(R_BLOCKED) }`.
  (`block_private` does not apply — Tor resolves at the exit, so there is no local IP to
  inspect; identical to the socks5/http/wireguard paths.)
- `tokio::time::timeout(cfg.connect_timeout, client.connect((host, port)))`.
- Map the outcome to a Wisp close reason via arti's `ErrorKind` (`tor_error::HasKind`):
  refused-ish → `R_REFUSED`, timeout/`Timeout` → `R_TIMEOUT`, everything else → `R_UNREACHABLE`.
  The outer `timeout` elapsing → `R_TIMEOUT`.
- On success, `.compat()` the `DataStream` and return it (the `.map(Conn::Tor)` above).

**First-request latency:** if a request arrives before background bootstrap finishes, the
on-demand bootstrap runs under `connect_timeout` and may elapse (→ `R_TIMEOUT`); the warmup
task keeps running, so retries succeed. Accepted trade vs. blocking startup on bootstrap.

## Security

- `block_private`: not applicable to Tor (exit-side resolution), same as the other proxied
  routes; documented.
- Host blacklist **is** enforced for Tor (hostname-substring, no resolution needed). Note: the
  socks5/http/wireguard arms do not currently enforce the blacklist — a pre-existing
  inconsistency. Out of scope to retrofit here; the Tor arm does the safe thing.
- No secrets to log; arti's own logs stay at its default level (its `tracing` output is
  filtered by the existing `EnvFilter`).

## Dependencies & build

`Cargo.toml`:

```toml
arti-client = { version = "0.x", default-features = false, features = [
    "tokio", "rustls", "onion-service-client",
] }
tor-rtcompat = "0.x"                       # PreferredRuntime
tokio-util = { version = "0.7", features = ["compat"] }   # DataStream trait bridge
```

- Exact `0.x` versions pinned at implementation time to the current release that shares arti's
  workspace version.
- `.gitignore`: add `arti-data/`.
- `rust-toolchain`/CI note: MSRV 1.91.

## Testing

- **Unit (offline, `src/route.rs` tests):** `type: tor` YAML parses to a `Route::Tor`; the
  optional `data_dir` parses; empty/duplicate/`direct`-reserved name rules still hold for a
  `tor` entry. (Building a real `TorClient` needs a runtime + spawns tasks, so parse-level
  tests assert the `RouteSpec` shape rather than constructing the client, or construct it
  inside a `#[tokio::test]` and assert it is `Route::Tor` without bootstrapping.)
- **Error mapping unit:** a pure `map_tor_err(kind) -> u8` function tested against representative
  `ErrorKind`s, mirroring `map_socks_reply` / `map_http_status`.
- **End-to-end (network, `#[ignore]`):** a `#[tokio::test] #[ignore]` that builds a Tor route,
  connects to a known clearnet host, and reads a response — run manually, not in default
  `cargo test`, like the existing real-WARP e2e.
- **Smoke test (manual, after implementation):** start the server with a `type: tor` route and
  drive a real request through it end-to-end (see below).

## Smoke test plan

After `cargo build` succeeds:

1. Point `config.yaml` at a `type: tor` route (plus `direct`).
2. Run the server (`cargo run`), confirm it binds immediately (startup not blocked on
   bootstrap) and logs the Tor warmup starting.
3. Wait for bootstrap, then issue a request through the Tor route — either via the Wisp
   endpoint from the frontend, or a direct integration-style check — to a target that echoes
   the **exit IP** (e.g. an ip-echo service), and confirm the observed source IP is a Tor exit,
   not the host's IP. Confirm `direct` still returns the host IP for contrast.
4. Confirm a bogus host through Tor closes the stream (fail-closed), and the server stays up.

## Files touched

| File | Change |
|---|---|
| `src/tor.rs` | **new** — `build_client` (unbootstrapped, on-demand, background warmup), error-kind mapping |
| `src/route.rs` | `Route::Tor` + `Conn::Tor` arms; `connect_tor`; `RouteSpec::Tor`; Debug arm; `build_route` arm |
| `src/lib.rs` | `pub mod tor;` |
| `Cargo.toml` | add `arti-client` (tokio, rustls, onion-service-client), `tor-rtcompat`, `tokio-util` (compat) |
| `.gitignore` | add `arti-data/` |
| `config.example.yaml`, `config.yaml` | replace the socks5 `tor` example with built-in `type: tor` |
| `README.md` | document `type: tor`: built-in, `.onion`, first-request bootstrap latency, `arti-data/` cache, MSRV 1.91 |

## Out of scope

- Per-Wisp-connection or per-stream **circuit isolation** (`isolated_client()`): the route
  shares one `TorClient`, like one shared `WgTunnel`. Could be a later enhancement.
- Running/exposing an onion **service** (we are a client only).
- Retrofitting host-blacklist enforcement onto the socks5/http/wireguard arms.
- Configurable exit country / bridges / pluggable transports.

## Risk note

The Tor route is isolated in `src/tor.rs` and is additive — the rest of the binary is
unchanged and independently verifiable. The main risks are dependency/version friction
(arti's large tree, MSRV 1.91, feature-flag combinations) and the `futures`↔`tokio` trait
bridge; both surface at compile time. Bootstrap flakiness is contained by non-blocking startup
and on-demand retry, so it degrades one route rather than the server.
