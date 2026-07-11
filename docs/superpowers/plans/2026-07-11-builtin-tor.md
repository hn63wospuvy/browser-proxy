# Built-in Tor Route Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an in-process `type: tor` route (embedded `arti-client`) that dials clearnet and `.onion` targets through Tor, with no external daemon and non-blocking startup.

**Architecture:** A new `Route::Tor(Arc<TorClient>)` holds one shared, long-lived arti client per route (like `Route::Wireguard(Arc<WgTunnel>)`). `Route::connect` gains a Tor arm that calls `client.connect((host, port))`, wraps the returned `DataStream` with `tokio_util::compat` into a new `Conn::Tor` variant, and enforces the existing timeout + host blacklist. The client is built unbootstrapped with on-demand bootstrap and warmed by a background task, so a slow/failed Tor bootstrap never blocks server startup.

**Tech Stack:** Rust, tokio, axum, `arti-client` 0.44 (features: `onion-service-client`; defaults keep `tokio` + `native-tls`), `tokio-util` (compat). Existing: boringtun/smoltcp (WireGuard), serde_yaml_ng.

## Global Constraints

- **arti-client 0.44** with `features = ["onion-service-client"]`, default features kept (tokio + native-tls). MSRV 1.91 (local toolchain is 1.96 — OK).
- **arti API is verified against the compiler, not docs** — docs.rs 0.44.0 doc-build failed. Where this plan shows an arti call (`TorClient::builder`, `create_unbootstrapped`, `BootstrapBehavior`, config dirs), treat the compiler as ground truth and adjust the exact path/method name if it differs; the shape (unbootstrapped + on-demand + background warmup) is fixed.
- **Fail closed:** unknown route rejected before upgrade (unchanged); a dead Tor connection closes the stream with a Wisp reason. Never fall back to Direct.
- **No secrets logged.** The `Route` Debug impl renders `Tor` as the bare word `"Tor"`.
- **Trait bridge:** arti's `DataStream` is `futures::io`; `Conn` uses `tokio::io`. Always wrap via `.compat()`.
- **State is project-local:** arti caches under `arti-data/` (gitignored), overridable per route via `data_dir`.

---

### Task 1: Dependencies + baseline build

**Files:**
- Modify: `Cargo.toml` (dependencies section)
- Modify: `.gitignore`

- [ ] **Step 1: Add the dependencies** (already applied — verify present)

```toml
# Embedded Tor route (in-process arti-client; no external tor/arti daemon).
arti-client = { version = "0.44", features = ["onion-service-client"] }
tokio-util = { version = "0.7", features = ["compat"] }
```

- [ ] **Step 2: Gitignore the arti cache dir**

Append to `.gitignore`:
```
# arti-client (built-in Tor) state + directory cache
arti-data/
```

- [ ] **Step 3: Build to resolve + compile the tree**

Run: `cargo build`
Expected: PASS (downloads ~200 crates the first time; slow). If a feature/version error appears, adjust the feature set (a known-good fallback is default features only + `onion-service-client`).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock .gitignore
git commit -m "build: add arti-client + tokio-util for built-in Tor route"
```

---

### Task 2: `tor.rs` — client construction + connect helper

**Files:**
- Create: `src/tor.rs`
- Modify: `src/lib.rs` (add `pub mod tor;`)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces:
  - `pub type TorClient = arti_client::TorClient<tor_rtcompat::PreferredRuntime>;` (or re-export the concrete type the compiler accepts)
  - `pub fn build_client(data_dir: &std::path::Path) -> Result<std::sync::Arc<TorClient>, String>`
  - `pub async fn connect(client: &TorClient, host: &str, port: u16, timeout: std::time::Duration) -> Result<tokio_util::compat::Compat<arti_client::DataStream>, u8>`

- [ ] **Step 1: Write the module with construction + connect**

Create `src/tor.rs`:

```rust
//! Embedded Tor route: an in-process `arti-client` TorClient that dials arbitrary TCP (and
//! `.onion`) through the Tor network. One client per `type: tor` route, shared by every stream,
//! mirroring the shared `WgTunnel`. Construction is non-blocking (unbootstrapped + on-demand);
//! a background task warms the bootstrap so a slow/failed Tor network degrades one route rather
//! than blocking startup.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arti_client::{BootstrapBehavior, TorClientConfig};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

use crate::wisp::R_UNREACHABLE;

/// The concrete arti client type used for `type: tor` routes.
pub type TorClient = arti_client::TorClient<tor_rtcompat::PreferredRuntime>;

/// Build a shared, non-bootstrapped Tor client and warm its bootstrap in the background.
/// Must be called inside a tokio runtime (the caller, `build_route`, already is). Caches arti
/// state under `data_dir` (`<data_dir>/state`, `<data_dir>/cache`).
pub fn build_client(data_dir: &Path) -> Result<Arc<TorClient>, String> {
    let cfg = config_for(data_dir)?;
    let client = arti_client::TorClient::builder()
        .config(cfg)
        .bootstrap_behavior(BootstrapBehavior::OnDemand)
        .create_unbootstrapped()
        .map_err(|e| format!("tor client init: {e}"))?;

    // Warm the directory bootstrap so the first request rarely races it. On-demand behavior
    // means a request arriving earlier still triggers bootstrap; this just front-runs it.
    let warm = client.clone();
    tokio::spawn(async move {
        if let Err(e) = warm.bootstrap().await {
            tracing::warn!("tor bootstrap failed (route will retry on demand): {e}");
        } else {
            tracing::info!("tor bootstrap complete");
        }
    });

    Ok(Arc::new(client))
}

/// Build a TorClientConfig whose state + cache live under `data_dir`.
fn config_for(data_dir: &Path) -> Result<TorClientConfig, String> {
    // VERIFY-API: preferred is the `from_directories` convenience; fall back to
    // `builder().storage().state_dir(..).cache_dir(..)` with `CfgPath` if it does not exist.
    TorClientConfig::builder()
        .storage()
        .state_dir(cfg_path(&data_dir.join("state")))
        .cache_dir(cfg_path(&data_dir.join("cache")))
        .build_unwrapped_or_err()   // placeholder name; see VERIFY-API note
        .map_err(|e| format!("tor config: {e}"))
}
```

> NOTE: `config_for` is the one arti-version-sensitive spot. Lock it against the compiler in Step 2. The two shapes to try, in order:
> 1. `TorClientConfigBuilder::from_directories(data_dir.join("state"), data_dir.join("cache")).build()?`
> 2. `let mut b = TorClientConfig::builder(); b.storage().state_dir(CfgPath::new_literal(data_dir.join("state"))).cache_dir(CfgPath::new_literal(data_dir.join("cache"))); b.build()?` where `CfgPath` is `arti_client::config::CfgPath`.
> If neither compiles quickly, ship with `TorClientConfig::default()` (OS dirs) and leave a `// TODO(data_dir)` — startup must not be blocked on this detail.

Then the connect helper (append to `src/tor.rs`):

```rust
/// Dial `host:port` through Tor, returning a tokio-compatible stream. Coarse error mapping:
/// any connect failure → unreachable; the outer timeout elapsing → timeout (mapped by caller).
pub async fn connect(
    client: &TorClient,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Compat<arti_client::DataStream>, u8> {
    match tokio::time::timeout(timeout, client.connect((host, port))).await {
        Ok(Ok(stream)) => Ok(stream.compat()),
        Ok(Err(e)) => {
            tracing::debug!("tor connect {host}:{port} failed: {e}");
            Err(R_UNREACHABLE)
        }
        Err(_) => Err(crate::wisp::R_TIMEOUT),
    }
}
```

- [ ] **Step 2: Add `pub mod tor;` to `src/lib.rs`**

In `src/lib.rs`, add to the module list (after `pub mod route;`):
```rust
pub mod tor;
```
Also add a bullet to the crate doc comment:
```rust
//! - [`tor`]: embedded Tor route (in-process arti-client).
```

- [ ] **Step 3: Compile the module against the real arti API**

Run: `cargo build`
Expected: PASS. Fix `config_for` per the VERIFY-API note and any exact method/enum-path differences the compiler reports (e.g. `BootstrapBehavior` import path, `builder()` vs `with_runtime()`).

- [ ] **Step 4: Commit**

```bash
git add src/tor.rs src/lib.rs
git commit -m "feat(tor): in-process arti-client construction + connect helper"
```

---

### Task 3: Wire the route into `route.rs`

**Files:**
- Modify: `src/route.rs` (Route enum, Conn enum, RouteSpec, build_route, Route::connect, Debug, tests)

**Interfaces:**
- Consumes: `crate::tor::{TorClient, build_client, connect}` from Task 2.
- Produces: a working `type: tor` route reachable via `Route::connect`.

- [ ] **Step 1: Write the failing YAML-parse test**

Add to the `tests` module in `src/route.rs`:

```rust
#[tokio::test]
async fn yaml_parses_tor_route() {
    let y = "routes:\n  - name: tor\n    type: tor\n";
    let m = routes_from_yaml(y).unwrap();
    assert!(matches!(&*m["tor"], Route::Tor(_)));
    assert!(m.contains_key(DIRECT));
}

#[tokio::test]
async fn yaml_parses_tor_route_with_data_dir() {
    let y = "routes:\n  - name: tor\n    type: tor\n    data_dir: \"custom-arti\"\n";
    let m = routes_from_yaml(y).unwrap();
    assert!(matches!(&*m["tor"], Route::Tor(_)));
}
```

> These are `#[tokio::test]` because building a Tor client spawns tasks (needs a runtime). They construct the client but do NOT bootstrap (on-demand), so they stay offline and fast.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib route::tests::yaml_parses_tor_route`
Expected: FAIL to compile (`Route::Tor` / `RouteSpec::Tor` do not exist).

- [ ] **Step 3: Add the `Tor` variants and wiring**

In `src/route.rs`:

Add the imports near the top:
```rust
use std::path::PathBuf;
use crate::tor::{self, TorClient};
```

Add to `enum Route`:
```rust
    /// Dial through an embedded, in-process Tor client (shared, one per route).
    Tor(Arc<TorClient>),
```

Add to the `Debug` impl match:
```rust
            Route::Tor(_) => write!(f, "Tor"),
```

Add to `enum Conn`:
```rust
    Tor(tokio_util::compat::Compat<arti_client::DataStream>),
```

Add the `Tor` arm to each of `Conn`'s four `poll_*` methods, mirroring `Wg`:
```rust
            Conn::Tor(s) => Pin::new(s).poll_read(cx, buf),
```
```rust
            Conn::Tor(s) => Pin::new(s).poll_write(cx, buf),
```
```rust
            Conn::Tor(s) => Pin::new(s).poll_flush(cx),
```
```rust
            Conn::Tor(s) => Pin::new(s).poll_shutdown(cx),
```

Add to `enum RouteSpec`:
```rust
    Tor {
        name: String,
        data_dir: Option<String>,
    },
```

Add `Tor` to the `RouteSpec::name` match:
```rust
            | RouteSpec::Tor { name, .. } => name,
```
(fold it into the existing `|` chain, before the closing `=> name,`)

Add the `build_route` arm:
```rust
        RouteSpec::Tor { data_dir, .. } => {
            let dir = PathBuf::from(data_dir.unwrap_or_else(|| "arti-data".to_string()));
            Ok(Route::Tor(tor::build_client(&dir).map_err(|e| {
                format!("tor route {name:?}: {e}")
            })?))
        }
```

Add the `Route::connect` arm (inside the `match self`):
```rust
            Route::Tor(client) => {
                if cfg.is_host_blacklisted(host) {
                    return Err(R_BLOCKED);
                }
                tor::connect(client, host, port, cfg.connect_timeout)
                    .await
                    .map(Conn::Tor)
            }
```

Update the test-helper `addr` fn in the `tests` module to cover the new variant:
```rust
            Route::Tor(_) => "tor".into(),
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib route::tests`
Expected: PASS (all existing route tests + the two new Tor tests).

- [ ] **Step 5: Full build + clippy**

Run: `cargo build && cargo clippy --all-targets -- -D warnings`
Expected: PASS. (Ensure the `R_BLOCKED` import is in scope in `route.rs` — it already is via the `wisp` import.)

- [ ] **Step 6: Commit**

```bash
git add src/route.rs
git commit -m "feat(tor): type: tor route (Route::Tor + Conn::Tor) wired into dispatch"
```

---

### Task 4: Config examples + docs

**Files:**
- Modify: `config.example.yaml`
- Modify: `config.yaml`
- Modify: `README.md`

**Interfaces:** none (docs/config only).

- [ ] **Step 1: Replace the socks5 `tor` example with the built-in form**

In `config.example.yaml`, change the SOCKS5 Tor block to:
```yaml
  # Built-in Tor, running in-process (embedded arti-client — no external tor/arti daemon).
  # Reaches clearnet and .onion. First request after startup may wait for Tor bootstrap.
  - name: tor
    type: tor
    # data_dir: "arti-data"   # where arti caches consensus + keys (default: arti-data)
```
Apply the same replacement in `config.yaml` (the active `tor` route currently `type: socks5`).

- [ ] **Step 2: Document the route in README**

In `README.md`, under the routes/config section, add a `type: tor` entry describing: in-process (no daemon/sidecar/bundled binary), `.onion` supported, non-blocking startup with possible first-request bootstrap latency, `arti-data/` cache dir, and the MSRV-1.91 note. Match the surrounding doc style for `type: warp`.

- [ ] **Step 3: Verify config still loads**

Run: `cargo run -- --help 2>/dev/null; CONFIG=config.yaml cargo run &` then stop it — or a lighter check:
Run: `cargo test --lib` (config/route parse tests exercise the YAML path)
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add config.example.yaml config.yaml README.md
git commit -m "docs(tor): document + example the built-in type: tor route"
```

---

### Task 5: Smoke test (manual, real network)

**Files:** none (verification only).

- [ ] **Step 1: Ensure `config.yaml` has a `tor` route** (from Task 4) alongside `direct`.

- [ ] **Step 2: Start the server**

Run: `cargo run`
Expected: binds and logs "listening on ..." **immediately** (startup not blocked); shortly after, a "tor bootstrap complete" (or a warmup warning) log line.

- [ ] **Step 3: Drive a request through Tor and check the exit IP**

Using the running server's Wisp endpoint (via the frontend route dropdown → select `tor`) or a scripted Wisp client, fetch an IP-echo endpoint (e.g. `https://api.ipify.org` or `https://check.torproject.org/api/ip`) through the `tor` route and through `direct`.
Expected: the `tor` route reports a **different IP than direct** (a Tor exit); `check.torproject.org` reports `IsTor: true`.

- [ ] **Step 4: Fail-closed check**

Request a bogus host (e.g. `http://nonexistent.invalid`) through `tor`.
Expected: the stream closes with a Wisp reason; the **server stays up** and other routes keep working.

- [ ] **Step 5: Record the result** in the PR/commit notes (observed exit IP differs from direct; server stayed up).

---

## Self-Review

**Spec coverage:**
- `type: tor` route + `.onion` → Tasks 2–4 (`onion-service-client` feature, `TorClient::connect`). ✓
- In-process, no daemon → Task 1–2 (arti-client embedded). ✓
- Non-blocking startup + background warmup → Task 2 `build_client`. ✓
- `Conn::Tor` trait bridge → Task 2/3 (`.compat()`). ✓
- Blacklist enforced, block_private N/A → Task 3 `connect` arm. ✓
- Coarse error mapping → Task 2 `connect` (simplified from spec's ErrorKind match — no `tor_error` dep; documented). ✓
- Project-local `arti-data/`, `data_dir` override → Task 2 `config_for`, Task 3 build_route, Task 1 gitignore. ✓
- Docs + config examples → Task 4. ✓
- Smoke test → Task 5. ✓
- Deviation logged: **native-tls (schannel) instead of rustls** for build robustness on Windows — still a single self-contained binary; note to user, revisit if cross-OS rustls is wanted.

**Placeholder scan:** `config_for` intentionally carries a VERIFY-API note (arti-version-sensitive, compiler is ground truth) with two concrete fallbacks + a safe default — not an open TODO. All other steps have complete code.

**Type consistency:** `TorClient` alias, `build_client(&Path) -> Arc<TorClient>`, `connect(...) -> Compat<DataStream>` used consistently across Tasks 2–3. `Conn::Tor` / `Route::Tor` names match throughout.
