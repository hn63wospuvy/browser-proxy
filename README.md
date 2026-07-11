# browser-proxy

A self-hosted web proxy, like [proxysite.com](https://www.proxysite.com/): open the
frontend, type any URL, and browse that site entirely through your server. Every request the
page makes afterwards — clicks, links, images, video, `fetch`/XHR, WebSocket — is
automatically routed through the server too, so it works on JavaScript-heavy sites and SPAs.

The client interception is done by [Scramjet](https://github.com/MercuryWorkshop/scramjet)
(a service-worker proxy). The performance-critical backend — a **Wisp** multiplexed
TCP-over-WebSocket relay — is written from scratch in **Rust** (axum + tokio).

```
Browser                                             Rust server (axum + tokio)
┌────────────────────────────────┐                 ┌────────────────────────────┐
│ Frontend (URL box + Go)        │  GET /,/scram/… │ static assets              │
│  → Scramjet service worker     │◀───────────────▶│ (scramjet/baremux/libcurl) │
│     intercepts every request   │                 │                            │
│  → libcurl transport (WASM,     │  wss://…/wisp/  │ Wisp v1 server /wisp/      │
│     Wisp client; does HTTP/TLS) │◀───────────────▶│  one TCP task per stream   │──▶ target
└────────────────────────────────┘   (multiplex)   └────────────────────────────┘   sites
```

Because HTTP and TLS run in the browser (inside the libcurl WASM), the Rust server never
parses HTTP — it just relays raw TCP bytes, so it streams by default and stays fast.

The client transport is actually a small **hybrid** ([`static/hybrid/index.mjs`](static/hybrid/index.mjs)):
libcurl by default (verifies TLS certificates), and — only for a host whose certificate fails
verification — an automatic per-request fall back to an **epoxy** client with verification
disabled, so cert-broken sites still load. See
[the design spec](docs/superpowers/specs/2026-07-11-insecure-tls-fallback-design.md).

## Requirements

- **Rust** 1.75+ (`cargo`) to build and run the server.
- **Node.js** 18+ (`npm`) — used **once** to vendor the client assets. Not needed at runtime.

## Setup

```bash
# 1. Vendor the Scramjet / bare-mux / libcurl / epoxy client assets into static/
node scripts/fetch-assets.mjs

# 2. Build and run
cargo run --release
```

Then open **http://localhost:8080/**, type a URL (e.g. `example.com`), and press Go.

> Service workers require a *secure context*. Use `http://localhost` (browsers treat
> localhost as secure) or put the server behind HTTPS. Plain `http://` on a LAN IP will not
> register the service worker.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `BIND` | `127.0.0.1:8080` | Full bind address. Loopback-only by default; set e.g. `0.0.0.0:8080` to expose it. |
| `PORT` | `8080` | Overrides just the port. |
| `STATIC_DIR` | `static` | Directory of the frontend + vendored assets. |
| `WISP_BUFFER_SIZE` | `128` | Wisp flow-control window (packets per stream); also the per-stream memory bound. |
| `CONNECT_TIMEOUT_SECS` | `15` | Outbound TCP connect timeout. |
| `IDLE_TIMEOUT_SECS` | `0` | Reap a stream whose target is silent this long. `0` disables it (keeps SSE/long-poll alive). |
| `MAX_CONNECTIONS` | `128` | Max concurrent Wisp WebSocket connections (further upgrades get 503). |
| `MAX_STREAMS` | `256` | Max concurrent streams per connection (further CONNECTs get refused). |
| `BLOCK_PRIVATE` | `0` | `1`/`true` refuses targets on private/loopback/link-local IPs (SSRF guard). |
| `HOST_BLACKLIST` | *(empty)* | Comma-separated hostname substrings to refuse. |
| `CONFIG` | `config.yaml` | Path to the YAML config (bind address + routes, see below). The default path being absent is fine (routes = `direct` only); an explicitly-set but missing/malformed config aborts startup. `BIND`/`PORT` override the file's `bind`. |
| `RUST_LOG` | `browser_proxy=info` | Log filter (`tower_http=debug` to log every request). |

## Routing through a VPN

Outbound connections can be sent through a VPN or proxy, chosen per-navigation from a
dropdown (on the landing page and in the top bar). Target sites then see the route's IP, not
the server's. Routes are defined in a YAML config file (`config.yaml` by default, or set
`CONFIG`). `direct` (no proxy) always exists; the dropdown is hidden when no other route is
configured. See [`config.example.yaml`](config.example.yaml).

The same file also sets the **bind address** (optional; `BIND`/`PORT` env vars override it):

```yaml
bind:
  interface: "127.0.0.1"   # 127.0.0.1 (loopback) or 0.0.0.0 to expose on the LAN
  port: 8080

routes:
  # Cloudflare WARP, registered in-process (one binary, no warp-cli / wireproxy):
  - name: warp
    type: warp

  # A generic WireGuard peer you configure yourself (e.g. wgcf-generated):
  - name: myvpn
    type: wireguard
    private_key: "<base64 private key>"
    peer_public_key: "<base64 peer public key>"
    endpoint: "engage.cloudflareclient.com:2408"
    address: "172.16.0.2/32"

  # Built-in Tor, running in-process (embedded arti-client — no external tor/arti daemon):
  - name: tor
    type: tor
    # data_dir: "arti-data"   # where arti caches consensus + keys (default: arti-data)

  # A SOCKS5 upstream (an external Tor daemon, WARP in `warp-cli mode proxy`, etc.):
  - name: socks
    type: socks5
    address: "127.0.0.1:9050"

  # An HTTP CONNECT proxy (optional credentials):
  - name: corp
    type: http
    address: "127.0.0.1:8080"
    # username: "u"
    # password: "p"
```

Then `cargo run --release` (with `config.yaml` in the working directory) and pick the route
in the UI.

### Route types

- **`warp`** — an embedded Cloudflare WARP tunnel. The server registers a WARP account on
  first start (via Cloudflare's unofficial registration API, the same one `wgcf` uses) and
  caches the credentials to `warp-<name>.json` (mode `0600` on Unix) so it does not
  re-register on every boot. No `warp-cli` or other sidecar process is needed.
- **`wireguard`** — a generic WireGuard peer you supply. Use this with any WireGuard provider;
  for WARP without in-process registration, generate a config with
  [`wgcf`](https://github.com/ViRb3/wgcf) and paste the keys.
- **`tor`** — an embedded [Tor](https://www.torproject.org/) client, running in-process via
  [`arti`](https://gitlab.torproject.org/tpo/core/arti) (the Tor Project's Rust implementation).
  No external `tor` or `arti` daemon, no bundled per-OS binary — just one self-contained server.
  Reaches clearnet **and `.onion`** addresses. Startup is *not* blocked on Tor; the Tor directory
  bootstraps in the background, so the first request after boot may wait a few seconds for it to
  finish. arti caches its consensus + keys under `data_dir` (default `arti-data/`).
- **`socks5`** — any SOCKS5 proxy (an external Tor daemon on `127.0.0.1:9050`; WARP via
  `warp-cli mode proxy` on `127.0.0.1:40000`; etc.).
- **`http`** — any HTTP proxy that supports the CONNECT method.

The `warp` and `wireguard` tunnels are userspace ([`boringtun`](https://github.com/cloudflare/boringtun)
+ [`smoltcp`](https://github.com/smoltcp-rs/smoltcp)); they need no root, no `NET_ADMIN`, and
do not touch the host routing table.

**Fail closed.** If the selected route doesn't exist the WebSocket upgrade is rejected
(HTTP 400); if the upstream is down the stream closes. Traffic is *never* silently sent
directly when a VPN route was requested.

**DNS.** On a `socks5`/`http` route the hostname is handed to the proxy to resolve; on a
`wireguard`/`warp` route it is resolved via `1.1.1.1` *inside* the tunnel; on a `tor` route it
is resolved at the exit relay. Either way no DNS query for the destination leaves this machine.
On the `direct` route the server resolves the hostname itself — by default via the OS resolver
(`system`), or via a **DNS-over-HTTPS** resolver chosen with the address-bar **DNS** picker (see
[Address bar](#address-bar-search-engine-dns-history) below).

**Caveats within the "personal use" scope:**

- The **WARP registration API is unofficial** and may change; if `type: warp` stops
  registering, delete `warp-<name>.json` or switch to a `wgcf`-generated `type: wireguard`
  route.
- A **freshly-registered WARP device can take a short while to activate** on Cloudflare's
  edge, and rapidly registering many devices gets rate-limited (the WireGuard endpoint then
  silently ignores handshakes). The credential cache means you normally register once, so
  this only bites during repeated fresh registrations — delete `warp-<name>.json` only when
  necessary, and if a new `warp` route won't connect, wait a minute and retry rather than
  re-registering in a loop.
- Embedding WireGuard roughly **doubles the dependency tree and build time** (`boringtun`,
  `smoltcp`, `ureq`, and their transitive crates). If you only need `socks5`/`http` routes,
  the tunnel is still compiled in.
- The **embedded Tor route pulls in `arti`** — a large dependency tree (~200 crates, SQLite
  bundled for arti's directory cache) that raises the minimum Rust toolchain to **1.91** and
  adds noticeably to build time. The first request on a `tor` route after startup may take a
  few seconds while the Tor directory finishes bootstrapping; a slow or failed bootstrap
  degrades only that route — the server and other routes stay up.
- `BLOCK_PRIVATE` cannot filter a *hostname* on a `socks5`/`http`/`wireguard`/`tor` route (the
  name is resolved by the proxy, inside the tunnel, or at the Tor exit, not here). IP-literal
  targets are still checked. The SSRF exposure is smaller on a VPN route anyway, since
  connections originate from the VPN's network, not this host.
- The client transport is a **SharedWorker shared across all tabs** of the origin. Selecting
  a route affects every open tab, not just the current one. Use one tab at a time if you
  rely on per-tab routes.

## Address bar (search engine, DNS, history)

The top bar stays slim — just the input and **Go**. The config controls (route, search engine,
DNS) live on the **landing page** shown before the first navigation. Once you're browsing, the
same controls move into a **⚙ popover** in the bar, so you can switch route/DNS mid-browse — e.g.
flip to a `warp`/`tor` route the moment a site is blocked. The input also remembers what you type.

- **Search engine** — when the input isn't a URL/host it's sent to the selected engine. Default
  is **Brave** (proxy-friendly; Google tends to CAPTCHA proxied traffic). Client-side only.
- **DNS** — how the **`direct`** route resolves hostnames. An editable combobox: pick a preset
  (`system`, or DNS-over-HTTPS to `cloudflare` / `google` / `quad9` + any custom `dns:` entries
  from `config.yaml`, see [`config.example.yaml`](config.example.yaml)), **or type a DNS-server
  IP** (e.g. `1.1.1.1`, or a LAN resolver) to query it over plain UDP/TCP. `system` (or an empty
  field) is the **non-interfering default** — no DNS override is sent, so the OS resolver is used
  and VPN/proxy routes keep resolving at their own exit. Changing it rebuilds the transport and
  reloads the page, like a route switch; it has no effect on proxied routes.
  - A custom DNS is useful when your ISP **DNS-hijacks** a domain (you'll see a TLS cert error
    for the wrong host — the ISP's block page). Note a hijacking ISP may also block by IP/port
    53; a VPN route (`warp`/`tor`) is the more robust bypass.
- **History + autocomplete** — submitted queries are saved in the browser (`localStorage`, most
  recent first). Typing ≥2 characters shows matching past entries; ↑/↓ to highlight, Enter to
  open, Esc to dismiss the list.
- **Esc** — while browsing, toggles the address bar and briefly flashes the current
  Route / Search / DNS before fading out.

Both selections and history live entirely in the browser; only the chosen route and DNS name/IP
(as URL path segments) reach the server.

## How it works

1. The frontend registers the Scramjet **service worker** (scope `/`) and points
   [bare-mux](https://github.com/MercuryWorkshop/bare-mux) at the **hybrid** transport
   (libcurl + an insecure-TLS epoxy fallback, see above), which speaks the
   [Wisp](https://github.com/MercuryWorkshop/wisp-protocol) protocol to `wss://<host>/wisp/`.
2. Pressing Go renders the proxied site in a **full-viewport iframe** via
   `scramjet.createFrame()`. The frontend page must stay alive because it hosts the libcurl
   transport (in the bare-mux SharedWorker); a top-level navigation would tear it down and
   only the first request would succeed. Scramjet neutralizes frame-busting, so the frame
   still behaves like the tab is the site.
3. The service worker intercepts every request the framed page makes, rewrites URLs, and
   performs the real requests via the libcurl WASM client.
4. libcurl opens Wisp streams over a single WebSocket to `/wisp/`.
5. The Rust **Wisp server** ([`src/wisp.rs`](src/wisp.rs)) opens one raw TCP socket per
   stream to the target host:port and relays bytes both ways, using the Wisp CONTINUE
   window for flow control and a bounded WebSocket-writer queue for backpressure.

## Project layout

- [`src/wisp.rs`](src/wisp.rs) — Wisp v1 server: framing, per-stream tokio tasks, flow control, TCP relay.
- [`src/server.rs`](src/server.rs) — axum router, static serving, COOP/COEP headers, `/wisp/` upgrade.
- [`src/config.rs`](src/config.rs) — env configuration + the SSRF `is_private_ip` guard.
- [`src/main.rs`](src/main.rs) — bootstrap.
- [`static/`](static/) — minimal frontend (`index.html`, `index.js`, `sw.js`, …) + vendored client assets.
- [`scripts/fetch-assets.mjs`](scripts/fetch-assets.mjs) — vendors the client assets from npm.
- [`tests/wisp_integration.rs`](tests/wisp_integration.rs) — WebSocket → Wisp → TCP relay tests.
- [`docs/superpowers/specs/`](docs/superpowers/specs/) — design spec.

## Testing

```bash
cargo test                      # unit + integration (local TCP echo relay)
cargo test -- --ignored         # also runs the real-internet relay test (needs network)
```

## Scope & limitations

- **Personal / small internal use.** No authentication, a shared process, no per-user
  isolation — by design. It binds **loopback only** by default and caps concurrent
  connections/streams and per-stream memory, but it is still an open outbound relay: do not
  expose it publicly (`BIND=0.0.0.0`) without adding auth and setting `BLOCK_PRIVATE=1`.
- **TCP only.** UDP/QUIC Wisp streams are refused; browsers fall back to TCP HTTP, which is
  what the libcurl transport uses anyway.
- **Rewriting gaps are Scramjet's, not the backend's.** On some sites a few resources (e.g.
  certain `img` URLs Scramjet fails to rewrite) load blank while the rest of the page works.
  That is the client-side rewriter (Scramjet v1), independent of the Rust Wisp relay.
- **Very heavy / DRM sites** (e.g. YouTube with Widevine) may not fully work — again a
  Scramjet-layer limitation, not the Rust backend. Ordinary sites, SPAs, images, and
  progressive video stream fine.
- Scramjet is pinned to v1.1.0 (matching the upstream demo); v2 is still alpha and rewrites
  more sites correctly.
- **Debug:** `GET /debug/stats` returns Wisp counters (connections/streams/failures) as JSON.

## Credits

Client interception by [Scramjet](https://github.com/MercuryWorkshop/scramjet),
[bare-mux](https://github.com/MercuryWorkshop/bare-mux),
[libcurl-transport](https://github.com/ading2210/libcurl.js), and
[epoxy-tls](https://github.com/MercuryWorkshop/epoxy-tls) (the insecure-TLS fallback) from
Mercury Workshop.
The Wisp backend here is an independent Rust implementation of the
[Wisp v1 protocol](https://github.com/MercuryWorkshop/wisp-protocol/tree/v1).
