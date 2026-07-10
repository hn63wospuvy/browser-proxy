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

## Requirements

- **Rust** 1.75+ (`cargo`) to build and run the server.
- **Node.js** 18+ (`npm`) — used **once** to vendor the client assets. Not needed at runtime.

## Setup

```bash
# 1. Vendor the Scramjet / bare-mux / libcurl client assets into static/
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
| `RUST_LOG` | `browser_proxy=info` | Log filter (`tower_http=debug` to log every request). |

## How it works

1. The frontend registers the Scramjet **service worker** (scope `/`) and points
   [bare-mux](https://github.com/MercuryWorkshop/bare-mux) at the **libcurl** transport,
   which speaks the [Wisp](https://github.com/MercuryWorkshop/wisp-protocol) protocol to
   `wss://<host>/wisp/`.
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
[bare-mux](https://github.com/MercuryWorkshop/bare-mux), and
[libcurl-transport](https://github.com/ading2210/libcurl.js) from Mercury Workshop.
The Wisp backend here is an independent Rust implementation of the
[Wisp v1 protocol](https://github.com/MercuryWorkshop/wisp-protocol/tree/v1).
