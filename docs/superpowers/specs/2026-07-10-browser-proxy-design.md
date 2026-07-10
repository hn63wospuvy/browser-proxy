# Browser Proxy — Design Spec

Date: 2026-07-10

## Goal

A self-hosted "web proxy" like [proxysite.com](https://www.proxysite.com/): the user
opens a frontend page, types any URL, presses Go, and browses that site fully through
our server. Every subsequent request the page makes — clicks, links, images, video, XHR,
`fetch`, WebSocket — is automatically routed through the server too. Must work on
JavaScript-heavy sites (SPAs, YouTube, video) and feel smooth (no lag).

## Key decisions (from brainstorming)

- **Interception**: service-worker based, so *every* browser request is intercepted and
  rewritten client-side. This is the only approach that handles SPAs / dynamic URLs /
  video, which pure server-side HTML rewriting cannot.
- **Client engine**: **Scramjet** (`@mercuryworkshop/scramjet`), the successor to
  Ultraviolet from Mercury Workshop. Its URL/JS rewriter is written in Rust→WASM, so it is
  fast and SPA-compatible. MIT/AGPL client assets are vendored as static files.
- **Transport**: **Wisp** (v1). Scramjet uses `bare-mux` to pick a transport; we use the
  **libcurl** transport, which speaks the Wisp protocol over one WebSocket. In-browser
  WASM (libcurl.js) performs the actual HTTP + TLS; our server only relays raw TCP.
- **Backend**: **Rust** (axum + tokio). It (1) serves the static Scramjet/bare-mux/libcurl
  assets + our minimal frontend, and (2) implements a **Wisp server** at `/wisp/` — a fast
  async multiplexed TCP relay. This is where Rust's performance matters.
- **Scale**: personal / small internal use. Shared process, no per-user isolation, no
  auth. SSRF guard for private IP ranges is available but off by default (configurable).
- **Frontend**: minimal — one URL input + Go button. On Go we render the proxied site in a
  **full-viewport iframe** (`scramjet.createFrame()`).

  > **Correction (post-implementation).** The original plan was top-level navigation. In
  > practice that breaks: top-level navigation destroys the frontend page that hosts the
  > libcurl transport (in the bare-mux SharedWorker), so only the first request succeeds and
  > every subresource fails client-side. The iframe keeps the page — and the transport —
  > alive, so all resource streams work. Scramjet neutralizes frame-busting, so a
  > full-viewport iframe still behaves like the tab is the site.

## Architecture

```
Browser (client)                                    Rust server (axum + tokio)
┌──────────────────────────────────┐               ┌─────────────────────────────┐
│ Frontend (URL input + Go)        │  GET /,/scram/│ 1. Static assets            │
│        │ register SW             │◀─────────────▶│    (scramjet, baremux,      │
│        ▼                         │  /baremux/... │     libcurl, frontend)      │
│ Scramjet Service Worker          │               │                             │
│   intercept + rewrite every req  │   wss:/wisp/  │ 2. Wisp WS endpoint /wisp/  │
│        │                         │◀─────────────▶│    parse frames, mux/demux  │
│        ▼                         │  (multiplex)  │        │                    │
│ libcurl transport (WASM,         │               │ 3. TCP relay (one tokio     │──▶ target
│   Wisp client; HTTP/TLS here)    │               │    task per Wisp stream)    │    sites
└──────────────────────────────────┘               └─────────────────────────────┘
```

### Data flow

1. User types URL, presses Go.
2. Frontend registers the Scramjet service worker, waits for it to be active, sets the
   bare-mux transport to libcurl pointing at `wss://<host>/wisp/`, then navigates the tab
   top-level to `scramjet.encodeUrl(url)`.
3. The service worker intercepts that navigation and every resource request the loaded
   page makes, rewrites URLs, and issues the real requests via libcurl (WASM).
4. libcurl opens Wisp streams over a single WebSocket to `/wisp/`.
5. Our Rust Wisp server opens a raw TCP socket per stream to the target host:port and
   relays bytes both ways. TLS/HTTP live entirely in the browser's WASM, so the server
   never parses HTTP and streams by default.

## Components (Rust)

### `src/config.rs`
Runtime config from env vars: bind address, port, Wisp buffer size, connect timeout,
`block_private` SSRF guard flag, hostname blacklist. Sensible defaults.

### `src/wisp.rs` — Wisp v1 protocol
Wire format (all little-endian): `[type: u8][stream_id: u32][payload]`.
Packet types: `CONNECT 0x01`, `DATA 0x02`, `CONTINUE 0x03`, `CLOSE 0x04`.

Server behavior:
- On WebSocket open, immediately send `CONTINUE(stream_id=0, buffer_remaining=BUFFER_SIZE)`
  (stream 0 signals Wisp v1 + the initial per-stream credit).
- **Read loop** (one per connection) parses each binary WS message as one packet:
  - `CONNECT`: parse stream type / port / hostname. TCP only (UDP refused with `CLOSE 0x41`).
    Create an unbounded per-stream data channel, register it in a `HashMap<stream_id, handle>`,
    spawn a stream task.
  - `DATA`: push payload into that stream's data channel (routing only; no blocking → no
    head-of-line blocking between streams).
  - `CLOSE`: remove the stream (drops its data sender and aborts its task → TCP closed).
  - `CONTINUE` from client / unknown types: ignored.
- **Stream task** (one per stream):
  - Connect TCP with timeout. On failure send `CLOSE` with the mapped reason
    (`0x42` unreachable, `0x43` timeout, `0x44` refused, `0x41` invalid).
  - client→TCP: drain the data channel, `write_all` to the socket. After every
    `BUFFER_SIZE/2` packets drained, send `CONTINUE(stream_id, BUFFER_SIZE)` to replenish
    the client's send credit — this is the flow-control window (bounds in-flight memory to
    ~BUFFER_SIZE packets without ever stalling).
  - TCP→client: read from the socket, wrap bytes in `DATA(stream_id, …)`, send to the
    shared WS-writer channel. On EOF/error send `CLOSE(stream_id, reason)` and self-remove.
- **WS writer task** (one per connection) owns the WebSocket sink; all streams send
  outgoing packets through a bounded mpsc to it, serializing writes and providing
  backpressure toward slow clients.
- On WebSocket drop, all stream tasks are aborted and sockets closed.

### `src/main.rs` — axum server
- Routes: `/wisp/` (WebSocket upgrade → Wisp handler); static `ServeDir`s for `/scram/`,
  `/baremux/`, `/libcurl/`, and the frontend at `/`.
- Middleware sets `Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Embedder-Policy: require-corp` on all responses (Scramjet + WASM require
  cross-origin isolation). Correct MIME for `.wasm`, `.mjs`.
- tokio multi-thread runtime; `tracing` logs.

## Frontend (`static/`)

- `index.html` — loads `/scram/scramjet.all.js` and `/baremux/index.js`, then our
  `register-sw.js`, `search.js`, `index.js`. URL input + Go form.
- `search.js` — normalizes input into a URL (or a Google search query fallback).
- `register-sw.js` — registers `/sw.js` (allows http on localhost).
- `sw.js` — `importScripts('/scram/scramjet.all.js')`, create `ScramjetServiceWorker`,
  handle `fetch` via `scramjet.route`/`scramjet.fetch`.
- `index.js` — construct `ScramjetController({files:{wasm,all,sync}})`, `init()`, create
  `BareMux.BareMuxConnection('/baremux/worker.js')`; on submit: register SW, wait for
  `serviceWorker.ready`, `setTransport('/libcurl/index.mjs', [{ websocket: wispUrl }])`,
  then `scramjet.createFrame()` and `frame.go(url)` into a full-viewport iframe (see the
  frontend correction above — top-level navigation kills the transport).

## Asset vendoring (`scripts/fetch-assets.mjs`)

Node script: `npm install` the three client packages into a temp dir, then copy their
`dist` outputs into `static/scram`, `static/baremux`, `static/libcurl`. Pinned to the
versions used by the official Scramjet-App demo so they interoperate:
`@mercuryworkshop/scramjet` (v1.1.0 release tgz), `@mercuryworkshop/bare-mux@^2.1.9`,
`@mercuryworkshop/libcurl-transport@^1.5.2`. Vendored assets are committed so runtime is
pure Rust (no Node needed to run).

## Performance ("no lag")

- Wisp multiplexes many streams over one WebSocket → low per-resource overhead.
- Pure streaming relay (never buffer whole bodies) → video / range requests stay smooth.
- Windowed flow control (Wisp CONTINUE) + bounded WS-writer channel → backpressure without
  unbounded memory; unbounded per-stream data channel avoids head-of-line blocking.
- `bytes::Bytes` to avoid copies; disable WebSocket permessage-deflate for binary.
- tokio multi-thread; connect + idle timeouts.

## Error handling & security

- Invalid frame / bad CONNECT / DNS failure / connect refused / timeout → `CLOSE` with the
  specific Wisp reason code; malformed packets never crash the connection.
- WebSocket drop → tear down every stream for that connection.
- Optional SSRF guard (`block_private`, default off for personal use): resolve target and
  refuse RFC1918/loopback/link-local with `CLOSE 0x48`. Hostname blacklist supported.
- No auth (personal use); documented as such. Requires secure context (https or localhost)
  because service workers demand it.

## Testing

- Unit: Wisp packet encode/decode round-trips; CONNECT payload parsing incl. malformed input.
- Integration: start the Wisp server, connect a WebSocket client, perform the handshake,
  CONNECT to a local TCP echo server, send DATA, assert echoed DATA returns; assert CLOSE
  tears down.
- End-to-end (manual, via browser-harness): load a real site and a video through the
  frontend; confirm it renders and plays.

## Out of scope (YAGNI)

Multi-user isolation, auth, per-user cookie jars, UDP/QUIC streams, a fancy browser UI
(back/forward/history), Bare-v3 transport fallback. Architecture leaves room to add later.

## Implementation order

1. Rust scaffold (Cargo.toml, modules).
2. `wisp.rs` + unit tests.
3. `main.rs` server + headers + static routes.
4. Frontend files.
5. `fetch-assets.mjs`; vendor assets.
6. Integration test.
7. Build, test, end-to-end verify.
```
