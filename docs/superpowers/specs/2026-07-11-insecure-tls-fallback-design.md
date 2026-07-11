# Insecure-TLS Fallback: libcurl → epoxy on cert-verification failure — Design Spec

Date: 2026-07-11

Lets the proxy load sites whose TLS certificate fails verification (curl error 60,
`CURLE_PEER_FAILED_VERIFICATION` — "SSL peer certificate or SSH remote key was not OK").
The reported trigger: `https://vlxx.moi/` fails inside the client-side libcurl-WASM TLS stack,
so the whole page (and every subresource) never loads.

## Where TLS actually happens (the key fact)

This proxy is a **raw TCP / Wisp tunnel**. The Rust server ([src/route.rs](../../../src/route.rs))
never terminates TLS to the target; it forwards bytes. The **TLS handshake and certificate
verification run in the browser**, inside the libcurl WASM transport
([static/libcurl/index.mjs](../../../static/libcurl/index.mjs), libcurl.js v0.7.4 = curl +
mbedTLS). So a "bypass TLS check" option cannot live in `dns.rs` or anywhere server-side — it
must change the client TLS engine.

libcurl.js source review (upstream `client/libcurl/{http,request,certs}.c`):
- `create_request` sets `CURLOPT_CAINFO_BLOB` to a **compiled-in CA bundle** and never sets
  `CURLOPT_SSL_VERIFYPEER`/`CURLOPT_SSL_VERIFYHOST`, so verification is on and pinned to that
  bundle.
- `http_set_options` reads only `_libcurl_verbose`, `_libcurl_http_version`, `method`,
  `headers`, `redirect` — **no** verify/insecure key, and no global JS API for it.

**Conclusion:** the vendored libcurl WASM offers no JS-level way to skip verification. Fixing
this requires a TLS engine that does. The alternative Wisp transport **epoxy**
(`@mercuryworkshop/epoxy-tls`, Rust + rustls in WASM) exposes
`EpoxyClientOptions.disable_certificate_validation: boolean` — a first-class `curl -k`.

## Goal / chosen behavior (from brainstorming)

Deploy **both** transports. Keep **libcurl as the default** (verified TLS, best site
compatibility). When a request fails specifically with a **cert-verification error**, retry that
request through **epoxy with `disable_certificate_validation: true`**. The epoxy path is
**always insecure** (no per-session toggle); it is only ever reached as a fallback, so verified
sites keep verified TLS and only cert-broken hosts get the unverified path. Automatic,
per-request, no page reload, no new UI.

## Architecture

A new **hybrid BareMux transport** composes the two existing transports behind BareMux's
transport interface (`init()`/`ready`, `request(url, method, body, headers, signal)` →
`{body, headers, status, statusText}`, `connect(...)` → `[send, close]` — verified against
[static/baremux/index.mjs](../../../static/baremux/index.mjs)). The frontend points bare-mux at
the hybrid instead of libcurl; nothing else changes.

```
index.js  --setTransport("/hybrid/index.mjs", [{websocket: wispUrl}])-->  bare-mux worker
                                                                              │ import()
                                                                              ▼
                                                    static/hybrid/index.mjs  (default export)
                                                       ├── LibcurlClient  (/libcurl/index.mjs)  [primary, verified]
                                                       └── epoxy          (/epoxy/epoxy.js)     [fallback, insecure]
```

Both transports dial the **same** Rust `/wisp/<route>/<dns>/` endpoint — the server is untouched.

## Components

### 1. Vendored epoxy — `static/epoxy/epoxy.js`
Copy of `@mercuryworkshop/epoxy-tls` `full/epoxy-bundled.js` (v2.1.19-1): the full build
(HTTP/2 + WebSockets) with the WASM inlined as base64, so it is one self-contained ESM file —
no separate `.wasm` route or MIME concern. Exports: default `init()` (no args; bundled),
`EpoxyClient`, `EpoxyClientOptions` (`.disable_certificate_validation`, `.user_agent`,
`.pem_files`), `EpoxyHandlers`. Added to `scripts/package.json` +
[scripts/fetch-assets.mjs](../../../scripts/fetch-assets.mjs) so re-vendoring is reproducible.
Committed to git like the other `static/` assets (`.gitignore` doesn't exclude `static/`).

**Response adaptation (a correctness requirement, found in verification).** epoxy's `fetch()`
returns a decoded, dechunked body but with `content-encoding` / `transfer-encoding` /
`content-length` still in its headers, and it exposes headers as `res.rawHeaders`. The hybrid's
epoxy→bare-mux adapter must therefore match what the libcurl transport returns: (a) **drop**
those encoding/length headers (they no longer describe the decoded body; forwarding
`content-encoding: gzip` makes the browser mangle the document), and (b) shape `headers` as an
**object whose values are arrays** (`{ "content-type": ["text/html"] }`), because Scramjet looks
headers up by key — an array-of-pairs loses every header and the page is served as `text/plain`.

### 2. Hybrid transport — `static/hybrid/index.mjs` (repo-authored glue, not vendored)
Default-exported class implementing the BareMux transport contract.
- Static `import LibcurlClient from "/libcurl/index.mjs"`. Epoxy is **lazily** loaded
  (`await import("/epoxy/epoxy.js")` + `init()` + client construction) on the **first** cert
  fallback, keeping epoxy's ~1.7 MB out of startup for the common (all-verified) case.
- Holds `insecureHosts: Set<string>` — hosts known to have failed verification this session.
- `init()`: construct + init the libcurl client eagerly (today's behavior).
- `request(remote, method, body, headers, signal)`:
  1. **Buffer `body` once** into a `Uint8Array` (a `ReadableStream` can only be read once; GET /
     navigations are null → no-op) so the request can be replayed on retry.
  2. If `remote.host ∈ insecureHosts` → go straight to epoxy.
  3. Else call libcurl. On success, return it. On a **cert-verification error**, add the host to
     `insecureHosts` and retry via epoxy. **Any other error is rethrown unchanged** (fail like
     today — we only relax TLS verification, nothing else).
- `connect(url, …)` (WebSocket): if `url.host ∈ insecureHosts` → epoxy, else libcurl. libcurl's
  WS wrapper surfaces no error code, so a WS can't self-detect a cert failure; but a page loads
  its document over HTTP first, which marks the host insecure, so its `wss://` follows.
- `meta()`: delegate to libcurl (no-op today).

### 3. Wire-up — `static/index.js`
One line: `ensureTransport()` calls `setTransport("/hybrid/index.mjs", …)` instead of
`"/libcurl/index.mjs"`. The `activeWispUrl` guard compares against `/hybrid/index.mjs`. The
`wispUrl()` route/DNS path logic is unchanged.

## Cert-error detection

libcurl's transport rejects with `TypeError("Request failed with error code <N>: <msg>")`.
Parse `N` via `/error code (\d+)/` and treat **60** (`CURLE_PEER_FAILED_VERIFICATION`, the
reported one) and **51** (its historical/deprecated code on some builds) as cert-verification
failures. Everything else rethrows. Matching on the numeric code (not the localized message) is
locale-stable.

## Data flow (the reported case, `vlxx.moi`)

1. Document GET for `vlxx.moi` → hybrid → libcurl → mbedTLS rejects the cert → error 60.
2. Hybrid adds `vlxx.moi` to `insecureHosts`, lazily inits epoxy, retries the GET via epoxy with
   verification off → 200, document streams back.
3. Each subresource on `vlxx.moi`: host already in `insecureHosts` → straight to epoxy (no
   wasted failing libcurl attempt). Subresources on other, valid-cert hosts → libcurl (verified).

## Error handling / edge cases

- **Non-cert errors** (refused, timeout, DNS, 4xx/5xx) propagate unchanged — no behavior change.
- **Body replay**: buffered to `Uint8Array` before the first attempt; both engines accept a
  buffer body. Large uploads buffer in memory (acceptable for this tool; unchanged from
  today's single-attempt semantics for the success path).
- **Epoxy load/dial failure** on the fallback: surfaces as the request error (the site simply
  fails, as it does today) — we do not silently fall back further.
- **AbortSignal** is threaded to whichever engine runs.

## Security note (explicit)

This **silently downgrades to unverified TLS** for any host whose certificate fails
verification, enabling undetectable MITM against exactly those hosts. This is the user's
explicit intent ("xử lý bằng mọi cách"), but it is a deliberate departure from the codebase's
otherwise fail-closed posture (SSRF guard, blacklist, fail-closed DNS). Verified hosts are
unaffected: they never touch the epoxy path.

## Testing / verification

- `cargo build` — no Rust changes; confirms nothing broke.
- Manual end-to-end via browser-harness against **badssl.com** (deterministic, no adult
  content): `https://self-signed.badssl.com/` and `https://expired.badssl.com/` should load
  (fallback fires), while `https://example.com/` still loads via libcurl (verified path intact).
- Sanity that a normal site still works (libcurl primary path unregressed).

## Out of scope / not done

- No settings-UI toggle (chosen: always-insecure fallback).
- No libcurl WASM rebuild (rejected: needs the emscripten/curl/mbedTLS toolchain).
- No server-side TLS termination (rejected: breaks the raw-tunnel model, server would see
  plaintext).
