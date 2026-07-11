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

## Goal / chosen behavior

Deploy **both** transports. Keep **libcurl as the default** (verified TLS, best site
compatibility). When a request fails specifically with a **cert-verification error**, retry that
request through **epoxy with `disable_certificate_validation: true`** — but only after the user
grants **per-host consent**. Verified sites keep verified TLS; a host the user approves is
remembered for the session and shown with a persistent **🔓 Insecure TLS** indicator; a host the
user declines keeps failing with its cert error.

> **Revision note.** The first cut auto-downgraded on any cert error with no prompt. An automated
> security review flagged the silent downgrade; the user then chose the per-host consent gate
> below (deny by default, explicit yes required, visible indicator). This section and the Security
> section reflect that final design.

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
  2. If `remote.host ∈ allowedHosts` (user already approved) → go straight to epoxy.
  3. Else call libcurl. On success, return it. On a **cert-verification error**, `askConsent(host)`
     (below); if approved → retry via epoxy, else **rethrow the cert error**. **Any other error is
     rethrown unchanged** (we only relax TLS verification, nothing else).
- `connect(url, …)` (WebSocket): if `url.host ∈ allowedHosts` → epoxy, else libcurl. libcurl's WS
  wrapper surfaces no error code, so a WS can't self-detect a cert failure; but a page loads its
  document over HTTP first, so an approved host's `wss://` follows (no separate prompt).
- `meta()`: delegate to libcurl (no-op today).

### 3. Per-host consent protocol (transport ⇄ page)
The transport runs in the bare-mux **SharedWorker** and can't show UI, so it asks the page over a
`BroadcastChannel("hybrid-tls-consent")`:
- `askConsent(host)`: `allowedHosts` → true, `deniedHosts` → false (both cached for the session);
  a concurrent request to the same host shares one in-flight prompt. Otherwise it posts
  `{type:"tls-ask", host}` and awaits `{type:"tls-answer", host, allow}`. **Fail closed:** if no
  answer arrives within 60 s (page closed, race), the request fails without caching a denial.
- Only an explicit answer caches the decision (`allowedHosts`/`deniedHosts`). Cross-tab: the first
  answer wins; other tabs reflect it (BroadcastChannel doesn't echo the sender).

### 4. Consent UI + indicator — `static/index.js`, `index.html`, `style.css`
- On `tls-ask`, the page shows a themed **alertdialog** ("⚠️ Chứng chỉ TLS không hợp lệ" + host +
  MITM warning + **Hủy** / **Tiếp tục (không an toàn)**), one host at a time (a small queue). It
  posts the decision back and, on approve, records the host so a persistent **🔓 Insecure TLS**
  badge (fixed, bottom-left) shows while that site is in the frame. Esc = cancel (deny). The Esc
  config-flash also lists a `TLS: ⚠ insecure` row when applicable.

### 5. Wire-up — `static/index.js`
`ensureTransport()` calls `setTransport("/hybrid/index.mjs", …)` instead of `"/libcurl/index.mjs"`
(the `activeWispUrl` guard compares against `/hybrid/index.mjs`). The `wispUrl()` route/DNS path
logic is unchanged. `updateTlsBadge()` runs on each navigation.

## Cert-error detection

libcurl's transport rejects with `TypeError("Request failed with error code <N>: <msg>")`.
Parse `N` via `/error code (\d+)/` and treat **60** (`CURLE_PEER_FAILED_VERIFICATION`, the
reported one) and **51** (its historical/deprecated code on some builds) as cert-verification
failures. Everything else rethrows. Matching on the numeric code (not the localized message) is
locale-stable.

## Data flow (the reported case, `vlxx.moi`)

1. Document GET for `vlxx.moi` → hybrid → libcurl → mbedTLS rejects the cert → error 60.
2. Hybrid `askConsent("vlxx.moi")` → the page shows the dialog. If the user clicks **Tiếp tục**,
   the host joins `allowedHosts`, epoxy lazily inits, and the GET retries via epoxy with
   verification off → 200; the document streams back and the 🔓 badge appears.
3. Each subresource on `vlxx.moi`: host already in `allowedHosts` → straight to epoxy (no wasted
   failing libcurl attempt, no re-prompt). Other, valid-cert hosts → libcurl (verified).
4. If the user clicks **Hủy**, `vlxx.moi` joins `deniedHosts` and every request to it surfaces the
   cert error (Scramjet shows its error page); nothing goes over the insecure path.

## Error handling / edge cases

- **Non-cert errors** (refused, timeout, DNS, 4xx/5xx) propagate unchanged — no behavior change.
- **Body replay**: buffered to `Uint8Array` before the first attempt; both engines accept a
  buffer body. Large uploads buffer in memory (acceptable for this tool; unchanged from
  today's single-attempt semantics for the success path).
- **Epoxy load/dial failure** on the fallback: surfaces as the request error (the site simply
  fails, as it does today) — we do not silently fall back further.
- **AbortSignal** is threaded to whichever engine runs.

## Security note (explicit)

Disabling TLS verification enables undetectable MITM, so it is gated: the downgrade happens **only
after an explicit per-host "yes"**, defaults to deny (fail closed on timeout/close), scopes the
decision to the session, and marks every insecure page with a persistent 🔓 indicator. Verified
hosts never touch the epoxy path. This keeps the feature the user asked for while respecting the
codebase's otherwise fail-closed posture (SSRF guard, blacklist, fail-closed DNS) and resolves the
automated review's "silent downgrade" finding.

## Testing / verification

- `cargo build` — no Rust changes; confirms nothing broke.
- Helper unit tests (Node, against the real module source): cert-code detection, body buffering,
  header normalization, and the epoxy→bare-mux response shape (object-with-array-values + stripped
  encoding headers).
- End-to-end via browser-harness against **badssl.com** (deterministic, no adult content):
  - `self-signed.badssl.com` → dialog shows the host → **Tiếp tục** → page renders (`text/html`,
    red bg) via epoxy, 🔓 badge visible.
  - `expired.badssl.com` → **Hủy** → page does **not** load (Scramjet error), no badge.
  - `example.com` → no dialog, renders via libcurl (verified), no badge.

## Out of scope / not done

- No libcurl WASM rebuild (rejected: needs the emscripten/curl/mbedTLS toolchain).
- No server-side TLS termination (rejected: breaks the raw-tunnel model, server would see
  plaintext).
- Consent is session-scoped (transport-instance lifetime); no persistence across restarts, and a
  route/DNS switch rebuilds the transport so an approved host is re-prompted on its next cert error.
