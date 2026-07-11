// Hybrid bare-mux transport: libcurl by default, epoxy (insecure) as a cert-failure fallback.
//
// Why this exists: TLS to the target is terminated in the browser by the vendored libcurl WASM
// (curl + mbedTLS), which verifies certificates against a compiled-in CA bundle and exposes no
// way to disable that check. So a site whose cert fails verification (curl error 60,
// CURLE_PEER_FAILED_VERIFICATION — "SSL peer certificate or SSH remote key was not OK") can never
// load. epoxy (rustls in WASM) does expose `disable_certificate_validation`, so we keep libcurl
// as the verified default and, only when a request fails specifically on cert verification, retry
// that request through an insecure epoxy client — but ONLY after the user grants per-host consent.
// This transport runs in the bare-mux SharedWorker and can't show UI, so it asks the page over a
// BroadcastChannel and waits for a decision (fail closed if none arrives). Verified hosts never
// touch the epoxy path; a host the user declines keeps failing with its cert error.
//
// See docs/superpowers/specs/2026-07-11-insecure-tls-fallback-design.md.

import LibcurlClient from "/libcurl/index.mjs";

// curl error codes that mean "the peer certificate failed verification". 60 is the modern code
// (and the one the user hit); 51 is its historical value on some builds. We match the numeric
// code parsed from libcurl's error message, not the localized text, so this is locale-stable.
const CERT_VERIFY_CODES = new Set([60, 51]);

// Consent channel to the page (see static/index.js). The page shows a confirm dialog and posts
// back {type:"tls-answer", host, allow}; we post {type:"tls-ask", host}. Fail closed if nobody
// answers within the timeout (e.g. the page was closed) — never downgrade TLS without a yes.
const CONSENT_CHANNEL = "hybrid-tls-consent";
const CONSENT_TIMEOUT_MS = 60000;

function isCertVerifyError(err) {
  const msg = err && err.message ? err.message : String(err);
  const m = /error code (\d+)/.exec(msg);
  return m ? CERT_VERIFY_CODES.has(Number(m[1])) : false;
}

// Read a request body once so a failed libcurl attempt can be replayed through epoxy. A
// ReadableStream is single-use, so it must be drained up front; a buffer/string is already
// replayable, and no body (GET / navigations — the common case) costs nothing.
async function bufferBody(body) {
  if (body == null) return null;
  if (body instanceof ReadableStream) {
    return new Uint8Array(await new Response(body).arrayBuffer());
  }
  return body;
}

// bare-mux v2.1.9 hands `request()` headers as a plain object, but normalize defensively so a
// Headers instance or an array of pairs also works. epoxy's fetch wants a plain object.
function toHeaderObject(headers) {
  if (!headers) return {};
  if (headers instanceof Headers) return Object.fromEntries(headers);
  if (Array.isArray(headers)) return Object.fromEntries(headers);
  return headers;
}

// Headers that describe the *encoded* body and must be dropped once it has been decoded.
// epoxy hands back a fully decoded, dechunked body but leaves these in `rawHeaders`; forwarding
// e.g. `content-encoding: gzip` on already-decompressed bytes makes the browser (via Scramjet)
// mis-handle the document and render it as plaintext. libcurl strips them for us, so match that.
const STRIP_RESP_HEADERS = new Set(["content-encoding", "content-length", "transfer-encoding"]);

// Adapt an epoxy fetch() Response to the bare-mux transport return shape. It MUST match what the
// libcurl transport returns so the downstream (bare-mux + Scramjet) reads it the same way:
// `headers` is an **object whose values are arrays** (`{ "content-type": ["text/html"] }`) —
// Scramjet looks headers up by key (`rawHeaders["content-type"]`), so an array-of-pairs would
// lose every header and the document would be served as text/plain. epoxy exposes the same
// object-with-array-values via `res.rawHeaders`; fall back to the standard Headers if absent.
function epoxyResponseToTransport(res) {
  const headers = {};
  const add = (key, value) => {
    if (STRIP_RESP_HEADERS.has(key.toLowerCase())) return;
    (headers[key] ??= []).push(value);
  };
  const raw = res.rawHeaders;
  if (raw) {
    for (const [key, value] of Object.entries(raw)) {
      if (Array.isArray(value)) for (const v of value) add(key, v);
      else add(key, value);
    }
  } else {
    for (const [key, value] of res.headers) add(key, value);
  }
  return { body: res.body, headers, status: res.status, statusText: res.statusText };
}

export default class HybridTransport {
  constructor(options) {
    this.options = options;
    // index.js passes { websocket: url }; LibcurlClient accepts `wisp` or `websocket`.
    this.wisp = options.wisp ?? options.websocket;
    this.libcurl = new LibcurlClient(options);

    this.epoxyMod = null; // the imported epoxy module (for EpoxyHandlers in connect())
    this.epoxy = null; // the constructed insecure EpoxyClient
    this.epoxyInit = null; // in-flight init promise, so concurrent callers share one init

    // Per-host TLS consent (session-scoped, i.e. this transport instance's lifetime).
    this.allowedHosts = new Set(); // user approved the insecure path for these
    this.deniedHosts = new Set(); // user rejected — keep failing, never go insecure
    this.pendingConsent = new Map(); // host -> {promise, resolve, timer}: one in-flight prompt/host
    this.consent = new BroadcastChannel(CONSENT_CHANNEL);
    this.consent.onmessage = (e) => {
      const d = e.data;
      if (!d || d.type !== "tls-answer") return;
      const entry = this.pendingConsent.get(d.host);
      if (!entry) return; // already resolved (timeout, or another tab answered first)
      clearTimeout(entry.timer);
      this.pendingConsent.delete(d.host);
      (d.allow ? this.allowedHosts : this.deniedHosts).add(d.host);
      entry.resolve(!!d.allow);
    };

    this.ready = false;
  }

  // Ask the page whether to proceed insecurely for `host`. Cached per host; concurrent requests
  // to the same host share one prompt. A timeout fails closed for that request WITHOUT caching a
  // denial (the user may have just been slow), so a later request re-asks.
  askConsent(host) {
    if (this.allowedHosts.has(host)) return Promise.resolve(true);
    if (this.deniedHosts.has(host)) return Promise.resolve(false);
    const existing = this.pendingConsent.get(host);
    if (existing) return existing.promise;

    let resolve;
    const promise = new Promise((r) => (resolve = r));
    const timer = setTimeout(() => {
      if (this.pendingConsent.delete(host)) resolve(false);
    }, CONSENT_TIMEOUT_MS);
    this.pendingConsent.set(host, { promise, resolve, timer });
    this.consent.postMessage({ type: "tls-ask", host });
    return promise;
  }

  async init() {
    await this.libcurl.init();
    this.ready = true;
  }

  async meta() {}

  // Build the insecure epoxy client on first use only — keeps epoxy's ~1.7 MB out of startup for
  // the common all-verified case. Memoized; the promise is cleared on failure so a transient
  // error (network, wasm) doesn't permanently disable the fallback.
  ensureEpoxy() {
    if (this.epoxy) return Promise.resolve(this.epoxy);
    if (!this.epoxyInit) {
      this.epoxyInit = this.#initEpoxy().catch((e) => {
        this.epoxyInit = null;
        throw e;
      });
    }
    return this.epoxyInit;
  }

  async #initEpoxy() {
    const epoxy = await import("/epoxy/epoxy.js");
    await epoxy.default(); // __wbg_init — bundled build inlines the wasm, so no argument
    const opts = new epoxy.EpoxyClientOptions();
    opts.user_agent = navigator.userAgent;
    opts.disable_certificate_validation = true; // curl -k: the entire reason epoxy is here
    this.epoxyMod = epoxy;
    this.epoxy = new epoxy.EpoxyClient(this.wisp, opts);
    return this.epoxy;
  }

  async epoxyRequest(remote, method, body, headers) {
    const client = await this.ensureEpoxy();
    const res = await client.fetch(remote.href, {
      method,
      body: body ?? undefined,
      headers: toHeaderObject(headers),
      redirect: "manual",
    });
    return epoxyResponseToTransport(res);
  }

  async request(remote, method, body, headers, signal) {
    const buffered = await bufferBody(body);
    const host = remote.host;

    // Host already approved insecure → skip the doomed libcurl attempt and its wasted round-trip.
    if (this.allowedHosts.has(host)) {
      return this.epoxyRequest(remote, method, buffered, headers);
    }

    try {
      return await this.libcurl.request(remote, method, buffered, headers, signal);
    } catch (err) {
      // Only relax TLS verification — every other failure (refused, timeout, DNS, HTTP status)
      // propagates unchanged, exactly as today.
      if (!isCertVerifyError(err)) throw err;
      // Never auto-downgrade: ask the user first. Declined (or no answer) → surface the cert error.
      const allow = await this.askConsent(host);
      if (!allow) throw err;
      console.warn(`[hybrid] user approved insecure TLS for ${host}; retrying via epoxy`);
      return this.epoxyRequest(remote, method, buffered, headers);
    }
  }

  connect(url, protocols, requestHeaders, onopen, onmessage, onclose, onerror) {
    let host = "";
    try {
      host = new URL(url.toString()).host;
    } catch {
      /* leave host empty → never treated as insecure */
    }
    // libcurl's WebSocket surfaces no error code, so a wss:// can't self-detect a cert failure.
    // But a page loads its document over HTTP first; if the user approved that host's insecure
    // path, its sockets to that host follow onto epoxy here (no separate prompt).
    if (this.allowedHosts.has(host)) {
      return this.epoxyConnect(url, protocols, requestHeaders, onopen, onmessage, onclose, onerror);
    }
    return this.libcurl.connect(url, protocols, requestHeaders, onopen, onmessage, onclose, onerror);
  }

  epoxyConnect(url, protocols, requestHeaders, onopen, onmessage, onclose, onerror) {
    const headersObj = toHeaderObject(requestHeaders);
    // Defer handler construction + connect until epoxy is ready (it always is by the time a host
    // is in allowedHosts, but this stays correct even if not). The send/close closures await the
    // same promise.
    const wsPromise = this.ensureEpoxy().then((client) => {
      const handlers = new this.epoxyMod.EpoxyHandlers(
        () => onopen(""),
        () => onclose(1000, "Closed by remote"),
        onerror,
        (data) => (data instanceof Uint8Array ? onmessage(data.buffer) : onmessage(data))
      );
      return client.connect_websocket(handlers, url.toString(), protocols, headersObj);
    });
    return [
      async (data) => {
        if (data instanceof Blob) data = await data.arrayBuffer();
        (await wsPromise).send(data);
      },
      async (code, reason) => {
        (await wsPromise).close(code, reason || "");
      },
    ];
  }
}
