// Hybrid bare-mux transport: libcurl by default, epoxy (insecure) as a cert-failure fallback.
//
// Why this exists: TLS to the target is terminated in the browser by the vendored libcurl WASM
// (curl + mbedTLS), which verifies certificates against a compiled-in CA bundle and exposes no
// way to disable that check. So a site whose cert fails verification (curl error 60,
// CURLE_PEER_FAILED_VERIFICATION — "SSL peer certificate or SSH remote key was not OK") can never
// load. epoxy (rustls in WASM) does expose `disable_certificate_validation`, so we keep libcurl
// as the verified default and, only when a request fails specifically on cert verification, retry
// that request through an insecure epoxy client. Verified hosts never touch the epoxy path.
//
// See docs/superpowers/specs/2026-07-11-insecure-tls-fallback-design.md.

import LibcurlClient from "/libcurl/index.mjs";

// curl error codes that mean "the peer certificate failed verification". 60 is the modern code
// (and the one the user hit); 51 is its historical value on some builds. We match the numeric
// code parsed from libcurl's error message, not the localized text, so this is locale-stable.
const CERT_VERIFY_CODES = new Set([60, 51]);

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
    this.insecureHosts = new Set(); // hosts whose cert failed verification this session

    this.ready = false;
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

    // Host already known to fail verification → skip the doomed libcurl attempt and its wasted
    // round-trip; go straight to epoxy.
    if (this.insecureHosts.has(host)) {
      return this.epoxyRequest(remote, method, buffered, headers);
    }

    try {
      return await this.libcurl.request(remote, method, buffered, headers, signal);
    } catch (err) {
      // Only relax TLS verification — every other failure (refused, timeout, DNS, HTTP status)
      // propagates unchanged, exactly as today.
      if (!isCertVerifyError(err)) throw err;
      this.insecureHosts.add(host);
      console.warn(`[hybrid] cert verification failed for ${host}; retrying insecurely via epoxy`);
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
    // But a page loads its document over HTTP first, which marks the host insecure, so its
    // sockets to that host follow onto epoxy here.
    if (this.insecureHosts.has(host)) {
      return this.epoxyConnect(url, protocols, requestHeaders, onopen, onmessage, onclose, onerror);
    }
    return this.libcurl.connect(url, protocols, requestHeaders, onopen, onmessage, onclose, onerror);
  }

  epoxyConnect(url, protocols, requestHeaders, onopen, onmessage, onclose, onerror) {
    const headersObj = toHeaderObject(requestHeaders);
    // Defer handler construction + connect until epoxy is ready (it always is by the time a host
    // is in insecureHosts, but this stays correct even if not). The send/close closures await the
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
