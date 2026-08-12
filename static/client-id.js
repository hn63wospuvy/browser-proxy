"use strict";

// Stable per-browser identity for profile sync (`GET`/`PUT /api/profiles/<id>`).
//
// This is separation, not authentication: the ID is derived from a fingerprint and sent by the
// client, so it proves nothing — it only says "same browser as last time". A fingerprint is used
// instead of a random UUID for one property: clearing localStorage wipes the cached ID, but
// recomputing it on the same browser lands on the same value, so the server hands the profiles
// back. The cache covers the opposite failure — a browser update that shifts the fingerprint must
// not orphan the stored document — so a usable cached ID always wins over a fresh computation.
//
// Everything is wrapped in an IIFE exposing exactly one global, because the shell loads this as a
// classic script alongside index.js: top-level `const`s share one global lexical scope, and a name
// collision there is a hard SyntaxError that kills whichever file parses second.
(function () {
  const CACHE_KEY = "proxy-client-id";
  // Exactly what the server accepts. A cached value that fails this is treated as corrupt and
  // recomputed — sending it would 400 on every request forever.
  const ID_RE = /^[0-9a-f]{32}$/;

  function readCache() {
    try {
      return localStorage.getItem(CACHE_KEY);
    } catch (_) {
      return null; // storage blocked (third-party context, hardened privacy settings)
    }
  }
  function writeCache(id) {
    try {
      localStorage.setItem(CACHE_KEY, id);
    } catch (_) {
      /* storage blocked/full: the ID stays stable for this session via the promise cache below */
    }
  }

  function hex(bytes) {
    let out = "";
    for (const b of bytes) out += b.toString(16).padStart(2, "0");
    return out;
  }

  // FNV-1a. Only used to fold bulky probes (the canvas data URL) down to a few chars — SHA-256
  // below does the real mixing, this just keeps the joined string from being a 10 KB data URI.
  function fold(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0).toString(16);
  }

  // Each probe runs in its own try/catch: a blocked or missing API (no WebGL, canvas readback
  // denied, `deviceMemory` absent) must only remove entropy, never throw the whole ID away. A
  // dropped probe shifts the remaining fields, which is harmless — the set of available APIs is
  // itself stable per browser, so the joined string stays stable too.
  function fingerprint() {
    const parts = [];
    const probe = (fn) => {
      try {
        parts.push(String(fn()));
      } catch (_) {
        /* entropy lost, ID still computable */
      }
    };

    probe(() => navigator.userAgent);
    probe(() => navigator.platform);
    probe(() => navigator.language + "," + (navigator.languages || []).join(","));
    probe(() => navigator.hardwareConcurrency);
    probe(() => navigator.deviceMemory);
    probe(() => Intl.DateTimeFormat().resolvedOptions().timeZone);
    probe(() => screen.width + "x" + screen.height + "x" + screen.colorDepth);
    probe(() => devicePixelRatio);
    probe(() => navigator.maxTouchPoints);
    // GPU model. `getExtension` returns null where the debug info is hidden (Firefox's
    // resistFingerprinting, some mobile drivers), so the property read throws and the probe drops.
    probe(() => {
      const gl = document.createElement("canvas").getContext("webgl");
      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      return gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
    });
    // A fixed 2D render: the exact pixels depend on the platform's font rasteriser and GPU, which
    // is the point. `toDataURL()` throws in browsers that block canvas readback.
    probe(() => {
      const cv = document.createElement("canvas");
      cv.width = 120;
      cv.height = 40;
      const ctx = cv.getContext("2d");
      ctx.fillStyle = "#f60";
      ctx.fillRect(10, 5, 60, 20);
      ctx.fillStyle = "#069";
      ctx.font = "14px Arial";
      ctx.textBaseline = "alphabetic";
      ctx.fillText("browser-proxy", 2, 30);
      return fold(cv.toDataURL());
    });

    // "|" delimits the fields so two neighbouring values can't blur into one another.
    return parts.join("|");
  }

  // 16 random bytes, hex. Deliberately NOT `crypto.randomUUID`: that is secure-context-only, so it
  // is undefined in exactly the situation this fallback exists for — and its 36-char dashed form
  // would fail both ID_RE and the server's check anyway.
  function randomId() {
    const bytes = new Uint8Array(16);
    try {
      crypto.getRandomValues(bytes);
    } catch (_) {
      // Last resort so the "always 32 hex" contract holds even without a usable `crypto`. The ID
      // only needs to be unique, never unguessable — it guards nothing.
      for (let i = 0; i < bytes.length; i++) bytes[i] = (Math.random() * 256) | 0;
    }
    return hex(bytes);
  }

  async function compute() {
    const cached = readCache();
    if (cached && ID_RE.test(cached)) return cached;

    let id;
    try {
      // No `crypto.subtle` means a non-secure context (plain HTTP off localhost). Sync still works
      // from a random ID; only cross-clear recovery is lost, and the shape stays identical.
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(fingerprint()));
      id = hex(new Uint8Array(digest).subarray(0, 16)); // first 16 bytes = the 32 hex chars
    } catch (_) {
      id = randomId();
    }
    writeCache(id);
    return id;
  }

  let pending = null;

  /**
   * Resolve this browser's client ID: a 32-character lowercase hex string. Exposed globally and
   * called from index.js / the sync path. Never rejects — a failure downgrades to a random ID.
   */
  function clientId() {
    // The in-flight promise is cached, not just the result: two callers racing before the first
    // localStorage write would otherwise each compute (and cache) a different random fallback ID,
    // splitting the user's profiles across two server documents.
    if (!pending) pending = compute();
    return pending;
  }

  window.clientId = clientId;
})();
