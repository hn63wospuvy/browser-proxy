"use strict";

const form = document.getElementById("proxy-form");
const address = document.getElementById("proxy-address");
const statusEl = document.getElementById("proxy-status");
const errorEl = document.getElementById("proxy-error");
const errorCode = document.getElementById("proxy-error-code");

const SEARCH_TEMPLATE = "https://www.google.com/search?q=%s";

// Scramjet controller: knows where its wasm/runtime files live.
const { ScramjetController } = $scramjetLoadController();
const scramjet = new ScramjetController({
  files: {
    wasm: "/scram/scramjet.wasm.wasm",
    all: "/scram/scramjet.all.js",
    sync: "/scram/scramjet.sync.js",
  },
});
scramjet.init();

// bare-mux connection; the chosen transport is stored in a SharedWorker and reused by the
// service worker after we navigate top-level.
const connection = new BareMux.BareMuxConnection("/baremux/worker.js");

function wispUrl() {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${location.host}/wisp/`;
}

/** Point bare-mux at our Rust Wisp backend via the libcurl transport (idempotent). */
async function ensureTransport() {
  if ((await connection.getTransport()) !== "/libcurl/index.mjs") {
    await connection.setTransport("/libcurl/index.mjs", [{ websocket: wispUrl() }]);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorEl.textContent = "";
  errorCode.textContent = "";

  const target = search(address.value.trim(), SEARCH_TEMPLATE);
  if (!target) return;

  try {
    statusEl.textContent = "Starting proxy…";
    await registerSW();
    await navigator.serviceWorker.ready;
    await ensureTransport();

    // Top-level navigation: the whole tab becomes the proxied site.
    const encoded = await scramjet.encodeUrl(target);
    statusEl.textContent = "Loading…";
    window.location.href = encoded;
  } catch (err) {
    statusEl.textContent = "";
    errorEl.textContent = "Failed to start the proxy.";
    errorCode.textContent = String(err && err.stack ? err.stack : err);
    console.error(err);
  }
});
