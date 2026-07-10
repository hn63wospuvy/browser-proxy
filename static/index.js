"use strict";

const form = document.getElementById("proxy-form");
const address = document.getElementById("proxy-address");
const statusEl = document.getElementById("proxy-status");
const errorEl = document.getElementById("proxy-error");
const errorCode = document.getElementById("proxy-error-code");
const frameHost = document.getElementById("frame-host");

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

// bare-mux connection; the libcurl transport (and its Wisp WebSocket) runs in the bare-mux
// SharedWorker owned by THIS page. We keep this page alive and render the proxied site in an
// iframe — a top-level navigation would tear this page down and kill the transport, so only
// the first request would succeed and every subresource would fail.
const connection = new BareMux.BareMuxConnection("/baremux/worker.js");

// Reused across navigations so the transport/frame stay alive.
let frame = null;

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
    statusEl.textContent = "Starting…";
    await registerSW();
    await navigator.serviceWorker.ready;
    await ensureTransport();

    if (!frame) {
      frame = scramjet.createFrame();
      frame.frame.id = "sj-frame";
      frameHost.appendChild(frame.frame);
    }
    document.body.classList.add("browsing"); // reveal the frame, hide the landing
    statusEl.textContent = "";
    frame.go(target);
  } catch (err) {
    statusEl.textContent = "";
    errorEl.textContent = "Failed to start the proxy.";
    errorCode.textContent = String(err && err.stack ? err.stack : err);
    console.error(err);
  }
});
