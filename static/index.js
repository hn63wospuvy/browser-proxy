"use strict";

const form = document.getElementById("proxy-form");
const address = document.getElementById("proxy-address");
const statusEl = document.getElementById("proxy-status");
const errorEl = document.getElementById("proxy-error");
const errorCode = document.getElementById("proxy-error-code");
const frameHost = document.getElementById("frame-host");
const routeSelect = document.getElementById("proxy-route");
const ROUTE_KEY = "proxy-route";

// Populate the route dropdown from the server. Hidden entirely when only `direct` exists,
// so users without any VPN configured see no extra control.
async function loadRoutes() {
  let routes = ["direct"];
  try {
    const res = await fetch("/routes.json");
    if (res.ok) {
      const json = await res.json();
      if (Array.isArray(json.routes) && json.routes.length) routes = json.routes;
    }
  } catch (_) {
    /* fall back to direct-only */
  }
  if (routes.length <= 1) return; // only `direct`: leave the select hidden

  routeSelect.replaceChildren();
  for (const name of routes) {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    routeSelect.appendChild(opt);
  }
  const saved = localStorage.getItem(ROUTE_KEY);
  if (saved && routes.includes(saved)) routeSelect.value = saved;
  routeSelect.hidden = false;
}

function currentRoute() {
  return routeSelect && !routeSelect.hidden ? routeSelect.value : "direct";
}

loadRoutes();

// Changing the route rebuilds the transport, which tears down the live WebSocket and every
// stream on it. Re-navigate the frame to the last target so the page reloads over the new
// route instead of dying half-loaded.
routeSelect.addEventListener("change", async () => {
  localStorage.setItem(ROUTE_KEY, routeSelect.value);
  if (!frame || !document.body.classList.contains("browsing")) return;
  try {
    await ensureTransport();
    const target = frame.__lastTarget;
    if (target) frame.go(target);
  } catch (err) {
    console.error("route switch failed", err);
  }
});

// Search engine used when the input is NOT a valid URL / IP / domain (see search.js).
// Google aggressively CAPTCHAs proxied traffic (all requests share one IP + the libcurl-WASM
// TLS fingerprint looks non-browser), so we default to a proxy-friendly engine. Swap to taste:
//   Brave      : "https://search.brave.com/search?q=%s"   (default)
//   DuckDuckGo : "https://duckduckgo.com/?q=%s"
//   DDG (lite) : "https://lite.duckduckgo.com/lite/?q=%s"
//   Bing       : "https://www.bing.com/search?q=%s"
//   Google     : "https://www.google.com/search?q=%s"     (expect CAPTCHAs via a proxy)
const SEARCH_TEMPLATE = "https://search.brave.com/search?q=%s";

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

// --- Top-bar visibility: fades out while browsing, toggled with Esc ---

let hintTimer = null;
function showHint() {
  const hint = document.getElementById("hint");
  if (!hint) return;
  hint.classList.add("show");
  clearTimeout(hintTimer);
  hintTimer = setTimeout(() => hint.classList.remove("show"), 3500);
}

function setBarHidden(hidden) {
  document.body.classList.toggle("bar-hidden", hidden);
  if (hidden) {
    showHint();
  } else {
    // Bar shown again: focus the URL box so a new destination can be typed.
    address.focus();
    address.select();
  }
}
function toggleBar() {
  setBarHidden(!document.body.classList.contains("bar-hidden"));
}
// Expose so the injected in-iframe listener can reach it via window.parent.
window.__toggleBar = toggleBar;

function isToggleKey(e) {
  return e.key === "Escape" || e.code === "Escape";
}

function onHotkey(e) {
  if (isToggleKey(e) && document.body.classList.contains("browsing")) {
    e.preventDefault();
    toggleBar();
  }
}

// Listen on the parent page (works when focus is outside the frame)...
window.addEventListener("keydown", onHotkey, true);

// ...and inside the frame on every load (the frame is same-origin, so Esc also works while
// the user is interacting with the proxied page).
function injectFrameHotkey() {
  try {
    const doc = frame.frame.contentDocument;
    if (doc) {
      doc.addEventListener(
        "keydown",
        (e) => {
          if (e.key === "Escape" || e.code === "Escape") {
            e.preventDefault();
            window.__toggleBar();
          }
        },
        true
      );
    }
  } catch (_) {
    /* frame not same-origin accessible; parent-level listener still applies */
  }
}

function wispUrl() {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  const route = currentRoute();
  const q = route && route !== "direct" ? `?route=${encodeURIComponent(route)}` : "";
  return `${scheme}://${location.host}/wisp/${q}`;
}

/**
 * Point bare-mux at our Wisp backend for the CURRENT route. Idempotent per URL: a route
 * change alters the URL, which forces a fresh setTransport (rebuilding the SharedWorker
 * transport and dropping the old WebSocket).
 */
let activeWispUrl = null;
async function ensureTransport() {
  const url = wispUrl();
  if ((await connection.getTransport()) !== "/libcurl/index.mjs" || activeWispUrl !== url) {
    await connection.setTransport("/libcurl/index.mjs", [{ websocket: url }]);
    activeWispUrl = url;
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
      frame.frame.addEventListener("load", injectFrameHotkey);
      frameHost.appendChild(frame.frame);
    }
    // Reveal the frame, hide the landing, then fade the bar out (with a hint).
    document.body.classList.add("browsing");
    statusEl.textContent = "";
    frame.__lastTarget = target; // remembered so a route switch can reload this URL
    frame.go(target);
    setBarHidden(true);
  } catch (err) {
    statusEl.textContent = "";
    errorEl.textContent = "Failed to start the proxy.";
    errorCode.textContent = String(err && err.stack ? err.stack : err);
    console.error(err);
  }
});
