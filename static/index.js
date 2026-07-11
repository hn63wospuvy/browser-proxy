"use strict";

const form = document.getElementById("proxy-form");
const address = document.getElementById("proxy-address");
const statusEl = document.getElementById("proxy-status");
const errorEl = document.getElementById("proxy-error");
const errorCode = document.getElementById("proxy-error-code");
const frameHost = document.getElementById("frame-host");
// Config controls live on the landing only (the bar stays a slim input + Go). The landing is
// hidden while browsing; set route / DNS / search there before navigating.
const routeSelect = document.getElementById("proxy-route-landing");
const routePicker = document.getElementById("route-picker");
const ROUTE_KEY = "proxy-route";

// Search-engine select. Pure client-side: picks the search template.
const engineSelect = document.getElementById("proxy-engine-landing");
const ENGINE_KEY = "proxy-engine";

// DNS control: an editable combobox — pick a preset name OR type a DNS server IP. Affects the
// `direct` route only (VPN/proxy routes resolve at their exit and keep their own DNS). Empty or
// the server default means "no interference" — no DNS segment is sent.
const dnsInput = document.getElementById("proxy-dns-landing");
const dnsPresets = document.getElementById("dns-presets"); // <datalist> of preset names
const DNS_KEY = "proxy-dns";
let dnsDefault = "system"; // server's default resolver name (from /dns.json)
let dnsPresetNames = ["system"]; // preset names from /dns.json (for validation)

// Autocomplete dropdown container + the dim Esc config flash panel.
const acContainer = document.getElementById("ac-list");
const configFlash = document.getElementById("config-flash");
let autocomplete = null; // set once the DOM refs exist (see below)

function fillSelect(sel, routes, value) {
  sel.replaceChildren();
  for (const name of routes) {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    sel.appendChild(opt);
  }
  sel.value = value;
}

// Populate the route dropdown from the server. Hidden entirely when only `direct` exists, so
// users without any VPN configured see no extra control.
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
  if (routes.length <= 1) return; // only `direct`: leave the picker hidden

  const saved = localStorage.getItem(ROUTE_KEY);
  const value = saved && routes.includes(saved) ? saved : routes[0];
  fillSelect(routeSelect, routes, value);
  routePicker.hidden = false;
}

function currentRoute() {
  return !routePicker.hidden ? routeSelect.value : "direct";
}

// Apply a route change: persist, and — while browsing — rebuild the transport (which tears down
// the live WebSocket) and reload the frame so the page reloads over the new route instead of
// dying half-loaded.
async function onRouteChange(value) {
  localStorage.setItem(ROUTE_KEY, value);
  if (!frame || !document.body.classList.contains("browsing")) return;
  try {
    await ensureTransport();
    if (frame.__lastTarget) frame.go(frame.__lastTarget);
  } catch (err) {
    console.error("route switch failed", err);
  }
}

routeSelect.addEventListener("change", () => onRouteChange(routeSelect.value));

loadRoutes();

// --- Search engine (client-side only; always shown — there are always several engines) ---

function fillEngineSelect(sel, value) {
  sel.replaceChildren();
  for (const e of SEARCH_ENGINES) {
    const opt = document.createElement("option");
    opt.value = e.id;
    opt.textContent = e.label;
    sel.appendChild(opt);
  }
  sel.value = value;
}

function currentEngine() {
  return (engineSelect && engineSelect.value) || DEFAULT_ENGINE;
}

(function initEngine() {
  const saved = localStorage.getItem(ENGINE_KEY);
  const value = SEARCH_ENGINES.some((e) => e.id === saved) ? saved : DEFAULT_ENGINE;
  fillEngineSelect(engineSelect, value);
  engineSelect.addEventListener("change", () =>
    localStorage.setItem(ENGINE_KEY, engineSelect.value)
  );
})();

// --- DNS: editable combobox — a preset name or a typed DNS-server IP. Only affects `direct`. ---

// A loose IPv4/IPv6 literal check for UI feedback; the server validates strictly.
function isIpLiteral(s) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s.split(".").every((o) => Number(o) <= 255);
  return /^[0-9a-fA-F:]+$/.test(s) && s.includes(":");
}

function dnsIsValid(v) {
  return !v || dnsPresetNames.includes(v) || isIpLiteral(v);
}

// The DNS name/IP sent to the server (a path segment). Empty or the server default means "no
// interference" → omit the segment, so the request matches the pre-DNS-feature behavior and any
// VPN/proxy route keeps resolving via its own exit.
function currentDns() {
  const v = (dnsInput.value || "").trim();
  if (!v || v === dnsDefault) return "";
  return v;
}

// A DNS switch, like a route switch, rebuilds the transport (its URL changes) and reloads the
// frame so the page reloads over the newly-selected resolver.
async function onDnsChange() {
  const v = (dnsInput.value || "").trim();
  dnsInput.classList.toggle("invalid", !dnsIsValid(v));
  localStorage.setItem(DNS_KEY, v);
  if (!frame || !document.body.classList.contains("browsing")) return;
  try {
    await ensureTransport();
    if (frame.__lastTarget) frame.go(frame.__lastTarget);
  } catch (err) {
    console.error("dns switch failed", err);
  }
}

async function loadDns() {
  let list = ["system"];
  try {
    const res = await fetch("/dns.json");
    if (res.ok) {
      const json = await res.json();
      if (Array.isArray(json.dns) && json.dns.length) list = json.dns;
      if (typeof json.default === "string") dnsDefault = json.default;
    }
  } catch (_) {
    /* fall back to system-only */
  }
  dnsPresetNames = list;
  // Preset names become datalist suggestions; the input still accepts a free-typed IP.
  dnsPresets.replaceChildren();
  for (const name of list) {
    const opt = document.createElement("option");
    opt.value = name;
    dnsPresets.appendChild(opt);
  }
  const saved = localStorage.getItem(DNS_KEY);
  dnsInput.value = saved != null && saved !== "" ? saved : dnsDefault;
  dnsInput.classList.toggle("invalid", !dnsIsValid(dnsInput.value.trim()));
}

dnsInput.addEventListener("change", onDnsChange);

loadDns();

// Wire the autocomplete dropdown now that the input/form/container all exist.
autocomplete = initAutocomplete({ input: address, form, container: acContainer });

// The search engine + template come from the selected engine (see search-engines.js / the
// #proxy-engine selects wired above).

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

// Build one "label: value" row for the config flash (textContent — never innerHTML).
function flashRow(label, value) {
  const row = document.createElement("div");
  row.className = "cf-row";
  const s = document.createElement("span");
  s.textContent = label;
  const b = document.createElement("b");
  b.textContent = value;
  row.append(s, b);
  return row;
}

// Flash the current Route / Search engine / DNS, dimmed, fading out over ~1s (CSS animation).
function showConfigFlash() {
  if (!configFlash) return;
  const route = !routePicker.hidden ? routeSelect.value : "direct";
  const dns = (dnsInput.value || "").trim() || dnsDefault;
  configFlash.replaceChildren(
    flashRow("Route", route),
    flashRow("Search", engineLabel(currentEngine())),
    flashRow("DNS", dns)
  );
  // Restart the fade animation: drop the class, force a reflow, re-add it.
  configFlash.classList.remove("show");
  void configFlash.offsetWidth;
  configFlash.classList.add("show");
}
// Reachable from the injected in-frame Esc listener.
window.__configFlash = showConfigFlash;

function onHotkey(e) {
  if (!isToggleKey(e)) return;
  // Precedence: an open autocomplete dropdown swallows Esc (just close it).
  if (autocomplete && autocomplete.isOpen()) {
    e.preventDefault();
    autocomplete.close();
    return;
  }
  if (document.body.classList.contains("browsing")) {
    e.preventDefault();
    toggleBar();
    showConfigFlash();
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
            if (window.__configFlash) window.__configFlash();
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
  const dns = currentDns();
  // Route and DNS are path segments (not a query) so the URL keeps its trailing slash — the
  // libcurl client rejects a WebSocket URL that doesn't end in "/". With a DNS selected the
  // route is named explicitly: /wisp/<route>/<dns>/. Otherwise: /wisp/[<route>/].
  let seg;
  if (dns) {
    seg = `${encodeURIComponent(route)}/${encodeURIComponent(dns)}/`;
  } else {
    seg = route && route !== "direct" ? `${encodeURIComponent(route)}/` : "";
  }
  return `${scheme}://${location.host}/wisp/${seg}`;
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

  const raw = address.value.trim();
  const target = search(raw, engineTemplate(currentEngine()));
  if (!target) return;
  pushHistory(raw); // remember what the user typed for autocomplete

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
