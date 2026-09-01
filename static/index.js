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
// The route used while the picker is hidden — i.e. when the server offers exactly one route.
// Usually `direct`, but a config can disable `direct` (`type: system`, `enabled: false`), and
// then the only route is something else; sending "direct" anyway would get the upgrade refused.
let defaultRoute = "direct";

// Search-engine select. Pure client-side: picks the search template.
const engineSelect = document.getElementById("proxy-engine-landing");
const ENGINE_KEY = "proxy-engine";

// DNS control: a plain dropdown of the resolvers the server offers, each labelled with its real
// addresses, plus a final "Custom…" entry that reveals a free-text field for a server IP.
// Affects the `direct` route only (VPN/proxy routes resolve at their exit and keep their own DNS).
// Empty or the server default means "no interference" — no DNS segment is sent.
const dnsSelect = document.getElementById("proxy-dns-landing");
const dnsCustom = document.getElementById("proxy-dns-custom");
const DNS_KEY = "proxy-dns";
// The sentinel `value` of the custom option. Not a legal resolver name (the server's names come
// from YAML keys) and not an IP, so it can never collide with a real selection.
const DNS_CUSTOM = "__custom__";
let dnsDefault = "system"; // server's default resolver name (from /dns.json)
let dnsPresetNames = ["system"]; // preset names from /dns.json (for validation)
// Whether /dns.json has come back and filled the control. Until it has, the empty select says
// nothing about the user's choice, so auto-save must not read it (see currentConfig).
let dnsSettled = false;
// The last value actually committed. Selecting "Custom…" reveals an empty field, and that
// half-finished state must not read as "no resolver": every other reader (auto-save, the transport
// URL, the Esc flash) would otherwise silently fall back to the server default on the next
// unrelated interaction — see dnsValue().
let dnsCommitted = "";

// Autocomplete dropdown container + the dim Esc config flash panel.
const acContainer = document.getElementById("ac-list");
const configFlash = document.getElementById("config-flash");
let autocomplete = null; // set once the DOM refs exist (see below)

// Mid-browse settings: a ⚙ button reveals a popover holding the SAME config controls. The
// landing's `.pickers` panel is reparented into the popover on the first navigation (one set of
// controls — no mirroring), so changing route/DNS while browsing rebuilds the transport + reloads.
const settingsToggle = document.getElementById("settings-toggle");
const settingsPopover = document.getElementById("settings-popover");
const pickers = document.querySelector(".pickers");
let pickersMoved = false;

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
  defaultRoute = routes[0];
  if (routes.length <= 1) return; // a single route: leave the picker hidden and use it implicitly

  const saved = localStorage.getItem(ROUTE_KEY);
  const value = saved && routes.includes(saved) ? saved : routes[0];
  fillSelect(routeSelect, routes, value);
  routePicker.hidden = false;
}

function currentRoute() {
  return !routePicker.hidden ? routeSelect.value : defaultRoute;
}

// Apply a route change: persist, and — while browsing — rebuild the transport (which tears down
// the live WebSocket) and reload the frame so the page reloads over the new route instead of
// dying half-loaded.
async function onRouteChange(value) {
  localStorage.setItem(ROUTE_KEY, value);
  autoSave(); // fold the change into the active profile; adds persistence, never a second reload
  if (!frame || !document.body.classList.contains("browsing")) return;
  try {
    await ensureTransport();
    if (frame.__lastTarget) {
      showLoading(frame.__lastTarget);
      frame.go(frame.__lastTarget);
    }
  } catch (err) {
    console.error("route switch failed", err);
  }
}

routeSelect.addEventListener("change", () => onRouteChange(routeSelect.value));

// Kept so the load-time sync can wait for the options to exist before repainting the controls
// from a server document (applyProfile skips a route the select doesn't offer yet).
const routesReady = loadRoutes();

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
  engineSelect.addEventListener("change", () => {
    localStorage.setItem(ENGINE_KEY, engineSelect.value);
    autoSave();
  });
})();

// --- DNS: a dropdown of the server's resolvers, plus "Custom…" for a typed IP ---

// A loose IPv4/IPv6 literal check for UI feedback; the server validates strictly.
function isIpLiteral(s) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s.split(".").every((o) => Number(o) <= 255);
  return /^[0-9a-fA-F:]+$/.test(s) && s.includes(":");
}

function dnsIsValid(v) {
  return !v || dnsPresetNames.includes(v) || isIpLiteral(v);
}

// The stored value: a preset name, a typed IP, or "" for the server default. Unchanged from when
// this was one text field — the dropdown is a different way to pick, not a different vocabulary,
// so profiles written by the old UI still load and proxy-esc.js still reads the mirror key.
function dnsValue() {
  // "Custom…" picked but nothing typed yet is not a choice — keep reporting what is actually in
  // force, so an unrelated change (search engine, a header edit) can't write "" over the resolver.
  if (dnsSelect.value === DNS_CUSTOM) return (dnsCustom.value || "").trim() || dnsCommitted;
  return dnsSelect.value || "";
}

// The DNS name/IP sent to the server (a path segment). Empty or the server default means "no
// interference" → omit the segment, so the request matches the pre-DNS-feature behavior and any
// VPN/proxy route keeps resolving via its own exit.
function currentDns() {
  const v = dnsValue();
  if (!v || v === dnsDefault) return "";
  return v;
}

// Point the control at a stored value: a known preset selects its option, anything else falls to
// "Custom…" with the value in the field. An unknown name (a resolver the operator removed from
// the config) therefore stays visible and editable instead of silently becoming the default.
function setDnsControl(value) {
  const v = (value || "").trim();
  dnsCommitted = v;
  const known = v && dnsPresetNames.includes(v);
  if (!v) {
    dnsSelect.value = dnsPresetNames.includes(dnsDefault) ? dnsDefault : dnsPresetNames[0] || "";
    dnsCustom.value = "";
  } else if (known) {
    dnsSelect.value = v;
    dnsCustom.value = "";
  } else {
    dnsSelect.value = DNS_CUSTOM;
    dnsCustom.value = v;
  }
  syncDnsCustomVisibility();
}

// The field exists only for the custom entry; blank it out of the tab order otherwise.
function syncDnsCustomVisibility() {
  const custom = dnsSelect.value === DNS_CUSTOM;
  dnsCustom.hidden = !custom;
  dnsCustom.classList.toggle("invalid", custom && !dnsIsValid((dnsCustom.value || "").trim()));
}

// A DNS switch, like a route switch, rebuilds the transport (its URL changes) and reloads the
// frame so the page reloads over the newly-selected resolver.
async function onDnsChange() {
  syncDnsCustomVisibility();
  // Picking "Custom…" only reveals the field — there is nothing to apply until something is
  // typed into it, and applying "" here would silently reset the resolver mid-browse.
  if (dnsSelect.value === DNS_CUSTOM && !(dnsCustom.value || "").trim()) {
    dnsCustom.focus();
    return;
  }
  const v = dnsValue();
  dnsCommitted = v;
  localStorage.setItem(DNS_KEY, v);
  autoSave(); // same deal as the route: persist here, the reload below stays the only reload
  if (!frame || !document.body.classList.contains("browsing")) return;
  try {
    await ensureTransport();
    if (frame.__lastTarget) {
      showLoading(frame.__lastTarget);
      frame.go(frame.__lastTarget);
    }
  } catch (err) {
    console.error("dns switch failed", err);
  }
}

// "cloudflare" + ["1.1.1.1", …] → "cloudflare (1.1.1.1)". Only the first address is shown: the
// presets each carry four (v4 + v6) and the label is a picker entry, not documentation.
function dnsLabel(entry) {
  const ip = Array.isArray(entry.addresses) ? entry.addresses[0] : null;
  return ip ? `${entry.name} (${ip})` : entry.name;
}

async function loadDns() {
  let list = [{ name: "system", addresses: [] }];
  try {
    const res = await fetch("/dns.json");
    if (res.ok) {
      const json = await res.json();
      if (Array.isArray(json.dns) && json.dns.length) {
        list = json.dns
          .map((d) => (typeof d === "string" ? { name: d, addresses: [] } : d))
          .filter((d) => d && typeof d.name === "string" && d.name);
      }
      if (typeof json.default === "string") dnsDefault = json.default;
    }
  } catch (_) {
    /* fall back to system-only */
  }
  dnsPresetNames = list.map((d) => d.name);

  dnsSelect.replaceChildren();
  for (const entry of list) {
    const opt = document.createElement("option");
    opt.value = entry.name;
    opt.textContent = dnsLabel(entry);
    dnsSelect.appendChild(opt);
  }
  const custom = document.createElement("option");
  custom.value = DNS_CUSTOM;
  custom.textContent = "Custom…";
  dnsSelect.appendChild(custom);

  setDnsControl(localStorage.getItem(DNS_KEY) || "");
  dnsSettled = true;
}

dnsSelect.addEventListener("change", onDnsChange);
// Committing the typed IP on blur/Enter, not on every keystroke: mid-typing values like "1.1" are
// valid-looking and would each rebuild the transport and reload the page.
dnsCustom.addEventListener("change", onDnsChange);
dnsCustom.addEventListener("input", () =>
  dnsCustom.classList.toggle("invalid", !dnsIsValid((dnsCustom.value || "").trim()))
);

const dnsReady = loadDns(); // see routesReady

// --- Header overrides: user-entered name/value pairs injected into every proxied request ---
//
// Entirely client-side: the user manages the pairs in the editor modal, they persist in
// localStorage, and `ensureTransport` hands them to the transport (static/hybrid/index.mjs), which
// replaces any same-named browser header before dialing the target. (The Wisp server relays raw
// TCP — and TLS is terminated in the browser — so header rewriting can only happen here.) Limits
// are enforced on save: at most MAX_HEADERS entries, each value ≤ MAX_HEADER_VALUE_BYTES bytes.
const HEADERS_KEY = "proxy-headers";
const MAX_HEADERS = 100;
const MAX_HEADER_VALUE_BYTES = 10240;
// RFC 7230 header-name token: visible ASCII, no delimiters (keeps CR/LF/space/":" out of names).
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
// UTF-8 byte length (String.length counts UTF-16 units; the cap is measured in bytes).
const byteLen = (s) => new TextEncoder().encode(s).length;

// The live set of overrides (array of {name, value}), loaded from localStorage. Defensive against
// hand-edited/corrupt storage: keep only well-formed string pairs, clamped to the limits.
function loadStoredHeaders() {
  try {
    const arr = JSON.parse(localStorage.getItem(HEADERS_KEY) || "[]");
    if (!Array.isArray(arr)) return [];
    return arr
      .filter((h) => h && typeof h.name === "string" && typeof h.value === "string" && h.name)
      .slice(0, MAX_HEADERS)
      .map((h) => ({ name: h.name, value: h.value }));
  } catch (_) {
    return [];
  }
}
let headerOverrides = loadStoredHeaders();

const headersRows = document.getElementById("headers-rows");
const headersError = document.getElementById("headers-error");
const headersAddBtn = document.getElementById("headers-add");
const headersCountBadge = document.getElementById("headers-count");

// "(N)" beside the Headers label when overrides are active; blank when there are none.
function updateHeadersBadge() {
  headersCountBadge.textContent = headerOverrides.length ? ` (${headerOverrides.length})` : "";
  headersAddBtn.disabled = headersRows.children.length >= MAX_HEADERS;
}

// Build one editable row (name + value + remove). Typing only tints the field; the authoritative
// check runs in commitHeaders() when the field is committed (blur / Enter).
function makeHeaderRow(name = "", value = "") {
  const row = document.createElement("div");
  row.className = "headers-row";

  const nameEl = document.createElement("input");
  nameEl.className = "h-name";
  nameEl.placeholder = "Name (e.g. User-Agent)";
  nameEl.spellcheck = false;
  nameEl.autocomplete = "off";
  nameEl.value = name;
  nameEl.addEventListener("input", () => {
    const v = nameEl.value.trim();
    nameEl.classList.toggle("invalid", v !== "" && !HEADER_NAME_RE.test(v));
  });

  const valueEl = document.createElement("input");
  valueEl.className = "h-value";
  valueEl.placeholder = "Value";
  valueEl.spellcheck = false;
  valueEl.autocomplete = "off";
  valueEl.value = value;
  valueEl.addEventListener("input", () => {
    valueEl.classList.toggle("invalid", byteLen(valueEl.value) > MAX_HEADER_VALUE_BYTES);
  });

  // Committing on `change` rather than `input`: every keystroke of a header value would otherwise
  // rebuild the transport and reload the proxied page.
  nameEl.addEventListener("change", commitHeaders);
  valueEl.addEventListener("change", commitHeaders);
  // Enter is the natural "done" in a one-line field, and it fires `change` first only if the value
  // actually differs — commit explicitly so Enter always means the same thing.
  const onEnter = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      commitHeaders();
    }
  };
  nameEl.addEventListener("keydown", onEnter);
  valueEl.addEventListener("keydown", onEnter);

  const rm = document.createElement("button");
  rm.type = "button";
  rm.className = "h-remove";
  rm.title = "Remove header";
  rm.textContent = "✕";
  rm.addEventListener("click", () => {
    row.remove();
    commitHeaders();
  });

  row.append(nameEl, valueEl, rm);
  return row;
}

// Paint the rows from the live overrides. Called on load and whenever a profile switch replaces
// them — the editor is on-screen now, so it can't wait to be opened to refresh itself.
function renderHeaderRows() {
  headersError.hidden = true;
  headersRows.replaceChildren();
  for (const h of headerOverrides) headersRows.appendChild(makeHeaderRow(h.name, h.value));
  updateHeadersBadge();
}

// Read the rows back into a validated list, or return {error} for the first problem found. Fully
// empty rows are skipped so a stray blank row never blocks saving.
function collectHeaders() {
  const out = [];
  const seen = new Set();
  for (const row of headersRows.querySelectorAll(".headers-row")) {
    const name = row.querySelector(".h-name").value.trim();
    const value = row.querySelector(".h-value").value;
    if (!name && !value) continue;
    if (!name) return { error: "A row is missing a header name." };
    if (!HEADER_NAME_RE.test(name)) return { error: `Invalid header name: "${name}".` };
    if (/[\r\n\0]/.test(value)) return { error: `The value of "${name}" contains a newline or control character.` };
    if (byteLen(value) > MAX_HEADER_VALUE_BYTES)
      return { error: `The value of "${name}" exceeds ${MAX_HEADER_VALUE_BYTES} bytes.` };
    if (seen.has(name.toLowerCase())) return { error: `Duplicate header name: "${name}".` };
    seen.add(name.toLowerCase());
    out.push({ name, value });
  }
  if (out.length > MAX_HEADERS) return { error: `Up to ${MAX_HEADERS} headers.` };
  return { headers: out };
}

// Commit whatever the rows currently say. There is no Save button any more — the editor is part of
// the panel, so a committed edit lands like any other setting change. An invalid row shows its
// reason and leaves the stored overrides untouched: the row is still on screen to be fixed, so
// nothing is lost, and the transport keeps using the last good set.
async function commitHeaders() {
  const res = collectHeaders();
  if (res.error) return showHeadersError(res.error);
  // The per-header caps don't bound the document: 100 headers of 10 KiB is already 1 MB, four
  // times what the server accepts. Refuse here, with the reason, rather than saving something
  // that would be silently trimmed by normalize() or rejected by the server.
  if (!docFits(withHeaders(res.headers)))
    return showHeadersError(
      `Config exceeds ${Math.floor(MAX_DOC_BYTES / 1024)} KB — shorten it or remove some headers.`
    );

  headersError.hidden = true;
  // Nothing actually changed (a blur with no edit, a removed blank row): don't touch the document,
  // or every click through the panel would bump `updated` and fire a pointless PUT.
  if (JSON.stringify(res.headers) === JSON.stringify(headerOverrides)) {
    updateHeadersBadge();
    return;
  }

  headerOverrides = res.headers;
  try {
    localStorage.setItem(HEADERS_KEY, JSON.stringify(headerOverrides));
  } catch (_) {
    /* storage blocked/full: keep the in-memory copy for this session */
  }
  updateHeadersBadge();
  autoSave();
  // Apply immediately while browsing: rebuild the transport (dropping the old WebSocket) and
  // reload the current page so it re-fetches with the new headers.
  if (frame && document.body.classList.contains("browsing")) {
    try {
      await ensureTransport();
      if (frame.__lastTarget) {
        showLoading(frame.__lastTarget);
        frame.go(frame.__lastTarget);
      }
    } catch (err) {
      console.error("header override apply failed", err);
    }
  }
}

function showHeadersError(msg) {
  headersError.textContent = msg;
  headersError.hidden = false;
}

headersAddBtn.addEventListener("click", () => {
  if (headersRows.children.length >= MAX_HEADERS) return;
  headersRows.appendChild(makeHeaderRow());
  updateHeadersBadge();
  headersRows.lastElementChild.querySelector(".h-name").focus();
});
renderHeaderRows();

// --- Configuration profiles: one auto-saved, server-synced document ---
//
// A profile bundles the user's whole configuration — Route, DNS, Search engine and the header
// overrides — under a name, and `default` always exists. Profiles used to be opt-in snapshots
// written only when the user pressed "Update", so the live config and the saved profile drifted
// apart constantly; now every change writes straight into the active profile, which is exactly why
// "Update" (and, with `default` always present, "Clear all") are gone.
//
// `proxy-config` is the source of truth. The four mirror keys (proxy-route / proxy-dns /
// proxy-engine / proxy-headers) are still written on every change: they're the read-fast copy that
// static/proxy-esc.js and the transport already read. Every write path must touch both.
const CONFIG_KEY = "proxy-config";
const LEGACY_PROFILES_KEY = "proxy-profiles";
const LEGACY_ACTIVE_KEY = "proxy-active-profile";
const CLIENT_ID_KEY = "proxy-client-id";
const DEFAULT_PROFILE = "default";
const MAX_PROFILES = 50;
const MAX_PROFILE_NAME = 64;
const MAX_PROFILE_FIELD = 128; // route / engine / dns — opaque strings, capped as the server caps them
const SYNC_DEBOUNCE_MS = 500;
// Must match MAX_BODY_BYTES in src/profiles.rs. The per-field caps alone don't bound the whole
// document — 100 headers × 10 KiB on each of 50 profiles is ~51 MB — so without this the client
// could build a perfectly valid-looking document the server refuses outright, and the 4xx rule
// below would then stop syncing it for good. Enforced at the paths that can actually grow the
// document (header editor, new profile) with a visible error, and again in normalize() as a
// last-resort trim for imported or hand-edited storage.
const MAX_DOC_BYTES = 256 * 1024;
// Browsers cap the total body of `keepalive` requests at 64 KiB. A bigger document simply can't
// leave on the closing-tab path; it stays in localStorage and goes up on the next load.
const MAX_KEEPALIVE_BYTES = 60 * 1024;
const CLIENT_ID_RE = /^[0-9a-f]{32}$/;

// localStorage can throw on read outright (blocked storage, hardened privacy settings), not just
// fail to persist — every access below goes through this.
function lsGet(key) {
  try {
    return localStorage.getItem(key);
  } catch (_) {
    return null;
  }
}

const profileSelect = document.getElementById("proxy-profile");
const profileNewBtn = document.getElementById("profile-new");
const profileCloneBtn = document.getElementById("profile-clone");
const profileRenameBtn = document.getElementById("profile-rename");
const profileDeleteBtn = document.getElementById("profile-delete");
const profileNote = document.getElementById("profile-note");
const syncEl = document.getElementById("profile-sync");
// Name modal, shared by "New" and "Rename".
const profileNameModal = document.getElementById("profile-name-modal");
const profileNameTitle = document.getElementById("profile-name-title");
const profileNameSub = document.getElementById("profile-name-sub");
const profileNameInput = document.getElementById("profile-name-input");
const profileNameSaveBtn = document.getElementById("profile-name-save");
const profileNameCancelBtn = document.getElementById("profile-name-cancel");
const profileNameError = document.getElementById("profile-name-error");

// --- Normalization: the client can never hold a document the server would reject ---

// Truncate to at most `max` UTF-16 units without splitting a surrogate pair. A lone surrogate
// survives JSON.stringify as a bare \uD8xx escape, which serde_json rejects — so a naive slice on
// a name ending in an emoji would produce a document the server 400s forever.
function clip(s, max) {
  if (s.length <= max) return s;
  const code = s.charCodeAt(max - 1);
  // A high surrogate in the last kept slot has had its partner cut off: drop it too.
  return s.slice(0, code >= 0xd800 && code <= 0xdbff ? max - 1 : max);
}

// Same rules the header editor enforces on save (name token, no CR/LF/NUL, byte cap, 100 entries),
// applied here to whatever the document happens to contain.
function normalizeProfileHeaders(list) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const h of list) {
    if (!h || typeof h.name !== "string" || typeof h.value !== "string") continue;
    if (!HEADER_NAME_RE.test(h.name)) continue;
    if (/[\r\n\0]/.test(h.value)) continue;
    if (byteLen(h.value) > MAX_HEADER_VALUE_BYTES) continue;
    out.push({ name: h.name, value: h.value });
    if (out.length >= MAX_HEADERS) break;
  }
  return out;
}

// Runs on EVERY write — every localStorage save and every PUT, not just the migration. The old
// code enforced its limits on the save paths only, so an old or hand-edited storage could feed an
// invalid document straight through the load path and then 400 on every push, forever.
function normalize(doc) {
  const src = doc && typeof doc === "object" ? doc : {};
  const entries = [];
  for (const raw of Array.isArray(src.profiles) ? src.profiles : []) {
    if (!raw || typeof raw !== "object" || typeof raw.name !== "string") continue;
    const name = clip(raw.name.trim(), MAX_PROFILE_NAME); // cap the name…
    if (!name) continue; // …and drop whatever is left of a blank one
    entries.push({
      from: raw.name, // pre-normalization name, so `active` can follow a rename below
      name,
      route: typeof raw.route === "string" ? clip(raw.route, MAX_PROFILE_FIELD) : "direct",
      engine:
        typeof raw.engine === "string" ? clip(raw.engine, MAX_PROFILE_FIELD) : DEFAULT_ENGINE,
      dns: typeof raw.dns === "string" ? clip(raw.dns, MAX_PROFILE_FIELD) : "",
      headers: normalizeProfileHeaders(raw.headers),
    });
  }

  // `default` always exists and always comes FIRST — that ordering is what makes the collision
  // rule below rename an imported/legacy "default" rather than the real one.
  const at = entries.findIndex((p) => p.name.toLowerCase() === DEFAULT_PROFILE);
  if (at < 0) {
    entries.unshift({
      from: DEFAULT_PROFILE,
      name: DEFAULT_PROFILE,
      route: "direct",
      engine: DEFAULT_ENGINE,
      dns: "",
      headers: [],
    });
  } else {
    const [d] = entries.splice(at, 1);
    d.name = DEFAULT_PROFILE; // fold a case variant ("Default") onto the canonical spelling
    entries.unshift(d);
  }

  // Case-insensitive collisions resolve in array order: the first occurrence keeps the name, each
  // later one takes " (2)", " (3)", … — re-truncated so the suffix still fits inside 64 chars.
  // The counter CHAINS: an entry already called "default (2)" that collides becomes "default (3)",
  // not "default (2) (2)", so migrating a store that was itself migrated once stays readable.
  const taken = new Set();
  for (const p of entries) {
    if (!taken.has(p.name.toLowerCase())) {
      taken.add(p.name.toLowerCase());
      continue;
    }
    const base = p.name.replace(/ \(\d+\)$/, "") || p.name;
    for (let n = 2; ; n++) {
      const suffix = ` (${n})`;
      const candidate = clip(base, MAX_PROFILE_NAME - suffix.length) + suffix;
      if (taken.has(candidate.toLowerCase())) continue;
      p.name = candidate;
      taken.add(candidate.toLowerCase());
      break;
    }
  }

  // Over the cap, the tail goes. Legacy entries carry no timestamp, so "oldest" isn't
  // implementable — array order is the only order there is, and `default` sits at the front.
  const kept = entries.slice(0, MAX_PROFILES);

  // `active` must name a survivor: follow the rename when there is one, else fall back.
  let active = typeof src.active === "string" ? src.active : DEFAULT_PROFILE;
  if (!kept.some((p) => p.name === active)) {
    const renamed = kept.find((p) => p.from === active);
    active = renamed ? renamed.name : DEFAULT_PROFILE;
  }

  const out = {
    updated: Number.isFinite(src.updated) && src.updated >= 0 ? Math.floor(src.updated) : 0,
    active,
    profiles: kept.map((p) => ({
      name: p.name,
      route: p.route,
      engine: p.engine,
      dns: p.dns,
      headers: p.headers,
    })),
  };

  // Last-resort size guard. The paths that can realistically grow the document (the header editor,
  // "New") refuse with a visible error before it ever gets here — see docFits(). This only
  // catches storage that arrived already oversized (hand-edited, or written by a future version),
  // where silently dropping the tail beats a document that can never be synced again. `default`
  // is never dropped; a profile that alone blows the budget loses its headers rather than the
  // whole profile, so switching to it still works.
  while (docBytes(out) > MAX_DOC_BYTES && out.profiles.length > 1) out.profiles.pop();
  if (docBytes(out) > MAX_DOC_BYTES) out.profiles[0].headers = [];
  if (!out.profiles.some((p) => p.name === out.active)) out.active = DEFAULT_PROFILE;
  return out;
}

const docBytes = (doc) => byteLen(JSON.stringify(doc));

// Would this document still be accepted? Used by the paths that can grow it, so the user gets an
// explanation instead of a silent trim.
function docFits(doc) {
  return docBytes(doc) <= MAX_DOC_BYTES;
}

// --- Migration: legacy keys → one document, once, on the first load after the upgrade ---

function loadStoredConfig() {
  const raw = lsGet(CONFIG_KEY);
  if (!raw) return null;
  try {
    const doc = JSON.parse(raw);
    if (!doc || typeof doc !== "object" || !Array.isArray(doc.profiles)) return null;
    // One bad clock reading must not pin the document forever: a stamp far in the future would
    // otherwise beat every server copy on every load, for good.
    if (typeof doc.updated === "number" && doc.updated > Date.now() + 60000) doc.updated = Date.now();
    return doc;
  } catch (_) {
    return null;
  }
}

// The legacy `proxy-profiles` list, filtered to entries worth carrying over. No field sanitizing
// here — normalize() does that for the whole document a few lines later.
function loadLegacyProfiles() {
  try {
    const arr = JSON.parse(lsGet(LEGACY_PROFILES_KEY) || "[]");
    if (!Array.isArray(arr)) return [];
    return arr
      .filter((p) => p && typeof p === "object" && typeof p.name === "string" && p.name)
      .slice(0, MAX_PROFILES);
  } catch (_) {
    return [];
  }
}

// Is there anything of the user's to carry over at all? Decides whether a freshly built document
// gets to outrank the server's copy (see below).
function hasLegacyState() {
  return Boolean(
    lsGet(ROUTE_KEY) ||
      lsGet(DNS_KEY) ||
      lsGet(ENGINE_KEY) ||
      lsGet(HEADERS_KEY) ||
      lsGet(LEGACY_PROFILES_KEY)
  );
}

function migrateConfig() {
  const stored = loadStoredConfig();
  if (stored) return normalize(stored); // a document already exists: use it and stop

  const doc = {
    // A document invented from an EMPTY storage must lose to anything the server holds — that
    // recovery ("clear localStorage, get your profiles back") is the whole reason the client ID is
    // a fingerprint rather than a random UUID. With real settings to carry over there is something
    // to defend, so the document is stamped now and wins instead.
    updated: hasLegacyState() ? Date.now() : 0,
    active: DEFAULT_PROFILE,
    profiles: [
      // `default` is exactly what the user is looking at right now, so nothing changes under them.
      {
        name: DEFAULT_PROFILE,
        route: lsGet(ROUTE_KEY) || "direct",
        engine: lsGet(ENGINE_KEY) || DEFAULT_ENGINE,
        dns: lsGet(DNS_KEY) || "",
        headers: headerOverrides.map((h) => ({ name: h.name, value: h.value })),
      },
      // Legacy snapshots keep their names. A legacy "default" is kept rather than absorbed —
      // normalize's collision rule renames it "default (2)", so no config is lost and there is no
      // special case here.
      ...loadLegacyProfiles(),
    ],
  };
  const legacyActive = lsGet(LEGACY_ACTIVE_KEY);
  if (legacyActive && doc.profiles.some((p) => p.name === legacyActive)) doc.active = legacyActive;

  // Normalizing matters most right here: the old loader returned up to 50 entries and the UI let a
  // user genuinely reach that cap, so `default` + 50 legacy = 51 — one over the server's limit.
  // Un-normalized, every PUT would 400 forever, breaking sync for exactly the heaviest users.
  const out = normalize(doc);
  try {
    localStorage.setItem(CONFIG_KEY, JSON.stringify(out));
    localStorage.removeItem(LEGACY_PROFILES_KEY);
    localStorage.removeItem(LEGACY_ACTIVE_KEY);
  } catch (_) {
    /* storage blocked/full: the in-memory document stays authoritative for this session */
  }
  return out;
}

let config = migrateConfig();

function activeProfile() {
  return config.profiles.find((p) => p.name === config.active) || config.profiles[0];
}

// The current live settings, as a profile-shaped object.
//
// A control that isn't live yet must not speak for the profile. `routePicker` stays hidden until
// /routes.json resolves — and forever when the server offers only `direct` — and the DNS select is
// empty until /dns.json fills it. Without these fallbacks, changing the search engine inside that
// window (the engine select is populated synchronously, so it is clickable immediately) would
// write route:"direct" / dns:"" over whatever the profile had saved, and sync the loss upward.
function currentConfig() {
  const p = activeProfile();
  return {
    route: routePicker.hidden ? p.route : routeSelect.value,
    engine: currentEngine(),
    dns: dnsSettled ? dnsValue() : p.dns,
    headers: headerOverrides.map((h) => ({ name: h.name, value: h.value })),
  };
}

// The document as it would look with a different header set on the active profile — so a save path
// can size-check its result before committing to it.
function withHeaders(headers) {
  const candidate = JSON.parse(JSON.stringify(config));
  const p = candidate.profiles.find((x) => x.name === candidate.active) || candidate.profiles[0];
  p.headers = headers.map((h) => ({ name: h.name, value: h.value }));
  return candidate;
}

// Restore a profile's settings into the live controls, then rebuild the transport + reload once
// (if browsing) so a single apply doesn't reload per setting. Fields are applied defensively: a
// saved route/engine that no longer exists is skipped rather than blanking the control.
async function applyProfile(p) {
  if (!routePicker.hidden && [...routeSelect.options].some((o) => o.value === p.route)) {
    routeSelect.value = p.route;
    localStorage.setItem(ROUTE_KEY, p.route);
  }
  if (SEARCH_ENGINES.some((e) => e.id === p.engine)) {
    engineSelect.value = p.engine;
    localStorage.setItem(ENGINE_KEY, p.engine);
  }
  setDnsControl(p.dns || "");
  localStorage.setItem(DNS_KEY, p.dns || "");

  headerOverrides = (p.headers || []).map((h) => ({ name: h.name, value: h.value }));
  try {
    localStorage.setItem(HEADERS_KEY, JSON.stringify(headerOverrides));
  } catch (_) {
    /* keep in-memory */
  }
  renderHeaderRows(); // the editor is on-screen now, so a profile switch must repaint it

  if (frame && document.body.classList.contains("browsing")) {
    try {
      await ensureTransport();
      if (frame.__lastTarget) {
        showLoading(frame.__lastTarget);
        frame.go(frame.__lastTarget);
      }
    } catch (err) {
      console.error("profile apply failed", err);
    }
  }
}

// --- Auto-save: mirror key → active profile → normalize → localStorage → debounced PUT ---

// Fold the live controls into the active profile. Called right after each mirror-key write so the
// two can't drift; the caller's own transport rebuild + reload (route, DNS, headers) is untouched,
// which is why auto-save never causes a second reload.
function autoSave() {
  Object.assign(activeProfile(), currentConfig());
  touchConfig();
}

// The single write path for the document. A localStorage write that throws (quota exceeded,
// storage blocked) is caught and ignored: the in-memory document stays authoritative for the
// session and the push still goes out.
function touchConfig() {
  config.updated = Date.now();
  config = normalize(config);
  try {
    localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
  } catch (_) {
    /* keep the in-memory copy for this session */
  }
  scheduleSync();
}

// --- Server sync: one document per browser, last-write-wins on `updated` ---

let syncTimer = null;
let syncSettled = false; // the status line stays hidden until the first attempt resolves
let syncBlocked = false; // 4xx: a document the server will never accept — stop pushing it
let syncSeq = 0; // bumped per scheduled write, so a slow response can't speak for a newer one
let clientIdValue = null;

function setSyncStatus(state, text, reason) {
  if (!syncEl) return;
  syncEl.dataset.state = state;
  syncEl.textContent = text;
  if (reason) syncEl.title = reason;
  else syncEl.removeAttribute("title");
  syncEl.hidden = !syncSettled;
}

// Terminal outcomes go through these; the first one is also what reveals the line, so a fresh
// landing never flashes a warning before the first attempt has even finished.
function syncSucceeded() {
  syncSettled = true;
  setSyncStatus("synced", "Synced");
}
function syncFailed(reason) {
  syncSettled = true;
  setSyncStatus("local", "Local only", reason);
}

function cachedClientId() {
  const v = lsGet(CLIENT_ID_KEY);
  return v && CLIENT_ID_RE.test(v) ? v : null;
}

// clientId() is the global from client-id.js (a classic script loaded just before this one). It
// caches in localStorage itself, so the cached read here is only a fast path — and the one the
// keepalive flush depends on, since that path can't await anything.
async function resolveClientId() {
  if (clientIdValue) return clientIdValue;
  clientIdValue = cachedClientId();
  if (clientIdValue) return clientIdValue;
  if (typeof clientId !== "function") return null; // client-id.js missing: local-only
  try {
    const id = await clientId();
    clientIdValue = CLIENT_ID_RE.test(id) ? id : null;
  } catch (_) {
    clientIdValue = null;
  }
  return clientIdValue;
}

async function readError(res) {
  try {
    return (await res.text()).trim().slice(0, 200);
  } catch (_) {
    return "";
  }
}

// Debouncing collapses a burst of changes (typing a DNS server, flipping through engines) into one
// PUT. Scheduling also un-blocks a previous 4xx: the document has changed, so it's worth one more
// attempt — but nothing else ever retries it.
function scheduleSync() {
  syncBlocked = false;
  syncSeq++;
  setSyncStatus("syncing", "Saving…");
  clearTimeout(syncTimer);
  syncTimer = setTimeout(() => {
    syncTimer = null;
    pushConfig(false);
  }, SYNC_DEBOUNCE_MS);
}

// A pending write must survive the tab closing: `keepalive` lets the request outlive the document.
function flushSync() {
  if (syncTimer === null) return;
  clearTimeout(syncTimer);
  syncTimer = null;
  pushConfig(true);
}

async function pushConfig(keepalive) {
  if (syncBlocked) return;
  // Whose write this is. A slow response that lands after the user has changed something else
  // must not report "Synced" while that newer document is still only in localStorage.
  const seq = syncSeq;
  // The keepalive path can't await: the page may already be gone. A browser with no ID computed
  // yet just pushes on its next change or its next load.
  const id = keepalive ? clientIdValue || cachedClientId() : await resolveClientId();
  if (!id) return syncFailed("Couldn't determine the browser ID");
  const body = JSON.stringify(config);
  try {
    const res = await fetch(`/api/profiles/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body,
      // Over the browser's keepalive quota the request would just fail; send it normally and let
      // the closing tab take its chances. The document is in localStorage either way, and the
      // next load pushes it.
      keepalive: keepalive && byteLen(body) <= MAX_KEEPALIVE_BYTES,
    });
    if (res.ok) {
      if (seq === syncSeq) syncSucceeded();
      return;
    }
    if (res.status < 500) {
      // Not transient — a client-side bug. Never re-PUT a document the server will never accept.
      // Only when this is still the current document: a late 4xx for a superseded one must not
      // block the newer write that has already been scheduled.
      if (seq !== syncSeq) return;
      syncBlocked = true;
      return syncFailed((await readError(res)) || `HTTP ${res.status}`);
    }
    syncFailed(`Server error (HTTP ${res.status})`);
  } catch (_) {
    syncFailed("Couldn't reach the server"); // the next change retries
  }
}

// Reconcile with the server once, on load. Clock skew is accepted: `updated` comes from whichever
// client wrote it, and two browsers sharing one fingerprint are almost certainly one machine.
async function syncOnLoad() {
  const id = await resolveClientId();
  if (!id) return syncFailed("Couldn't determine the browser ID");
  let res;
  try {
    res = await fetch(`/api/profiles/${id}`, { cache: "no-store" });
  } catch (_) {
    return syncFailed("Couldn't reach the server");
  }
  if (res.status === 404) return scheduleSync(); // the server has nothing for us yet
  if (res.status >= 500) return syncFailed(`Server error (HTTP ${res.status})`);
  if (!res.ok) {
    syncBlocked = true;
    return syncFailed((await readError(res)) || `HTTP ${res.status}`);
  }
  let remote;
  try {
    remote = normalize(await res.json());
  } catch (_) {
    return syncFailed("Server returned unreadable data");
  }
  if (remote.updated <= config.updated) return scheduleSync(); // ties push local

  // The server's copy is newer: adopt it wholesale. Wait for the route/DNS fetches first —
  // applyProfile skips a route the select doesn't offer yet, and loadDns() would otherwise
  // overwrite the input right after we set it. Nothing has navigated, so no transport rebuild.
  await Promise.all([routesReady, dnsReady]);
  config = remote;
  try {
    localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
  } catch (_) {
    /* keep the in-memory copy */
  }
  renderProfileSelect();
  try {
    await applyProfile(activeProfile());
  } catch (_) {
    /* blocked storage makes its mirror writes throw; the document is adopted either way */
  }
  syncSucceeded();
}

// The debounce is worthless if a closing tab drops it, and both events are needed: `pagehide`
// covers navigation away, `visibilitychange` covers mobile task-switching that never fires it.
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") flushSync();
});
window.addEventListener("pagehide", flushSync);

// --- The profile control: select / New / Rename / Delete ---

// Rebuild the dropdown from the document. No placeholder option — `default` always exists, so
// "no profile selected" isn't a state any more.
function renderProfileSelect() {
  profileSelect.replaceChildren();
  for (const p of config.profiles) {
    const o = document.createElement("option");
    o.value = p.name;
    o.textContent = p.name;
    profileSelect.appendChild(o);
  }
  profileSelect.value = config.active;
  updateProfileButtons();
  updateProfileNote();
}

// `default` is what everything falls back to, so it can be neither renamed nor deleted.
function updateProfileButtons() {
  const isDefault = config.active === DEFAULT_PROFILE;
  profileRenameBtn.disabled = isDefault;
  profileDeleteBtn.disabled = isDefault;
}

// Spells out the ownership the indentation only hints at.
function updateProfileNote() {
  if (!profileNote) return;
  profileNote.textContent = `These settings belong to the "${config.active}" profile — auto-saved.`;
}

// Picking a profile applies its whole configuration at once.
profileSelect.addEventListener("change", () => {
  const picked = config.profiles.find((p) => p.name === profileSelect.value);
  if (!picked) return renderProfileSelect(); // a stale option: repaint from the document
  config.active = picked.name;
  touchConfig();
  updateProfileButtons();
  updateProfileNote();
  applyProfile(activeProfile()); // re-read: touchConfig normalizes into fresh objects
});

// --- The name modal, shared by "New" and "Rename" ---

let nameModalMode = "create";

function showNameError(msg) {
  profileNameError.textContent = msg || "";
  profileNameError.hidden = !msg;
}
// A free name of the form "<base> (2)", "<base> (3)", … for the clone dialog's prefill. normalize()
// would resolve a collision anyway, but silently renaming what the user just typed is worse than
// offering a name that is already free.
function suggestCopyName(base) {
  const trimmed = base.replace(/ \(\d+\)$/, "") || base;
  for (let n = 2; n < MAX_PROFILES + 2; n++) {
    const candidate = clip(trimmed, MAX_PROFILE_NAME - ` (${n})`.length) + ` (${n})`;
    if (!config.profiles.some((p) => p.name.toLowerCase() === candidate.toLowerCase()))
      return candidate;
  }
  return "";
}

const NAME_MODAL_TEXT = {
  create: {
    title: "New profile",
    sub: "A new profile starts from the default settings (default Search, DNS, Route, no headers).",
  },
  clone: {
    title: "Clone profile",
    sub: "", // filled in with the source profile's name
  },
  rename: { title: "Rename profile", sub: "" },
};

function openNameModal(mode) {
  nameModalMode = mode;
  closeSettings(); // don't leave the popover open behind the modal
  showNameError("");
  const text = NAME_MODAL_TEXT[mode] || NAME_MODAL_TEXT.create;
  profileNameTitle.textContent = text.title;
  if (mode === "rename") {
    profileNameSub.textContent = `Give the "${config.active}" profile a new name. Its settings stay the same.`;
    profileNameInput.value = config.active;
  } else if (mode === "clone") {
    profileNameSub.textContent = `Copy all of the "${config.active}" profile's settings into a new profile.`;
    profileNameInput.value = suggestCopyName(config.active);
  } else {
    profileNameSub.textContent = text.sub;
    profileNameInput.value = "";
  }
  profileNameModal.hidden = false;
  profileNameInput.focus();
  profileNameInput.select();
}
function closeNameModal() {
  profileNameModal.hidden = true;
}

// The blank config a "New" profile starts from. Deliberately not the live settings: under
// auto-save the active profile already IS the live settings, so a create that copied them would be
// indistinguishable from "Clone".
function blankConfig() {
  return { route: "direct", engine: DEFAULT_ENGINE, dns: "", headers: [] };
}

// Create starts blank, clone copies the active profile, rename only relabels it. All three share
// the same name rules, which are the server's rules.
function submitNameModal() {
  const name = (profileNameInput.value || "").trim();
  if (!name) return showNameError("Enter a profile name.");
  if (name.length > MAX_PROFILE_NAME) return showNameError(`Name is at most ${MAX_PROFILE_NAME} characters.`);
  const taken = (p) => p.name.toLowerCase() === name.toLowerCase();

  if (nameModalMode === "rename") {
    const current = activeProfile();
    if (!current || current.name === DEFAULT_PROFILE) return closeNameModal();
    if (config.profiles.some((p) => p !== current && taken(p)))
      return showNameError("A profile with that name already exists.");
    current.name = name;
  } else {
    if (config.profiles.some(taken)) return showNameError("A profile with that name already exists.");
    if (config.profiles.length >= MAX_PROFILES) return showNameError(`Up to ${MAX_PROFILES} profiles.`);
    const source = nameModalMode === "clone" ? currentConfig() : blankConfig();
    const added = { name, ...source };
    // Cloning a header-heavy profile is the other way the document can outgrow what the server
    // accepts; say so instead of letting normalize() drop it back off again.
    if (!docFits({ ...config, profiles: [...config.profiles, added] }))
      return showNameError(`Config exceeds ${Math.floor(MAX_DOC_BYTES / 1024)} KB.`);
    config.profiles.push(added);
  }
  config.active = name;
  closeNameModal();
  touchConfig();
  renderProfileSelect();
  // Only a blank "New" changes what the controls should show. A clone's settings are by
  // definition the ones already on screen, and a rename touches no setting at all — applying
  // either would rebuild the transport and reload the proxied page for nothing.
  if (nameModalMode === "create") applyProfile(activeProfile());
}

// Delete: the active profile goes and `default` takes over, applied like any other switch.
function deleteActiveProfile() {
  if (config.active === DEFAULT_PROFILE) return;
  config.profiles = config.profiles.filter((p) => p.name !== config.active);
  config.active = DEFAULT_PROFILE;
  touchConfig();
  renderProfileSelect();
  applyProfile(activeProfile());
}

profileNewBtn.addEventListener("click", () => openNameModal("create"));
profileCloneBtn.addEventListener("click", () => openNameModal("clone"));
profileRenameBtn.addEventListener("click", () => openNameModal("rename"));
profileDeleteBtn.addEventListener("click", deleteActiveProfile);
profileNameSaveBtn.addEventListener("click", submitNameModal);
profileNameCancelBtn.addEventListener("click", closeNameModal);
profileNameInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    submitNameModal();
  }
});

// Initial paint (no apply: the mirror keys already drive the controls, so the live config matches),
// then reconcile with the server.
renderProfileSelect();
syncOnLoad();

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

// The real (unrewritten) URL of the page currently in the frame. Scramjet's `urlchange` event
// carries the decoded URL on every top-frame navigation — a typed go(), an in-frame link click,
// history back/forward, pushState — so we track it here to prefill the address bar when it's
// revealed with Esc (letting the user see the current site and edit it to navigate elsewhere).
let currentUrl = "";
function trackUrlChange(e) {
  if (e && e.url) currentUrl = e.url;
}
// Best guess at the page currently shown: the tracked urlchange value, else the live client URL
// getter (decoded), else the last URL we explicitly navigated to.
function currentFrameUrl() {
  if (currentUrl) return currentUrl;
  try {
    if (frame && frame.url && frame.url.href) return frame.url.href;
  } catch (_) {
    /* the Scramjet client inside the frame isn't ready yet */
  }
  return (frame && frame.__lastTarget) || "";
}

// --- Loading overlay: a fun animation over the frame while a proxied page loads ---

const loadingEl = document.getElementById("loading");
const loaderCore = document.getElementById("loader-core");
const loaderHost = document.getElementById("loader-host");
const loaderSub = document.getElementById("loader-sub");

// Playful status lines cycled while waiting. Tor is slow (relay hops), so it gets its own set.
const LOAD_MSGS = [
  "Routing the request…",
  "Setting up a secure connection…",
  "Loading content…",
  "Almost there…",
];
const LOAD_MSGS_TOR = [
  "Peeling back the onion layers… 🧅",
  "Hopping across Tor relays…",
  "Tor tends to be slower — hang tight…",
];

let loadMsgTimer = null;
let loadSafetyTimer = null;

function loaderHostname(url) {
  try {
    return new URL(url).host || url;
  } catch (_) {
    return url || "";
  }
}

// Reveal the animation, themed by the current route, and start cycling messages. A safety timer
// hides it even if the frame's `load` never arrives (so a stray event can't strand the spinner).
function showLoading(url) {
  if (!loadingEl) return;
  const isTor = /tor/i.test(currentRoute());
  loaderCore.textContent = isTor ? "🧅" : "🌐";
  loaderHost.textContent = loaderHostname(url);
  const list = isTor ? LOAD_MSGS_TOR.concat(LOAD_MSGS) : LOAD_MSGS;
  let i = 0;
  loaderSub.textContent = list[0];
  clearInterval(loadMsgTimer);
  loadMsgTimer = setInterval(() => {
    i = (i + 1) % list.length;
    loaderSub.textContent = list[i];
  }, 2500);
  loadingEl.hidden = false;
  clearTimeout(loadSafetyTimer);
  loadSafetyTimer = setTimeout(hideLoading, 90000);
}

function hideLoading() {
  if (!loadingEl) return;
  loadingEl.hidden = true;
  clearInterval(loadMsgTimer);
  clearTimeout(loadSafetyTimer);
}

// The frame fires `load` for its initial about:blank too; ignore that so it doesn't hide the
// spinner before the real page has even started.
function onFrameLoad() {
  try {
    if (frame.frame.contentWindow && frame.frame.contentWindow.location.href === "about:blank") return;
  } catch (_) {
    /* cross-origin (shouldn't happen for our same-origin frame) — treat as a real load */
  }
  hideLoading();
}

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
    // Bar shown again: drop the loading overlay (the user wants to type), then prefill the current
    // page's real URL so it's visible and editable, focus and select it so typing replaces it.
    hideLoading();
    const url = currentFrameUrl();
    if (url) address.value = url;
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
  const route = currentRoute();
  const dns = dnsValue() || dnsDefault;
  const rows = [
    // The profile owns every row below it — and one is always active now, so it always shows.
    flashRow("Profile", config.active),
    flashRow("Route", route),
    flashRow("Search", engineLabel(currentEngine())),
    flashRow("DNS", dns),
  ];
  if (headerOverrides.length) {
    rows.push(flashRow("Headers", `${headerOverrides.length} overrides`));
  }
  // Surface the insecure-TLS state too, when the current site is on the unverified path.
  const host = currentTargetHost();
  if (host && insecureHosts.has(host)) {
    rows.push(flashRow("TLS", "⚠ insecure (cert not verified)"));
  }
  configFlash.replaceChildren(...rows);
  // Restart the fade animation: drop the class, force a reflow, re-add it.
  configFlash.classList.remove("show");
  void configFlash.offsetWidth;
  configFlash.classList.add("show");
}
// Reachable from the injected in-frame Esc listener.
window.__configFlash = showConfigFlash;

// --- Mid-browse settings popover ---

const settingsOpen = () => settingsPopover && !settingsPopover.hidden;
function closeSettings() {
  if (settingsPopover) settingsPopover.hidden = true;
}
// Move the landing's config controls into the bar popover on the first navigation, and reveal ⚙.
function movePickersToPopover() {
  if (pickersMoved || !pickers || !settingsPopover) return;
  settingsPopover.appendChild(pickers);
  settingsToggle.hidden = false;
  pickersMoved = true;
}
if (settingsToggle) {
  settingsToggle.addEventListener("click", (e) => {
    e.stopPropagation();
    settingsPopover.hidden = !settingsPopover.hidden;
  });
}
// Click outside the popover (and not on the toggle) closes it.
document.addEventListener("click", (e) => {
  if (!settingsOpen() || e.target === settingsToggle) return;
  // A control that removed itself as part of handling this very click — the ✕ on a header row —
  // is already detached by the time this runs, so `contains` says false and the popover would
  // close under the user mid-edit. Treat a detached target as "came from inside".
  if (!e.target.isConnected) return;
  if (!settingsPopover.contains(e.target)) closeSettings();
});

// --- The "i" hint next to each setting's label ---
//
// Hover and keyboard focus are pure CSS (`.hint:hover` / `:focus-within`). This adds the click
// toggle, which is the only way in on touch, where there is no hover: tap to pin a bubble open,
// tap anywhere else to dismiss it. One at a time — two open bubbles would overlap.
function closeHint(hint) {
  hint.classList.remove("open");
  const btn = hint.querySelector(".hint-btn");
  if (!btn) return;
  btn.setAttribute("aria-expanded", "false");
  // The bubble is also shown by `.hint:focus-within` (so tabbing to the button reveals it), and a
  // click leaves the button focused — without this the class comes off and the bubble stays up,
  // making the second click on the same "i" look like it did nothing.
  if (document.activeElement === btn) btn.blur();
}

function closeHints(except) {
  for (const hint of document.querySelectorAll(".hint.open")) {
    if (hint !== except) closeHint(hint);
  }
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest?.(".hint-btn");
  if (!btn) {
    closeHints(null);
    return;
  }
  const hint = btn.closest(".hint");
  // Three of these buttons sit inside a <label>; cancelling the click keeps the label from
  // forwarding it to its <select>, which would drop the dropdown over the bubble we just opened.
  e.preventDefault();
  const wasOpen = hint.classList.contains("open");
  // Skipping `hint` here matters: closing it would blur this button, and a keyboard user who
  // pressed Enter on it should keep their focus.
  closeHints(hint);
  if (wasOpen) {
    closeHint(hint);
    return;
  }
  hint.classList.add("open");
  btn.setAttribute("aria-expanded", "true");
});

// --- Insecure-TLS: per-host consent dialog + persistent indicator ---
//
// The transport (static/hybrid/index.mjs) runs in the bare-mux SharedWorker and can't show UI, so
// when a site's certificate fails verification it asks over the "hybrid-tls-consent"
// BroadcastChannel. We prompt the user (one host at a time), reply with their decision, and — if
// approved — remember the host to show a persistent "🔓 Insecure TLS" badge. Nothing goes over the
// unverified path without an explicit yes.
const tlsModal = document.getElementById("tls-modal");
const tlsModalHost = document.getElementById("tls-modal-host");
const tlsCancelBtn = document.getElementById("tls-cancel");
const tlsProceedBtn = document.getElementById("tls-proceed");
const tlsBadge = document.getElementById("tls-badge");
const tlsConsent = new BroadcastChannel("hybrid-tls-consent");
const insecureHosts = new Set(); // hosts the user approved (drives the indicator)
const consentQueue = []; // hosts awaiting a prompt (one modal at a time)
let consentHost = null; // host currently shown in the modal, or null

function currentTargetHost() {
  try {
    return new URL(frame && frame.__lastTarget ? frame.__lastTarget : "").host;
  } catch (_) {
    return "";
  }
}

// Show the "🔓 Insecure TLS" badge iff the site currently in the frame is on the unverified path.
function updateTlsBadge() {
  const host = currentTargetHost();
  tlsBadge.hidden = !(host && insecureHosts.has(host));
}
window.__updateTlsBadge = updateTlsBadge;

function processConsentQueue() {
  if (consentHost || !consentQueue.length) return;
  const host = consentQueue.shift();
  if (insecureHosts.has(host)) return processConsentQueue(); // decided since queued
  consentHost = host;
  tlsModalHost.textContent = host;
  tlsModal.hidden = false;
  tlsProceedBtn.focus();
}

// Settle the current prompt: reply to the transport (and other tabs) and, if approved, remember
// the host for the indicator. Exposed so the Esc handler can cancel (deny) an open dialog.
function answerConsent(allow) {
  if (!consentHost) return;
  const host = consentHost;
  consentHost = null;
  tlsModal.hidden = true;
  tlsConsent.postMessage({ type: "tls-answer", host, allow });
  if (allow) {
    insecureHosts.add(host);
    updateTlsBadge();
  }
  processConsentQueue();
}
window.__tlsConsentActive = () => consentHost !== null;
window.__tlsConsentCancel = () => answerConsent(false);

function enqueueConsent(host) {
  if (insecureHosts.has(host) || consentHost === host || consentQueue.includes(host)) return;
  consentQueue.push(host);
  processConsentQueue();
}

tlsProceedBtn.addEventListener("click", () => answerConsent(true));
tlsCancelBtn.addEventListener("click", () => answerConsent(false));

tlsConsent.onmessage = (e) => {
  const d = e.data;
  if (!d) return;
  if (d.type === "tls-ask") {
    enqueueConsent(d.host);
  } else if (d.type === "tls-answer") {
    // Another tab decided this host first (BroadcastChannel doesn't echo our own posts): reflect
    // the decision and drop any prompt of ours still showing/queued for it.
    if (d.allow) {
      insecureHosts.add(d.host);
      updateTlsBadge();
    }
    if (consentHost === d.host) {
      consentHost = null;
      tlsModal.hidden = true;
      processConsentQueue();
    }
    const i = consentQueue.indexOf(d.host);
    if (i >= 0) consentQueue.splice(i, 1);
  }
};

function onHotkey(e) {
  if (!isToggleKey(e)) return;
  // An open TLS consent dialog takes precedence — Esc cancels it (deny, the safe default).
  if (consentHost) {
    e.preventDefault();
    answerConsent(false);
    return;
  }
  // The profile name modal ("New" / "Clone" / "Rename") closes on Esc.
  if (profileNameModal && !profileNameModal.hidden) {
    e.preventDefault();
    closeNameModal();
    return;
  }
  // Precedence: an open autocomplete dropdown swallows Esc (just close it)...
  if (autocomplete && autocomplete.isOpen()) {
    e.preventDefault();
    autocomplete.close();
    return;
  }
  // ...then an open settings popover...
  if (settingsOpen()) {
    e.preventDefault();
    closeSettings();
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
 *
 * The transport is the hybrid client (see static/hybrid/index.mjs): libcurl by default, with an
 * automatic fall back to an insecure epoxy client for any host whose TLS certificate fails
 * verification (curl error 60). Both dial this same Wisp backend, so the URL logic is unchanged.
 */
const TRANSPORT = "/hybrid/index.mjs";
let activeWispUrl = null;
let activeHeadersKey = null;
async function ensureTransport() {
  const url = wispUrl();
  // Header overrides ride along in the transport options. A change to them (like a route/DNS
  // change) must rebuild the transport, so fold them into the cache key — otherwise a same-URL
  // save would keep the stale transport and never apply the new headers.
  const headersKey = JSON.stringify(headerOverrides);
  if (
    (await connection.getTransport()) !== TRANSPORT ||
    activeWispUrl !== url ||
    activeHeadersKey !== headersKey
  ) {
    await connection.setTransport(TRANSPORT, [{ websocket: url, headerOverrides }]);
    activeWispUrl = url;
    activeHeadersKey = headersKey;
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
      // Hide the loading overlay once the frame finishes loading a real page.
      frame.frame.addEventListener("load", onFrameLoad);
      // Track in-frame navigations (link clicks, history, pushState) so Esc always prefills the
      // page you're actually on, not the URL you first typed.
      frame.addEventListener("urlchange", trackUrlChange);
      // Show the loader when an in-frame navigation (e.g. a link click) starts a new page load.
      frame.addEventListener("navigate", (e) => showLoading((e && e.url) || frame.__lastTarget || ""));
      frameHost.appendChild(frame.frame);
    }
    // Reveal the frame, hide the landing, then fade the bar out (with a hint).
    document.body.classList.add("browsing");
    movePickersToPopover(); // config controls now live in the ⚙ popover
    statusEl.textContent = "";
    frame.__lastTarget = target; // remembered so a route switch can reload this URL
    currentUrl = target; // immediate value for Esc; urlchange refines it after any redirect
    showLoading(target); // fun animation until the frame's `load` fires
    frame.go(target);
    updateTlsBadge(); // reflect whether the new target host is on the insecure path
    setBarHidden(true);
  } catch (err) {
    hideLoading();
    statusEl.textContent = "";
    errorEl.textContent = "Failed to start the proxy.";
    errorCode.textContent = String(err && err.stack ? err.stack : err);
    console.error(err);
  }
});
