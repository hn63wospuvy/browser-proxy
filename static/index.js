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
    if (frame.__lastTarget) {
      showLoading(frame.__lastTarget);
      frame.go(frame.__lastTarget);
    }
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
    if (frame.__lastTarget) {
      showLoading(frame.__lastTarget);
      frame.go(frame.__lastTarget);
    }
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

const headersModal = document.getElementById("headers-modal");
const headersRows = document.getElementById("headers-rows");
const headersError = document.getElementById("headers-error");
const headersCounter = document.getElementById("headers-counter");
const headersAddBtn = document.getElementById("headers-add");
const headersSaveBtn = document.getElementById("headers-save");
const headersCancelBtn = document.getElementById("headers-cancel");
const headersEditBtn = document.getElementById("headers-edit");
const headersCountBadge = document.getElementById("headers-count");

// "(N)" next to the Headers button when overrides are active; blank when there are none.
function updateHeadersBadge() {
  headersCountBadge.textContent = headerOverrides.length ? `(${headerOverrides.length})` : "";
}

// Row count / limit indicator, and disable "Add" once the cap is hit.
function updateHeadersCounter() {
  const n = headersRows.children.length;
  headersCounter.textContent = `${n} / ${MAX_HEADERS}`;
  headersAddBtn.disabled = n >= MAX_HEADERS;
}

// Build one editable row (name + value + remove). Live validation only tints the field; the
// authoritative check runs on save (see collectHeaders).
function makeHeaderRow(name = "", value = "") {
  const row = document.createElement("div");
  row.className = "headers-row";

  const nameEl = document.createElement("input");
  nameEl.className = "h-name";
  nameEl.placeholder = "Tên (VD: User-Agent)";
  nameEl.spellcheck = false;
  nameEl.autocomplete = "off";
  nameEl.value = name;
  nameEl.addEventListener("input", () => {
    const v = nameEl.value.trim();
    nameEl.classList.toggle("invalid", v !== "" && !HEADER_NAME_RE.test(v));
  });

  const valueEl = document.createElement("input");
  valueEl.className = "h-value";
  valueEl.placeholder = "Giá trị";
  valueEl.spellcheck = false;
  valueEl.autocomplete = "off";
  valueEl.value = value;
  valueEl.addEventListener("input", () => {
    valueEl.classList.toggle("invalid", byteLen(valueEl.value) > MAX_HEADER_VALUE_BYTES);
  });

  const rm = document.createElement("button");
  rm.type = "button";
  rm.className = "h-remove";
  rm.title = "Xóa header";
  rm.textContent = "✕";
  rm.addEventListener("click", () => {
    row.remove();
    updateHeadersCounter();
  });

  row.append(nameEl, valueEl, rm);
  return row;
}

function openHeadersEditor() {
  closeSettings(); // don't leave the popover open behind the modal
  headersError.hidden = true;
  headersRows.replaceChildren();
  for (const h of headerOverrides) headersRows.appendChild(makeHeaderRow(h.name, h.value));
  if (!headerOverrides.length) headersRows.appendChild(makeHeaderRow()); // one empty row to start
  updateHeadersCounter();
  headersModal.hidden = false;
}

function closeHeadersEditor() {
  headersModal.hidden = true;
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
    if (!name) return { error: "Có dòng thiếu tên header." };
    if (!HEADER_NAME_RE.test(name)) return { error: `Tên header không hợp lệ: "${name}".` };
    if (/[\r\n\0]/.test(value)) return { error: `Giá trị của "${name}" chứa ký tự xuống dòng/điều khiển.` };
    if (byteLen(value) > MAX_HEADER_VALUE_BYTES)
      return { error: `Giá trị của "${name}" vượt quá ${MAX_HEADER_VALUE_BYTES} byte.` };
    if (seen.has(name.toLowerCase())) return { error: `Header trùng tên: "${name}".` };
    seen.add(name.toLowerCase());
    out.push({ name, value });
  }
  if (out.length > MAX_HEADERS) return { error: `Tối đa ${MAX_HEADERS} header.` };
  return { headers: out };
}

async function saveHeaders() {
  const res = collectHeaders();
  if (res.error) {
    headersError.textContent = res.error;
    headersError.hidden = false;
    return;
  }
  headerOverrides = res.headers;
  try {
    localStorage.setItem(HEADERS_KEY, JSON.stringify(headerOverrides));
  } catch (_) {
    /* storage blocked/full: keep the in-memory copy for this session */
  }
  updateHeadersBadge();
  closeHeadersEditor();
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

headersEditBtn.addEventListener("click", openHeadersEditor);
headersCancelBtn.addEventListener("click", closeHeadersEditor);
headersSaveBtn.addEventListener("click", saveHeaders);
headersAddBtn.addEventListener("click", () => {
  if (headersRows.children.length >= MAX_HEADERS) return;
  headersRows.appendChild(makeHeaderRow());
  updateHeadersCounter();
  headersRows.lastElementChild.querySelector(".h-name").focus();
});
updateHeadersBadge();

// --- Configuration profiles: named snapshots of the whole config, stored in localStorage ---
//
// A profile bundles the user's settings — Route, DNS, Search engine, and the header overrides —
// under a name. Saving captures the current config; applying restores all of it at once (and, while
// browsing, rebuilds the transport + reloads). Everything lives client-side in localStorage.
const PROFILES_KEY = "proxy-profiles";
const MAX_PROFILES = 50;
const MAX_PROFILE_NAME = 64;

// Load + sanitize the saved profiles (defensive against hand-edited/corrupt storage): keep only
// well-formed entries, and normalize each field so a missing/garbage value can't break apply.
function loadProfiles() {
  try {
    const arr = JSON.parse(localStorage.getItem(PROFILES_KEY) || "[]");
    if (!Array.isArray(arr)) return [];
    return arr
      .filter((p) => p && typeof p.name === "string" && p.name)
      .slice(0, MAX_PROFILES)
      .map((p) => ({
        name: p.name,
        route: typeof p.route === "string" ? p.route : "direct",
        engine: typeof p.engine === "string" ? p.engine : DEFAULT_ENGINE,
        dns: typeof p.dns === "string" ? p.dns : "",
        headers: Array.isArray(p.headers)
          ? p.headers
              .filter((h) => h && typeof h.name === "string" && typeof h.value === "string" && h.name)
              .slice(0, MAX_HEADERS)
              .map((h) => ({ name: h.name, value: h.value }))
          : [],
      }));
  } catch (_) {
    return [];
  }
}
let profiles = loadProfiles();

const PROFILE_ACTIVE_KEY = "proxy-active-profile";
const profileSelect = document.getElementById("proxy-profile");
const profileNewBtn = document.getElementById("profile-new");
const profileUpdateBtn = document.getElementById("profile-update");
const profileDeleteBtn = document.getElementById("profile-delete");
const profileClearBtn = document.getElementById("profile-clear");
// "Tạo mới" name modal.
const profileNameModal = document.getElementById("profile-name-modal");
const profileNameInput = document.getElementById("profile-name-input");
const profileNameSaveBtn = document.getElementById("profile-name-save");
const profileNameCancelBtn = document.getElementById("profile-name-cancel");
const profileNameError = document.getElementById("profile-name-error");

// Transient UI state: the two-step "Xóa hết" confirm and the "Cập nhật" success flash.
let clearArmed = false;
let clearTimer = null;
let updateFeedbackTimer = null;

function saveProfiles() {
  try {
    localStorage.setItem(PROFILES_KEY, JSON.stringify(profiles));
  } catch (_) {
    /* storage blocked/full: keep the in-memory copy for this session */
  }
}

// The current live settings, as a profile-shaped object.
function currentConfig() {
  return {
    route: currentRoute(),
    engine: currentEngine(),
    dns: (dnsInput.value || "").trim(),
    headers: headerOverrides.map((h) => ({ name: h.name, value: h.value })),
  };
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
  dnsInput.value = p.dns || "";
  localStorage.setItem(DNS_KEY, p.dns || "");
  dnsInput.classList.toggle("invalid", !dnsIsValid((p.dns || "").trim()));

  headerOverrides = (p.headers || []).map((h) => ({ name: h.name, value: h.value }));
  try {
    localStorage.setItem(HEADERS_KEY, JSON.stringify(headerOverrides));
  } catch (_) {
    /* keep in-memory */
  }
  updateHeadersBadge();

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

// Rebuild the dropdown from `profiles`, keeping `selected` if it still exists; a leading
// placeholder means "no profile selected". Also refreshes the action buttons' enabled state.
function renderProfileSelect(selected = profileSelect.value) {
  profileSelect.replaceChildren();
  const ph = document.createElement("option");
  ph.value = "";
  ph.textContent = profiles.length ? "— Chọn hồ sơ —" : "— Chưa có hồ sơ —";
  profileSelect.appendChild(ph);
  for (const p of profiles) {
    const o = document.createElement("option");
    o.value = p.name;
    o.textContent = p.name;
    profileSelect.appendChild(o);
  }
  profileSelect.value = profiles.some((p) => p.name === selected) ? selected : "";
  updateProfileButtons();
}

// Cập nhật / Xóa act on the selected profile; "Xóa hết" needs at least one profile to exist.
function updateProfileButtons() {
  profileUpdateBtn.disabled = !profileSelect.value;
  profileDeleteBtn.disabled = !profileSelect.value;
  profileClearBtn.disabled = !profiles.length;
  disarmClear(); // a render/selection change cancels any pending "Xóa hết" confirm
}

// Persist which profile is active so the dropdown restores its selection on reload.
function setActiveProfile(name) {
  try {
    localStorage.setItem(PROFILE_ACTIVE_KEY, name || "");
  } catch (_) {
    /* ignore */
  }
  profileSelect.value = name || "";
  updateProfileButtons();
}

// Picking a profile from the dropdown applies it and marks it active; the placeholder clears it.
profileSelect.addEventListener("change", () => {
  const name = profileSelect.value;
  if (!name) {
    setActiveProfile("");
    return;
  }
  const p = profiles.find((x) => x.name === name);
  if (p) {
    setActiveProfile(name);
    applyProfile(p);
  } else {
    updateProfileButtons();
  }
});

// --- Tạo mới: enter a name in a small modal, then save the current config as a new profile ---
function showNameError(msg) {
  profileNameError.textContent = msg || "";
  profileNameError.hidden = !msg;
}
function openNameModal() {
  closeSettings(); // don't leave the popover open behind the modal
  showNameError("");
  profileNameInput.value = "";
  profileNameModal.hidden = false;
  profileNameInput.focus();
}
function closeNameModal() {
  profileNameModal.hidden = true;
}
function createProfile() {
  const name = (profileNameInput.value || "").trim();
  if (!name) return showNameError("Nhập tên hồ sơ.");
  if (name.length > MAX_PROFILE_NAME) return showNameError(`Tên tối đa ${MAX_PROFILE_NAME} ký tự.`);
  if (profiles.some((p) => p.name.toLowerCase() === name.toLowerCase()))
    return showNameError("Tên hồ sơ đã tồn tại.");
  if (profiles.length >= MAX_PROFILES) return showNameError(`Tối đa ${MAX_PROFILES} hồ sơ.`);
  profiles.push({ name, ...currentConfig() });
  saveProfiles();
  closeNameModal();
  renderProfileSelect(name);
  setActiveProfile(name);
}

// --- Cập nhật: overwrite the selected profile with the current config ---
function updateSelectedProfile() {
  const name = profileSelect.value;
  const at = profiles.findIndex((p) => p.name === name);
  if (at < 0) return;
  profiles[at] = { name, ...currentConfig() };
  saveProfiles();
  profileUpdateBtn.textContent = "Đã lưu ✓"; // brief inline confirmation
  clearTimeout(updateFeedbackTimer);
  updateFeedbackTimer = setTimeout(() => (profileUpdateBtn.textContent = "Cập nhật"), 1500);
}

// --- Xóa: remove the selected profile ---
function deleteSelectedProfile() {
  const name = profileSelect.value;
  if (!name) return;
  profiles = profiles.filter((p) => p.name !== name);
  saveProfiles();
  setActiveProfile("");
  renderProfileSelect("");
}

// --- Xóa hết: two-step confirm on the button itself (no native dialog) ---
function disarmClear() {
  if (!clearArmed) return;
  clearArmed = false;
  clearTimeout(clearTimer);
  profileClearBtn.textContent = "Xóa hết";
  profileClearBtn.classList.remove("armed");
}
function onClearClick() {
  if (!profiles.length) return;
  if (!clearArmed) {
    clearArmed = true;
    profileClearBtn.textContent = "Chắc chắn?";
    profileClearBtn.classList.add("armed");
    clearTimer = setTimeout(disarmClear, 3000);
    return;
  }
  disarmClear();
  profiles = [];
  saveProfiles();
  setActiveProfile("");
  renderProfileSelect("");
}

profileNewBtn.addEventListener("click", openNameModal);
profileUpdateBtn.addEventListener("click", updateSelectedProfile);
profileDeleteBtn.addEventListener("click", deleteSelectedProfile);
profileClearBtn.addEventListener("click", onClearClick);
profileNameSaveBtn.addEventListener("click", createProfile);
profileNameCancelBtn.addEventListener("click", closeNameModal);
profileNameInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    createProfile();
  }
});

// Initial render, restoring the previously-active selection (without re-applying — the individual
// settings are already persisted, so the live config already matches).
renderProfileSelect(localStorage.getItem(PROFILE_ACTIVE_KEY) || "");

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
  "Đang định tuyến yêu cầu…",
  "Đang thiết lập kết nối an toàn…",
  "Đang tải nội dung…",
  "Sắp xong rồi…",
];
const LOAD_MSGS_TOR = [
  "Đang bóc từng lớp củ hành… 🧅",
  "Đang nhảy qua các relay Tor…",
  "Tor thường chậm hơn, kiên nhẫn chút nhé…",
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
  const route = !routePicker.hidden ? routeSelect.value : "direct";
  const dns = (dnsInput.value || "").trim() || dnsDefault;
  const rows = [
    flashRow("Route", route),
    flashRow("Search", engineLabel(currentEngine())),
    flashRow("DNS", dns),
  ];
  if (headerOverrides.length) {
    rows.push(flashRow("Headers", `${headerOverrides.length} ghi đè`));
  }
  if (profileSelect && profileSelect.value) {
    rows.push(flashRow("Profile", profileSelect.value));
  }
  // Surface the insecure-TLS state too, when the current site is on the unverified path.
  const host = currentTargetHost();
  if (host && insecureHosts.has(host)) {
    rows.push(flashRow("TLS", "⚠ insecure (không xác thực cert)"));
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
  if (settingsOpen() && !settingsPopover.contains(e.target) && e.target !== settingsToggle) {
    closeSettings();
  }
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
  // An open header editor closes on Esc (discarding unsaved edits) before anything else.
  if (headersModal && !headersModal.hidden) {
    e.preventDefault();
    closeHeadersEditor();
    return;
  }
  // Likewise the "Tạo mới" profile name modal.
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
