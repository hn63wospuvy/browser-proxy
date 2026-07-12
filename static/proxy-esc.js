"use strict";

// Injected into every TOP-LEVEL Scramjet-proxied page by the service worker (see sw.js).
//
// When a proxied page is opened as its own tab or a link breaks it out of the app-shell iframe,
// the app's address bar (index.html / index.js) isn't there — so Esc had nothing to toggle. This
// overlay restores that: press Esc to reveal a bar prefilled with the current real URL, edit it,
// and go. A ⚙ button opens the same Route / DNS / Search config as the start page.
//
// It's appended AFTER Scramjet's rewrite pass, so it runs as plain (un-rewritten) JS: it reads the
// browser's own location / localStorage / fetch (the SAME real-origin storage the app shell uses)
// and drives navigation via the known `/scramjet/` prefix rather than through Scramjet's proxy.
(function () {
  // Only the top document needs this. Inside the app-shell iframe the shell already handles Esc,
  // and inside nested proxied subframes an address bar makes no sense.
  try {
    if (window.top !== window.self) return;
  } catch (_) {
    return; // cross-origin top we can't reason about
  }

  var PREFIX = "/scramjet/";
  var ROUTE_KEY = "proxy-route";
  var DNS_KEY = "proxy-dns";
  var ENGINE_KEY = "proxy-engine";
  var TRANSPORT = "/hybrid/index.mjs";

  // Mirrors static/search-engines.js — kept in sync by hand since this overlay is self-contained.
  var SEARCH_ENGINES = [
    { id: "brave", label: "Brave", template: "https://search.brave.com/search?q=%s" },
    { id: "duckduckgo", label: "DuckDuckGo", template: "https://duckduckgo.com/?q=%s" },
    { id: "ddg-lite", label: "DuckDuckGo Lite", template: "https://lite.duckduckgo.com/lite/?q=%s" },
    { id: "startpage", label: "Startpage", template: "https://www.startpage.com/sp/search?query=%s" },
    { id: "bing", label: "Bing", template: "https://www.bing.com/search?q=%s" },
    { id: "google", label: "Google", template: "https://www.google.com/search?q=%s" },
  ];
  var DEFAULT_ENGINE = "brave";

  // Config loaded from the server (same endpoints the app shell uses).
  var routes = ["direct"];
  var dnsDefault = "system";

  function ls(key) {
    try {
      return localStorage.getItem(key);
    } catch (_) {
      return null;
    }
  }
  function setLs(key, val) {
    try {
      localStorage.setItem(key, val);
    } catch (_) {}
  }

  // The real URL is the single encoded path segment right after the prefix (default codec is
  // encodeURIComponent, e.g. /scramjet/https%3A%2F%2Fexample.com%2Fpath).
  function currentRealUrl() {
    var p = location.pathname;
    if (p.indexOf(PREFIX) !== 0) return "";
    var enc = p.slice(PREFIX.length);
    try {
      return decodeURIComponent(enc);
    } catch (_) {
      return enc;
    }
  }

  function proxied(url) {
    return PREFIX + encodeURIComponent(url);
  }

  // --- Route / DNS / Search selection (reads the SAME localStorage the app shell writes) ---

  function currentRoute() {
    var v = ls(ROUTE_KEY);
    return v && routes.indexOf(v) >= 0 ? v : "direct";
  }
  function currentDns() {
    var v = (ls(DNS_KEY) || "").trim();
    if (!v || v === dnsDefault) return "";
    return v;
  }
  function currentEngine() {
    var v = ls(ENGINE_KEY);
    return SEARCH_ENGINES.some(function (e) {
      return e.id === v;
    })
      ? v
      : DEFAULT_ENGINE;
  }
  function engineTemplate(id) {
    for (var i = 0; i < SEARCH_ENGINES.length; i++) if (SEARCH_ENGINES[i].id === id) return SEARCH_ENGINES[i].template;
    return SEARCH_ENGINES[0].template;
  }

  // Wisp backend URL for the current route/DNS — identical to index.js's wispUrl().
  function wispUrl() {
    var scheme = location.protocol === "https:" ? "wss" : "ws";
    var route = currentRoute();
    var dns = currentDns();
    var seg;
    if (dns) seg = encodeURIComponent(route) + "/" + encodeURIComponent(dns) + "/";
    else seg = route && route !== "direct" ? encodeURIComponent(route) + "/" : "";
    return scheme + "://" + location.host + "/wisp/" + seg;
  }

  // Mirrors static/search.js search(): a real URL is used as-is, a bare host gets https://, and
  // anything else becomes a search on the selected engine.
  function toTarget(input) {
    input = (input || "").trim();
    if (!input) return "";
    try {
      var u = new URL(input);
      if (u.protocol === "http:" || u.protocol === "https:") return u.toString();
    } catch (_) {}
    try {
      var h = new URL("https://" + input);
      if (h.hostname.indexOf(".") >= 0 || h.port) return h.toString();
    } catch (_) {}
    return engineTemplate(currentEngine()).replace("%s", encodeURIComponent(input));
  }

  // Rebuild the shared bare-mux transport for the freshly-picked route/DNS, then reload so the
  // page comes back over it. The transport lives in the "bare-mux-worker" SharedWorker shared with
  // the service worker, so setting it here is exactly what the app shell's ensureTransport() does.
  var applying = false;
  function applyTransportAndReload() {
    if (applying) return;
    applying = true;
    showLoad(currentRealUrl(), "Đang đổi tuyến kết nối…");
    (async function () {
      try {
        var BM = window.BareMux;
        if (!BM) {
          // Lazy-load bare-mux with the real fetch + indirect eval (its UMD sets window.BareMux).
          var code = await (await fetch("/baremux/index.js")).text();
          (0, eval)(code);
          BM = window.BareMux;
        }
        if (BM) {
          var conn = new BM.BareMuxConnection("/baremux/worker.js");
          await conn.setTransport(TRANSPORT, [{ websocket: wispUrl() }]);
        }
      } catch (_) {
        /* best effort — reload anyway so persisted prefs at least take hold where possible */
      }
      location.reload();
    })();
  }

  // --- DOM: fixed bar (input + ⚙ + Go) with a collapsible config panel, hidden until Esc ---

  var wrap = document.createElement("div");
  wrap.id = "__bp_esc_wrap";
  wrap.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;display:none;flex-direction:column;" +
    "background:#1e1e1e;border-bottom:1px solid #444;box-shadow:0 2px 10px rgba(0,0,0,.45);" +
    "font:14px system-ui,-apple-system,sans-serif;box-sizing:border-box;";

  var bar = document.createElement("div");
  bar.style.cssText = "display:flex;gap:8px;padding:8px;align-items:center;box-sizing:border-box;";

  var input = document.createElement("input");
  input.type = "text";
  input.setAttribute("aria-label", "URL");
  input.setAttribute("spellcheck", "false");
  input.style.cssText =
    "flex:1;min-width:0;padding:8px 10px;border:1px solid #555;border-radius:6px;" +
    "background:#2a2a2a;color:#eee;font:inherit;outline:none;";

  var gear = document.createElement("button");
  gear.type = "button";
  gear.textContent = "⚙";
  gear.title = "Route / DNS / Search";
  gear.setAttribute("aria-label", "Route / DNS / Search settings");
  gear.style.cssText =
    "padding:8px 12px;border:1px solid #555;border-radius:6px;background:#2a2a2a;color:#eee;" +
    "font:inherit;cursor:pointer;flex:none;line-height:1;";

  var go = document.createElement("button");
  go.type = "button";
  go.textContent = "Go";
  go.style.cssText =
    "padding:8px 14px;border:0;border-radius:6px;background:#3b82f6;color:#fff;" +
    "font:inherit;cursor:pointer;flex:none;";

  bar.appendChild(input);
  bar.appendChild(gear);
  bar.appendChild(go);

  // Config panel (Route / DNS / Search), hidden until ⚙ is clicked.
  var cfg = document.createElement("div");
  cfg.style.cssText =
    "display:none;gap:14px;flex-wrap:wrap;align-items:center;padding:0 8px 10px;" +
    "border-top:1px solid #333;color:#ccc;box-sizing:border-box;";

  function labeled(text) {
    var l = document.createElement("label");
    l.style.cssText = "display:inline-flex;gap:6px;align-items:center;color:#ccc;";
    l.appendChild(document.createTextNode(text));
    return l;
  }
  var ctlStyle =
    "padding:6px 8px;border:1px solid #555;border-radius:6px;background:#2a2a2a;color:#eee;font:inherit;";

  // Route (hidden unless the server offers more than just `direct`).
  var routeLabel = labeled("Route:");
  routeLabel.style.display = "none";
  var routeSel = document.createElement("select");
  routeSel.style.cssText = ctlStyle;
  routeLabel.appendChild(routeSel);

  // DNS (editable combobox: a preset name or a typed IP).
  var dnsLabel = labeled("DNS:");
  var dnsInput = document.createElement("input");
  dnsInput.setAttribute("list", "__bp_dns_presets");
  dnsInput.setAttribute("spellcheck", "false");
  dnsInput.placeholder = "system or e.g. 1.1.1.1";
  dnsInput.style.cssText = ctlStyle + "min-width:180px;";
  var dnsPresets = document.createElement("datalist");
  dnsPresets.id = "__bp_dns_presets";
  dnsLabel.appendChild(dnsInput);
  dnsLabel.appendChild(dnsPresets);

  // Search engine.
  var engLabel = labeled("Search:");
  var engSel = document.createElement("select");
  engSel.style.cssText = ctlStyle;
  for (var i = 0; i < SEARCH_ENGINES.length; i++) {
    var o = document.createElement("option");
    o.value = SEARCH_ENGINES[i].id;
    o.textContent = SEARCH_ENGINES[i].label;
    engSel.appendChild(o);
  }
  engSel.value = currentEngine();
  engLabel.appendChild(engSel);

  cfg.appendChild(routeLabel);
  cfg.appendChild(dnsLabel);
  cfg.appendChild(engLabel);

  wrap.appendChild(bar);
  wrap.appendChild(cfg);

  var hint = document.createElement("div");
  hint.textContent = "Nhấn Esc để hiện/ẩn thanh địa chỉ";
  hint.style.cssText =
    "position:fixed;bottom:12px;left:50%;transform:translateX(-50%);z-index:2147483647;" +
    "display:none;padding:6px 12px;border-radius:6px;background:rgba(0,0,0,.82);color:#fff;" +
    "font:13px system-ui,-apple-system,sans-serif;pointer-events:none;";

  // --- Loading overlay: shown right before a (slow, esp. Tor) top-level navigation. The browser
  // keeps this page until the response's first bytes arrive, so it covers most of the wait. ---
  var style = document.createElement("style");
  style.textContent =
    "@keyframes __bp_spin{to{transform:rotate(360deg)}}" +
    "@keyframes __bp_bob{0%,100%{transform:translateY(-3px)}50%{transform:translateY(3px)}}";

  var load = document.createElement("div");
  load.id = "__bp_loading";
  load.style.cssText =
    "position:fixed;inset:0;z-index:2147483646;display:none;flex-direction:column;align-items:center;" +
    "justify-content:center;gap:16px;background:radial-gradient(circle at 50% 38%,#1a2030,#0f1115 70%);" +
    "color:#e8eaed;font:15px system-ui,-apple-system,sans-serif;";
  var loadEmoji = document.createElement("div");
  loadEmoji.style.cssText = "font-size:2.2rem;animation:__bp_bob 2.2s ease-in-out infinite;";
  loadEmoji.textContent = "🌐";
  var loadRing = document.createElement("div");
  loadRing.style.cssText =
    "width:60px;height:60px;border-radius:50%;border:4px solid rgba(108,140,255,.25);" +
    "border-top-color:#6c8cff;animation:__bp_spin 1s linear infinite;";
  var loadText = document.createElement("p");
  loadText.style.cssText = "margin:0;font-size:1.05rem;font-weight:600;";
  var loadHost = document.createElement("span");
  loadHost.style.cssText = "color:#6c8cff;word-break:break-all;";
  loadText.appendChild(document.createTextNode("Đang tải "));
  loadText.appendChild(loadHost);
  var loadSub = document.createElement("p");
  loadSub.style.cssText = "margin:0;font-size:.9rem;color:#9aa0a6;min-height:1.2em;";
  load.appendChild(loadEmoji);
  load.appendChild(loadRing);
  load.appendChild(loadText);
  load.appendChild(loadSub);

  function hostOf(url) {
    try {
      return new URL(url).host || url;
    } catch (_) {
      return url || "";
    }
  }
  function showLoad(url, note) {
    var isTor = /tor/i.test(currentRoute());
    loadEmoji.textContent = isTor ? "🧅" : "🌐";
    loadHost.textContent = hostOf(url);
    loadSub.textContent = note || (isTor ? "Qua Tor — có thể mất một lúc…" : "");
    load.style.display = "flex";
  }

  function mount() {
    var root = document.body || document.documentElement;
    (document.head || document.documentElement).appendChild(style);
    root.appendChild(wrap);
    root.appendChild(hint);
    root.appendChild(load);
  }
  if (document.body) mount();
  else document.addEventListener("DOMContentLoaded", mount);

  // --- Populate Route / DNS from the server (same endpoints as the app shell) ---

  fetch("/routes.json")
    .then(function (r) {
      return r.json();
    })
    .then(function (j) {
      if (j && Array.isArray(j.routes) && j.routes.length) routes = j.routes;
      if (routes.length <= 1) return; // only `direct`: leave the route picker hidden
      routeSel.replaceChildren();
      for (var k = 0; k < routes.length; k++) {
        var op = document.createElement("option");
        op.value = routes[k];
        op.textContent = routes[k];
        routeSel.appendChild(op);
      }
      routeSel.value = currentRoute();
      routeLabel.style.display = "inline-flex";
    })
    .catch(function () {});

  fetch("/dns.json")
    .then(function (r) {
      return r.json();
    })
    .then(function (j) {
      var list = j && Array.isArray(j.dns) && j.dns.length ? j.dns : ["system"];
      if (j && typeof j.default === "string") dnsDefault = j.default;
      dnsPresets.replaceChildren();
      for (var k = 0; k < list.length; k++) {
        var op = document.createElement("option");
        op.value = list[k];
        dnsPresets.appendChild(op);
      }
      var saved = ls(DNS_KEY);
      dnsInput.value = saved != null && saved !== "" ? saved : dnsDefault;
    })
    .catch(function () {});

  // --- Wiring ---

  routeSel.addEventListener("change", function () {
    setLs(ROUTE_KEY, routeSel.value);
    applyTransportAndReload();
  });
  dnsInput.addEventListener("change", function () {
    setLs(DNS_KEY, (dnsInput.value || "").trim());
    applyTransportAndReload();
  });
  engSel.addEventListener("change", function () {
    setLs(ENGINE_KEY, engSel.value); // pure client-side: only the URL box's search uses it
  });

  function cfgOpen() {
    return cfg.style.display !== "none";
  }
  function openCfg() {
    cfg.style.display = "flex";
  }
  function closeCfg() {
    cfg.style.display = "none";
  }
  gear.addEventListener("click", function (e) {
    e.stopPropagation();
    if (cfgOpen()) closeCfg();
    else openCfg();
  });

  var hintTimer = null;
  function flashHint() {
    hint.style.display = "block";
    clearTimeout(hintTimer);
    hintTimer = setTimeout(function () {
      hint.style.display = "none";
    }, 3000);
  }

  function isOpen() {
    return wrap.style.display !== "none";
  }
  function show() {
    input.value = currentRealUrl();
    wrap.style.display = "flex";
    input.focus();
    input.select();
  }
  function hide() {
    closeCfg();
    wrap.style.display = "none";
    flashHint();
  }

  function submit() {
    var target = toTarget(input.value);
    if (!target) return;
    showLoad(target);
    location.href = proxied(target);
  }

  go.addEventListener("click", submit);
  input.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      e.preventDefault();
      submit();
    }
  });

  // Own Esc globally (capture on window = earliest), mirroring the app shell's behavior. An open
  // config panel swallows the first Esc (just closes it), then Esc toggles the bar.
  window.addEventListener(
    "keydown",
    function (e) {
      if (e.key !== "Escape" && e.code !== "Escape") return;
      e.preventDefault();
      e.stopPropagation();
      if (isOpen() && cfgOpen()) {
        closeCfg();
        return;
      }
      if (isOpen()) hide();
      else show();
    },
    true
  );
})();
