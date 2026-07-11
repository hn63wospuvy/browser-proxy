"use strict";

// Search engines used when the address-bar input is NOT a URL / host (see search.js).
// Google aggressively CAPTCHAs proxied traffic (all requests share one server IP + the
// libcurl-WASM TLS fingerprint looks non-browser), so the default is a proxy-friendly engine.
// Each `template` has a `%s` placeholder that `search()` fills with the encoded query.
const SEARCH_ENGINES = [
  { id: "brave", label: "Brave", template: "https://search.brave.com/search?q=%s" },
  { id: "duckduckgo", label: "DuckDuckGo", template: "https://duckduckgo.com/?q=%s" },
  { id: "ddg-lite", label: "DuckDuckGo Lite", template: "https://lite.duckduckgo.com/lite/?q=%s" },
  { id: "startpage", label: "Startpage", template: "https://www.startpage.com/sp/search?query=%s" },
  { id: "bing", label: "Bing", template: "https://www.bing.com/search?q=%s" },
  { id: "google", label: "Google", template: "https://www.google.com/search?q=%s" },
];

// Proxy-friendly default (expect CAPTCHAs on Google via a proxy).
const DEFAULT_ENGINE = "brave";

// Resolve an engine id to its search template, falling back to the default engine.
function engineTemplate(id) {
  const found = SEARCH_ENGINES.find((e) => e.id === id);
  return (found || SEARCH_ENGINES.find((e) => e.id === DEFAULT_ENGINE) || SEARCH_ENGINES[0]).template;
}

// Human-readable label for an engine id (used by the config flash).
function engineLabel(id) {
  const found = SEARCH_ENGINES.find((e) => e.id === id);
  return found ? found.label : id;
}
