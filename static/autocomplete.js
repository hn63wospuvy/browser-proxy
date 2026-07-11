"use strict";

// Address-bar query history (browser-local) + an autocomplete dropdown.
//
// History is the raw text the user submitted (a URL, a host, or a search query), most-recent
// first, deduped, capped. Autocomplete shows matches once the input has >= 2 characters.

const HISTORY_KEY = "proxy-history";
const HISTORY_MAX = 100;
const AC_MIN_CHARS = 2;
const AC_MAX_ITEMS = 8;

function loadHistory() {
  try {
    const v = JSON.parse(localStorage.getItem(HISTORY_KEY));
    return Array.isArray(v) ? v : [];
  } catch (_) {
    return [];
  }
}

function saveHistory(list) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, HISTORY_MAX)));
  } catch (_) {
    /* storage full / disabled: history is best-effort */
  }
}

// Record a submitted query: move-to-front, dedupe, cap.
function pushHistory(query) {
  const q = (query || "").trim();
  if (!q) return;
  const list = loadHistory().filter((x) => x !== q);
  list.unshift(q);
  saveHistory(list);
}

// History entries containing `prefix` (case-insensitive), most-recent first, capped.
function matchHistory(prefix) {
  const p = (prefix || "").trim().toLowerCase();
  if (p.length < AC_MIN_CHARS) return [];
  return loadHistory()
    .filter((x) => x.toLowerCase().includes(p))
    .slice(0, AC_MAX_ITEMS);
}

/**
 * Wire an autocomplete dropdown to the address input.
 * @returns {{ isOpen: () => boolean, close: () => void }} controller (used for Esc precedence).
 */
function initAutocomplete({ input, form, container }) {
  let items = [];
  let active = -1; // highlighted index, -1 = none

  const isOpen = () => !container.hidden;

  function close() {
    container.hidden = true;
    container.replaceChildren();
    items = [];
    active = -1;
  }

  function render() {
    container.replaceChildren();
    items.forEach((text, i) => {
      const el = document.createElement("div");
      el.className = "ac-item" + (i === active ? " active" : "");
      el.setAttribute("role", "option");
      el.textContent = text;
      // mousedown (not click) so it fires before the input's blur closes the list.
      el.addEventListener("mousedown", (e) => {
        e.preventDefault();
        choose(text);
      });
      container.appendChild(el);
    });
    container.hidden = items.length === 0;
  }

  function choose(text) {
    input.value = text;
    close();
    // Navigate immediately, as if the user pressed Go.
    if (typeof form.requestSubmit === "function") form.requestSubmit();
    else form.dispatchEvent(new Event("submit", { cancelable: true }));
  }

  function refresh() {
    items = matchHistory(input.value);
    active = -1;
    render();
  }

  input.addEventListener("input", refresh);
  input.addEventListener("focus", refresh);
  // Delay so a mousedown on an item is handled before we tear the list down.
  input.addEventListener("blur", () => setTimeout(close, 120));

  input.addEventListener("keydown", (e) => {
    if (!isOpen() || items.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      active = (active + 1) % items.length;
      render();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      active = (active - 1 + items.length) % items.length;
      render();
    } else if (e.key === "Enter") {
      // Enter accepts the highlighted item; with none highlighted, let the form submit normally.
      if (active >= 0) {
        e.preventDefault();
        choose(items[active]);
      }
    }
    // Escape is intentionally NOT handled here — the window-level hotkey in index.js owns Esc
    // precedence (close the dropdown first, else toggle the bar).
  });

  return { isOpen, close };
}
