"use strict";

// Load the Scramjet service-worker runtime.
importScripts("/scram/scramjet.all.js");

const { ScramjetServiceWorker } = $scramjetLoadWorker();
const scramjet = new ScramjetServiceWorker();

// Source of the Esc address-bar overlay, fetched once and inlined into top-level proxied pages.
let overlaySrc = null;
async function getOverlaySrc() {
  if (overlaySrc === null) {
    try {
      overlaySrc = await (await fetch("/proxy-esc.js")).text();
    } catch (_) {
      overlaySrc = ""; // proxying still works without the overlay
    }
  }
  return overlaySrc;
}

// A top-level proxied document (a link opened in a new tab, or a page that broke out of the
// app-shell iframe) has no address bar around it. Inline our overlay so Esc still reveals an
// editable URL bar. Injected AFTER Scramjet's rewrite pass, so it runs as plain (un-rewritten)
// JS. Only real documents get it — iframe loads (destination "iframe") stay untouched, so the
// app shell keeps owning Esc inside its frame.
async function withOverlay(event, response) {
  if (event.request.destination !== "document") return response;
  const ct = response.headers.get("content-type") || "";
  if (!ct.includes("text/html")) return response;
  const src = await getOverlaySrc();
  if (!src) return response;
  let html;
  try {
    html = await response.text();
  } catch (_) {
    return response;
  }
  const tag = "<script>" + src + "</script>";
  const out = html.includes("</body>") ? html.replace("</body>", tag + "</body>") : html + tag;
  const headers = new Headers(response.headers);
  headers.delete("content-length"); // body length changed
  return new Response(out, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function handleRequest(event) {
  await scramjet.loadConfig();
  // Scramjet handles requests under its prefix; everything else is a normal fetch
  // (our own frontend + asset files).
  if (scramjet.route(event)) {
    return withOverlay(event, await scramjet.fetch(event));
  }
  return fetch(event.request);
}

self.addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event));
});

// Take control promptly so an updated worker (e.g. new overlay logic) applies on the next reload
// instead of waiting for every proxied tab to close first.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
