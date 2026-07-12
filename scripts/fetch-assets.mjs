// Vendors the Scramjet client engine, bare-mux, the libcurl transport, and the epoxy
// (insecure-TLS fallback) transport into ../static/{scram,libcurl,baremux,epoxy}. Run once
// (or after bumping versions):
//
//     node scripts/fetch-assets.mjs
//
// Node is only needed here; the copied files are committed to the repo and embedded into the
// Rust binary at `cargo build` (see src/assets.rs), so the running server ships them itself.

import { execSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const staticDir = join(here, "..", "static");

console.log("Installing client packages with npm…");
execSync("npm install --no-audit --no-fund --loglevel=error", {
  cwd: here,
  stdio: "inherit",
});

// These path exports resolve to each package's dist directory.
const { scramjetPath } = await import("@mercuryworkshop/scramjet/path");
const { libcurlPath } = await import("@mercuryworkshop/libcurl-transport");
const { baremuxPath } = await import("@mercuryworkshop/bare-mux/node");

const targets = [
  ["scram", scramjetPath],
  ["libcurl", libcurlPath],
  ["baremux", baremuxPath],
];

for (const [name, src] of targets) {
  const dest = join(staticDir, name);
  rmSync(dest, { recursive: true, force: true });
  mkdirSync(dest, { recursive: true });
  cpSync(src, dest, { recursive: true });
  console.log(`  ${name.padEnd(8)} <- ${src}`);
}

// epoxy ships no `path` export; its `.` entry resolves to full/epoxy-bundled.js — the full
// build (HTTP/2 + WebSockets) with the WASM inlined, so a single self-contained ESM file is
// vendored as static/epoxy/epoxy.js. Used only as the insecure-TLS fallback (see
// static/hybrid/index.mjs); the primary path stays libcurl.
const require = createRequire(import.meta.url);
const epoxyBundled = require.resolve("@mercuryworkshop/epoxy-tls"); // -> full/epoxy-bundled.js
const epoxyDir = dirname(epoxyBundled);
const epoxyDest = join(staticDir, "epoxy");
rmSync(epoxyDest, { recursive: true, force: true });
mkdirSync(epoxyDest, { recursive: true });
cpSync(epoxyBundled, join(epoxyDest, "epoxy.js"));
cpSync(join(epoxyDir, "epoxy-bundled.d.ts"), join(epoxyDest, "epoxy.d.ts"));
console.log(`  ${"epoxy".padEnd(8)} <- ${epoxyBundled}`);

console.log("Done. Assets vendored into static/.");
