// Vendors the Scramjet client engine, bare-mux, and the libcurl transport into
// ../static/{scram,libcurl,baremux}. Run once (or after bumping versions):
//
//     node scripts/fetch-assets.mjs
//
// Node is only needed here; the running server is pure Rust and serves the copied files.

import { execSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync } from "node:fs";
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

console.log("Done. Assets vendored into static/.");
