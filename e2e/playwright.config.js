import { defineConfig, devices } from "@playwright/test";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..");

// A fixed port keeps the webServer URL knowable; the suite owns it for the run.
const PORT = 8099;
export const BASE_URL = `http://127.0.0.1:${PORT}`;

// Each run gets its own profile store, so a previous run's documents can never satisfy an
// assertion about what this run wrote. Playwright's global setup empties it before the suite.
export const PROFILES_DIR = path.join(os.tmpdir(), `bp-e2e-profiles-${process.pid}`);

// The debug binary; `cargo build` must have run. Release works too if you point this at it.
const binary = path.join(
  repo,
  "target",
  "debug",
  process.platform === "win32" ? "browser-proxy.exe" : "browser-proxy"
);

export default defineConfig({
  testDir: here,
  // The suite asserts on server-side documents keyed by browser fingerprint; parallel workers
  // would share one store and one fingerprint per browser build. Serial keeps that honest.
  workers: 1,
  fullyParallel: false,
  reporter: [["list"]],
  timeout: 30_000,
  expect: { timeout: 10_000 },
  globalSetup: path.join(here, "global-setup.js"),
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `"${binary}"`,
    cwd: repo,
    url: BASE_URL,
    reuseExistingServer: false,
    stdout: "pipe",
    stderr: "pipe",
    timeout: 60_000,
    env: {
      // Bind explicitly rather than trusting the default, and keep the real config.yaml (warp /
      // tor) out of the picture.
      BIND: `127.0.0.1:${PORT}`,
      CONFIG: path.join(here, "config.e2e.yaml"),
      // Deliberately NOT setting STATIC_DIR. A debug build already reads static/ from disk (see
      // src/assets.rs), so edits need no rebuild either way — and the ServeDir path that STATIC_DIR
      // switches on is built with append_index_html_on_directories(false), which makes "/" a 404.
      PROFILES_DIR,
      RUST_LOG: "browser_proxy=debug,tower_http=warn",
    },
  },
});
