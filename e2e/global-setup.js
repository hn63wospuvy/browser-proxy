import fs from "node:fs";
import { PROFILES_DIR } from "./playwright.config.js";

// Start every run from an empty store. The eviction / "this browser has no document yet"
// assertions are only meaningful if nothing survives from a previous run.
export default function globalSetup() {
  fs.rmSync(PROFILES_DIR, { recursive: true, force: true });
  fs.mkdirSync(PROFILES_DIR, { recursive: true });
}
