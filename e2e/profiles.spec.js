import { test, expect } from "@playwright/test";

// End-to-end coverage for configuration profiles: the nested layout, auto-save to localStorage
// and to the server, profile CRUD, and per-browser isolation.
//
// Identity note: the client ID is derived from the browser fingerprint, so every test in this
// file would otherwise share ONE server-side document and read each other's writes. Each test
// therefore seeds its own `proxy-client-id` before the page's scripts run (clientId() reuses a
// cached value verbatim). The one test that must exercise the real fingerprint —
// "recovers from the server after localStorage is cleared" — deliberately seeds nothing.

/** Force a known identity for a test, so its server document is its own. */
async function seedIdentity(page, id) {
  await page.addInitScript((value) => {
    try {
      localStorage.setItem("proxy-client-id", value);
    } catch (_) {
      /* storage blocked — the test will fail on its assertions, not here */
    }
  }, id);
}

/** A distinct, valid (32 lowercase hex) client id per test. */
const identity = (n) => String(n).padStart(2, "0").repeat(16).slice(0, 32);

async function clientId(page) {
  return page.evaluate(() => localStorage.getItem("proxy-client-id"));
}

async function localDoc(page) {
  return page.evaluate(() => JSON.parse(localStorage.getItem("proxy-config") || "null"));
}

/** The document the SERVER holds for this id, or null when it has none. */
async function serverDoc(request, id) {
  const res = await request.get(`/api/profiles/${id}`);
  if (res.status() === 404) return null;
  expect(res.status(), "GET /api/profiles should be 200 or 404").toBe(200);
  return res.json();
}

const syncStatus = (page) => page.locator("#profile-sync");

/** Drive the DNS control the way a user would: a preset by name, anything else via "Tùy chỉnh…". */
async function pickDns(page, value) {
  const presets = await page.locator("#proxy-dns-landing option").evaluateAll((os) =>
    os.map((o) => o.value)
  );
  if (presets.includes(value)) {
    await page.selectOption("#proxy-dns-landing", value);
    await expect(page.locator("#proxy-dns-custom")).toBeHidden();
    return;
  }
  await page.selectOption("#proxy-dns-landing", "__custom__");
  await expect(page.locator("#proxy-dns-custom")).toBeVisible();
  await page.fill("#proxy-dns-custom", value);
  await page.locator("#proxy-dns-custom").blur();
}

/** Add one header override through the inline editor (no modal any more). */
async function addHeader(page, name, value) {
  await page.locator("#headers-add").click();
  const row = page.locator(".headers-row").last();
  await row.locator(".h-name").fill(name);
  await row.locator(".h-value").fill(value);
  await row.locator(".h-value").blur();
}

/** Wait for the debounced PUT to land. */
async function expectSynced(page) {
  await expect(syncStatus(page)).toHaveAttribute("data-state", "synced");
}

async function gotoLanding(page) {
  await page.goto("/");
  await expect(page.locator("#proxy-profile")).toBeVisible();
  // The route picker is populated from /routes.json; waiting for it avoids racing the fetch.
  await expect(page.locator("#proxy-route-landing")).toBeVisible();
}

test.describe("configuration profiles", () => {
  test("the profile block sits above the settings and visually owns them", async ({ page }) => {
    await seedIdentity(page, identity(1));
    await gotoLanding(page);

    const head = page.locator(".profile-head");
    const scope = page.locator(".profile-scope");
    await expect(head).toBeVisible();
    await expect(scope).toBeVisible();

    // The profile control lives in the head block, the four settings in the scoped block.
    await expect(head.locator("#proxy-profile")).toHaveCount(1);
    for (const id of [
      "#proxy-engine-landing",
      "#proxy-dns-landing",
      "#proxy-route-landing",
      "#headers-picker",
    ]) {
      await expect(scope.locator(id), `${id} should be nested under the profile`).toHaveCount(1);
    }

    // Nesting must be visible, not just structural: the scope is indented and rule-marked.
    const box = await scope.boundingBox();
    const headBox = await head.boundingBox();
    expect(headBox.y, "profile row is above the settings").toBeLessThan(box.y);
    expect(box.x, "settings are indented relative to the profile row").toBeGreaterThan(headBox.x);

    // `default` exists and is selected, with no placeholder option.
    await expect(page.locator("#proxy-profile")).toHaveValue("default");
    const options = await page.locator("#proxy-profile option").allTextContents();
    expect(options).toEqual(["default"]);
  });

  test("changing a setting auto-saves to localStorage and to the server", async ({
    page,
    request,
  }) => {
    const id = identity(2);
    await seedIdentity(page, id);
    await gotoLanding(page);

    await page.selectOption("#proxy-engine-landing", "google");
    await pickDns(page, "1.1.1.1"); // not a preset name → the custom field
    await page.selectOption("#proxy-route-landing", "fake");

    await expectSynced(page);

    // Local copy.
    const local = await localDoc(page);
    const localDefault = local.profiles.find((p) => p.name === "default");
    expect(localDefault).toMatchObject({ engine: "google", dns: "1.1.1.1", route: "fake" });
    expect(local.active).toBe("default");

    // Server copy — no button was pressed; auto-save alone must have pushed it.
    const remote = await serverDoc(request, id);
    expect(remote, "the server must have the document").not.toBeNull();
    const remoteDefault = remote.profiles.find((p) => p.name === "default");
    expect(remoteDefault).toMatchObject({ engine: "google", dns: "1.1.1.1", route: "fake" });
  });

  test("settings survive a reload", async ({ page }) => {
    await seedIdentity(page, identity(3));
    await gotoLanding(page);

    await page.selectOption("#proxy-engine-landing", "bing");
    await expectSynced(page);

    await page.reload();
    await expect(page.locator("#proxy-engine-landing")).toHaveValue("bing");
    await expect(page.locator("#proxy-profile")).toHaveValue("default");
  });

  test("recovers from the server after localStorage is cleared", async ({ page, request }) => {
    // No seeded identity: this is the whole point of a fingerprint rather than a random UUID —
    // the same browser must recompute the same id and get its configuration back.
    await gotoLanding(page);
    await page.selectOption("#proxy-engine-landing", "startpage");
    await expectSynced(page);

    const id = await clientId(page);
    expect(id, "the client id must be 32 lowercase hex").toMatch(/^[0-9a-f]{32}$/);
    expect(await serverDoc(request, id)).not.toBeNull();

    await page.evaluate(() => localStorage.clear());
    await page.reload();

    await expect(page.locator("#proxy-engine-landing")).toHaveValue("startpage");
    expect(await clientId(page), "the recomputed fingerprint must match").toBe(id);
  });

  test("a different fingerprint gets a separate document", async ({ page, request }) => {
    const mine = identity(5);
    await seedIdentity(page, mine);
    await gotoLanding(page);
    await page.selectOption("#proxy-engine-landing", "duckduckgo");
    await expectSynced(page);

    const theirs = identity(6);
    expect(await serverDoc(request, theirs), "another browser has its own store").toBeNull();

    const remote = await serverDoc(request, mine);
    expect(remote.profiles.find((p) => p.name === "default").engine).toBe("duckduckgo");
  });

  test("create, rename and delete a profile", async ({ page, request }) => {
    const id = identity(7);
    await seedIdentity(page, id);
    await gotoLanding(page);

    // "Tạo mới" starts from the defaults — it leaves `default`'s own settings alone and does not
    // carry them into the new profile. ("Nhân bản" is what copies; see its own test.)
    await page.selectOption("#proxy-engine-landing", "bing");
    await page.locator("#profile-new").click();
    await page.fill("#profile-name-input", "Công việc");
    await page.locator("#profile-name-save").click();

    await expect(page.locator("#proxy-profile")).toHaveValue("Công việc");
    await expect(page.locator("#proxy-engine-landing")).toHaveValue("brave");
    await expectSynced(page);

    let remote = await serverDoc(request, id);
    expect(remote.profiles.map((p) => p.name)).toEqual(["default", "Công việc"]);
    expect(remote.active).toBe("Công việc");
    expect(remote.profiles[0].engine, "default kept what it had").toBe("bing");
    expect(remote.profiles[1].engine, "the new profile started blank").toBe("brave");

    // Rename keeps it active and keeps its config.
    await page.locator("#profile-rename").click();
    await page.fill("#profile-name-input", "Việc riêng");
    await page.locator("#profile-name-save").click();
    await expect(page.locator("#proxy-profile")).toHaveValue("Việc riêng");
    await expectSynced(page);

    remote = await serverDoc(request, id);
    expect(remote.profiles.map((p) => p.name)).toEqual(["default", "Việc riêng"]);
    expect(remote.active).toBe("Việc riêng");

    // Delete falls back to `default`.
    await page.locator("#profile-delete").click();
    await expect(page.locator("#proxy-profile")).toHaveValue("default");
    await expectSynced(page);

    remote = await serverDoc(request, id);
    expect(remote.profiles.map((p) => p.name)).toEqual(["default"]);
    expect(remote.active).toBe("default");
  });

  test("switching profiles restores that profile's whole configuration", async ({ page }) => {
    await seedIdentity(page, identity(8));
    await gotoLanding(page);

    // `default` = Brave + system DNS + direct.
    await page.selectOption("#proxy-engine-landing", "brave");
    await pickDns(page, "system");
    await page.selectOption("#proxy-route-landing", "direct");
    await expectSynced(page);

    // A second profile with a different everything, including a custom DNS IP.
    await page.locator("#profile-new").click();
    await page.fill("#profile-name-input", "Riêng tư");
    await page.locator("#profile-name-save").click();
    await page.selectOption("#proxy-engine-landing", "google");
    await pickDns(page, "9.9.9.9");
    await page.selectOption("#proxy-route-landing", "fake");
    await expectSynced(page);

    // Switching back restores all three at once — and puts the DNS control back into preset mode.
    await page.selectOption("#proxy-profile", "default");
    await expect(page.locator("#proxy-engine-landing")).toHaveValue("brave");
    await expect(page.locator("#proxy-dns-landing")).toHaveValue("system");
    await expect(page.locator("#proxy-dns-custom")).toBeHidden();
    await expect(page.locator("#proxy-route-landing")).toHaveValue("direct");

    await page.selectOption("#proxy-profile", "Riêng tư");
    await expect(page.locator("#proxy-engine-landing")).toHaveValue("google");
    await expect(page.locator("#proxy-dns-landing")).toHaveValue("__custom__");
    await expect(page.locator("#proxy-dns-custom")).toBeVisible();
    await expect(page.locator("#proxy-dns-custom")).toHaveValue("9.9.9.9");
    await expect(page.locator("#proxy-route-landing")).toHaveValue("fake");
  });

  test("DNS presets are labelled with their addresses and only Custom reveals the field", async ({
    page,
  }) => {
    await seedIdentity(page, identity(13));
    await gotoLanding(page);

    const labels = await page
      .locator("#proxy-dns-landing option")
      .evaluateAll((os) => os.map((o) => [o.value, o.textContent.trim()]));

    // The server's own resolvers, each carrying its real IP — no hardcoded list in the frontend.
    expect(labels.map(([v]) => v)).toEqual([
      "system",
      "cloudflare",
      "google",
      "quad9",
      "__custom__",
    ]);
    expect(Object.fromEntries(labels).cloudflare).toBe("cloudflare (1.1.1.1)");
    expect(Object.fromEntries(labels).google).toBe("google (8.8.8.8)");
    expect(Object.fromEntries(labels).quad9).toBe("quad9 (9.9.9.9)");
    expect(Object.fromEntries(labels).system, "the OS resolver has no address").toBe("system");

    // The field is for the custom entry only.
    await expect(page.locator("#proxy-dns-custom")).toBeHidden();
    await page.selectOption("#proxy-dns-landing", "cloudflare");
    await expect(page.locator("#proxy-dns-custom")).toBeHidden();
    await page.selectOption("#proxy-dns-landing", "__custom__");
    await expect(page.locator("#proxy-dns-custom")).toBeVisible();

    // Selecting Custom without typing anything must not overwrite the saved resolver — not at this
    // instant, and not on the NEXT unrelated change either. The half-finished state has to keep
    // reporting the resolver actually in force, or auto-save quietly writes "" over it.
    expect((await localDoc(page)).profiles[0].dns).toBe("cloudflare");
    await page.selectOption("#proxy-engine-landing", "bing");
    await expectSynced(page);
    const doc = await localDoc(page);
    expect(doc.profiles[0], "an unrelated edit must not clear the resolver").toMatchObject({
      engine: "bing",
      dns: "cloudflare",
    });
    expect(
      await page.evaluate(() => localStorage.getItem("proxy-dns")),
      "the mirror key and the profile must still agree"
    ).toBe("cloudflare");
  });

  test("Nhân bản copies the profile, Tạo mới starts blank", async ({ page }) => {
    await seedIdentity(page, identity(14));
    await gotoLanding(page);

    await page.selectOption("#proxy-engine-landing", "google");
    await pickDns(page, "quad9");
    await addHeader(page, "X-Clone", "yes");
    await expectSynced(page);

    // Clone: same settings, new name, prefilled suggestion.
    await page.locator("#profile-clone").click();
    await expect(page.locator("#profile-name-input")).toHaveValue("default (2)");
    await page.locator("#profile-name-save").click();

    await expect(page.locator("#proxy-profile")).toHaveValue("default (2)");
    await expect(page.locator("#proxy-engine-landing")).toHaveValue("google");
    await expect(page.locator("#proxy-dns-landing")).toHaveValue("quad9");
    await expect(page.locator(".headers-row .h-name")).toHaveValue("X-Clone");
    await expectSynced(page);

    // New: back to the defaults, not a second copy of the live settings.
    await page.locator("#profile-new").click();
    await page.fill("#profile-name-input", "Trống");
    await page.locator("#profile-name-save").click();

    await expect(page.locator("#proxy-profile")).toHaveValue("Trống");
    await expect(page.locator("#proxy-engine-landing")).toHaveValue("brave");
    await expect(page.locator("#proxy-dns-landing")).toHaveValue("system");
    await expect(page.locator(".headers-row")).toHaveCount(0);
    await expectSynced(page);

    // The clone kept its copy; the original is untouched.
    const doc = await localDoc(page);
    expect(doc.profiles.map((p) => p.name)).toEqual(["default", "default (2)", "Trống"]);
    expect(doc.profiles[1]).toMatchObject({ engine: "google", dns: "quad9" });
    expect(doc.profiles[1].headers).toEqual([{ name: "X-Clone", value: "yes" }]);
    expect(doc.profiles[2]).toMatchObject({ engine: "brave", dns: "", headers: [] });
  });

  test("the default profile cannot be renamed or deleted", async ({ page }) => {
    await seedIdentity(page, identity(9));
    await gotoLanding(page);

    await expect(page.locator("#proxy-profile")).toHaveValue("default");
    await expect(page.locator("#profile-rename")).toBeDisabled();
    await expect(page.locator("#profile-delete")).toBeDisabled();

    // Another profile re-enables them.
    await page.locator("#profile-new").click();
    await page.fill("#profile-name-input", "Khác");
    await page.locator("#profile-name-save").click();
    await expect(page.locator("#profile-rename")).toBeEnabled();
    await expect(page.locator("#profile-delete")).toBeEnabled();
  });

  test("header overrides edit in place and auto-save", async ({ page, request }) => {
    const id = identity(10);
    await seedIdentity(page, id);
    await gotoLanding(page);

    // No modal: the rows are part of the panel.
    await expect(page.locator("#headers-modal")).toHaveCount(0);
    await expect(page.locator("#headers-rows")).toHaveCount(1);
    await expect(page.locator(".headers-row")).toHaveCount(0);

    await addHeader(page, "X-Test", "e2e");
    await expect(page.locator("#headers-count")).toHaveText("(1)");
    await expectSynced(page);

    let remote = await serverDoc(request, id);
    expect(remote.profiles.find((p) => p.name === "default").headers).toEqual([
      { name: "X-Test", value: "e2e" },
    ]);

    // An invalid name reports itself and leaves the stored set alone.
    await addHeader(page, "Bad Name", "nope");
    await expect(page.locator("#headers-error")).toBeVisible();
    remote = await serverDoc(request, id);
    expect(remote.profiles[0].headers, "the last good set survives").toEqual([
      { name: "X-Test", value: "e2e" },
    ]);

    // Fixing the row commits both.
    await page.locator(".headers-row").last().locator(".h-name").fill("X-Second");
    await page.locator(".headers-row").last().locator(".h-name").blur();
    await expect(page.locator("#headers-error")).toBeHidden();
    await expectSynced(page);
    remote = await serverDoc(request, id);
    expect(remote.profiles[0].headers).toEqual([
      { name: "X-Test", value: "e2e" },
      { name: "X-Second", value: "nope" },
    ]);

    // Removing a row commits too.
    await page.locator(".headers-row").last().locator(".h-remove").click();
    await expectSynced(page);
    remote = await serverDoc(request, id);
    expect(remote.profiles[0].headers).toEqual([{ name: "X-Test", value: "e2e" }]);
  });

  // Migration is the one path that can build a document the server refuses outright — and a
  // refused document stops syncing for good. The seed below is deliberately hostile: it is already
  // at the legacy 50-profile cap (so adding `default` makes 51), it collides on `default` twice
  // (so the suffix counter has to chain), it carries an over-long name ending in an emoji (so a
  // careless truncation would leave a lone surrogate that serde_json rejects), and it holds header
  // values the old load path never validated.
  test("a hostile legacy store migrates into a document the server accepts", async ({
    page,
    request,
  }) => {
    const id = identity(12);
    await seedIdentity(page, id);
    await page.addInitScript(() => {
      const legacy = [
        { name: "default", route: "direct", engine: "bing", dns: "", headers: [] },
        { name: "default (2)", route: "direct", engine: "brave", dns: "", headers: [] },
        {
          name: "x".repeat(63) + "\u{1F600}", // 65 UTF-16 units; the 64-char cut lands mid-pair
          route: "direct",
          engine: "brave",
          dns: "",
          headers: [{ name: "Bad Name", value: "dropped" }],
        },
        {
          name: "junk-headers",
          route: "direct",
          engine: "brave",
          dns: "",
          headers: [
            { name: "X-Ok", value: "kept" },
            { name: "X-Newline", value: "a\nb" },
            { name: "X-Huge", value: "z".repeat(10241) },
          ],
        },
      ];
      while (legacy.length < 50) legacy.push({ name: `hồ sơ ${legacy.length}`, headers: [] });
      localStorage.setItem("proxy-profiles", JSON.stringify(legacy));
      localStorage.setItem("proxy-active-profile", "x".repeat(63) + "\u{1F600}");
      localStorage.setItem("proxy-engine", "google");
    });

    await gotoLanding(page);
    await expectSynced(page); // the server took it — no 400, no permanent local-only

    const remote = await serverDoc(request, id);
    const names = remote.profiles.map((p) => p.name);

    expect(names.length, "clamped to the server's cap").toBe(50);
    expect(new Set(names.map((n) => n.toLowerCase())).size, "names unique").toBe(50);
    expect(names[0], "default is first and keeps its name").toBe("default");
    // The counter chains rather than stacking suffixes: not "default (2) (2)".
    expect(names).toContain("default (2)");
    expect(names).toContain("default (3)");
    expect(Math.max(...names.map((n) => n.length)), "names within 64").toBeLessThanOrEqual(64);
    expect(names.some((n) => /[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(n)), "no lone surrogate")
      .toBe(false);
    expect(names, "active names a survivor").toContain(remote.active);

    // `default` reflects what the user was actually looking at, and junk headers are gone.
    expect(remote.profiles[0].engine).toBe("google");
    expect(remote.profiles.find((p) => p.name === "junk-headers").headers).toEqual([
      { name: "X-Ok", value: "kept" },
    ]);

    // The legacy keys are retired.
    expect(
      await page.evaluate(() => [
        localStorage.getItem("proxy-profiles"),
        localStorage.getItem("proxy-active-profile"),
      ])
    ).toEqual([null, null]);
  });

  // The "i" next to each setting's label. Hover is CSS-only; these cover the two things that are
  // easy to break: the click toggle (which needs a blur, because `:focus-within` also shows the
  // bubble) and the <label> still belonging to its <select> rather than to the button inside it.
  test("each setting's label carries an i hint that opens on hover and toggles on click", async ({
    page,
  }) => {
    await seedIdentity(page, identity(15));
    await gotoLanding(page);

    const bubble = (id) => page.locator(`#hint-${id}`);
    const btn = (id) => page.locator(`#hint-${id}`).locator("xpath=../button");
    const ids = ["profile", "engine", "dns", "route", "headers"];

    // One per setting, and every bubble starts hidden.
    for (const id of ids) {
      await expect(btn(id), `${id} has an i button`).toHaveCount(1);
      await expect(bubble(id)).toBeHidden();
    }

    // Hover reveals it (pure CSS), moving away hides it again.
    await btn("dns").hover();
    await expect(bubble("dns")).toBeVisible();
    await page.mouse.move(0, 0);
    await expect(bubble("dns")).toBeHidden();

    // Click pins it open — the path touch devices have to use, since they never hover.
    await btn("route").click();
    await expect(bubble("route")).toBeVisible();
    await expect(btn("route")).toHaveAttribute("aria-expanded", "true");

    // Only one at a time.
    await btn("headers").click();
    await expect(bubble("route")).toBeHidden();
    await expect(bubble("headers")).toBeVisible();

    // A second click on the same button unpins it. The pointer is still on the button afterwards,
    // and hover alone is enough to show a bubble — so move away before asking whether it is gone.
    await btn("headers").click();
    await expect(btn("headers")).toHaveAttribute("aria-expanded", "false");
    await page.mouse.move(0, 0);
    await expect(bubble("headers")).toBeHidden();

    // A click anywhere else dismisses it too.
    await btn("engine").click();
    await page.mouse.move(0, 0);
    await page.locator("h1").click();
    await expect(bubble("engine")).toBeHidden();
  });

  test("the i button does not steal the label's click from its select", async ({ page }) => {
    await seedIdentity(page, identity(16));
    await gotoLanding(page);

    const focused = () => page.evaluate(() => document.activeElement.id);

    // A <label> without `for` targets its FIRST labelable descendant — which the i <button> now
    // is. Clicking the label text must still reach the dropdown, and clicking the i must not.
    await page.locator("#engine-picker .picker-label").click({ position: { x: 4, y: 8 } });
    expect(await focused(), "clicking 'Search:' focuses the engine select").toBe(
      "proxy-engine-landing"
    );

    await page.locator("#hint-engine").locator("xpath=../button").click();
    expect(await focused(), "clicking the i focuses the i, not the select").toBe("");
    await expect(page.locator("#proxy-engine-landing")).toHaveValue("brave");
  });

  test("the removed Cập nhật / Xóa hết buttons are gone", async ({ page }) => {
    await seedIdentity(page, identity(11));
    await gotoLanding(page);
    await expect(page.locator("#profile-update")).toHaveCount(0);
    await expect(page.locator("#profile-clear")).toHaveCount(0);
  });
});
