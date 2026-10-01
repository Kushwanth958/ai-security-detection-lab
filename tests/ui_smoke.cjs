// Optional browser verification. See docs/validation.md for dependency setup.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");

(async () => {
  const browser = await chromium.launch({headless: true});
  try {
    const page = await browser.newPage({viewport: {width: 1440, height: 1100}, deviceScaleFactor: 1});
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("console", message => { if (message.type() === "error") errors.push(message.text()); });
    await page.goto(process.env.LAB_UI_URL || "http://127.0.0.1:8765");
    await page.locator("#trials tr").first().waitFor();
    assert.match(await page.locator("#message").innerText(), /Fixture|fixture/);
    assert.equal(await page.locator("#metrics .metric").count(), 4);
    await page.locator("#mode-filter").selectOption("secured");
    assert.match(await page.locator("#trial-count").innerText(), /150 matching/);
    await page.locator("#search").fill("encoded_leakage");
    assert.match(await page.locator("#trial-count").innerText(), /15 matching/);
    await page.locator(".evidence-button").first().click();
    assert.equal(await page.locator("#evidence-dialog").isVisible(), true);
    assert.match(await page.locator("#evidence-content").innerText(), /output_was_filtered/);
    await page.keyboard.press("Escape");
    assert.equal(await page.locator("#evidence-dialog").isVisible(), false);
    await page.locator("#search").fill("");
    await page.locator("#mode-filter").selectOption("");
    await page.locator("#next").click();
    assert.match(await page.locator("#page-info").innerText(), /Page 2/);
    await page.locator("#previous").click();
    const outputDir = process.env.LAB_SCREENSHOT_DIR;
    if (outputDir) {
      fs.mkdirSync(outputDir, {recursive: true});
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({path: path.join(outputDir, "dashboard.png")});
    }
    await page.locator("#soc-tab").click();
    await page.locator(".soc-card").first().waitFor();
    assert.equal(await page.locator(".soc-card").count(), 4);
    assert.match(await page.locator("#message").innerText(), /Scripted/);
    if (outputDir) await page.screenshot({path: path.join(outputDir, "soc-investigations.png"), fullPage: true});
    await page.setViewportSize({width: 390, height: 844});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    await page.locator("#evaluation-tab").click();
    assert.equal(await page.locator("#evaluation-view").isVisible(), true);
    // A hostile persisted response must render as text in the evidence inspector.
    await page.route("**/api/run?*", async route => {
      const response = await route.fetch();
      const body = await response.json();
      body.trials[0].output_redacted = '<img src=x onerror="window.labXSS=true">';
      await route.fulfill({response, json: body});
    });
    await page.reload();
    await page.locator("#trials tr").first().waitFor();
    await page.locator(".evidence-button").first().click();
    assert.match(await page.locator("#evidence-content").innerText(), /onerror/);
    assert.equal(await page.evaluate(() => window.labXSS), undefined);
    assert.equal(await page.locator("#evidence-dialog img").count(), 0);
    assert.deepEqual(errors, []);
    console.log("Browser checks passed: filtering, pagination, evidence, SOC, mobile layout, XSS rendering, console.");
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
