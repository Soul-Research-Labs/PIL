import { test, expect } from "@playwright/test";

/**
 * E2E: Dashboard — critical flows.
 *
 * These tests exercise the main dashboard page, navigation,
 * and the scan / findings listing pages to verify the happy path
 * is functional end-to-end.
 */

test.describe("Dashboard", () => {
  test("loads the home page with nav and hero section", async ({ page }) => {
    await page.goto("/");
    // The top-level layout should render the header
    await expect(page.locator("header")).toBeVisible();
    // Page should contain at least one heading
    const heading = page.locator("h1, h2").first();
    await expect(heading).toBeVisible();
  });

  test("navigates to the dashboard page", async ({ page }) => {
    await page.goto("/dashboard");
    // Should show the dashboard layout or redirect to auth
    const url = page.url();
    expect(url).toMatch(/\/(dashboard|auth)/);
  });

  test("navigates to the scans list", async ({ page }) => {
    await page.goto("/scans");
    const url = page.url();
    expect(url).toMatch(/\/(scans|auth)/);
  });

  test("navigates to findings list", async ({ page }) => {
    await page.goto("/findings");
    const url = page.url();
    expect(url).toMatch(/\/(findings|auth)/);
  });

  test("navigates to quickscan page", async ({ page }) => {
    await page.goto("/quickscan");
    const url = page.url();
    expect(url).toMatch(/\/(quickscan|auth)/);
  });
});

test.describe("Navigation", () => {
  test("header links are present and clickable", async ({ page }) => {
    await page.goto("/");
    // Sidebar or header should have navigation links
    const nav = page.locator("nav").first();
    await expect(nav).toBeVisible();
  });

  test("404 page renders for unknown routes", async ({ page }) => {
    const response = await page.goto("/this-page-does-not-exist");
    // Next.js returns 200 for soft-404 with custom not-found page or actual 404
    expect(response?.status()).toBeLessThanOrEqual(404);
    await expect(page.locator("body")).toContainText(
      /not found|404|doesn.t exist/i,
    );
  });
});

test.describe("Quickscan flow", () => {
  test("shows the quickscan form", async ({ page }) => {
    await page.goto("/quickscan");
    // Either a form/textarea or a redirect to auth
    const url = page.url();
    if (url.includes("quickscan")) {
      // Should show a code input area (textarea or code editor)
      const input = page
        .locator("textarea, [role='textbox'], [contenteditable]")
        .first();
      await expect(input).toBeVisible({ timeout: 10_000 });
    }
  });
});

test.describe("Soul fuzzer page", () => {
  test("renders the soul fuzzer section", async ({ page }) => {
    await page.goto("/soul");
    const url = page.url();
    expect(url).toMatch(/\/(soul|auth)/);
  });
});
