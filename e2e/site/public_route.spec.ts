/**
 * The public call page shows the programme's route as static SVG with
 * scripts off (R-JV-06, R-PB-04, ADR-015 amendment of 2026-11-06, I-96;
 * lane j4).
 *
 * - r_jv_06_public_call_page_shows_the_route_with_scripts_off: with
 *   JavaScript disabled, the call page the public open calls page links
 *   holds one route map, the renderer's `route-svg` group, with every
 *   formal state named and no viewer position. The page holds no script
 *   element, and its response carries the `/p` CSP with `script-src
 *   'none'`. The map paints itself, since /p links no stylesheet: a
 *   node label fills in the page text colour at 4.5:1 or more on the
 *   page, over a shape with no fill (I-70, review J4-REV-1).
 *
 * Every person, call and text is synthetic. Lane j4 test author: red
 * until the call page holds the route.
 */

import { expect } from '@playwright/test';
import { test } from '../playwright.config';
import { ApplicantControl } from '../applicant/support';
import { FrontDoor, SITE, suiteCell } from './contract';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** The sixteen formal states of the proposal route (I-96). */
const STATES = [
  'DRAFT',
  'SUBMITTED',
  'STAGE1',
  'STAGE2',
  'RANKED',
  'IRC_REVIEW',
  'NEGOTIATION',
  'GRANTED',
  'IN_EXECUTION',
  'COMPLETED',
  'DEFERRED',
  'INELIGIBLE',
  'NOT_SELECTED',
  'DECLINED',
  'WITHDRAWN',
  'TERMINATED',
] as const;

test.describe('R-JV-06 public route', () => {
  /** R-JV-06, R-PB-04, I-96. */
  test('r_jv_06_public_call_page_shows_the_route_with_scripts_off', async ({ browser, request }) => {
    const cell = suiteCell();
    const control = new ApplicantControl(request, cell);
    await control.reset();
    const s = await control.scenario('OPEN_CALL');

    const door = await FrontDoor.open(browser, cell);
    let href: string;
    try {
      const link = door.page.locator(SITE.demo.publicCalls);
      await expect(link, 'the demo front door links the public open calls page').toHaveCount(1);
      href = (await link.getAttribute('href')) ?? '';
    } finally {
      await door.close();
    }

    const context = await browser.newContext({ javaScriptEnabled: false });
    try {
      const page = await context.newPage();
      await page.goto(new URL(href, cell.control).href);
      const callLink = page.locator('main a', { hasText: s.call.title }).first();
      await expect(callLink, 'the list links the call page').toBeVisible();
      const [response] = await Promise.all([page.waitForResponse((r) => r.request().isNavigationRequest()), callLink.click()]);
      await page.waitForLoadState('load');
      await expect(page.locator('main h1'), 'the call page names the call').toHaveText(s.call.title);

      const csp = (await response.allHeaders())['content-security-policy'] ?? '';
      expect(csp, 'the /p CSP admits no script').toContain("script-src 'none'");
      expect(await page.locator('script').count(), 'R-PB-04: no script on the call page').toBe(0);

      const svg = page.locator('main svg.route-svg');
      await expect(svg, 'R-JV-06: the route map is present with scripts off').toHaveCount(1);
      await expect(svg, 'the map is visible').toBeVisible();
      const names = await svg.locator('[aria-label]').evaluateAll((els) => els.map((e) => e.getAttribute('aria-label') ?? ''));
      for (const state of STATES) {
        expect(names.some((n) => n.includes(`(${state})`)), `I-96: a node names ${state}`).toBe(true);
      }
      const markup = await svg.evaluate((e) => e.outerHTML);
      for (const mark of ['current stage', 'current-ring', 'svg-current', 'aria-current', 'edge--done']) {
        expect(markup.includes(mark), `R-JV-06: no viewer position (${mark})`).toBe(false);
      }

      // I-70, review J4-REV-1: an SVG text or shape with no paint fills
      // black. A node label reaches 4.5:1 on what lies under it: its
      // shape's fill, or the page background when the shape has none.
      // With no stylesheet linked, the map paints itself: the label fills
      // in the page text colour and the shape has no fill.
      const paint = await svg.evaluate((root) => {
        const rgb = (c: string): number[] | null => {
          const m = /^rgba?\(([^)]*)\)$/.exec(c.trim());
          if (m === null) {
            return null;
          }
          const parts = (m[1] ?? "").split(/[ ,\/]+/).filter((x) => x !== "").map(Number);
          return parts.length >= 3 ? parts : null;
        };
        const lum = (c: number[]): number => {
          const ch = c.slice(0, 3).map((v) => {
            const x = v / 255;
            return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
          });
          return 0.2126 * (ch[0] ?? 0) + 0.7152 * (ch[1] ?? 0) + 0.0722 * (ch[2] ?? 0);
        };
        const label = root.querySelector("text.node-label");
        const shape = root.querySelector("rect.node-shape");
        if (label === null || shape === null) {
          return { found: false, sheet: false, labelFill: "", textColour: "", shapeFill: "", ratio: 0 };
        }
        const labelFill = getComputedStyle(label).fill;
        const textColour = getComputedStyle(document.body).color;
        let bg = rgb(getComputedStyle(document.body).backgroundColor);
        if (bg === null || (bg[3] ?? 1) === 0) {
          bg = rgb(getComputedStyle(document.documentElement).backgroundColor);
        }
        if (bg === null || (bg[3] ?? 1) === 0) {
          bg = [255, 255, 255];
        }
        const shapeFill = getComputedStyle(shape).fill;
        const under = rgb(shapeFill) ?? bg;
        const fg = rgb(labelFill);
        const ratio = fg === null ? 0 : (Math.max(lum(fg), lum(under)) + 0.05) / (Math.min(lum(fg), lum(under)) + 0.05);
        const sheet = document.querySelector("link[rel~=stylesheet]") !== null;
        return { found: true, sheet, labelFill, textColour, shapeFill, ratio };
      });
      expect(paint.found, "the map holds a node label and a node shape").toBe(true);
      if (!paint.sheet) {
        expect(paint.labelFill, "I-70: the label fills in the page text colour").toBe(paint.textColour);
        expect(paint.shapeFill, "I-70: the node shape paints no fill over its label").toBe("none");
      }
      expect(paint.ratio, "I-70: the node label reaches 4.5:1 on the page").toBeGreaterThanOrEqual(4.5);
    } finally {
      await context.close();
    }
  });
});
