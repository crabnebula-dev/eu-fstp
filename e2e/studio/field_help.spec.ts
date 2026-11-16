/**
 * Field help in the Programme editor and the set-up wizard, by clicking
 * from sign-in (SA-13, Daniel 2026-11-15 night; R-NF-03; the
 * click-through rule: each person reaches their work by clicking from
 * sign-in).
 *
 * The demo scene is the programme set-up scene: programme manager M1
 * holds a fully built draft, and tenant admin A2 belongs to an active
 * organisation.
 *
 * - r_nf_03_sa13_programme_manager_opens_and_closes_field_help_in_the_editor:
 *   M1 clicks from home to the Programme editor, then to step 2. The "i"
 *   button of "Programme name" is collapsed and its help hidden. A click
 *   shows it, Enter hides it, Space shows it, and a click hides it again.
 * - r_nf_03_sa13_tenant_admin_opens_and_closes_field_help_in_the_wizard:
 *   A2 clicks from home to stage 1 of the wizard and does the same with
 *   the help of "Programme name".
 *
 * With the help open, each page passes the in-house accessibility checks
 * of the suite (`structureProblems`, contrast in both themes), and the
 * button's glyph and border meet contrast in both themes. With
 * `FSTP_HELP_SHOTS` set to a directory, the open help is saved there as
 * screenshots in both themes. Run with
 * `tools/demo/run.sh e2e studio/field_help.spec.ts` against the demo.
 * Every person and value is synthetic.
 */

import { join } from 'node:path';
import { expect, type Page } from '@playwright/test';
import { test } from '../playwright.config';
import { contrastBothThemes, structureProblems } from '../creator/support';
import { settle } from '../navigation/support';
import { DOOR, FrontDoor, suiteCell } from '../site/contract';
import { Seat } from '../speedrun/support';

test.use({ navigationTimeout: 30_000, actionTimeout: 30_000 });

/** Tenant admin A2 of the programme set-up scene. */
const A2 = /Tenant admin A2/;

/** Waits for the page at `path` to be ready. */
async function readyAt(page: Page, path: RegExp): Promise<void> {
  await page.waitForURL((u) => path.test(u.pathname));
  await settle(page);
  await expect(page.locator('main[data-ready="true"]')).toHaveCount(1);
}

/** The contrast ratio of two computed CSS colours, as the browser resolves them. */
async function buttonContrast(page: Page, name: string): Promise<{ glyph: number; border: number }> {
  return page.getByRole('button', { name }).evaluate((b) => {
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (ctx === null) return { glyph: 0, border: 0 };
    const rgb = (c: string): number[] => {
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = c;
      ctx.fillRect(0, 0, 1, 1);
      return Array.from(ctx.getImageData(0, 0, 1, 1).data).slice(0, 3);
    };
    const lin = (v: number): number => {
      const s = v / 255;
      return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
    };
    const lum = (c: number[]): number => 0.2126 * lin(c[0] ?? 0) + 0.7152 * lin(c[1] ?? 0) + 0.0722 * lin(c[2] ?? 0);
    const ratio = (a: number[], b: number[]): number => (Math.max(lum(a), lum(b)) + 0.05) / (Math.min(lum(a), lum(b)) + 0.05);
    const own = getComputedStyle(b);
    const glyph = getComputedStyle(b, '::before');
    let page = 'rgb(255, 255, 255)';
    for (let e: Element | null = b.parentElement; e !== null; e = e.parentElement) {
      const bg = getComputedStyle(e).backgroundColor;
      if (bg !== 'rgba(0, 0, 0, 0)' && bg !== 'transparent') {
        page = bg;
        break;
      }
    }
    return {
      glyph: ratio(rgb(glyph.color), rgb(own.backgroundColor)),
      border: ratio(rgb(own.borderTopColor), rgb(page)),
    };
  });
}

/**
 * Opens and closes the help of the field labelled `label` by click,
 * Enter and Space, and checks the page with the help open.
 */
async function toggleHelp(page: Page, label: string, where: string): Promise<void> {
  const name = `About ${label}`;
  const button = page.getByRole('button', { name, exact: true });
  await expect(button).toHaveCount(1);
  await expect(button).toHaveAttribute('type', 'button');
  await expect(button).toHaveAttribute('aria-expanded', 'false');
  const regionId = await button.getAttribute('aria-controls');
  expect(regionId, 'the button names its help region').toBeTruthy();
  const region = page.locator(`[id="${regionId ?? ''}"]`);
  await expect(region).toBeHidden();

  // A click shows the help under the label.
  await button.click();
  await expect(button).toHaveAttribute('aria-expanded', 'true');
  await expect(region).toBeVisible();
  await expect(region).not.toHaveText('');
  const labelBox = await page.locator('label', { hasText: label }).first().boundingBox();
  const regionBox = await region.boundingBox();
  expect(labelBox !== null && regionBox !== null && regionBox.y >= labelBox.y + labelBox.height - 1, 'the help sits under the label').toBe(true);

  const dir = process.env['FSTP_HELP_SHOTS'];
  if (dir !== undefined && dir !== '') {
    for (const colorScheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme });
      await region.screenshot({ path: join(dir, `${where.replace(/\W+/g, '-')}-${colorScheme}.png`) });
      await page.screenshot({ path: join(dir, `${where.replace(/\W+/g, '-')}-${colorScheme}-page.png`) });
    }
    await page.emulateMedia({ colorScheme: null });
  }

  // The page with the help open passes the suite's checks.
  expect(await structureProblems(page, where)).toEqual([]);
  expect(await contrastBothThemes(page, where)).toEqual([]);
  for (const colorScheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme });
    for (const open of [true, false]) {
      if ((await button.getAttribute('aria-expanded')) !== String(open)) await button.click();
      const c = await buttonContrast(page, name);
      expect(c.glyph, `${where}: the glyph, ${colorScheme}, ${open ? 'open' : 'closed'}`).toBeGreaterThanOrEqual(4.5);
      expect(c.border, `${where}: the border, ${colorScheme}, ${open ? 'open' : 'closed'}`).toBeGreaterThanOrEqual(3);
    }
  }
  await page.emulateMedia({ colorScheme: null });
  // The loop leaves the help closed.
  await expect(button).toHaveAttribute('aria-expanded', 'false');
  await expect(region).toBeHidden();

  // Keyboard: Space shows the help, Enter hides it again.
  await button.focus();
  await page.keyboard.press('Space');
  await expect(button).toHaveAttribute('aria-expanded', 'true');
  await expect(region).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(button).toHaveAttribute('aria-expanded', 'false');
  await expect(region).toBeHidden();

  // A click opens it once more, and a second click closes it.
  await button.click();
  await expect(region).toBeVisible();
  await button.click();
  await expect(button).toHaveAttribute('aria-expanded', 'false');
  await expect(region).toBeHidden();
}

/** Collects console errors of `page`. */
function watch(page: Page): () => string[] {
  const out: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error' && !m.text().includes('status of 401')) out.push(m.text());
  });
  page.on('pageerror', (e) => out.push(String(e)));
  return () => out;
}

test.describe('field help', () => {
  test.describe.configure({ timeout: 300_000 });

  test.beforeEach(async ({ browser }) => {
    const door = await FrontDoor.open(browser, suiteCell());
    await door.chooseScene('/demo/setup');
    await expect(door.page.locator('#demo-scene')).toContainText('programme_setup');
    await door.close();
  });

  /** SA-13, R-NF-03, R-PG-01: a programme manager on a Programme editor step. */
  test('r_nf_03_sa13_programme_manager_opens_and_closes_field_help_in_the_editor', async ({ browser }) => {
    const m1 = await Seat.signIn(browser, suiteCell(), DOOR.m1);
    const errors = watch(m1.page);
    try {
      await m1.page.locator('#home-work a[data-work="studio"]').first().click();
      await readyAt(m1.page, /^\/app\/programmes\/\d+\/studio$/);
      await m1.page.locator('#creator-steps li[data-step="identity"] a').first().click();
      await readyAt(m1.page, /^\/app\/programmes\/\d+\/creator\/identity$/);
      await expect(m1.page.locator('[data-field="identity.name"]')).toBeVisible();
      await toggleHelp(m1.page, 'Programme name', 'editor step 2');
      expect(errors(), 'no console error').toEqual([]);
    } finally {
      await m1.close();
    }
  });

  /** SA-13, R-NF-03, R-PG-01: a tenant admin on stage 1 of the wizard. */
  test('r_nf_03_sa13_tenant_admin_opens_and_closes_field_help_in_the_wizard', async ({ browser }) => {
    const a2 = await Seat.signIn(browser, suiteCell(), A2);
    const errors = watch(a2.page);
    try {
      // SA-12: the home also links the wizard of each draft of the
      // tenant, so pick the link that starts a new programme.
      await a2.page.locator('#home-work a[data-work="setup"][href="/app/setup/new"]').click();
      await readyAt(a2.page, /^\/app\/setup\/new$/);
      await toggleHelp(a2.page, 'Programme name', 'wizard stage 1');
      expect(errors(), 'no console error').toEqual([]);
    } finally {
      await a2.close();
    }
  });
});
