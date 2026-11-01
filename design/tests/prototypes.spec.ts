// Playwright tests for the static design prototypes in ../prototypes.
// They check the hard rules of the design brief and ADR-014 and ADR-015,
// plus the key behaviour of each screen. Synthetic data only.
import { test, expect, type Page } from '@playwright/test';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const DIR = resolve(__dirname, '..', 'prototypes');
const FILES = readdirSync(DIR).filter(f => f.endsWith('.html')).sort();
const url = (file: string) => pathToFileURL(join(DIR, file)).href;

const FORMAL_STATES = [
  'DRAFT', 'SUBMITTED', 'INELIGIBLE', 'STAGE1', 'STAGE2', 'RANKED', 'IRC_REVIEW', 'DEFERRED',
  'NEGOTIATION', 'GRANTED', 'IN_EXECUTION', 'COMPLETED', 'NOT_SELECTED', 'DECLINED', 'WITHDRAWN', 'TERMINATED',
];

// Voyage pack words that must not appear in primary chrome (12-journey-ui §4, §5.2).
// Naming the pack itself ("Voyage pack", "Voyage label") is allowed.
const METAPHOR = /\b(voyages?(?! (?:pack|label))|voyager|scouts?|council|treaty|charter|crossing|ascent|ascending|wintering|harbour|expedition|border check|packing|chronicle|route|logbook|crew|departed|passage diary|planning studio)\b/i;

/** Opens a prototype and records every request that is not a local file. */
async function open(page: Page, file: string) {
  const external: string[] = [];
  page.on('request', r => { if (!r.url().startsWith('file://')) external.push(r.url()); });
  await page.goto(url(file));
  return external;
}

/** WCAG contrast ratio between an element's text colour and its effective background. */
async function lowContrast(page: Page, selector: string, min = 4.5) {
  return page.locator(selector).evaluateAll((els, min) => {
    const parse = (c: string) => (c.match(/[\d.]+/g) || []).map(Number);
    const lum = ([r, g, b]: number[]) => {
      const f = (v: number) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
    };
    const bgOf = (el: Element | null): number[] => {
      while (el) {
        const c = parse(getComputedStyle(el).backgroundColor);
        if (c.length >= 3 && (c.length === 3 || c[3] > 0)) return c.slice(0, 3);
        el = el.parentElement;
      }
      return [255, 255, 255];
    };
    const bad: string[] = [];
    for (const el of els) {
      const fg = parse(getComputedStyle(el).color).slice(0, 3);
      const a = lum(fg), b = lum(bgOf(el));
      const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
      if (ratio < (min as number)) bad.push(`${(el.textContent || '').trim().slice(0, 40)}: ${ratio.toFixed(2)}`);
    }
    return bad;
  }, min);
}

test('every expected prototype exists', () => {
  expect(FILES).toHaveLength(35);
  for (const f of ['route-map.html', 'diary.html', 'irc-view.html', 'profile.html', 'tokens-showcase.html']) {
    expect(FILES).toContain(f);
  }
});

for (const file of FILES) {
  test.describe(`${file}: shared rules`, () => {
    test('source has no script, no inline handlers, no em dash and one stylesheet', () => {
      const html = readFileSync(join(DIR, file), 'utf8');
      expect(html.startsWith('<!DOCTYPE html>\n<html lang="en">')).toBe(true);
      expect(html).not.toMatch(/<scr[i]pt/i);
      expect(html).not.toMatch(/\son[a-z]+\s*=/i);
      expect(html).not.toMatch(/inner[H]TML|ev[a]l\(|new [F]unction/); // bracketed so this file stays free of the banned names
      expect(html).not.toMatch(/[\u2013\u2014]/);
      const sheets = [...html.matchAll(/<link [^>]*rel="stylesheet"[^>]*>/g)].map(m => m[0]);
      expect(sheets).toEqual(['<link rel="stylesheet" href="../tokens.css">']);
    });

    test('loads no external resource', async ({ page }) => {
      const external = await open(page, file);
      await page.waitForLoadState('load');
      expect(external).toEqual([]);
    });

    test('has title, landmarks and a prototype state label', async ({ page }) => {
      await open(page, file);
      await expect(page).toHaveTitle(/ - FSTP$/);
      await expect(page.locator('html')).toHaveAttribute('lang', 'en');
      await expect(page.locator('body > header')).toHaveCount(1);
      await expect(page.locator('main#main-content')).toHaveCount(1);
      await expect(page.locator('body > footer')).toHaveCount(1);
      await expect(page.getByRole('navigation', { name: /Main navigation/ }).first()).toBeVisible();
      await expect(page.locator('.proto-state')).toContainText('Prototype state:');
      await expect(page.locator('footer')).toContainText('TODO(legal)');
    });

    test('skip link is the first tab stop and becomes visible', async ({ page }) => {
      await open(page, file);
      await page.keyboard.press('Tab');
      const skip = page.getByRole('link', { name: 'Skip to main content' });
      await expect(skip).toBeFocused();
      const box = await skip.boundingBox();
      expect(box && box.y).toBeGreaterThanOrEqual(0);
      await page.keyboard.press('Enter');
      await expect(page).toHaveURL(/#main-content$/);
    });

    test('marks the current page in the main navigation', async ({ page }) => {
      await open(page, file);
      const current = page.locator('header [aria-current="page"]');
      expect(await current.count()).toBeGreaterThanOrEqual(1);
    });

    test('every form control has an accessible name', async ({ page }) => {
      await open(page, file);
      const controls = page.locator('main input:not([type=hidden]), main select, main textarea');
      const n = await controls.count();
      for (let i = 0; i < n; i++) {
        await expect(controls.nth(i)).toHaveAccessibleName(/\S/);
      }
    });

    test('primary chrome uses plain grant language, the Voyage pack stays secondary (Goal B, O-55)', async ({ page }) => {
      await open(page, file);
      const chrome = page.locator('nav, h1, h2, h3, h4, button, .btn, .badge, label, legend, caption, th, .role-chip, .card-kicker, title');
      const texts = await chrome.evaluateAll(els => els.filter(el => !el.closest('.voyage-label')).map(el => {
        const c = el.cloneNode(true) as Element;
        c.querySelectorAll('.voyage-label').forEach(v => v.remove());
        return c.textContent || '';
      }));
      const bad = texts.filter(t => METAPHOR.test(t)).map(t => t.trim().slice(0, 60));
      expect(bad).toEqual([]);
    });

    test('badges and primary buttons meet AA contrast in light and dark', async ({ page }) => {
      for (const colorScheme of ['light', 'dark'] as const) {
        await page.emulateMedia({ colorScheme });
        await open(page, file);
        expect(await lowContrast(page, '.badge, .btn--primary:not(:disabled), .btn--danger, .count-badge, main p, main td')).toEqual([]);
      }
    });
  });
}

test.describe('route map (I-95, I-96, R-JV-05)', () => {
  test.beforeEach(async ({ page }) => { await open(page, 'route-map.html'); });

  test('SVG has one keyboard-reachable link per state, each naming the formal state', async ({ page }) => {
    const nodes = page.locator('svg.route-svg a');
    await expect(nodes).toHaveCount(16);
    for (const s of FORMAL_STATES) {
      const node = page.locator(`svg.route-svg a[href="#node-${s}"]`);
      await expect(node).toHaveAttribute('aria-label', new RegExp(`\\(${s}\\)`));
    }
    const current = page.locator('svg.route-svg a[href="#node-STAGE2"]');
    await current.focus();
    await expect(current).toBeFocused();
    await expect(current).toHaveAttribute('aria-label', /Stage 2 questions \(STAGE2\), current stage/);
  });

  test('text alternative lists all 16 states with status words', async ({ page }) => {
    const items = page.locator('ol.journey-list > li');
    await expect(items).toHaveCount(16);
    for (const s of FORMAL_STATES) await expect(page.locator('ol.journey-list')).toContainText(`(${s})`);
    await expect(page.locator('ol.journey-list > li[aria-current="step"]')).toContainText('Stage 2 questions');
    await expect(page.locator('ol.journey-list')).toContainText('Completed');
  });

  test('help panel shows STAGE2 by default and switches without script', async ({ page }) => {
    const stage2 = page.locator('#node-STAGE2');
    await expect(stage2).toBeVisible();
    await expect(stage2).toContainText('Your window closes in 8 days');
    await expect(stage2).toContainText('Who acts');
    await expect(stage2.locator('.voyage-label')).toHaveText('Voyage pack label: Ascent: questions from the scouts');
    await page.locator('ol.journey-list a[href="#node-RANKED"]').click();
    await expect(page.locator('#node-RANKED')).toBeVisible();
    await expect(stage2).toBeHidden();
  });

  test('WITHDRAWN is one node and DEFERRED re-entry is labelled', async ({ page }) => {
    await expect(page.locator('svg a[href="#node-WITHDRAWN"]')).toHaveCount(1);
    await expect(page.locator('svg')).toContainText('re-enters at the stage it left');
    await expect(page.locator('svg')).toContainText('Withdraw: possible in any state before GRANTED, including DEFERRED');
  });

  test('current ring stops under reduced motion', async ({ page }) => {
    const anim = () => page.locator('.current-ring').evaluate(el => getComputedStyle(el).animationName);
    expect(await anim()).toBe('ring-pulse');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    expect(await anim()).toBe('none');
  });
});

test.describe('diary (O-56, I-81)', () => {
  test('shows 8 entry kinds, erased placeholder, anchor pending and pagination', async ({ page }) => {
    await open(page, 'diary.html');
    await expect(page.locator('ol.diary > li')).toHaveCount(8);
    await expect(page.locator('.diary-entry--erased')).toContainText('Entry text erased on 2024-11-15, reason: retention period ended.');
    await expect(page.getByText('Anchor pending')).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Activity log pages' }).locator('[aria-current="page"]')).toHaveText('1');
    for (const time of await page.locator('ol.diary time').all()) await expect(time).toHaveAttribute('datetime', /\d{4}-\d{2}-\d{2}/);
  });
});

test.describe('public calls with scripts off (R-PB-04)', () => {
  test.use({ javaScriptEnabled: false });
  test('lists 2 calls and searches with a GET form', async ({ page }) => {
    await open(page, 'calls-public.html');
    await expect(page.locator('main article.card')).toHaveCount(2);
    await expect(page.locator('form[role=search]')).toHaveAttribute('method', 'get');
    await page.getByLabel('Search calls').fill('wellbeing');
    await page.getByRole('button', { name: 'Search' }).click();
    await expect(page).toHaveURL(/calls-public\.html\?q=wellbeing$/);
  });
});

test.describe('applicant screens', () => {
  test('plan editor: submit disabled with a reason, findings not scores', async ({ page }) => {
    await open(page, 'plan-editor.html');
    await expect(page.getByRole('button', { name: 'Submit', exact: true })).toBeDisabled();
    await expect(page.getByText('482 / 500 characters')).toBeVisible();
    await expect(page.getByLabel(/Objectives/)).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByText(/Findings only, not scores \(R-LA-06\)/)).toBeVisible();
    await expect(page.getByText('Call closes in 14 days')).toBeVisible();
  });

  test('receipt: ids, UTC time and anchor pending (O-56)', async ({ page }) => {
    await open(page, 'submission-receipt.html');
    for (const t of ['CSW-2024-0042', '2024-10-15 14:32:07 UTC', '00000000-0001-4f8c', 'Anchor pending (ADR-015 O-56)']) {
      await expect(page.getByText(t, { exact: true })).toBeVisible();
    }
    await expect(page.getByLabel('Email address')).toHaveAttribute('type', 'email');
  });

  test('stage 2: window clock, 3 anonymous questions, audience note', async ({ page }) => {
    await open(page, 'stage2-questions.html');
    await expect(page.getByText('8 days 4 hours')).toBeVisible();
    await expect(page.locator('fieldset legend')).toHaveText(['Question 1 from reviewer-7f3a', 'Question 2 from reviewer-2b9c', 'Question 3 from reviewer-2b9c']);
    await expect(page.getByText('Your answers are seen by the assigned reviewers and the FSTP coordinator.')).toBeVisible();
  });

  test('negotiation: exact amount, sign disabled, step-up and TODO(legal)', async ({ page }) => {
    await open(page, 'negotiation.html');
    await expect(page.getByText('48 750.00 EUR', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Accept and sign' })).toBeDisabled();
    await expect(page.getByText('Signing requires a passkey confirmation.')).toBeVisible();
    await page.getByText(/Grant agreement summary/).click();
    await expect(page.getByText(/TODO\(legal\)/).first()).toBeVisible();
  });

  test('end states: INELIGIBLE has no scores, NOT_SELECTED shows anonymous scores (O-54)', async ({ page }) => {
    await open(page, 'end-states.html');
    const inel = page.locator('section', { has: page.getByRole('heading', { name: 'Not eligible', exact: true }) });
    await expect(inel).toContainText('INELIGIBLE');
    await expect(inel.locator('table')).toHaveCount(0);
    const notSel = page.locator('section', { has: page.getByRole('heading', { name: 'Not selected', exact: true }) });
    await expect(notSel).toContainText('NOT_SELECTED');
    await expect(notSel.locator('table')).toContainText('reviewer-7f3a');
    const done = page.locator('section', { has: page.getByRole('heading', { name: 'Completed', exact: true }) });
    await expect(done.getByRole('link', { name: /proposal history/ })).toBeVisible();
  });
});

test.describe('judging roles', () => {
  test('IRC pages never show a route strip (O-58)', async ({ page }) => {
    for (const file of ['home-irc.html', 'irc-view.html']) {
      await open(page, file);
      await expect(page.locator('.strip, svg.route-svg')).toHaveCount(0);
      await expect(page.getByText('Proposal status', { exact: true })).toHaveCount(0);
    }
  });

  test('IRC review offers validate or raise a concern, with no deliberation (R-IR-03, Q16)', async ({ page }) => {
    await open(page, 'irc-view.html');
    await expect(page.getByRole('radio')).toHaveCount(2);
    await expect(page.getByLabel(/^Validate/)).toBeVisible();
    await expect(page.getByLabel('Raise a concern.')).toBeVisible();
    await expect(page.locator('main dl')).not.toContainText(/score|rank|rationale|ballot/i);
    await expect(page.locator('#concern-effect')).toContainText('Deferred to the next call (DEFERRED)');
    await expect(page.locator('#concern-effect')).toContainText('Declined (DECLINED)');
    await expect(page.getByText(/Concern sent to applicant per R-IR-02/)).toBeVisible();
  });

  test('reviewer and committee pages show the strip with the current stop', async ({ page }) => {
    for (const [file, state] of [['reviewer-scoring.html', 'STAGE2'], ['committee-ranking.html', 'RANKED']]) {
      await open(page, file);
      await expect(page.locator('.strip [aria-current="step"]')).toContainText(`(${state})`);
    }
  });

  test('conflict declaration is yes or no only', async ({ page }) => {
    await open(page, 'reviewer-assignments.html');
    const group = page.getByRole('group', { name: /conflict of interest/ });
    await expect(group.getByRole('radio')).toHaveCount(2);
    await expect(group.locator('textarea, input[type=text]')).toHaveCount(0);
  });

  test('committee ranking: budget, cut-off row, recusal hides score, tie-break field', async ({ page }) => {
    await open(page, 'committee-ranking.html');
    await expect(page.getByText('112 500.00 EUR', { exact: true })).toBeVisible();
    await expect(page.getByRole('rowheader', { name: /Cut-off/ })).toBeVisible();
    const recused = page.getByRole('row', { name: /Recused/ });
    await expect(recused).toContainText('Hidden');
    await expect(page.getByLabel('Tie-break rationale for position 3')).toHaveAttribute('required', '');
    await expect(page.getByRole('rowheader', { name: 'Cut-off after position 3' })).toBeVisible();
    const ballot = page.getByRole('group', { name: /Your ballot/ });
    await expect(ballot.getByRole('radio')).toHaveCount(2);
    await expect(page.getByLabel('Or delegate your ballot to')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Cast ballot' })).toBeVisible();
  });
});

test.describe('programme staff', () => {
  test('coordinator: read is locked until conflicts are answered', async ({ page }) => {
    await open(page, 'coordinator-conflict.html');
    const read = page.locator('.steps').first().getByText('Read application', { exact: true });
    await expect(read).toHaveAttribute('aria-disabled', 'true');
    expect(await read.getAttribute('href')).toBeNull();
    await expect(page.getByText('Conflict declared: reassigning (SoD enforced)')).toBeVisible();
  });

  test('stage 1 close offers only "Confirm this outcome" (R-LA-03)', async ({ page }) => {
    await open(page, 'stage1-close.html');
    await expect(page.locator('main button')).toHaveText(['Confirm this outcome']);
    await expect(page.getByText('This outcome is computed from reviewer scores. You cannot change it. (R-LA-03)')).toBeVisible();
    await expect(page.getByText('Confirming will send non-selection notices to 3 applicants.')).toBeVisible();
  });

  test('programme set-up: 5 groups, the 11 creator steps in spec order, step 6 current, I-50 refusal linked', async ({ page }) => {
    await open(page, 'planning-studio.html');
    const nav = page.getByRole('navigation', { name: 'Set-up steps' });
    await expect(nav.locator('h2')).toHaveText(['Funder and identity', 'Eligibility and scope', 'Evaluation, money and contract', 'Support, people and communications', 'Review and approval']);
    await expect(nav.locator('.voyage-label')).toHaveText(['Studio: Surveying the territory', 'Studio: Border rules', 'Studio: Instruments', 'Studio: Support and crew', 'Studio: Charter seal']);
    await expect(nav.locator('li li')).toHaveCount(11);
    const steps = ['Funder and instrument', 'Programme identity', 'Eligibility', 'What we fund', 'Evaluation', 'Money', 'Contract', 'Support and complaints', 'People (live SoD checks)', 'Communications', 'Review'];
    for (let i = 0; i < steps.length; i++) await expect(nav.locator('li li').nth(i)).toContainText(`${i + 1}. ${steps[i]}`);
    await expect(nav.locator('[aria-current="step"]')).toContainText('6. Money');
    await expect(page.getByLabel(/Cap per recipient, P-05/)).toHaveAttribute('aria-invalid', 'true');
    await expect(page.getByRole('alert')).toContainText('(I-50)');
    await expect(page.getByText(/Confirmed by pm-a1k4 on 28 Oct 2026 \(I-65\)/)).toBeVisible();
    await expect(page.getByText(/cannot be activated \(I-66\)/)).toBeVisible();
    await expect(page.locator('main')).not.toContainText('Open Call 3');
  });

  test('approval and publication: activation by a second approver first, then non-drafter publication', async ({ page }) => {
    await open(page, 'seal-ceremony.html');
    const heads = page.locator('main ol.steps > li > h2');
    await expect(heads.nth(0)).toContainText(/Activate programme, requires a second approver \(I-67\)/);
    await expect(heads.nth(1)).toContainText('Approve and publish the call');
    await expect(page.getByText(/Awaiting approval from a non-drafter \(R-PC-03\)/)).toBeVisible();
    await expect(page.getByText(/You cannot choose the approver/)).toBeVisible();
    await expect(page.locator('main select')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Publish call' })).toBeEnabled();
  });

  test('reviewer scoring uses the SuperSAFE 0 to 5 scale with weights', async ({ page }) => {
    await open(page, 'reviewer-scoring.html');
    const first = page.getByLabel('Score for Excellence, 0 to 5');
    await expect(first).toHaveAttribute('min', '0');
    await expect(first).toHaveAttribute('max', '5');
    await expect(page.locator('fieldset legend')).toHaveText(['Criterion 1: Excellence (weight 30%)', 'Criterion 2: Impact (weight 40%)', 'Criterion 3: Implementation (weight 30%)']);
  });

  test('finance home separates approver and releaser (SoD-04)', async ({ page }) => {
    await open(page, 'home-finance.html');
    await expect(page.getByRole('heading', { name: '3 payment requests awaiting approval' })).toBeVisible();
    await expect(page.getByRole('heading', { name: '2 requests approved, awaiting release' })).toBeVisible();
    await expect(page.locator('main .callout').getByText(/SoD-04/)).toBeVisible();
  });
});

test.describe('navigation and home (3-click rule)', () => {
  const primary: [string, string, string][] = [
    ['home-voyager.html', 'Answer reviewer questions', 'stage2-questions.html'],
    ['home-coordinator.html', 'Start conflict check', 'coordinator-conflict.html'],
    ['home-reviewer.html', 'Score this proposal', 'reviewer-scoring.html'],
    ['home-committee.html', 'Review rankings', 'committee-ranking.html'],
    ['home-irc.html', 'Review nomination', 'irc-view.html'],
  ];
  for (const [home, action, target] of primary) {
    test(`${home}: primary task is one click away`, async ({ page }) => {
      await open(page, home);
      await page.getByRole('link', { name: action }).click();
      await expect(page).toHaveURL(new RegExp(`${target.replace('.', '\\.')}$`));
    });
  }

  test('applicant home: plain label primary, formal state beside it, Voyage label secondary (I-96)', async ({ page }) => {
    await open(page, 'home-voyager.html');
    const card = page.locator('.card--primary');
    await expect(card.locator('.badge').first()).toHaveText('Stage 2 questions');
    await expect(card).toContainText('Formal state: STAGE2');
    await expect(card.locator('.voyage-label')).toContainText('Ascent: questions from the scouts');
  });

  test('coordinator home shows counts and pseudonymous ids only (O-57)', async ({ page }) => {
    await open(page, 'home-coordinator.html');
    await expect(page.getByRole('table')).not.toContainText('Community Wellbeing Navigator');
    await expect(page.getByText('1 proposal in SUBMITTED for 12 days', { exact: false })).toBeVisible();
  });

  test('account avatar leads to the profile page', async ({ page }) => {
    await open(page, 'home-voyager.html');
    await page.getByRole('link', { name: /Account: meridian-social-lab/ }).click();
    await expect(page).toHaveURL(/profile\.html$/);
    await expect(page.getByRole('heading', { name: 'Security' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign out all sessions' })).toBeVisible();
  });
});

test.describe('tokens', () => {
  test('dark theme follows the system and data-theme forces light', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await open(page, 'tokens-showcase.html');
    const bg = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(await bg()).toBe('rgb(15, 23, 42)');
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'));
    expect(await bg()).toBe('rgb(255, 255, 255)');
  });

  test('focus outline is visible on buttons', async ({ page }) => {
    await open(page, 'tokens-showcase.html');
    const btn = page.getByRole('button', { name: 'Primary' });
    await btn.focus();
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Tab');
    const outline = await btn.evaluate(el => getComputedStyle(el).outlineWidth);
    expect(outline).toBe('3px');
  });
});


// Files added or reworked by Daniel's decisions of 2026-11-01 (spec-questions Q16 to Q23).
const NEW_FILES = ['auth-signup.html', 'auth-check-email.html', 'auth-enrol.html', 'auth-signin.html',
  'call-detail-public.html', 'coordinator-conflicts-list.html', 'reviewer-stage2.html', 'irc-cases.html'];
const UPDATED_FILES = ['plan-editor.html', 'end-states.html', 'reviewer-scoring.html', 'committee-ranking.html', 'irc-view.html'];

for (const file of [...NEW_FILES, ...UPDATED_FILES]) {
  test.describe(`${file}: 2026-11-01 decision checks`, () => {
    test('loads with status 200 over HTTP and has one main landmark', async ({ page }) => {
      // file:// has no status code, so the page is fulfilled from disk through a local route.
      const body = readFileSync(join(DIR, file), 'utf8');
      const css = readFileSync(join(DIR, '..', 'tokens.css'), 'utf8');
      await page.route('http://proto.test/**', route => route.request().url().endsWith('/tokens.css')
        ? route.fulfill({ status: 200, contentType: 'text/css', body: css })
        : route.fulfill({ status: 200, contentType: 'text/html', body }));
      const res = await page.goto(`http://proto.test/prototypes/${file}`);
      expect(res?.status()).toBe(200);
      await expect(page.getByRole('main')).toHaveCount(1);
    });

    test('no metaphor word in primary headings or button labels', async ({ page }) => {
      await open(page, file);
      const texts = await page.locator('h1, h2, h3, button, .btn').evaluateAll(els => els.filter(el => !el.closest('.voyage-label')).map(el => el.textContent || ''));
      expect(texts.filter(t => METAPHOR.test(t)).map(t => t.trim())).toEqual([]);
    });

    test('TODO markers are HTML comments, never rendered text in main', async ({ page }) => {
      const html = readFileSync(join(DIR, file), 'utf8');
      const main = html.slice(html.indexOf('<main'), html.indexOf('</main>'));
      const withoutComments = main.replace(/<!--[\s\S]*?-->/g, '');
      expect(withoutComments).not.toMatch(/TODO/);
      await open(page, file);
      await expect(page.locator('main')).not.toContainText('TODO');
    });
  });
}

test.describe('auth flow (Q16, m4-demo J0 and J4)', () => {
  test('sign-up: email field, submit, sign-in link, legal text as a comment', async ({ page }) => {
    await open(page, 'auth-signup.html');
    await expect(page.getByLabel('Email address')).toHaveAttribute('type', 'email');
    await expect(page.getByRole('button', { name: 'Send confirmation link' })).toBeEnabled();
    await expect(page.locator('main').getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', 'auth-signin.html');
    expect(readFileSync(join(DIR, 'auth-signup.html'), 'utf8')).toMatch(/<!-- TODO\(legal\): terms of use and privacy notice/);
  });

  test('check email: synthetic address, no resend control', async ({ page }) => {
    await open(page, 'auth-check-email.html');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Check your email');
    await expect(page.getByText('demo@e2e.invalid')).toBeVisible();
    await expect(page.locator('main button')).toHaveCount(0);
    expect(readFileSync(join(DIR, 'auth-check-email.html'), 'utf8')).toMatch(/<!-- TODO\(legal\): email body/);
  });

  test('enrol: disabled create button with a reason, device name, one enrolled device', async ({ page }) => {
    await open(page, 'auth-enrol.html');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Create a passkey');
    const btn = page.getByRole('button', { name: 'Create passkey' });
    await expect(btn).toBeDisabled();
    await expect(btn).toHaveAccessibleDescription(/passkey prompt/);
    await expect(page.getByLabel('Device name')).toBeVisible();
    await expect(page.locator('main tbody tr')).toHaveCount(1);
    const html = readFileSync(join(DIR, 'auth-enrol.html'), 'utf8');
    expect(html).toMatch(/<!-- TODO\(js\)/);
    expect(html).toMatch(/<!-- TODO\(legal\): consent text/);
  });

  test('sign-in: disabled passkey button, different device link, access terms comment', async ({ page }) => {
    await open(page, 'auth-signin.html');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Sign in');
    await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeDisabled();
    await expect(page.getByRole('link', { name: 'Use a different device' })).toBeVisible();
    await expect(page.locator('header [aria-current="page"]')).toHaveText('Sign in');
    expect(readFileSync(join(DIR, 'auth-signin.html'), 'utf8')).toMatch(/<!-- TODO\(legal\): access terms/);
  });
});

test.describe('2026-11-01 surfaces', () => {
  test('public call page works with scripts off: two zones, amounts, AI disclosure (Q18, R-LA-08)', async ({ browser }) => {
    const context = await browser.newContext({ javaScriptEnabled: false });
    const page = await context.newPage();
    await open(page, 'call-detail-public.html');
    await expect(page.getByText('15 Dec 2024, 17:00 Europe/Brussels (16:00 UTC)')).toBeVisible();
    await expect(page.getByText('15 Oct 2024, 09:00 Europe/Brussels (07:00 UTC)')).toBeVisible();
    await expect(page.getByText('5 000.00 to 100 000.00 EUR')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Use of AI tools' })).toBeVisible();
    const nav = page.getByRole('navigation', { name: 'Main navigation' });
    await expect(nav.getByRole('link', { name: 'Back to calls' })).toBeVisible();
    await expect(nav.getByRole('link', { name: 'Sign in' })).toBeVisible();
    expect(readFileSync(join(DIR, 'call-detail-public.html'), 'utf8')).toMatch(/<!-- TODO\(legal\): AI disclosure/);
    await context.close();
  });

  test('coordinator conflicts list: drafts only, "Reviewer" only, one submitted (Q19, R-CF-04)', async ({ page }) => {
    await open(page, 'coordinator-conflicts-list.html');
    await expect(page.locator('thead th')).toHaveText(['Proposal id', 'Declared by', 'Declaration date', 'Status']);
    const declaredBy = await page.locator('tbody tr td:nth-child(2)').allTextContents();
    expect(new Set(declaredBy)).toEqual(new Set(['Reviewer']));
    await expect(page.locator('tbody .badge', { hasText: 'Submitted' })).toHaveCount(1);
    await expect(page.locator('main')).not.toContainText(/reviewer-[0-9a-f]{4}/);
    await expect(page.locator('.callout')).toContainText('R-CF-04');
  });

  test('reviewer stage 2: read-only stage 1 scores, question field, no-questions radio, disabled submit (Q20)', async ({ page }) => {
    await open(page, 'reviewer-stage2.html');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Stage 2 evaluation');
    await expect(page.locator('table caption')).toContainText('read-only');
    await expect(page.locator('table input')).toHaveCount(0);
    await expect(page.getByLabel('Your question for the applicant')).toBeVisible();
    await expect(page.getByLabel('No questions')).toHaveAttribute('type', 'radio');
    await expect(page.getByRole('button', { name: 'Submit', exact: true })).toBeDisabled();
  });

  test('reviewer scoring: summary split in three, correction needs a reason (Q20, I-23)', async ({ page }) => {
    await open(page, 'reviewer-scoring.html');
    await expect(page.getByText('Ranking summary and overall comment')).toHaveCount(0);
    for (const l of ['Title', 'Neutral summary', 'Rationale']) await expect(page.getByLabel(l, { exact: true })).toHaveAttribute('required', '');
    await expect(page.getByText('3 of 5, submitted 28 Jan 2025, 10:14 Europe/Malta')).toBeVisible();
    await expect(page.getByLabel(/Reason for correction/)).toHaveAttribute('required', '');
    await expect(page.getByRole('button', { name: 'Save correction' })).toBeDisabled();
  });

  test('committee ranking: per-criterion columns, requested, remaining budget row, not-served labels (Q21)', async ({ page }) => {
    await open(page, 'committee-ranking.html');
    for (const c of ['Excellence (weight 30%)', 'Impact (weight 40%)', 'Implementation (weight 30%)', 'Requested (\u20AC)']) {
      await expect(page.getByRole('columnheader', { name: c, exact: true })).toBeVisible();
    }
    await expect(page.getByRole('rowheader', { name: /Remaining budget/ })).toBeVisible();
    await expect(page.getByText('Not served in M4 demo', { exact: true })).toHaveCount(2);
    await expect(page.getByRole('row', { name: /Recused/ })).not.toContainText(/\d\.\d\d/);
  });

  test('IRC cases: four statuses, disabled declare on the pending row (Q22)', async ({ page }) => {
    await open(page, 'irc-cases.html');
    for (const s of ['Pending declaration', 'In review', 'Validated', 'Concern raised']) await expect(page.locator('tbody .badge', { hasText: s })).toHaveCount(1);
    const pending = page.getByRole('row', { name: /Pending declaration/ });
    await expect(pending.getByRole('button', { name: 'Declare and open' })).toBeDisabled();
    await expect(page.getByText(/declare any conflict before you can read a case/)).toBeVisible();
    await expect(page.locator('.strip')).toHaveCount(0);
  });

  test('IRC view: validation count and a held proposal with no action (Q22, I-18)', async ({ page }) => {
    await open(page, 'irc-view.html');
    await expect(page.getByText('1 of 2 validations complete.')).toBeVisible();
    const hold = page.locator('section', { has: page.getByRole('heading', { name: /Held proposal/ }) });
    await expect(hold.getByText('On hold: guardian consent required')).toBeVisible();
    await expect(hold).toContainText('The applicant has been notified. No identity detail is shown here.');
    await expect(hold.locator('input, button, select, textarea')).toHaveCount(0);
  });

  test('plan editor: four panels, current step, eligibility warning, submit ticks, late state (Q17)', async ({ page }) => {
    await open(page, 'plan-editor.html');
    await expect(page.locator('section.panel h2')).toHaveText(['1. Plan', '2. Eligibility', '3. Submit', 'Submit, after the deadline']);
    await expect(page.locator('[aria-current="step"]')).toContainText('1. Plan');
    await expect(page.getByText('Last saved 14:32')).toBeVisible();
    await expect(page.getByLabel(/^Neutral summary, visible to reviewers before conflict declaration/)).toBeVisible();
    await expect(page.locator('#panel-plan tbody tr').first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Add milestone' })).toBeVisible();
    await expect(page.getByRole('button', { name: /^Remove milestone/ })).toHaveCount(2);
    await expect(page.locator('#panel-elig fieldset')).toHaveCount(3);
    await expect(page.locator('#panel-elig input[value="no"]:checked')).toHaveCount(1);
    await expect(page.getByText('This answer may make your proposal ineligible.')).toBeVisible();
    await expect(page.getByLabel('I confirm the information above is accurate')).toHaveAttribute('type', 'checkbox');
    await expect(page.getByLabel('No ethics issue')).toHaveAttribute('type', 'checkbox');
    const late = page.locator('#panel-late');
    await expect(late).toContainText('Submission closed');
    await expect(late).toContainText('Europe/Brussels');
    await expect(late).toContainText('your zone');
    await expect(late.getByText('The deadline for this call has passed.')).toBeVisible();
    await expect(late.locator('button')).toHaveCount(0);
  });

  test('end states: deferred after a concern shows frozen rules, minor hold says nothing about the guardian (Q23, O-60)', async ({ page }) => {
    await open(page, 'end-states.html');
    const def = page.locator('section', { has: page.getByRole('heading', { name: 'Your proposal has been deferred' }) });
    await expect(def).toContainText('Rules of SuperSAFE Call 1, version 2');
    await expect(def.getByRole('link', { name: 'View frozen rules' })).toHaveAttribute('href', '#');
    await expect(def).toContainText('If a suitable future call opens, your proposal may be reconsidered under these rules.');
    const hold = page.locator('section', { has: page.getByRole('heading', { name: 'Your proposal is on hold' }) });
    await expect(hold).toContainText('We need a guardian consent record before your application can continue.');
    await expect(hold.locator('a, button, input')).toHaveCount(0);
    expect(readFileSync(join(DIR, 'end-states.html'), 'utf8')).toMatch(/<!-- TODO\(legal\): notification wording/);
  });
});
