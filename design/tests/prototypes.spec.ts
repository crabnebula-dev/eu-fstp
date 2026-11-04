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
  expect(FILES).toHaveLength(69);
  for (const f of ['route-map.html', 'diary.html', 'irc-view.html', 'profile.html', 'tokens-showcase.html', 'admin-masquerade.html']) {
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
      const current = page.locator('header [aria-current="page"], .page-body > .sidebar [aria-current="page"]');
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

  test('sidebar Account link leads to the profile page on desktop', async ({ page }) => {
    await open(page, 'home-voyager.html');
    await page.locator('.page-body > .sidebar').getByRole('link', { name: 'Account', exact: true }).click();
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


// Tenant admin screens (roles-and-sod, programme-creator onboarding, white-labelling I-68 to I-72).
const ADMIN_FILES = ['home-admin.html', 'admin-org.html', 'admin-members.html', 'admin-branding.html', 'admin-domains.html'];
// Voyage pack labels from 12-journey-ui §5.2 must not appear on admin screens at all, not even as a secondary line.
const VOYAGE_PACK = /At the departure hall|Departed|Crossing|Ascent|Awaiting the council|Independent watch|Treaty|Charter in force|On the road|Safe harbour|Wintering|Route closed|Route ended/;

for (const file of ADMIN_FILES) {
  test.describe(`${file}: tenant admin checks`, () => {
    test('loads with status 200 over HTTP and has one main landmark', async ({ page }) => {
      const body = readFileSync(join(DIR, file), 'utf8');
      const css = readFileSync(join(DIR, '..', 'tokens.css'), 'utf8');
      await page.route('http://proto.test/**', route => route.request().url().endsWith('/tokens.css')
        ? route.fulfill({ status: 200, contentType: 'text/css', body: css })
        : route.fulfill({ status: 200, contentType: 'text/html', body }));
      const res = await page.goto(`http://proto.test/prototypes/${file}`);
      expect(res?.status()).toBe(200);
      await expect(page.getByRole('main')).toHaveCount(1);
    });

    test('no metaphor word in primary headings or button labels, no Voyage labels', async ({ page }) => {
      await open(page, file);
      const texts = await page.locator('h1, h2, h3, button, .btn').evaluateAll(els => els.map(el => el.textContent || ''));
      expect(texts.filter(t => METAPHOR.test(t)).map(t => t.trim())).toEqual([]);
      await expect(page.locator('.voyage-label')).toHaveCount(0);
      expect(await page.locator('body').innerText()).not.toMatch(VOYAGE_PACK);
    });

    test('tenant admin shell: role label, Horizon Bridges brand, admin nav', async ({ page }) => {
      await open(page, file);
      await expect(page.locator('.role-chip')).toHaveText('Signed in as Tenant admin');
      await expect(page.locator('header .brand')).toContainText('Horizon Bridges');
      const nav = page.getByRole('navigation', { name: 'Main navigation' });
      for (const href of ADMIN_FILES) await expect(nav.locator(`a[href="${href}"]`)).toHaveCount(1);
    });

    test('TODO markers are HTML comments, disabled buttons carry TODO(js) and a reason', async ({ page }) => {
      const html = readFileSync(join(DIR, file), 'utf8');
      const main = html.slice(html.indexOf('<main'), html.indexOf('</main>'));
      expect(main.replace(/<!--[\s\S]*?-->/g, '')).not.toMatch(/TODO/);
      const disabled = (main.match(/<button[^>]*disabled/g) || []).length;
      expect((main.match(/<!-- TODO\(js\)/g) || []).length).toBeGreaterThanOrEqual(disabled);
      await open(page, file);
      const buttons = page.locator('main button[disabled]');
      for (let i = 0; i < await buttons.count(); i++) {
        await expect(buttons.nth(i)).toHaveAttribute('aria-describedby', /\S/);
      }
    });
  });
}

test.describe('tenant admin surfaces', () => {
  test('home: heading, two cards, members, domains, programmes with set-up links, attribution note', async ({ page }) => {
    await open(page, 'home-admin.html');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Administration');
    await expect(page.locator('main a[href="admin-org.html"]')).toBeVisible();
    await expect(page.locator('main a[href="admin-branding.html"]')).toBeVisible();
    await expect(page.locator('main a[href="admin-members.html"]')).toBeVisible();
    await expect(page.locator('main a[href="admin-domains.html"]')).toBeVisible();
    const rows = page.locator('main table tbody tr');
    await expect(rows).toHaveCount(2);
    await expect(rows.nth(0)).toContainText('SuperSAFE');
    await expect(rows.nth(1)).toContainText('OpenTech Fund');
    await expect(page.locator('main table a[href="planning-studio.html"]')).toHaveCount(2);
    await expect(page.locator('footer')).toContainText('Platform attribution: FSTP platform (TODO(legal)).');
  });

  test('organisation: definition lists, disabled edit buttons, agreements, SoD-07 note', async ({ page }) => {
    await open(page, 'admin-org.html');
    await expect(page.locator('main dl')).toHaveCount(4);
    await expect(page.locator('main dt', { hasText: 'Legal entity name' })).toBeVisible();
    await expect(page.locator('main dt', { hasText: 'Registered address' })).toBeVisible();
    await expect(page.getByRole('button', { name: /^Edit/ })).toHaveCount(3);
    for (const b of await page.getByRole('button', { name: /^Edit/ }).all()) await expect(b).toBeDisabled();
    const agreements = page.locator('main table tbody tr');
    await expect(agreements).toHaveCount(3);
    await expect(agreements.nth(0)).toContainText('Signed');
    await expect(agreements.nth(1)).toContainText('Signed');
    await expect(page.getByRole('link', { name: 'View current list' })).toBeVisible();
    await expect(page.locator('main')).toContainText('Changes to legal entity details require approval by a second tenant admin (SoD-07).');
    expect((readFileSync(join(DIR, 'admin-org.html'), 'utf8').match(/<!-- TODO\(legal\)/g) || []).length).toBe(3);
  });

  test('members: table, two admins, self row highlighted with SoD-07, pending invite, SoD-09 note', async ({ page }) => {
    await open(page, 'admin-members.html');
    await expect(page.getByRole('button', { name: 'Invite member' })).toBeDisabled();
    const rows = page.locator('main table').first().locator('tbody tr');
    await expect(rows).toHaveCount(4);
    await expect(page.locator('main table').first().locator('thead th', { hasText: 'Tenant-wide roles' })).toHaveCount(1);
    await expect(rows.locator('.badge', { hasText: 'Tenant admin' })).toHaveCount(2);
    await expect(rows.nth(0)).toContainText('Programme manager, SuperSAFE');
    await expect(rows.nth(2)).toContainText('Assigned reviewer, SuperSAFE');
    await expect(page.getByRole('button', { name: /^Grant role/ })).toHaveCount(4);
    const self = page.locator('tr.row-self');
    await expect(self).toHaveCount(1);
    await expect(self).toContainText('a.chen@horizon-bridges.example');
    await expect(self).toContainText('SoD-07');
    await expect(page.locator('main')).toContainText('Granting a role to your own account requires approval by a second tenant admin (SoD-07).');
    const invite = page.locator('main table').nth(1).locator('tbody tr');
    await expect(invite).toHaveCount(1);
    await expect(invite).toContainText('r.gomez@example.org');
    await expect(invite).toContainText('Call drafter');
    await expect(invite).toContainText('OpenTech Fund');
    await expect(invite).toContainText('3 days ago');
    await expect(page.locator('main')).toContainText('Drafting and Judging bindings require verified identity at binding time (SoD-09).');
  });

  test('branding: one failing pair blocks save, mandatory elements present, overrides limited to labels', async ({ page }) => {
    await open(page, 'admin-branding.html');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Branding');
    await expect(page.locator('.upload-slot')).toHaveCount(3);
    await expect(page.locator('main')).toContainText('SVG is sanitised on upload per I-68');
    const tokens = page.locator('main table').first().locator('tbody tr');
    await expect(tokens).toHaveCount(3);
    await expect(tokens.nth(2).locator('.badge--error')).toHaveText('Fails WCAG 2.2 AA');
    await expect(page.locator('main')).toContainText('Packages with failing pairs are rejected (I-70).');
    await expect(page.locator('main')).toContainText('No third-party font hosts are loaded (I-68).');
    await expect(page.locator('.check-list li')).toHaveCount(5);
    await expect(page.locator('.check-list .badge--success')).toHaveCount(5);
    await expect(page.locator('main')).toContainText('These elements cannot be removed by branding (I-69).');
    await expect(page.getByRole('button', { name: 'Save' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Save' })).toHaveAccessibleDescription('Saving is blocked while contrast failures exist.');
    await expect(page.locator('main')).toContainText('Contracts and notices keep their approved wording (I-72).');
  });

  test('domains: pending domain links to instructions, email checks pass, ACME note', async ({ page }) => {
    await open(page, 'admin-domains.html');
    const rows = page.locator('main table tbody tr');
    await expect(rows).toHaveCount(3);
    await expect(rows.filter({ hasText: 'Verified' })).toHaveCount(2);
    await expect(rows.nth(2)).toContainText('Awaiting DNS TXT record');
    await rows.nth(2).getByRole('link', { name: 'see instructions' }).click();
    await expect(page).toHaveURL(/#dns-steps$/);
    await expect(page.locator('main')).toContainText('A domain serves traffic only after verified ownership (I-71).');
    await expect(page.getByRole('button', { name: 'Add domain' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Re-check' })).toBeDisabled();
    await expect(page.locator('main dl .badge--success')).toHaveCount(3);
    await expect(page.locator('main')).toContainText('Certificates are issued automatically through ACME after the ownership check.');
  });
});


// Post-grant, complaints, transparency, reporting, support and onboarding screens (10-post-grant-screens.md).
const POST_GRANT_FILES = [
  'payment-request-form.html', 'payment-request-review.html', 'payment-release.html', 'payment-status.html',
  'contract-view.html', 'contract-signatory.html', 'contract-amendment.html', 'home-signatory.html',
  'complaint-file.html', 'complaint-coordinator-review.html', 'complaint-irc-escalation.html', 'complaint-status.html',
  'public-grants.html', 'grantee-visibility.html', 'public-calls-feed.html',
  'audit-log.html', 'funder-report.html', 'report-approval.html',
  'grantee-support.html', 'mentor-assignment.html', 'onboarding.html',
  'payment-checks-failed.html', 'contract-drafted.html', 'contract-advanced-approval.html', 'contract-terminal.html',
  'home-mentor.html', 'home-operations.html', 'report-generation-failure.html',
];

for (const file of POST_GRANT_FILES) {
  test.describe(`${file}: post-grant checks`, () => {
    test('loads with status 200 over HTTP and has one main landmark', async ({ page }) => {
      const body = readFileSync(join(DIR, file), 'utf8');
      const css = readFileSync(join(DIR, '..', 'tokens.css'), 'utf8');
      await page.route('http://proto.test/**', route => route.request().url().endsWith('/tokens.css')
        ? route.fulfill({ status: 200, contentType: 'text/css', body: css })
        : route.fulfill({ status: 200, contentType: 'text/html', body }));
      const res = await page.goto(`http://proto.test/prototypes/${file}`);
      expect(res?.status()).toBe(200);
      await expect(page.getByRole('main')).toHaveCount(1);
    });

    test('plain primary labels: no metaphor words, no Voyage labels, Horizon Bridges brand', async ({ page }) => {
      await open(page, file);
      const texts = await page.locator('h1, h2, h3, button, .btn, th, label, legend').evaluateAll(els => els.map(el => el.textContent || ''));
      expect(texts.filter(t => METAPHOR.test(t)).map(t => t.trim())).toEqual([]);
      await expect(page.locator('.voyage-label')).toHaveCount(0);
      expect(await page.locator('body').innerText()).not.toMatch(VOYAGE_PACK);
      await expect(page.locator('header .brand')).toContainText('Horizon Bridges');
    });

    test('TODO markers are comments; disabled buttons carry TODO(js) and a reason', async ({ page }) => {
      const html = readFileSync(join(DIR, file), 'utf8');
      const main = html.slice(html.indexOf('<main'), html.indexOf('</main>'));
      expect(main.replace(/<!--[\s\S]*?-->/g, '')).not.toMatch(/TODO/);
      expect((main.match(/<!-- TODO\(js\)/g) || []).length).toBeGreaterThanOrEqual((main.match(/<button[^>]*disabled/g) || []).length);
      await open(page, file);
      const buttons = page.locator('main button[disabled]');
      for (let i = 0; i < await buttons.count(); i++) await expect(buttons.nth(i)).toHaveAttribute('aria-describedby', /\S/);
    });
  });
}

test.describe('post-grant surfaces', () => {
  test('payment form: plan order, paid-in-full row disabled, pending amount, running total', async ({ page }) => {
    await open(page, 'payment-request-form.html');
    await expect(page.getByRole('heading', { level: 2 })).toContainText(['Task 1: Community outreach', 'Task 2: Software delivery', 'Request total']);
    await expect(page.locator('main .badge', { hasText: 'Paid in full' })).toBeVisible();
    await expect(page.getByLabel('Requested amount (EUR), milestone 1.1')).toBeDisabled();
    await expect(page.locator('main')).toContainText('5 000.00 EUR in PR-2026-0012');
    await expect(page.getByRole('button', { name: /^Fill available/ })).toHaveCount(3);
    await expect(page.locator('main')).toContainText('18 000.00 EUR');
    await expect(page.getByRole('button', { name: 'Submit request' })).toBeDisabled();
    await expect(page.locator('main .callout')).toContainText('publicly reachable without authentication');
  });

  test('payment review: three passing checks, full, partial and reject lines, SoD-04', async ({ page }) => {
    await open(page, 'payment-request-review.html');
    await expect(page.locator('main table').first().locator('.badge--success')).toHaveCount(3);
    await expect(page.getByLabel('Approve partial amount').nth(1)).toBeChecked();
    await expect(page.getByLabel('Approved amount (EUR), line 2')).toHaveValue('10000.00');
    await expect(page.getByLabel('Reject').nth(2)).toBeChecked();
    await expect(page.getByLabel('Reason for rejection, line 3')).toBeVisible();
    await expect(page.locator('main')).toContainText('must be different from the approver (SoD-04)');
  });

  test('payment release and status: SoD-04 block, record-only mode, five request states', async ({ page }) => {
    await open(page, 'payment-release.html');
    await expect(page.getByRole('button', { name: /^Release/ })).toHaveCount(2);
    await expect(page.locator('main')).toContainText('Record-only: approved payments are exported to your finance system.');
    await expect(page.locator('#sod-why')).toContainText('SoD-04');
    await open(page, 'payment-status.html');
    for (const s of ['CHECKS_FAILED', 'UNDER_REVIEW', 'CHANGES_REQUESTED', 'ACCEPTED', 'PAID', 'WITHDRAWN']) await expect(page.locator('main table')).toContainText(s);
    await expect(page.locator('main table a[href="payment-request-form.html"]')).toHaveCount(5);
    await expect(page.locator('main table a[href="payment-checks-failed.html"]')).toHaveCount(1);
    await expect(page.locator('main .callout')).toContainText(['Review the failed checks and resubmit.']);
  });

  test('contracts: SENT cascade, decline, countersign queue, amendment diff', async ({ page }) => {
    await open(page, 'contract-view.html');
    await expect(page.locator('main')).toContainText('SENT');
    await expect(page.locator('ol.cascade > li')).toHaveCount(3);
    await expect(page.getByRole('button', { name: 'Sign with your EUDI Wallet' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Decline' })).toBeDisabled();
    await expect(page.locator('main')).toContainText('R-NG-04');
    await open(page, 'contract-signatory.html');
    await expect(page.getByRole('button', { name: /^Countersign/ })).toHaveCount(3);
    await expect(page.locator('main')).toContainText('EFFECTIVE');
    await open(page, 'contract-amendment.html');
    await expect(page.locator('main del')).toHaveCount(2);
    await expect(page.locator('main ins')).toHaveCount(2);
    await expect(page.locator('main')).toContainText('The proposal state does not change while an amendment is pending.');
    await open(page, 'home-signatory.html');
    await page.getByRole('link', { name: 'Review contracts' }).click();
    await expect(page).toHaveURL(/contract-signatory\.html$/);
  });

  test('complaints: scope, I-57, SoD-13, IRC outcome, five statuses', async ({ page }) => {
    await open(page, 'complaint-file.html');
    await expect(page.getByLabel('Decision being contested').locator('option')).toHaveCount(3);
    await expect(page.locator('main')).toContainText('(I-57)');
    await open(page, 'complaint-coordinator-review.html');
    await expect(page.locator('main')).toContainText('SoD-13');
    await expect(page.getByRole('button', { name: 'Mark resolved' })).toBeDisabled();
    await open(page, 'complaint-irc-escalation.html');
    await expect(page.getByLabel('Remedy').locator('option')).toHaveCount(3);
    await expect(page.getByLabel('Dismiss the complaint')).toBeVisible();
    await open(page, 'complaint-status.html');
    for (const s of ['FILED', 'COORDINATOR_REVIEW', 'RESOLVED', 'ESCALATED', 'UPHELD']) await expect(page.locator('main table')).toContainText(s);
    await expect(page.locator('main')).toContainText('A procedural error was found. The remedy is recorded.');
  });

  test('transparency: three visibility levels, limits, no-tracking footer, feed', async ({ page }) => {
    await open(page, 'public-grants.html');
    const cards = page.locator('main article');
    await expect(cards).toHaveCount(3);
    await expect(cards.nth(0)).not.toContainText('Grantee');
    await expect(cards.nth(1)).toContainText('Grantee');
    await expect(cards.nth(1)).not.toContainText('EUR');
    await expect(cards.nth(2)).toContainText('48 500.00 EUR');
    await expect(page.locator('footer')).toContainText('No tracking scripts and no cookies');
    expect(readFileSync(join(DIR, 'public-grants.html'), 'utf8')).toMatch(/<!-- I-42/);
    await open(page, 'grantee-visibility.html');
    await expect(page.getByRole('radio', { checked: true })).toHaveCount(2);
    await expect(page.getByText('Not available: a team member is a minor (I-42).')).toHaveCount(4);
    await expect(page.locator('main .callout')).toContainText("One or more members of this proposal's team are minors.");
    for (const id of ['fu-h', 'fu-p', 'fi-h', 'fi-p']) await expect(page.locator('#' + id)).toBeEnabled();
    for (const id of ['fu-pg', 'fu-f', 'fi-pg', 'fi-f']) await expect(page.locator('#' + id)).toBeDisabled();
    await open(page, 'public-calls-feed.html');
    await expect(page.locator('pre code')).toContainText('"status"');
  });

  test('reporting, support and onboarding', async ({ page }) => {
    await open(page, 'audit-log.html');
    await expect(page.locator('main table tbody tr')).toHaveCount(6);
    await expect(page.locator('main')).toContainText('R-CF-03');
    await open(page, 'funder-report.html');
    await expect(page.locator('main table tbody tr')).toHaveCount(4);
    await expect(page.locator('main')).toContainText('(I-44)');
    await open(page, 'report-approval.html');
    await expect(page.locator('main')).toContainText('You must not be the person who generated this report.');
    await open(page, 'grantee-support.html');
    await expect(page.locator('main section.card')).toHaveCount(4);
    await expect(page.locator('main')).toContainText('SoD-12');
    await open(page, 'mentor-assignment.html');
    await expect(page.getByRole('link', { name: /^Session notes/ })).toHaveCount(3);
    await open(page, 'onboarding.html');
    const steps = page.getByRole('navigation', { name: 'Onboarding steps' }).locator('li');
    await expect(steps).toHaveCount(9);
    await expect(steps.first()).toHaveAttribute('aria-current', 'step');
    await expect(page.locator('.steps-bar .badge', { hasText: 'Locked' })).toHaveCount(8);
    await expect(page.getByLabel('Legal entity name')).toHaveValue('Horizon Bridges');
  });

  test('navigation updates reach the new screens', async ({ page }) => {
    const links: [string, string[]][] = [
      ['home-finance.html', ['payment-request-review.html', 'payment-release.html']],
      ['home-auditor.html', ['audit-log.html', 'funder-report.html']],
      ['negotiation.html', ['contract-view.html']],
      ['end-states.html', ['payment-status.html', 'grantee-support.html', 'grantee-visibility.html']],
      ['home-voyager.html', ['payment-status.html', 'complaint-status.html', 'grantee-visibility.html', 'grantee-support.html']],
      ['home-admin.html', ['onboarding.html']],
      ['negotiation.html', ['contract-drafted.html']],
      ['contract-view.html', ['contract-terminal.html', 'contract-advanced-approval.html']],
      ['funder-report.html', ['report-generation-failure.html']],
      ['payment-status.html', ['payment-checks-failed.html']],
      ['home-mentor.html', ['mentor-assignment.html']],
      ['home-operations.html', ['payment-request-review.html', 'payment-release.html', 'contract-signatory.html', 'report-approval.html']],
    ];
    for (const [file, targets] of links) {
      await open(page, file);
      for (const t of targets) expect(await page.locator(`main a[href="${t}"]`).count(), `${file} -> ${t}`).toBeGreaterThan(0);
    }
  });
});

test.describe('decisions Q25 to Q27 (2026-11-01)', () => {
  test('Q25: role prerequisite callout links to Members and roles on review and release', async ({ page }) => {
    for (const file of ['payment-request-review.html', 'payment-release.html']) {
      await open(page, file);
      const callout = page.locator('main .callout', { hasText: 'must be assigned before this workflow is available' });
      await expect(callout).toContainText('Payment request roles (Finance approver and Payment releaser)');
      await expect(callout).toContainText('Assign roles in Administration > Members and roles.');
      await expect(callout.locator('a[href="admin-members.html"]')).toHaveCount(1);
    }
    await open(page, 'payment-request-review.html');
    await expect(page.locator('main')).toContainText('PAYMENT_APPROVED');
    await expect(page.getByRole('button', { name: 'Confirm request total' })).toBeDisabled();
  });

  test('Q27: scope decision panel, out of scope view, SoD-13 and P-63 notes', async ({ page }) => {
    await open(page, 'complaint-coordinator-review.html');
    await expect(page.getByRole('heading', { name: 'Scope decision' }).first()).toBeVisible();
    await expect(page.getByLabel('In scope: proceed to review').first()).toBeChecked();
    await expect(page.getByLabel('Out of scope: provide reasoned response')).toHaveCount(2);
    const oos = page.locator('#out-of-scope-view');
    await expect(oos.getByRole('heading', { name: 'Out of scope view' })).toBeVisible();
    await expect(oos.getByLabel('Out of scope: provide reasoned response')).toBeChecked();
    await expect(oos.getByLabel('Reasoned response for the out of scope decision')).toBeVisible();
    await expect(oos.getByRole('button', { name: 'Record as out of scope' })).toBeDisabled();
    await expect(page.locator('main')).toContainText('SoD-13 applies. Only staff who took no part in the contested decision may make this determination.');
    await expect(oos).toContainText('The complainant can escalate an out-of-scope decision within the complaint window (P-63).');
  });

  test('Q27: terms and conditions TODO(legal) comment on the three complaint screens', async ({ page }) => {
    for (const file of ['complaint-file.html', 'complaint-coordinator-review.html', 'complaint-irc-escalation.html']) {
      expect(readFileSync(join(DIR, file), 'utf8')).toContain('<!-- TODO(legal): Reference to this complaint procedure must appear in the terms and conditions of participation and in the grant application submission terms. -->');
    }
    await open(page, 'complaint-file.html');
    await expect(page.locator('main')).toContainText('The complaints procedure forms part of the terms and conditions of participation and the grant application.');
  });
});

test.describe('remaining screens (2026-11-01)', () => {
  test('onboarding: nine step panels, Step N of 9, back links, locked notes, step content', async ({ page }) => {
    await open(page, 'onboarding.html');
    for (let n = 1; n <= 9; n++) {
      const s = page.locator('#step-' + n);
      await expect(s).toHaveCount(1);
      await expect(s.locator('.step-count')).toHaveText('Step ' + n + ' of 9');
      await expect(s.getByRole('button', { name: /^Save and continue/ })).toBeDisabled();
      if (n > 1) {
        await expect(s.locator('a[href="#step-' + (n - 1) + '"]')).toHaveCount(1);
        await expect(s).toContainText('This step opens after the previous step is completed and validated.');
      }
    }
    await expect(page.locator('main hr')).toHaveCount(8);
    await expect(page.getByRole('button', { name: /^Re-sign/ })).toHaveCount(2);
    await expect(page.locator('#step-3 a[href="admin-branding.html"]')).toHaveCount(1);
    await expect(page.getByLabel('Organisation name')).toHaveAttribute('readonly', '');
    await expect(page.locator('#step-4 a[href="admin-domains.html"]')).toHaveCount(1);
    await expect(page.getByLabel('Primary domain')).toHaveValue('horizon-bridges.example');
    await expect(page.getByRole('switch', { name: 'Accept EUDI Wallet credentials (P-45).' })).toBeChecked();
    await expect(page.locator('#step-5 input[type=checkbox]:not([role=switch])')).toHaveCount(2);
    await expect(page.getByLabel('Model (P-21)')).toHaveValue('fstp-default-v2');
    await expect(page.getByLabel(/^Record-only/)).toBeChecked();
    await expect(page.getByLabel('Bank interface')).toBeDisabled();
    await expect(page.locator('#step-7')).toContainText('The platform never holds or controls funds (I-16).');
    await expect(page.locator('#step-8')).toContainText('This must be a tenant-owned account (O-21).');
    await expect(page.locator('#step-9 tbody .badge', { hasText: 'Confirmed' })).toHaveCount(2);
    await expect(page.getByRole('button', { name: 'Activate organisation' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Invite another admin' })).toBeDisabled();
  });

  test('payment checks failed: two failing checks, one pass, resubmit note', async ({ page }) => {
    await open(page, 'payment-checks-failed.html');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Payment request: checks failed');
    await expect(page.locator('main table tbody .badge', { hasText: 'Fail' })).toHaveCount(2);
    await expect(page.locator('main table tbody .badge', { hasText: 'Pass' })).toHaveCount(1);
    await expect(page.locator('main')).toContainText('Resubmitting creates a new request reference.');
    await expect(page.getByRole('button', { name: 'Edit and resubmit' })).toBeDisabled();
    await expect(page.locator('main a[href="payment-status.html"]')).toHaveText('Return to payment requests');
  });

  test('contract draft, advanced approval and history', async ({ page }) => {
    await open(page, 'contract-drafted.html');
    await expect(page.locator('main')).toContainText('DRAFTED');
    await expect(page.locator('main table tbody tr')).toHaveCount(2);
    await expect(page.getByRole('button', { name: 'Propose a change' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Decline the contract' })).toBeDisabled();
    await expect(page.locator('main')).toContainText('(R-NG-04)');
    await open(page, 'contract-advanced-approval.html');
    await expect(page.getByLabel('Reason for approval')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Approve' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Refuse' })).toBeDisabled();
    await expect(page.locator('main')).toContainText('(P-30 step 3)');
    await open(page, 'contract-terminal.html');
    for (const s of ['SUPERSEDED', 'EFFECTIVE', 'TERMINATED']) await expect(page.locator('main')).toContainText(s);
    await expect(page.getByRole('link', { name: /^Download PDF/ })).toHaveCount(2);
    await expect(page.getByRole('link', { name: /^Download sealed draft/ })).toHaveCount(1);
    await expect(page.locator('main')).toContainText('(I-30)');
  });

  test('mentor and operations homes, report failure', async ({ page }) => {
    await open(page, 'home-mentor.html');
    await expect(page.locator('main')).toContainText('SoD-12');
    await open(page, 'home-operations.html');
    await expect(page.locator('main section.card')).toHaveCount(4);
    const nav = page.getByRole('navigation', { name: 'Main navigation' });
    for (const h of ['payment-request-review.html', 'payment-release.html', 'contract-signatory.html', 'report-approval.html']) await expect(nav.locator('a[href="' + h + '"]')).toHaveCount(1);
    await expect(page.locator('main')).toContainText('SoD-04');
    await expect(page.locator('main')).toContainText('SoD-03');
    await open(page, 'report-generation-failure.html');
    await expect(page.locator('main table tbody tr')).toHaveCount(2);
    await expect(page.locator('main')).toContainText('(I-44)');
    await expect(page.locator('main a[href="funder-report.html"]')).toHaveText('Back to reports');
    expect(readFileSync(join(DIR, 'report-generation-failure.html'), 'utf8')).toMatch(/<!-- TODO\(legal\): support channel/);
  });
});

test.describe('Financial signatory and Legal signatory (2026-11-01)', () => {
  test('members: tenant-wide badges, one person holds both, callout, grant note', async ({ page }) => {
    await open(page, 'admin-members.html');
    const rows = page.locator('main table').first().locator('tbody tr');
    const badges = async (i: number) => (await rows.nth(i).locator('td').nth(2).locator('.badge').allInnerTexts()).map(s => s.trim());
    expect(await badges(0)).toEqual(['Tenant admin', 'Legal signatory']);
    expect(await badges(1)).toEqual(['Tenant admin', 'Financial signatory']);
    expect(await badges(2)).toEqual([]);
    await expect(rows.nth(3)).toContainText('k.wu@horizon-bridges.example');
    expect(await badges(3)).toEqual(['Financial signatory', 'Legal signatory']);
    await expect(page.locator('main .callout')).toContainText(['Financial signatory and Legal signatory are tenant-wide roles. Both must be assigned to at least one person before the organisation can be activated.']);
    await expect(page.locator('#grant-why')).toContainText('Tenant-wide roles include Financial signatory and Legal signatory.');
  });

  test('roles can be changed later: Change roles per row, callout, links from organisation and onboarding', async ({ page }) => {
    await open(page, 'admin-members.html');
    const change = page.getByRole('button', { name: /^Change roles/ });
    await expect(change).toHaveCount(4);
    for (const b of await change.all()) { await expect(b).toBeDisabled(); await expect(b).toHaveAttribute('aria-describedby', 'change-why'); }
    await expect(page.locator('main .callout')).toContainText(['Tenant admins can add, change or remove tenant-wide and programme roles at any time after activation. Removing the last Financial signatory or Legal signatory is blocked.']);
    await open(page, 'admin-org.html');
    await expect(page.locator('main')).toContainText('Tenant admins can add or change signatory holders at any time in Members and roles.');
    await open(page, 'onboarding.html');
    await expect(page.locator('#step-9')).toContainText('You can add or change any role later in Administration > Members and roles');
    await expect(page.locator('#step-9 a[href="admin-members.html"]')).toHaveCount(1);
  });

  test('organisation: two signatory subsections with holders and notes', async ({ page }) => {
    await open(page, 'admin-org.html');
    const fin = page.locator('dl[aria-labelledby="fin-sig-h"]');
    const leg = page.locator('dl[aria-labelledby="leg-sig-h"]');
    await expect(page.getByRole('heading', { name: 'Financial signatory' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Legal signatory' })).toBeVisible();
    expect(await fin.locator('dt').allInnerTexts()).toEqual(['M. Diop', 'K. Wu']);
    expect(await leg.locator('dt').allInnerTexts()).toEqual(['A. Chen', 'K. Wu']);
    await expect(page.getByText('At least one person must hold this role before the organisation can be activated.')).toHaveCount(2);
    await expect(page.locator('main')).toContainText('One person may hold both Financial signatory and Legal signatory.');
    await expect(page.getByRole('button', { name: 'Edit signatories' })).toBeDisabled();
  });

  test('onboarding step 9: signatory tables, Assign buttons, activation conditions', async ({ page }) => {
    await open(page, 'onboarding.html');
    const s9 = page.locator('#step-9');
    await expect(s9.locator('table[aria-labelledby="fin-sig-h"] tbody tr')).toHaveCount(2);
    await expect(s9.locator('table[aria-labelledby="leg-sig-h"] tbody tr')).toHaveCount(2);
    await expect(s9.getByRole('button', { name: /^Assign/ })).toHaveCount(2);
    for (const b of await s9.getByRole('button', { name: /^Assign/ }).all()) await expect(b).toBeDisabled();
    await expect(s9.locator('.callout--warning')).toContainText('Activation requires: at least two tenant admins confirmed (SoD-07), a Financial signatory assigned, and a Legal signatory assigned. One person may hold both signatory roles.');
    const note = page.locator('#act-why');
    for (const c of ['(SoD-07)', 'a Financial signatory is assigned', 'a Legal signatory is assigned']) await expect(note).toContainText(c);
  });
});

test.describe('decisions Q28 to Q30 (2026-11-01)', () => {
  test('Q28: terminated contract shows the sealed draft note and link', async ({ page }) => {
    await open(page, 'contract-terminal.html');
    const panel = page.locator('section[aria-labelledby="term-h"]');
    await expect(panel).toContainText('This contract was terminated before any party signed it. The draft PDF is sealed with the tenant\'s electronic seal and stored at the point of termination (Q28 decision, 2026-11-01).');
    await expect(panel).toContainText('The sealed PDF is downloadable and its hash is in the audit log (I-30).');
    await expect(panel.getByRole('link', { name: /^Download sealed draft/ })).toHaveCount(1);
    await expect(panel.getByRole('link', { name: /^Download PDF/ })).toHaveCount(0);
  });

  test('Q29: step 9 activation approval panel and explicit second-admin note', async ({ page }) => {
    await open(page, 'onboarding.html');
    const panel = page.locator('#step-9 section[aria-labelledby="act-st-h"]');
    await expect(panel).toContainText('a.chen@horizon-bridges.example');
    await expect(panel).toContainText('m.diop@horizon-bridges.example (second admin, did not complete setup)');
    await expect(panel.getByRole('button', { name: 'Approve activation' })).toBeDisabled();
    await expect(page.locator('#act-why')).toContainText('Activation must be approved by a second tenant admin who did not complete this setup. This is by analogy with I-67 (programme activation). A new rule is pending spec amendment (Q29).');
  });

  test('Q30: step 5 lists two verification methods and the advanced signature note', async ({ page }) => {
    await open(page, 'onboarding.html');
    const s5 = page.locator('#step-5');
    await expect(s5.getByLabel('EUDI Wallet (qualified)')).toBeChecked();
    await expect(s5.getByLabel('Remote qualified (QTSP)')).toBeChecked();
    await expect(s5.getByLabel('Advanced signature')).toHaveCount(0);
    await expect(s5).toContainText('Advanced signature is a fallback signing route (P-30), not a verification method. It is configured in the contract signing flow, not here.');
  });
});

// Layout shell (01-navigation-home.md, "Sidebar layout" and "Layout and routing contract").
const PUBLIC_FILES = ['auth-signup.html', 'auth-check-email.html', 'auth-enrol.html', 'auth-signin.html', 'call-detail-public.html', 'calls-public.html', 'public-grants.html', 'public-calls-feed.html'];
const APP_FILES = FILES.filter(f => !PUBLIC_FILES.includes(f));
const MASQUERADE_PAGES: Record<string, string> = { 'home-voyager.html': 'Applicant', 'reviewer-scoring.html': 'Assigned reviewer' };

test.describe('layout shell: app layout with sidebar', () => {
  test('public and app page lists cover every prototype', () => {
    expect(PUBLIC_FILES.every(f => FILES.includes(f))).toBe(true);
    expect(APP_FILES).toHaveLength(61);
  });

  for (const file of APP_FILES) {
    test(`${file}: sidebar holds the nav, role chip, account links and a masquerade slot`, async ({ page }) => {
      await open(page, file);
      const aside = page.locator('.page-body:not(.page-body--public) > aside.sidebar[aria-label="Main navigation"]');
      await expect(aside).toHaveCount(1);
      await expect(aside).toBeVisible();
      await expect(page.locator('header nav')).toHaveCount(0);
      await expect(aside.locator('nav.main-nav[aria-label="Main navigation"]')).toHaveCount(1);
      await expect(aside.locator('.role-chip')).toHaveText(/^(Signed in|Viewing) as /);
      await expect(aside.locator('.sidebar-foot a[href="profile.html"]')).toHaveText('Account');
      await expect(aside.locator('.sidebar-foot a[href="#"]')).toHaveText('Sign out');
      const first = await page.locator('.page-body > :first-child > :first-child').getAttribute('class');
      expect(first).toMatch(/^masquerade-banner/);
      await expect(aside.locator('.masquerade-banner')).toHaveCount(1);
      await expect(aside.locator('.masquerade-banner a[href="home-admin.html"]')).toHaveText('Exit masquerade');
      if (MASQUERADE_PAGES[file]) {
        await expect(aside.locator('.masquerade-banner')).not.toHaveClass(/masquerade-banner--hidden/);
      } else {
        await expect(aside.locator('.masquerade-banner')).toHaveClass('masquerade-banner masquerade-banner--hidden');
        await expect(aside.locator('.masquerade-banner')).toBeHidden();
      }
    });
  }

  test('desktop: 220 pixel sticky sidebar left of main, avatar hidden, main at most 960 pixels', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await open(page, 'home-admin.html');
    const aside = page.locator('.page-body > .sidebar');
    const a = await aside.boundingBox();
    const m = await page.locator('main').boundingBox();
    expect(a && Math.round(a.width)).toBe(220);
    expect(a && m && a.x + a.width <= m.x).toBe(true);
    expect(m && m.width).toBeLessThanOrEqual(960);
    await expect(aside).toHaveCSS('position', 'sticky');
    await expect(page.locator('header .avatar')).toBeHidden();
    await expect(aside.locator('.sidebar-account')).toBeVisible();
  });

  test('mobile: nav stacks below the top bar, always visible, avatar shown, no script', async ({ browser }) => {
    const context = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 375, height: 800 } });
    const page = await context.newPage();
    await open(page, 'home-admin.html');
    const h = await page.locator('header').boundingBox();
    const a = await page.locator('.page-body > .sidebar').boundingBox();
    const m = await page.locator('main').boundingBox();
    expect(h && a && a.y >= h.y + h.height - 1).toBe(true);
    expect(a && m && m.y >= a.y + a.height - 1).toBe(true);
    await expect(page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'Members and roles' })).toBeVisible();
    await page.getByRole('link', { name: /Account: a\.chen@horizon-bridges\.example/ }).click();
    await expect(page).toHaveURL(/profile\.html$/);
    await context.close();
  });

  test('active link and sidebar text meet AA contrast in light and dark', async ({ page }) => {
    for (const colorScheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme });
      for (const file of ['home-voyager.html', 'home-admin.html']) {
        await open(page, file);
        await expect(page.locator('.sidebar [aria-current="page"]').first()).toBeVisible();
        expect(await lowContrast(page, '.page-body > .sidebar a, .page-body > .sidebar .role-chip, .page-body > .sidebar .sidebar-label, .masquerade-banner:not(.masquerade-banner--hidden) p')).toEqual([]);
      }
    }
  });
});

test.describe('layout shell: public layout without sidebar', () => {
  for (const file of PUBLIC_FILES) {
    test(`${file}: public layout, nav in the top bar, no sidebar or masquerade slot`, async ({ page }) => {
      await open(page, file);
      await expect(page.locator('.page-body.page-body--public')).toHaveCount(1);
      await expect(page.locator('.sidebar')).toHaveCount(0);
      await expect(page.locator('.masquerade-banner')).toHaveCount(0);
      await expect(page.locator('header nav.main-nav[aria-label="Main navigation"]')).toBeVisible();
    });
  }
});

test.describe('masquerade mode (Tenant admin, read-only)', () => {
  for (const [file, role] of Object.entries(MASQUERADE_PAGES)) {
    test(`${file}: banner visible above the ${role} nav`, async ({ page }) => {
      await open(page, file);
      const banner = page.locator('.page-body > .sidebar .masquerade-banner');
      await expect(banner).toBeVisible();
      await expect(banner).toHaveText(`Masquerading as ${role}. This is a read-only admin view. You are still signed in as a.chen@horizon-bridges.example. Exit masquerade`);
      await expect(page.locator('.page-body > .sidebar .role-chip')).toHaveText(`Viewing as ${role}`);
      const b = await banner.boundingBox();
      const n = await page.locator('.page-body > .sidebar nav').boundingBox();
      expect(b && n && b.y + b.height <= n.y).toBe(true);
      await banner.getByRole('link', { name: 'Exit masquerade' }).click();
      await expect(page).toHaveURL(/home-admin\.html$/);
    });
  }

  test('no other page shows the banner', async ({ page }) => {
    for (const file of APP_FILES.filter(f => !MASQUERADE_PAGES[f])) {
      await open(page, file);
      await expect(page.locator('.page-body > .sidebar .masquerade-banner'), file).toBeHidden();
    }
  });

  test('admin-masquerade lists ten read-only views and the note', async ({ page }) => {
    await open(page, 'admin-masquerade.html');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Masquerade as another role');
    const main = page.locator('main');
    await expect(main).toContainText('Switch to a read-only view of the platform as seen by a specific role. You remain signed in as a.chen@horizon-bridges.example. All actions are disabled in masquerade mode.');
    for (const home of ['home-voyager', 'home-reviewer', 'home-committee', 'home-irc', 'home-finance', 'home-signatory', 'home-auditor', 'home-mentor', 'home-operations', 'home-coordinator']) {
      await expect(main.locator(`a[href="${home}.html"]`)).toHaveText(/^View as /);
    }
    await expect(main.getByRole('link', { name: 'View as Applicant' })).toHaveAttribute('href', 'home-voyager.html');
    await expect(main).toContainText('Masquerade is read-only. No action taken during masquerade is recorded against any real account.');
    await expect(page.locator('.role-chip')).toHaveText('Signed in as Tenant admin');
    await expect(page.locator('.sidebar [aria-current="page"]')).toHaveText('Support tools');
    expect(readFileSync(join(DIR, 'admin-masquerade.html'), 'utf8')).toMatch(/<!-- TODO\(js\): real masquerade needs a session flag/);
  });

  test('home-admin links to the masquerade tool under Support tools', async ({ page }) => {
    await open(page, 'home-admin.html');
    const section = page.locator('section[aria-labelledby="support-h"]');
    await expect(section.getByRole('heading', { level: 2 })).toHaveText('Support tools');
    await section.getByRole('link', { name: 'Masquerade as another role' }).click();
    await expect(page).toHaveURL(/admin-masquerade\.html$/);
  });
});
