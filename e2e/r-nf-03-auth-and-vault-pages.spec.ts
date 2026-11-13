/**
 * R-NF-03: the user interface meets WCAG 2.2 level AA. R-NF-04: the user
 * interface is localisable. M3 design section 11.2, ADR-003.
 *
 * No third-party checker is allowed, so these checks are in-house and
 * cover what a browser can check on the auth pages of the cell origin
 * and the write and release pages of the vault origin:
 *
 * - page structure: a language, a title, one `main` landmark, a heading;
 * - every control has an accessible name, as Chromium computes it;
 * - focus order follows the page, and focus is visible at every stop;
 * - text colour pairs meet the AA contrast ratio, in light and dark;
 * - field errors are tied to their field;
 * - each flow completes by keyboard alone.
 *
 * A manual WCAG 2.2 AA review of each page is recorded in the exit audit
 * (design section 11.2). These checks do not replace it.
 *
 * `r_nf_04_pages_have_no_literal_user_strings` scans the TypeScript
 * sources of `web/src/auth` and `web/src/vault`, their HTML, and the
 * server-rendered pages of `fstp-vault` and `fstp-cell` for user-visible
 * literals outside a message catalogue. It needs no stack.
 */

import { expect, type APIRequestContext, type Page } from '@playwright/test';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import {
  Control,
  PAGES,
  UI,
  VirtualAuthenticator,
  call,
  enrolByInvite,
  expectSignedIn,
  expectSignedInAfterInvite,
  keyForNextPasskey,
  okJson,
  openLink,
  pageCdp,
  releaseTicketBody,
  stack,
  syntheticEmail,
  test,
} from './playwright.config';

// ---------------------------------------------------------------------------
// Page states
// ---------------------------------------------------------------------------

type Check = (page: Page, label: string) => Promise<void>;

/**
 * Visits every page state the M3 pages have, and runs `check` on each:
 * login, signup, recovery, magic-link confirm, invitation, the account
 * page, the step-up dialog, the vault write page and the release page.
 */
async function eachPageState(
  person: () => Promise<Page>,
  request: APIRequestContext,
  check: Check,
): Promise<void> {
  const cell = stack().cells.a;
  const control = new Control(request, cell);
  const fresh = await control.reset();

  const anon = await person();
  for (const [label, path] of [
    ['login', PAGES.login],
    ['signup', PAGES.signup],
    ['recovery', PAGES.recovery],
    ['magic confirm', PAGES.magic],
  ] as const) {
    await anon.goto(`${cell.origin}${path}`);
    await check(anon, label);
  }

  const page = await person();
  await VirtualAuthenticator.attach(page);
  await page.goto(fresh.first_admin.url);
  await check(page, 'invitation');
  await page.locator(UI.invite.register).click();
  await expectSignedInAfterInvite(page, cell.origin);
  await check(page, 'account');
  await page.locator(UI.account.addPasskey).click();
  await expect(page.locator(UI.stepup.dialog)).toBeVisible();
  await check(page, 'step-up dialog');
  await page.keyboard.press('Escape');
  await expect(page.locator(UI.stepup.dialog)).toBeHidden();

  const s = await control.negotiation();
  const writer = await person();
  await writer.goto(await control.writeTicketUrl('AffiliationDeclared'));
  await check(writer, 'vault write');

  const ops = await person();
  await VirtualAuthenticator.attach(ops);
  await enrolByInvite(ops, cell.origin, s.operations.invite_url);
  const ticket = okJson(
    await call(ops, cell.origin, 'POST', '/api/v1/vault-tickets', releaseTicketBody(s.proposal)),
    'release ticket',
  )['url'];
  if (typeof ticket !== 'string') throw new Error('release ticket: `url` must be a string');
  await ops.goto(ticket);
  const firstCanary = s.released[0];
  if (firstCanary === undefined) throw new Error('the scenario names no released canary');
  await expect(ops.locator('body')).toContainText(firstCanary);
  await check(ops, 'vault release');
}

// ---------------------------------------------------------------------------
// Structure and accessible names
// ---------------------------------------------------------------------------

/** Roles of controls, which need an accessible name. */
const CONTROL_ROLES = new Set([
  'button',
  'link',
  'textbox',
  'searchbox',
  'checkbox',
  'radio',
  'combobox',
  'listbox',
  'option',
  'menuitem',
  'switch',
  'tab',
  'slider',
  'spinbutton',
]);

interface AxNode {
  ignored?: boolean;
  role?: { value?: unknown };
  name?: { value?: unknown };
  backendDOMNodeId?: number;
}

async function structureProblems(page: Page, label: string): Promise<string[]> {
  const problems: string[] = [];
  const doc = await page.evaluate(() => ({
    lang: document.documentElement.lang,
    title: document.title.trim(),
    mains: document.querySelectorAll('main, [role="main"]').length,
    headings: document.querySelectorAll('h1').length,
    positiveTabindex: Array.from(document.querySelectorAll('[tabindex]')).filter(
      (e) => Number(e.getAttribute('tabindex')) > 0,
    ).length,
  }));
  if (doc.lang === '') problems.push(`${label}: no document language`);
  if (doc.title === '') problems.push(`${label}: no title`);
  if (doc.mains !== 1) problems.push(`${label}: ${doc.mains} main landmarks, not 1`);
  if (doc.headings < 1) problems.push(`${label}: no h1`);
  if (doc.positiveTabindex > 0) problems.push(`${label}: positive tabindex`);

  // The page's one CDP session: Chromium's own accessible name computation.
  const cdp = await pageCdp(page);
  const { nodes } = (await cdp.send('Accessibility.getFullAXTree')) as { nodes: AxNode[] };
  for (const n of nodes) {
    const role = typeof n.role?.value === 'string' ? n.role.value : '';
    if (n.ignored === true || !CONTROL_ROLES.has(role)) continue;
    const name = typeof n.name?.value === 'string' ? n.name.value.trim() : '';
    if (name === '') problems.push(`${label}: a ${role} has no accessible name`);
  }
  return problems;
}

// ---------------------------------------------------------------------------
// Focus order and focus visibility
// ---------------------------------------------------------------------------

/**
 * Marks the tabbable elements in page order and returns how many there
 * are. Inside an open modal dialog, only its elements count.
 */
async function markTabbable(page: Page): Promise<number> {
  return page.evaluate(() => {
    const scope: ParentNode = document.querySelector('dialog:modal') ?? document;
    const all = Array.from(
      scope.querySelectorAll<HTMLElement>(
        'a[href], button, input, select, textarea, summary, [tabindex], [contenteditable="true"]',
      ),
    );
    const tabbable = all.filter((e) => {
      if (e.matches(':disabled')) return false;
      if (e instanceof HTMLInputElement && e.type === 'hidden') return false;
      const ti = e.getAttribute('tabindex');
      if (ti !== null && Number(ti) < 0) return false;
      if (e.closest('[inert]') !== null) return false;
      const d = e.closest('dialog');
      if (d !== null && !d.open) return false;
      if (e.getClientRects().length === 0) return false;
      return getComputedStyle(e).visibility === 'visible';
    });
    for (const e of document.querySelectorAll('[data-e2e-tab]')) e.removeAttribute('data-e2e-tab');
    tabbable.forEach((e, i) => e.setAttribute('data-e2e-tab', String(i)));
    return tabbable.length;
  });
}

async function focusProblems(page: Page, label: string): Promise<string[]> {
  const problems: string[] = [];
  const n = await markTabbable(page);
  // Moves the sequential focus starting point to the top of the page,
  // or of the open modal dialog.
  await page.evaluate(() => {
    const start = document.querySelector<HTMLElement>('dialog:modal') ?? document.body;
    const had = start.getAttribute('tabindex');
    start.setAttribute('tabindex', '-1');
    start.focus();
    if (had === null) start.removeAttribute('tabindex');
    else start.setAttribute('tabindex', had);
  });
  const order: string[] = [];
  for (let i = 0; i < n; i++) {
    await page.keyboard.press('Tab');
    const stop = await page.evaluate(() => {
      const a = document.activeElement;
      if (!(a instanceof HTMLElement)) return { at: 'none', visible: false };
      const cs = getComputedStyle(a);
      const outline = cs.outlineStyle !== 'none' && cs.outlineWidth !== '0px';
      const shadow = cs.boxShadow !== 'none';
      return { at: a.getAttribute('data-e2e-tab') ?? `untracked ${a.tagName}`, visible: outline || shadow };
    });
    order.push(stop.at);
    if (!stop.visible) problems.push(`${label}: focus not visible at stop ${i}`);
  }
  const expected = Array.from({ length: n }, (_, i) => String(i));
  if (order.join(',') !== expected.join(',')) {
    problems.push(`${label}: focus order ${order.join(',')} is not the page order ${expected.join(',')}`);
  }
  return problems;
}

// ---------------------------------------------------------------------------
// Contrast
// ---------------------------------------------------------------------------

/**
 * Text elements whose colour pair misses the AA ratio: 4.5:1, or 3:1 for
 * large text (24px, or 18.66px bold). Colours are resolved by the
 * browser's own canvas, so any CSS colour syntax works. A background
 * image under text cannot be measured and counts as a problem.
 */
async function contrastProblems(page: Page, label: string): Promise<string[]> {
  const found = await page.evaluate(() => {
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (ctx === null) return ['no canvas'];
    const rgba = (c: string): [number, number, number, number] => {
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = c;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return [d[0] ?? 0, d[1] ?? 0, d[2] ?? 0, (d[3] ?? 0) / 255];
    };
    const over = (top: number[], bottom: number[]): [number, number, number, number] => {
      const a = top[3] ?? 1;
      return [
        (top[0] ?? 0) * a + (bottom[0] ?? 0) * (1 - a),
        (top[1] ?? 0) * a + (bottom[1] ?? 0) * (1 - a),
        (top[2] ?? 0) * a + (bottom[2] ?? 0) * (1 - a),
        1,
      ];
    };
    const probe = document.createElement('div');
    probe.style.background = 'Canvas';
    document.body.append(probe);
    const canvasColour = rgba(getComputedStyle(probe).backgroundColor);
    probe.remove();
    const lin = (v: number): number => {
      const s = v / 255;
      return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
    };
    const lum = (c: number[]): number =>
      0.2126 * lin(c[0] ?? 0) + 0.7152 * lin(c[1] ?? 0) + 0.0722 * lin(c[2] ?? 0);
    const out: string[] = [];
    for (const el of Array.from(document.body.querySelectorAll<HTMLElement>('*'))) {
      const own = Array.from(el.childNodes).some(
        (n) => n.nodeType === Node.TEXT_NODE && (n.textContent ?? '').trim() !== '',
      );
      if (!own || el.getClientRects().length === 0) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility !== 'visible') continue;
      if (el.closest(':disabled') !== null) continue;
      // The background: ancestors' colours composed over the canvas.
      const layers: [number, number, number, number][] = [];
      let image = false;
      for (let e: Element | null = el; e !== null; e = e.parentElement) {
        const s = getComputedStyle(e);
        if (s.backgroundImage !== 'none') image = true;
        const c = rgba(s.backgroundColor);
        if (c[3] > 0) layers.push(c);
        if (c[3] >= 1) break;
      }
      if (image) {
        out.push(`text over a background image: ${el.tagName}`);
        continue;
      }
      let bg: [number, number, number, number] = canvasColour;
      for (const l of layers.reverse()) bg = over(l, bg);
      const fg = over(rgba(cs.color), bg);
      const l1 = lum(fg);
      const l2 = lum(bg);
      const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
      const size = Number.parseFloat(cs.fontSize);
      const bold = Number.parseInt(cs.fontWeight, 10) >= 700;
      const large = size >= 24 || (bold && size >= 18.66);
      const need = large ? 3 : 4.5;
      if (ratio < need) {
        const text = (el.textContent ?? '').trim().slice(0, 40);
        out.push(`${el.tagName} "${text}" ratio ${ratio.toFixed(2)} < ${need}`);
      }
    }
    return out;
  });
  return found.map((f) => `${label}: ${f}`);
}

// ---------------------------------------------------------------------------
// Keyboard
// ---------------------------------------------------------------------------

/** Presses Tab until `selector` has focus. Fails after `max` presses. */
async function tabTo(page: Page, selector: string, max = 40): Promise<void> {
  for (let i = 0; i < max; i++) {
    if (await page.evaluate((s) => document.activeElement?.matches(s) === true, selector)) return;
    await page.keyboard.press('Tab');
  }
  throw new Error(`${selector} is not reachable by Tab within ${max} presses`);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('R-NF-03 auth and vault pages', () => {
  test('r_nf_03_pages_have_structure_and_every_control_is_named', async ({ person, request }) => {
    const problems: string[] = [];
    await eachPageState(person, request, async (page, label) => {
      problems.push(...(await structureProblems(page, label)));
    });
    expect(problems).toEqual([]);
  });

  test('r_nf_03_focus_order_follows_the_page_and_focus_is_visible', async ({ person, request }) => {
    const problems: string[] = [];
    await eachPageState(person, request, async (page, label) => {
      problems.push(...(await focusProblems(page, label)));
    });
    expect(problems).toEqual([]);
  });

  test('r_nf_03_text_contrast_meets_aa_in_light_and_dark', async ({ person, request }) => {
    const problems: string[] = [];
    await eachPageState(person, request, async (page, label) => {
      for (const colorScheme of ['light', 'dark'] as const) {
        await page.emulateMedia({ colorScheme });
        problems.push(...(await contrastProblems(page, `${label} (${colorScheme})`)));
      }
      await page.emulateMedia({ colorScheme: null });
    });
    expect(problems).toEqual([]);
  });

  test('r_nf_03_field_errors_are_tied_to_their_field', async ({ person, request }) => {
    const cell = stack().cells.a;
    await new Control(request, cell).reset();
    const page = await person();
    for (const [path, field, submit] of [
      [PAGES.signup, UI.signup.email, UI.signup.submit],
      [PAGES.recovery, UI.recovery.email, UI.recovery.submit],
      [PAGES.login, UI.login.email, UI.login.magic],
    ] as const) {
      await page.goto(`${cell.origin}${path}`);
      await page.locator(field).fill('not an address');
      await page.locator(submit).click();
      const input = page.locator(field);
      await expect(input, `${path}: the field is marked invalid`).toHaveAttribute('aria-invalid', 'true');
      const refs = await input.evaluate((e) =>
        `${e.getAttribute('aria-describedby') ?? ''} ${e.getAttribute('aria-errormessage') ?? ''}`
          .split(/\s+/)
          .filter((x) => x !== ''),
      );
      expect(refs.length, `${path}: the field references its error`).toBeGreaterThan(0);
      const texts: string[] = [];
      for (const id of refs) {
        const el = page.locator(`[id="${id}"]`);
        if ((await el.count()) === 1 && (await el.isVisible())) texts.push((await el.innerText()).trim());
      }
      expect(texts.filter((t) => t !== '').length, `${path}: a visible error text`).toBeGreaterThan(0);
    }
  });

  test('r_nf_03_flows_complete_by_keyboard_alone', async ({ person, request }) => {
    const cell = stack().cells.a;
    const control = new Control(request, cell);
    const fresh = await control.reset();

    // Invitation enrolment.
    const page = await person();
    await VirtualAuthenticator.attach(page);
    await page.goto(fresh.first_admin.url);
    await tabTo(page, UI.invite.register);
    await page.keyboard.press('Enter');
    await expectSignedInAfterInvite(page, cell.origin);

    // Adding a passkey, with its step-up dialog.
    await keyForNextPasskey(page);
    await tabTo(page, UI.account.addPasskey);
    await page.keyboard.press('Enter');
    await expect(page.locator(UI.stepup.dialog)).toBeVisible();
    await tabTo(page, UI.stepup.confirm);
    await page.keyboard.press('Enter');
    await expect(page.locator(UI.stepup.dialog)).toBeHidden();
    await expect(page.locator(`${UI.account.devices} > li`)).toHaveCount(2);

    // Passkey login.
    await page.context().clearCookies();
    await page.goto(`${cell.origin}${PAGES.login}`);
    await tabTo(page, UI.login.passkey);
    await page.keyboard.press('Enter');
    await expectSignedIn(page, cell.origin);

    // Self-registration with its email proof.
    const email = syntheticEmail('keyboard');
    const applicant = await person();
    await VirtualAuthenticator.attach(applicant);
    await applicant.goto(`${cell.origin}${PAGES.signup}`);
    await tabTo(applicant, UI.signup.email);
    await applicant.keyboard.type(email);
    await tabTo(applicant, UI.signup.submit);
    await applicant.keyboard.press('Enter');
    await expect(applicant.locator(UI.signup.status)).toBeVisible();
    await openLink(applicant, (await control.newest(email, 'signup')).link);
    await tabTo(applicant, UI.signup.register);
    await applicant.keyboard.press('Enter');
    await expectSignedIn(applicant, cell.origin);
  });
});

// ---------------------------------------------------------------------------
// R-NF-04 source scan
// ---------------------------------------------------------------------------

const ROOT = resolve(__dirname, '..');

function filesUnder(dir: string, ext: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name !== 'node_modules' && e.name !== 'dist' && e.name !== 'target') {
        out.push(...filesUnder(p, ext));
      }
    } else if (e.isFile() && e.name.endsWith(ext)) {
      out.push(p);
    }
  }
  return out;
}

/** A message catalogue file: `messages[.<locale>].ts` or under `messages/`. */
function isTsCatalogue(path: string): boolean {
  const parts = path.split(/[\\/]/);
  const base = parts[parts.length - 1] ?? '';
  return (
    /^(messages|catalogue)(\.[a-z]{2,3}(-[A-Z]{2})?)?\.ts$/.test(base) ||
    parts.slice(0, -1).some((d) => d === 'messages' || d === 'catalogue')
  );
}

/** A Rust message catalogue: `messages.rs` or under `messages/`. */
function isRustCatalogue(path: string): boolean {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] === 'messages.rs' || parts.slice(0, -1).includes('messages');
}

/** Tokens a page may spell that are not interface text. */
const TECHNICAL = new Set([
  'Enter',
  'Escape',
  'Tab',
  'Home',
  'End',
  'Space',
  'ArrowUp',
  'ArrowDown',
  'ArrowLeft',
  'ArrowRight',
  'Error',
  'TypeError',
  'AbortError',
  'NotAllowedError',
  'InvalidStateError',
  'NotSupportedError',
  'SecurityError',
]);

/** Whether a literal reads as interface text in some language. */
function looksLikeUserText(s: string): boolean {
  const t = s.trim();
  if (!/\p{L}/u.test(t) || TECHNICAL.has(t)) return false;
  if (/\p{L}[.!?,]?\s+\p{L}/u.test(t)) return true;
  return /^\p{Lu}\p{Ll}+[.!?:]?$/u.test(t);
}

interface Literal {
  readonly text: string;
  readonly line: number;
  readonly pos: number;
}

/**
 * The string literals of TypeScript source `src`, with the static parts
 * of template literals, and without module specifiers. Comments and
 * regular expression literals are skipped.
 */
function tsLiterals(src: string): Literal[] {
  const out: Literal[] = [];
  const keywordsBeforeRegex = new Set([
    'return',
    'typeof',
    'case',
    'do',
    'else',
    'in',
    'of',
    'new',
    'delete',
    'void',
    'throw',
    'yield',
    'await',
  ]);
  let i = 0;
  let prev = '';
  let prev2 = '';
  const lineAt = (p: number): number => src.slice(0, p).split('\n').length;
  const push = (text: string, pos: number, specifier: boolean): void => {
    if (!specifier) out.push({ text, line: lineAt(pos), pos });
  };
  const sig = (t: string): void => {
    prev2 = prev;
    prev = t;
  };
  const readString = (q: string): string => {
    let s = '';
    i++;
    while (i < src.length && src[i] !== q) {
      if (src[i] === '\\') {
        s += src[i + 1] ?? '';
        i += 2;
      } else {
        s += src[i];
        i++;
      }
    }
    i++;
    return s;
  };
  // Lexes from `i` until the `}` that closes a template expression when
  // `inTemplate`, or until the end.
  const lex = (inTemplate: boolean): void => {
    let depth = 0;
    while (i < src.length) {
      const c = src[i] ?? '';
      const d = src[i + 1] ?? '';
      if (/\s/.test(c)) {
        i++;
      } else if (c === '/' && d === '/') {
        while (i < src.length && src[i] !== '\n') i++;
      } else if (c === '/' && d === '*') {
        const end = src.indexOf('*/', i + 2);
        i = end < 0 ? src.length : end + 2;
      } else if (c === "'" || c === '"') {
        const start = i;
        const s = readString(c);
        const specifier = prev === 'from' || prev === 'import' || (prev === '(' && prev2 === 'import');
        push(s, start, specifier);
        sig('"');
      } else if (c === '`') {
        i++;
        let chunk = '';
        let start = i;
        while (i < src.length && src[i] !== '`') {
          if (src[i] === '\\') {
            chunk += src[i + 1] ?? '';
            i += 2;
          } else if (src[i] === '$' && src[i + 1] === '{') {
            push(chunk, start, false);
            chunk = '';
            i += 2;
            lex(true);
            start = i;
          } else {
            chunk += src[i];
            i++;
          }
        }
        push(chunk, start, false);
        i++;
        sig('`');
      } else if (c === '/') {
        const regex = prev === '' || /^[(,=:[!&|?{};+\-*%<>~^]$/.test(prev) || keywordsBeforeRegex.has(prev);
        if (regex) {
          i++;
          let cls = false;
          while (i < src.length) {
            const r = src[i];
            if (r === '\\') {
              i += 2;
              continue;
            }
            if (r === '[') cls = true;
            else if (r === ']') cls = false;
            else if (r === '/' && !cls) break;
            i++;
          }
          i++;
          while (/[a-z]/.test(src[i] ?? '')) i++;
          sig('regex');
        } else {
          i++;
          sig('/');
        }
      } else if (/[A-Za-z_$0-9]/.test(c)) {
        let w = '';
        while (/[A-Za-z_$0-9]/.test(src[i] ?? '')) {
          w += src[i];
          i++;
        }
        sig(w);
      } else {
        if (inTemplate && c === '{') depth++;
        if (inTemplate && c === '}') {
          if (depth === 0) {
            i++;
            return;
          }
          depth--;
        }
        i++;
        sig(c);
      }
    }
  };
  lex(false);
  return out;
}

interface RustScan {
  readonly literals: Literal[];
  /** Function bodies as [start, end) offsets. */
  readonly fns: [number, number][];
}

/**
 * The string literals and function bodies of Rust source `src`. Comments
 * are skipped, and so is every item under `#[cfg(test)]`.
 */
function rustScan(src: string): RustScan {
  const literals: Literal[] = [];
  const fns: [number, number][] = [];
  const lineAt = (p: number): number => src.slice(0, p).split('\n').length;
  const openFns: { depth: number; start: number }[] = [];
  let pendingFn = false;
  let skipFrom: number | null = null;
  let skipDepth = 0;
  let depth = 0;
  let i = 0;
  while (i < src.length) {
    const c = src[i] ?? '';
    const d = src[i + 1] ?? '';
    if (src.startsWith('#[cfg(test)]', i)) {
      skipFrom = depth;
      i += 12;
      continue;
    }
    if (c === '/' && d === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && d === '*') {
      let n = 1;
      i += 2;
      while (i < src.length && n > 0) {
        if (src.startsWith('/*', i)) {
          n++;
          i += 2;
        } else if (src.startsWith('*/', i)) {
          n--;
          i += 2;
        } else {
          i++;
        }
      }
      continue;
    }
    const raw = /^b?r(#*)"/.exec(src.slice(i, i + 8));
    if (raw !== null && (i === 0 || !/[A-Za-z0-9_]/.test(src[i - 1] ?? ''))) {
      const hashes = raw[1] ?? '';
      const start = i + raw[0].length;
      const end = src.indexOf(`"${hashes}`, start);
      const stop = end < 0 ? src.length : end;
      if (skipFrom === null) literals.push({ text: src.slice(start, stop), line: lineAt(i), pos: i });
      i = stop + 1 + hashes.length;
      continue;
    }
    if (c === '"' || (c === 'b' && d === '"' && !/[A-Za-z0-9_]/.test(src[i - 1] ?? ''))) {
      const at = i;
      i += c === 'b' ? 2 : 1;
      let s = '';
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\') {
          s += src[i + 1] === '"' ? '"' : `\\${src[i + 1] ?? ''}`;
          i += 2;
        } else {
          s += src[i];
          i++;
        }
      }
      i++;
      if (skipFrom === null) literals.push({ text: s, line: lineAt(at), pos: at });
      continue;
    }
    if (c === "'") {
      // A char literal, or a lifetime.
      if (d === '\\') {
        const end = src.indexOf("'", i + 3);
        i = end < 0 ? src.length : end + 1;
      } else {
        const cp = src.codePointAt(i + 1) ?? 0;
        const w = cp > 0xffff ? 2 : 1;
        if (src[i + 1 + w] === "'") {
          i += 2 + w;
        } else {
          i++;
          while (/[A-Za-z0-9_]/.test(src[i] ?? '')) i++;
        }
      }
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let w = '';
      while (/[A-Za-z0-9_]/.test(src[i] ?? '')) {
        w += src[i];
        i++;
      }
      if (w === 'fn' && skipFrom === null) pendingFn = true;
      continue;
    }
    if (c === ';' && pendingFn) {
      pendingFn = false;
    }
    if (c === '{') {
      if (skipFrom !== null && skipDepth === 0) skipDepth = depth + 1;
      depth++;
      if (pendingFn) {
        openFns.push({ depth, start: i });
        pendingFn = false;
      }
    } else if (c === '}') {
      const top = openFns[openFns.length - 1];
      if (top !== undefined && top.depth === depth) {
        fns.push([top.start, i + 1]);
        openFns.pop();
      }
      if (skipFrom !== null && skipDepth === depth) {
        skipFrom = null;
        skipDepth = 0;
      }
      depth--;
    } else if (c === ';' && skipFrom !== null && skipDepth === 0 && depth === skipFrom) {
      // `#[cfg(test)]` on an item without a body, such as `use`.
      skipFrom = null;
    }
    i++;
  }
  return { literals, fns };
}

const HTML_TAG = /<[A-Za-z!/]/;

/** The text a browser would show for an HTML fragment literal. */
function htmlText(s: string): string {
  return s
    .replace(/<[^>]*>/g, ' ')
    .replace(/\{[^{}]*\}/g, ' ')
    .replace(/&[A-Za-z0-9#]+;/g, ' ');
}

/** Attribute values a browser shows or reads out. */
function htmlShownAttributes(s: string): string[] {
  const out: string[] = [];
  // A value in double quotes, escaped or not inside a Rust literal, or in
  // single quotes.
  const re =
    /\b(title|alt|placeholder|aria-label|aria-description|value)\s*=\s*(?:\\?"([^"\\]*)\\?"|'([^']*)')/g;
  for (let m = re.exec(s); m !== null; m = re.exec(s)) {
    const v = (m[2] ?? m[3] ?? '').replace(/\{[^{}]*\}/g, '');
    if (/\p{L}/u.test(v)) out.push(v);
  }
  return out;
}

/** User-visible literals of the Rust sources that render HTML. */
function rustViolations(path: string): string[] {
  const src = readFileSync(path, 'utf8');
  const { literals, fns } = rustScan(src);
  const rel = relative(ROOT, path);
  const out: string[] = [];
  const innermost = (pos: number): [number, number] | undefined =>
    fns
      .filter(([s, e]) => s <= pos && pos < e)
      .sort((x, y) => x[1] - x[0] - (y[1] - y[0]))[0];
  const renders = new Set<string>();
  for (const l of literals) {
    if (HTML_TAG.test(l.text)) {
      const f = innermost(l.pos);
      if (f !== undefined) renders.add(`${f[0]}`);
    }
  }
  for (const l of literals) {
    if (HTML_TAG.test(l.text)) {
      if (/\p{L}/u.test(htmlText(l.text))) out.push(`${rel}:${l.line}: HTML text "${l.text.slice(0, 60)}"`);
      for (const a of htmlShownAttributes(l.text)) out.push(`${rel}:${l.line}: HTML attribute "${a}"`);
      continue;
    }
    const f = innermost(l.pos);
    if (f !== undefined && renders.has(`${f[0]}`) && /\p{L}/u.test(l.text.replace(/\{[^{}]*\}/g, ''))) {
      out.push(`${rel}:${l.line}: literal in a page renderer "${l.text.slice(0, 60)}"`);
    }
  }
  return out;
}

/** User-visible text of a static HTML file. */
function htmlFileViolations(path: string): string[] {
  const src = readFileSync(path, 'utf8')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ');
  const rel = relative(ROOT, path);
  const out: string[] = [];
  const text = src.replace(/<[^>]*>/g, ' ').replace(/&[A-Za-z0-9#]+;/g, ' ');
  if (/\p{L}/u.test(text)) out.push(`${rel}: HTML text "${text.trim().slice(0, 60)}"`);
  for (const a of htmlShownAttributes(src)) out.push(`${rel}: HTML attribute "${a}"`);
  return out;
}

test.describe('R-NF-04 localisable pages', () => {
  test('r_nf_04_pages_have_no_literal_user_strings', () => {
    const problems: string[] = [];
    const web = join(ROOT, 'web', 'src');
    for (const dir of ['auth', 'vault']) {
      const ts = filesUnder(join(web, dir), '.ts');
      if (ts.length === 0) problems.push(`web/src/${dir}: no TypeScript sources to scan`);
      for (const f of ts) {
        if (isTsCatalogue(f)) continue;
        for (const l of tsLiterals(readFileSync(f, 'utf8'))) {
          if (looksLikeUserText(l.text)) {
            problems.push(`${relative(ROOT, f)}:${l.line}: literal "${l.text.trim().slice(0, 60)}"`);
          }
        }
      }
      for (const f of filesUnder(join(web, dir), '.html')) problems.push(...htmlFileViolations(f));
    }
    const catalogues = filesUnder(web, '.ts').filter(isTsCatalogue);
    if (catalogues.length === 0) problems.push('web/src: no message catalogue');

    for (const crate of ['fstp-vault', 'fstp-cell']) {
      for (const f of filesUnder(join(ROOT, 'crates', crate, 'src'), '.rs')) {
        if (!isRustCatalogue(f)) problems.push(...rustViolations(f));
      }
    }
    expect(problems).toEqual([]);
  });

  test('r_nf_04_scanner_flags_literals_and_spares_technical_tokens', () => {
    // The scanner's own teeth: a page that spells text must fail.
    const ts = tsLiterals(
      [
        "import { h } from '../core/dom';",
        "const x = 'Sign in with a passkey';",
        'const y = `Welcome ${name}, please wait`;',
        "if (e.key === 'Enter') submit();",
        "const re = /it's a regex/u;",
        "// 'In a comment'",
        "el.textContent = t('auth.login.title');",
        "const z = 'Continue';",
      ].join('\n'),
    )
      .filter((l) => looksLikeUserText(l.text))
      .map((l) => l.text.trim());
    expect(ts).toEqual(['Sign in with a passkey', 'Welcome', ', please wait', 'Continue']);

    const rs = rustScan(
      [
        '/// "Doc text"',
        'fn page(v: &str) -> String {',
        '    let label = "Account";',
        '    format!("<h1>Identity release</h1><td>{}</td>{label}", v)',
        '}',
        'fn headers() -> &\'static str { "no-store" }',
        '#[cfg(test)]',
        'mod tests { fn t() { let _ = "<p>Test text</p>"; } }',
      ].join('\n'),
    );
    expect(rs.literals.map((l) => l.text)).toEqual([
      'Account',
      '<h1>Identity release</h1><td>{}</td>{label}',
      'no-store',
    ]);
    expect(rs.fns).toHaveLength(2);
    expect(htmlText('<h1>Identity release</h1><td>{}</td>').trim()).toBe('Identity release');
    expect(htmlText('<tr><th>{}</th><td>{}</td></tr>').trim()).toBe('');
    expect(looksLikeUserText('application/json; charset=utf-8')).toBe(false);
    expect(looksLikeUserText("default-src 'none'")).toBe(false);
    expect(looksLikeUserText('auth.login.title')).toBe(false);
  });
});
