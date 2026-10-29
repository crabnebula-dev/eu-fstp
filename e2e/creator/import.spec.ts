/**
 * I-65 in the browser: every value proposed by document import is
 * confirmed or edited by a named programme manager before it takes
 * effect (design sections 2.2 J1, 3.3 and 8.2 `creator/import`).
 *
 * The annex `fixtures/synthetic-annex.md` is synthetic and untrusted. It
 * carries instruction-like text and markup that must stay data. The e2e
 * cell's `FakeProposer` proposes values for it (contract in
 * `contract.ts`, `M4Control`). There is no bulk accept (Q30): each value
 * is resolved one by one, and an unresolved proposal fails validation.
 *
 * Red until the pages of lane W4a, the import bridge of lane W2b and
 * `fstp-e2e-cell` of lane W5 exist.
 */

import { expect, type Locator, type Page } from '@playwright/test';
import { join } from 'node:path';
import { test } from '../playwright.config';
import { APP, CREATOR_UI, IMPORT_UI } from './contract';
import {
  addProgrammeManager,
  canon,
  cellA,
  draftValue,
  onboardedTenant,
  openDraft,
  readDraft,
  readReport,
  setValueIn,
  type Draft,
  type Json,
  type Person,
  type Tenant,
} from './support';

test.describe.configure({ timeout: 600_000 });

const ANNEX = join(__dirname, 'fixtures', 'synthetic-annex.md');

/** One proposal as the import review page shows it. */
interface Shown {
  readonly item: Locator;
  readonly field: string;
  readonly value: Json;
  readonly flagged: boolean;
}

/** Every field key of a draft spec, `<step>.<member>`. */
function keysOf(d: Draft): string[] {
  const out: string[] = [];
  for (const [step, v] of Object.entries(d.spec)) {
    if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
      for (const m of Object.keys(v)) out.push(`${step}.${m}`);
    }
  }
  return out.sort();
}

/** The field keys whose values differ between two drafts. */
function changed(a: Draft, b: Draft): string[] {
  return keysOf(b).filter((k) => canon(draftValue(a, k)) !== canon(draftValue(b, k)));
}

/** Uploads the annex on the starting point page and waits for the review page. */
async function upload(m1: Person, origin: string, p: string): Promise<void> {
  await m1.page.goto(`${origin}${APP.creatorStart(p)}`);
  await m1.page.locator('[data-start="import"]').click();
  await m1.page.locator(CREATOR_UI.importFile).setInputFiles(ANNEX);
  await m1.page.locator(CREATOR_UI.importUpload).click();
  await expect(m1.page).toHaveURL((u) => u.pathname === APP.creatorImports(p));
  await expect(m1.page.locator(`${IMPORT_UI.proposals} ${IMPORT_UI.item}`).first()).toBeVisible();
}

/** The proposals the review page shows, unresolved ones first in page order. */
async function proposals(page: Page): Promise<Shown[]> {
  const items = page.locator(`${IMPORT_UI.proposals} ${IMPORT_UI.item}`);
  const out: Shown[] = [];
  const n = await items.count();
  for (let i = 0; i < n; i++) {
    const item = items.nth(i);
    const field = await item.getAttribute('data-field');
    const json = await item.locator('[data-role="value"]').getAttribute('data-json');
    if (field === null || json === null) {
      throw new Error(`proposal ${i}: data-field and the value's data-json are required`);
    }
    await expect(item.locator('[data-role="evidence"]'), `proposal ${i} shows its evidence`).not.toHaveText('');
    out.push({ item, field, value: JSON.parse(json) as Json, flagged: (await item.getAttribute('data-flagged')) === 'true' });
  }
  return out;
}

/** A tenant, a draft and M1, then the annex uploaded. Returns the draft before the upload too. */
async function imported(
  person: () => Promise<Page>,
  request: Parameters<typeof cellA>[0],
): Promise<{ t: Tenant; p: string; m1: Person; before: Draft; shown: Shown[] }> {
  const t = await onboardedTenant(person, cellA(request));
  const origin = t.cell.origin;
  const p = await openDraft(t.a1, origin);
  const { m1 } = await addProgrammeManager(person, t, p);
  const before = await readDraft(m1.page, origin, p);
  await upload(m1, origin, p);
  const shown = await proposals(m1.page);
  return { t, p, m1, before, shown };
}

test.describe('I-65 document import', () => {
  /**
   * I-65: no proposal changes the draft until M1 resolves it. A confirm
   * applies exactly the shown value to exactly its field, an edit applies
   * exactly the edited value, and a dismiss applies nothing. Unresolved
   * proposals fail validation (Q30, interim).
   */
  test('i65_each_imported_value_takes_effect_only_after_a_named_pm_resolves_it', async ({ person, request }) => {
    const { t, p, m1, before, shown } = await imported(person, request);
    const origin = t.cell.origin;
    const page = m1.page;
    let last = await readDraft(page, origin, p);
    expect(changed(before, last), 'the upload alone changes no field').toEqual([]);
    expect((await readReport(page, origin, p)).filter((r) => r.severity === 'failure').map((r) => r.check)).toContain(
      'ImportUnresolved',
    );

    const plain = shown.filter((s) => !s.flagged && typeof s.value === 'string');
    expect(plain.length, 'the fake proposer offers at least two unflagged text values').toBeGreaterThanOrEqual(2);
    const [confirmIt, editIt] = plain as [Shown, Shown];

    await confirmIt.item.locator('[data-action="confirm"]').click();
    await expect(confirmIt.item).toHaveAttribute('data-resolution', 'confirmed');
    let now = await readDraft(page, origin, p);
    expect(changed(last, now)).toEqual([confirmIt.field]);
    expect(draftValue(now, confirmIt.field)).toEqual(confirmIt.value);
    last = now;

    const edited = `${String(editIt.value)} (edited)`;
    await editIt.item.locator('[data-action="edit"]').click();
    await setValueIn(editIt.item, editIt.field, edited);
    await editIt.item.locator('[data-action="save-edit"]').click();
    await expect(editIt.item).toHaveAttribute('data-resolution', 'edited');
    now = await readDraft(page, origin, p);
    expect(changed(last, now)).toEqual([editIt.field]);
    expect(draftValue(now, editIt.field)).toBe(edited);
    last = now;

    for (const s of shown) {
      if ((await s.item.getAttribute('data-resolution')) !== null) continue;
      await s.item.locator('[data-action="dismiss"]').click();
      await expect(s.item).toHaveAttribute('data-resolution', 'dismissed');
    }
    now = await readDraft(page, origin, p);
    expect(changed(last, now), 'a dismissal applies nothing').toEqual([]);
    expect((await readReport(page, origin, p)).map((r) => r.check)).not.toContain('ImportUnresolved');
  });

  /**
   * I-65 and `programme-creator.md`: a proposal that conflicts with the
   * funder profile (P-05 above the P-58 ceiling, L-10) is flagged, never
   * adjusted. Confirming it needs an explicit acknowledgement, and then
   * the value is exactly the proposed one.
   */
  test('i65_profile_conflict_is_flagged_and_needs_explicit_acknowledgement', async ({ person, request }) => {
    const { t, p, m1, shown } = await imported(person, request);
    const origin = t.cell.origin;
    const page = m1.page;
    const cap = shown.find((s) => s.field === 'money.p05_recipient_cap');
    if (cap === undefined) throw new Error('the fake proposer must propose money.p05_recipient_cap');
    expect(cap.flagged, 'the cap above the ceiling is flagged').toBe(true);
    const ack = cap.item.locator('input[type="checkbox"][data-role="conflict-ack"]');
    await expect(ack).toHaveCount(1);
    const before = draftValue(await readDraft(page, origin, p), cap.field);

    await ack.setChecked(false);
    await cap.item.locator('[data-action="confirm"]').click();
    await expect(page.getByRole('alert').first()).toBeVisible();
    expect(await cap.item.getAttribute('data-resolution')).toBeNull();
    expect(draftValue(await readDraft(page, origin, p), cap.field)).toEqual(before);

    await ack.setChecked(true);
    await cap.item.locator('[data-action="confirm"]').click();
    await expect(cap.item).toHaveAttribute('data-resolution', 'confirmed');
    expect(draftValue(await readDraft(page, origin, p), cap.field), 'flagged, never adjusted').toEqual(cap.value);
  });

  /**
   * I-65 with `04-llm-assessment/assessment.md`: the annex is untrusted
   * data. Its instructions change no value, and its markup never runs or
   * renders.
   */
  test('i65_injected_annex_changes_no_value_without_confirmation', async ({ person, request }) => {
    const { t, p, m1, before, shown } = await imported(person, request);
    const origin = t.cell.origin;
    const page = m1.page;
    expect(changed(before, await readDraft(page, origin, p))).toEqual([]);
    for (const s of shown) {
      expect(await s.item.getAttribute('data-resolution'), `${s.field} stays unresolved`).toBeNull();
    }
    expect(await page.evaluate(() => (window as unknown as Record<string, unknown>)['__fstpImportXss'])).toBeUndefined();
    await expect(page.locator(`${IMPORT_UI.proposals} img, ${IMPORT_UI.proposals} script`)).toHaveCount(0);
    await expect(page.locator(`${IMPORT_UI.proposals} a[href^="javascript:"]`)).toHaveCount(0);

    await page.reload();
    for (const s of await proposals(page)) {
      expect(await s.item.getAttribute('data-resolution')).toBeNull();
    }
    expect(changed(before, await readDraft(page, origin, p))).toEqual([]);
  });

  /** I-65 with Q30 (interim): the review page offers no action that resolves more than one proposal. */
  test('i65_import_review_offers_no_bulk_resolution', async ({ person, request }) => {
    const { m1, shown } = await imported(person, request);
    expect(shown.length).toBeGreaterThan(0);
    const stray = await m1.page.evaluate(() =>
      Array.from(document.querySelectorAll('[data-action]'))
        .filter((e) => {
          const a = e.getAttribute('data-action') ?? '';
          const resolving = ['confirm', 'edit', 'save-edit', 'dismiss'].includes(a);
          return (resolving && e.closest('li[data-proposal]') === null) || /all|bulk/i.test(a);
        })
        .map((e) => e.getAttribute('data-action')),
    );
    expect(stray).toEqual([]);
    for (const s of shown) {
      await expect(s.item.locator('[data-action="confirm"]')).toHaveCount(1);
    }
  });
});
