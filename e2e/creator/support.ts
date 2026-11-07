/**
 * Shared flows and checks of the creator and onboarding specs (M4 lane
 * W4a). The page contract is in `contract.ts`.
 *
 * Nothing here spells a policy value. Programme values come from the
 * SuperSAFE fixture of `fstp-programme`, which
 * `r_pg_01_supersafe_fixture_matches_policy_defaults` checks against the
 * SuperSAFE column of `policy-parameters.md`.
 */

import { expect, type Locator, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  VirtualAuthenticator,
  call,
  canonicalJson,
  confirmStepUp,
  enrolByInvite,
  okJson,
  openLink,
  pageCdp,
  stack,
  syntheticEmail,
  type CellEndpoints,
} from '../playwright.config';
import {
  API,
  APP,
  CREATOR_PATH,
  CREATOR_STEPS,
  CREATOR_UI,
  FOOTER,
  IDENTITY_UI,
  INVITATION_UI,
  M4Control,
  ONBOARDING_STEPS,
  ONBOARDING_UI,
  PEOPLE_UI,
  SIGNATORY_ROLES,
  STEPUP,
  signatoryHolder,
  signatoryRoleChoice,
  type CreatorStepName,
  type OnboardingStepName,
  type SignatoryRoleName,
} from './contract';

/** The repository root. */
export const REPO = join(__dirname, '..', '..');

// ---------------------------------------------------------------------------
// The SuperSAFE fixture
// ---------------------------------------------------------------------------

/** A JSON object. */
export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/** The SuperSAFE fixture: the spec, and the fields the shipped template leaves unset. */
export interface SuperSafe {
  /** The `fstp.programme/1` spec, which sets every field. */
  readonly spec: { readonly [step: string]: Json };
  /**
   * The field keys whose fixture value is synthetic, as `<step>.<member>`.
   * The shipped template leaves exactly these unset, so a person enters
   * them in the creator.
   */
  readonly synthetic: readonly string[];
}

function objectOf(v: unknown, what: string): { [k: string]: Json } {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new Error(`${what} must be a JSON object`);
  }
  return v as { [k: string]: Json };
}

/**
 * Reads `crates/fstp-programme/fixtures/supersafe.programme.json`. A
 * provenance key names a policy field by its parameter, such as `P-58`,
 * or an artefact field by its key. Each parameter is mapped to the one
 * field whose member starts with its lower-case id, such as
 * `p58_recipient_ceiling`.
 */
export function superSafe(): SuperSafe {
  const raw = objectOf(
    JSON.parse(readFileSync(join(REPO, 'crates', 'fstp-programme', 'fixtures', 'supersafe.programme.json'), 'utf8')),
    'the SuperSAFE fixture',
  );
  const spec = objectOf(raw['spec'], 'the fixture spec');
  const provenance = objectOf(raw['provenance'], 'the fixture provenance');
  const keys: string[] = [];
  for (const step of CREATOR_STEPS) {
    for (const member of Object.keys(objectOf(spec[step], `the fixture step ${step}`))) {
      keys.push(`${step}.${member}`);
    }
  }
  const synthetic: string[] = [];
  for (const k of Object.keys(provenance)) {
    const m = /^P-(\d{2})$/.exec(k);
    const found = m === null ? keys.filter((f) => f === k) : keys.filter((f) => f.split('.')[1]?.startsWith(`p${m[1]}_`));
    if (found.length !== 1 || found[0] === undefined) {
      throw new Error(`fixture provenance ${k} names ${found.length} fields, not one`);
    }
    synthetic.push(found[0]);
  }
  return { spec, synthetic };
}

/** The fixture value of field `key`, `<step>.<member>`. */
export function fixtureValue(f: SuperSafe, key: string): Json {
  const [step, member] = key.split('.');
  if (step === undefined || member === undefined) {
    throw new Error(`${key} is not a field key`);
  }
  const s = objectOf(f.spec[step], `fixture step ${step}`);
  const v = s[member];
  if (v === undefined) {
    throw new Error(`the fixture has no field ${key}`);
  }
  return v;
}

/** The field keys of one step, in fixture order. */
export function stepFields(f: SuperSafe, step: CreatorStepName): string[] {
  return Object.keys(objectOf(f.spec[step], `fixture step ${step}`)).map((m) => `${step}.${m}`);
}

// ---------------------------------------------------------------------------
// Draft and report reads
// ---------------------------------------------------------------------------

/** The draft as `GET /api/v1/programmes/{p}/draft` answers it. */
export interface Draft {
  readonly spec: { readonly [k: string]: Json };
  readonly revision: string;
  readonly status: string;
}

/** Reads the draft. `page` must show a page of the cell origin. */
export async function readDraft(page: Page, origin: string, p: string): Promise<Draft> {
  const body = okJson(await call(page, origin, 'GET', API.draft(p)), 'GET draft');
  const spec = objectOf(body['spec'], 'draft.spec');
  const revision = body['revision'];
  const status = body['status'];
  if (typeof revision !== 'string' || typeof status !== 'string') {
    throw new Error('GET draft: `revision` and `status` must be strings');
  }
  return { spec, revision, status };
}

/** The value of field `key` in a draft spec. A gap is `null`. */
export function draftValue(d: Draft, key: string): Json {
  const [step, member] = key.split('.');
  const s = objectOf(d.spec[step ?? ''], `draft step ${step ?? ''}`);
  const v = s[member ?? ''];
  if (v === undefined) {
    throw new Error(`the draft spec has no member ${key}; a gap must be null`);
  }
  return v;
}

/** One validation result as the report read answers it. */
export interface ReportResult {
  readonly check: string;
  readonly severity: 'failure' | 'warning';
  readonly acknowledged: boolean;
}

/** Reads the validation report of the draft. */
export async function readReport(page: Page, origin: string, p: string): Promise<ReportResult[]> {
  const body = okJson(await call(page, origin, 'GET', API.report(p)), 'GET report');
  const results = body['results'];
  if (!Array.isArray(results)) {
    throw new Error('GET report: `results` must be an array');
  }
  return results.map((r, i) => {
    const o = objectOf(r, `report result ${i}`);
    const check = o['check'];
    const severity = o['severity'];
    const acknowledged = o['acknowledged'];
    if (typeof check !== 'string' || (severity !== 'failure' && severity !== 'warning') || typeof acknowledged !== 'boolean') {
      throw new Error(`report result ${i}: expected {check, severity, acknowledged}`);
    }
    return { check, severity, acknowledged };
  });
}

/** The canonical text of a value, for equality in failure messages. */
export function canon(v: unknown): string {
  return canonicalJson(v);
}

// ---------------------------------------------------------------------------
// The field value contract
// ---------------------------------------------------------------------------

/** RFC 6901 escaping of one reference token. */
function token(k: string): string {
  return k.replace(/~/g, '~0').replace(/\//g, '~1');
}

/**
 * Sets the value of field `key` on the step page in `page`.
 *
 * The field value contract (interim, pending Daniel):
 *
 * - The field is the element `[data-field="<key>"]`.
 * - Every leaf of the value has one control inside it with `data-path`
 *   set to the leaf's JSON pointer (RFC 6901) within the field value. A
 *   scalar field's control has `data-path=""`. A `select` is chosen by
 *   option value, a checkbox holds a boolean, and any other control holds
 *   the leaf's text: a string as it is, an integer in decimal digits, an
 *   ADR-006 amount as its string. An empty text control is `null`.
 * - A list has a container `[data-path="<ptr>"][data-kind="list"]`. Its
 *   items are `[data-item="<ptr>/<i>"]`, numbered from 0 and renumbered on
 *   removal. `[data-action="add"][data-for="<ptr>"]` appends an item, and
 *   `[data-action="remove"][data-for="<ptr>/<i>"]` removes one.
 * - A set of tokens may instead be a container with `data-kind="set"`
 *   holding one checkbox per token, whose `value` is the token.
 * - An `id` member of a list item may have no control. The page then
 *   numbers items from 1 in order.
 * - Within an object, the member `kind` is set first, since it chooses
 *   which other members a tagged value has.
 */
export async function setFieldValue(page: Page, key: string, value: Json): Promise<void> {
  const group = page.locator(`[data-field="${key}"]`);
  await expect(group, `the step page shows field ${key}`).toHaveCount(1);
  await setAt(group, '', value, key);
}

/** Sets a value through the value controls inside `scope`, as `setFieldValue` does for a field. */
export async function setValueIn(scope: Locator, key: string, value: Json): Promise<void> {
  await setAt(scope, '', value, key);
}

async function setAt(scope: Locator, ptr: string, v: Json, key: string): Promise<void> {
  if (Array.isArray(v)) {
    await setList(scope, ptr, v, key);
    return;
  }
  if (v !== null && typeof v === 'object') {
    const members = Object.keys(v).sort((a, b) => (a === 'kind' ? -1 : b === 'kind' ? 1 : 0));
    for (const m of members) {
      const x = v[m];
      if (x !== undefined) {
        await setAt(scope, `${ptr}/${token(m)}`, x, key);
      }
    }
    return;
  }
  const control = scope.locator(`[data-path="${ptr}"]`);
  if ((await control.count()) === 0 && ptr.endsWith('/id')) {
    return;
  }
  await expect(control, `${key}: one control for ${ptr === '' ? 'the value' : ptr}`).toHaveCount(1);
  const shape = await control.evaluate((e) => ({
    tag: e.tagName.toLowerCase(),
    type: e instanceof HTMLInputElement ? e.type : '',
  }));
  if (shape.tag === 'select') {
    await control.selectOption(v === null ? '' : String(v));
  } else if (shape.type === 'checkbox') {
    if (typeof v !== 'boolean') {
      throw new Error(`${key}: a checkbox at ${ptr} for a non-boolean value`);
    }
    await control.setChecked(v);
  } else {
    await control.fill(v === null ? '' : String(v));
  }
}

async function setList(scope: Locator, ptr: string, items: Json[], key: string): Promise<void> {
  const container = scope.locator(`[data-path="${ptr}"]`);
  await expect(container, `${key}: one list container for ${ptr === '' ? 'the value' : ptr}`).toHaveCount(1);
  const kind = await container.getAttribute('data-kind');
  if (kind === 'set') {
    const wanted = new Set(items.map((x) => (typeof x === 'string' ? x : canon(x))));
    const boxes = container.locator('input[type="checkbox"]');
    const n = await boxes.count();
    const offered = new Set<string>();
    for (let i = 0; i < n; i++) {
      const box = boxes.nth(i);
      const value = (await box.getAttribute('value')) ?? '';
      offered.add(value);
      await box.setChecked(wanted.has(value));
    }
    for (const w of wanted) {
      expect(offered.has(w), `${key}: the set offers ${w}`).toBe(true);
    }
    return;
  }
  expect(kind, `${key}: ${ptr} is a list or a set`).toBe('list');
  const first = scope.locator(`[data-item="${ptr}/0"]`);
  for (let guard = 0; (await first.count()) > 0; guard++) {
    expect(guard, `${key}: removing the items of ${ptr} ends`).toBeLessThan(1000);
    await scope.locator(`[data-action="remove"][data-for="${ptr}/0"]`).click();
  }
  for (let i = 0; i < items.length; i++) {
    await scope.locator(`[data-action="add"][data-for="${ptr}"]`).click();
    await expect(scope.locator(`[data-item="${ptr}/${i}"]`), `${key}: item ${i} of ${ptr}`).toHaveCount(1);
    const item = items[i];
    if (item !== undefined) {
      await setAt(scope, `${ptr}/${i}`, item, key);
    }
  }
}

/** Accepts every template narrative the step page offers for acceptance. */
export async function acceptNarratives(page: Page): Promise<number> {
  const buttons = page.locator('[data-action="accept-narrative"]');
  let accepted = 0;
  for (let guard = 0; (await buttons.count()) > 0; guard++) {
    expect(guard, 'accepting narratives ends').toBeLessThan(500);
    await buttons.first().click();
    accepted++;
  }
  return accepted;
}

/** Saves the step and returns the severities of its check results. */
export async function saveStep(page: Page): Promise<{ failures: string[]; warnings: string[] }> {
  await page.locator(CREATOR_UI.stepSave).click();
  await expect(page.locator(CREATOR_UI.stepStatus)).toHaveAttribute('data-state', 'saved');
  const items = page.locator(`${CREATOR_UI.stepChecks} li[data-check]`);
  const failures: string[] = [];
  const warnings: string[] = [];
  const n = await items.count();
  for (let i = 0; i < n; i++) {
    const it = items.nth(i);
    const check = (await it.getAttribute('data-check')) ?? '';
    const severity = await it.getAttribute('data-severity');
    if (severity === 'failure') failures.push(check);
    else if (severity === 'warning') warnings.push(check);
    else throw new Error(`step check ${check}: data-severity must be failure or warning`);
  }
  return { failures, warnings };
}

/** The programme id of a creator page URL. */
export function programmeOf(page: Page): string {
  const m = CREATOR_PATH.exec(new URL(page.url()).pathname);
  if (m === null || m[1] === undefined) {
    throw new Error(`${page.url()} is not a creator page`);
  }
  return m[1];
}

// ---------------------------------------------------------------------------
// People and accounts
// ---------------------------------------------------------------------------

/** A person in a browser context of their own, with a platform authenticator. */
export interface Person {
  readonly page: Page;
  readonly email: string;
  readonly authenticator: VirtualAuthenticator;
}

/** Opens a new person: a new browser context with an authenticator. */
export async function newPerson(person: () => Promise<Page>, email: string): Promise<Person> {
  const page = await person();
  const authenticator = await VirtualAuthenticator.attach(page);
  return { page, email, authenticator };
}

/** Runs a high-risk action whose control is `trigger`: click, then complete the step-up dialog. */
export async function withStepUp(page: Page, trigger: Locator): Promise<void> {
  await trigger.click();
  await confirmStepUp(page);
}

/** Clicks `trigger`, then cancels the step-up dialog with Escape. */
export async function cancelStepUp(page: Page, trigger: Locator): Promise<void> {
  await trigger.click();
  const dialog = page.locator(STEPUP.dialog);
  await expect(dialog).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
}

/**
 * Verifies the signed-in person's identity on the identity page (J0,
 * `me.begin_verification`). The page starts the vault flow. The synthetic
 * vault then records the check, as a wallet or document check would.
 */
export async function verifyOnIdentityPage(
  p: Person,
  control: M4Control,
  origin: string,
  sameIdentityAs?: string,
): Promise<string> {
  await p.page.goto(`${origin}${APP.identity}`);
  await expect(p.page.locator(IDENTITY_UI.status)).toHaveAttribute('data-status', 'unverified');
  const started = p.page.waitForResponse(
    (r) => new URL(r.url()).pathname === API.meVerification && r.request().method() === 'POST',
  );
  await p.page.locator(IDENTITY_UI.verify).click();
  expect((await started).ok(), 'the verification starts').toBe(true);
  const account = await control.account(p.email);
  await control.verify(account, sameIdentityAs);
  await p.page.goto(`${origin}${APP.identity}`);
  await expect(p.page.locator(IDENTITY_UI.status)).toHaveAttribute('data-status', 'verified');
  return account;
}

/**
 * The invitee's side of a programme role invitation (J2): open the link,
 * accept the confidentiality terms (enrolling a passkey first), then
 * start identity verification for SoD-09 and let the synthetic vault
 * record it.
 */
export async function acceptInvitation(
  p: Person,
  control: M4Control,
  origin: string,
  sameIdentityAs?: string,
): Promise<string> {
  const mail = await control.newest(p.email, 'invitation');
  const u = new URL(mail.link);
  expect(u.pathname).toBe(APP.invitation);
  expect(u.search, 'no token in the query string').toBe('');
  expect(u.hash.length, 'the invitation token travels in the fragment').toBeGreaterThan(1);
  await openLink(p.page, mail.link);
  await expect(p.page.locator(INVITATION_UI.terms)).not.toHaveText('');
  await p.page.locator(INVITATION_UI.accept).click();
  await expect(p.page.locator(INVITATION_UI.status)).toHaveAttribute('data-status', 'accepted');
  const started = p.page.waitForResponse(
    (r) => /^\/api\/v1\/invitations\/[^/]+\/verification$/.test(new URL(r.url()).pathname) && r.request().method() === 'POST',
  );
  await p.page.locator(INVITATION_UI.verify).click();
  expect((await started).ok(), 'the verification starts').toBe(true);
  const account = await control.account(p.email);
  await control.verify(account, sameIdentityAs);
  await p.page.goto(`${origin}${APP.identity}`);
  await expect(p.page.locator(IDENTITY_UI.status)).toHaveAttribute('data-status', 'verified');
  return account;
}

/** Invites `email` as `role` on the creator's People step of programme `p`. */
export async function invite(page: Page, origin: string, p: string, email: string, role: string): Promise<Locator> {
  if (new URL(page.url()).pathname !== APP.creatorStep(p, 'people')) {
    await page.goto(`${origin}${APP.creatorStep(p, 'people')}`);
  }
  await page.locator(PEOPLE_UI.email).fill(email);
  await page.locator(PEOPLE_UI.role).selectOption(role);
  await page.locator(PEOPLE_UI.submit).click();
  const item = page.locator(`${PEOPLE_UI.invitations} li[data-invitation][data-email="${email}"]`);
  await expect(item).toHaveCount(1);
  await expect(item).toHaveAttribute('data-sod', /^(pass|fail|unchecked)$/);
  return item;
}

/** Grants the accepted invitation of `email` on the people admin page, with its own step-up. */
export async function grant(page: Page, origin: string, p: string, email: string): Promise<void> {
  await page.goto(`${origin}${APP.people(p)}`);
  const item = page.locator(`${PEOPLE_UI.invitations} li[data-invitation][data-email="${email}"]`);
  await expect(item).toHaveCount(1);
  await expect(item, 'the invitee accepted the terms and verified identity').toHaveAttribute('data-state', 'verified');
  await withStepUp(page, item.locator('[data-action="grant"]'));
  await expect(item).toHaveAttribute('data-state', 'granted');
}

// ---------------------------------------------------------------------------
// Onboarding (J0)
// ---------------------------------------------------------------------------

/**
 * Synthetic values of each onboarding step, by control `name`. The
 * Identity and Inference defaults equal what the SuperSAFE fixture holds
 * for P-45 and P-21, so the creator's prefill agrees with the fixture.
 */
export const ONBOARDING_VALUES = {
  dataProtectionContact: 'Synthetic data protection contact, e2e test tenant.',
  sendingDomain: 'mail.e2e.invalid',
  p18: ['eudi_wallet', 'document_upload'],
  p45: 'tenant_registration',
  provider: 'placeholder',
  primary: 'placeholder-model',
  p20: 'record_only',
  bankInterface: 'not_connected',
} as const;

/** Saves the open onboarding step and expects `outcome`. */
export async function saveOnboardingStep(page: Page, outcome: string): Promise<void> {
  await page.locator(ONBOARDING_UI.save).click();
  await expect(page.locator(ONBOARDING_UI.outcome)).toHaveAttribute('data-outcome', outcome);
}

/** Fills the form of one onboarding step, except Administrators, with the synthetic values. */
export async function fillOnboardingStep(page: Page, step: OnboardingStepName): Promise<void> {
  const form = page.locator(ONBOARDING_UI.form);
  await expect(form).toHaveCount(1);
  const v = ONBOARDING_VALUES;
  switch (step) {
    case 'organisation':
      await form.locator('[name="data_protection_contact"]').fill(v.dataProtectionContact);
      await form.locator('input[type="checkbox"][name="signatories"]').first().check();
      return;
    case 'agreements':
      return;
    case 'branding':
      await form.locator('input[type="radio"][name="package"][value="default"]').check();
      return;
    case 'domains_and_email':
      await form.locator('[name="sending_domain"]').fill(v.sendingDomain);
      return;
    case 'identity':
      for (const m of v.p18) await form.locator(`input[type="checkbox"][name="p18"][value="${m}"]`).check();
      await form.locator(`input[type="radio"][name="p45"][value="${v.p45}"]`).check();
      return;
    case 'inference':
      await form.locator('[name="provider"]').fill(v.provider);
      await form.locator('[name="primary"]').fill(v.primary);
      return;
    case 'payments':
      await page.locator(`${ONBOARDING_UI.p20}[value="${v.p20}"]`).check();
      await withStepUp(page, page.locator(ONBOARDING_UI.p20Save));
      await form.locator(`input[type="radio"][name="bank_interface"][value="${v.bankInterface}"]`).check();
      return;
    case 'channels':
      return;
    case 'administrators':
      return;
  }
}

/** The onboarding status of each step, as the step navigation shows it. */
export async function navStatuses(page: Page): Promise<Record<string, string>> {
  const items = page.locator(`${ONBOARDING_UI.steps} li[data-step]`);
  const out: Record<string, string> = {};
  const n = await items.count();
  for (let i = 0; i < n; i++) {
    const it = items.nth(i);
    out[(await it.getAttribute('data-step')) ?? `#${i}`] = (await it.getAttribute('data-status')) ?? '';
  }
  return out;
}

/** A tenant whose onboarding completed: two verified tenant admins in their own contexts. */
export interface Tenant {
  readonly cell: CellEndpoints;
  readonly control: M4Control;
  readonly a1: Person;
  readonly a2: Person;
  readonly a1Account: string;
  readonly a2Account: string;
}

/** Enrols the first admin A1 from the reset cell's one-time link, and verifies A1's identity. */
export async function firstAdmin(
  person: () => Promise<Page>,
  control: M4Control,
): Promise<{ a1: Person; a1Account: string }> {
  const fresh = await control.reset();
  const a1 = await newPerson(person, fresh.email);
  await enrolByInvite(a1.page, control.cell.origin, fresh.url);
  const a1Account = await verifyOnIdentityPage(a1, control, control.cell.origin);
  return { a1, a1Account };
}

/**
 * Walks steps Organisation to Channels for A1, each validated before the
 * next opens (R-TN-01).
 */
export async function walkStepsBeforeAdministrators(page: Page, origin: string): Promise<void> {
  for (const step of ONBOARDING_STEPS) {
    if (step === 'administrators') return;
    await page.goto(`${origin}${APP.onboarding(step)}`);
    await fillOnboardingStep(page, step);
    await saveOnboardingStep(page, 'validated');
    await expect(page.locator(ONBOARDING_UI.next)).toHaveCount(1);
  }
}

/**
 * A1 invites A2 as tenant admin with step-up. A2 enrols through the M3
 * invitation link and verifies identity. Returns A2.
 */
export async function inviteSecondAdmin(
  person: () => Promise<Page>,
  control: M4Control,
  a1: Person,
  sameIdentityAs?: string,
): Promise<{ a2: Person; a2Account: string }> {
  const origin = control.cell.origin;
  const email = syntheticEmail('a2');
  await a1.page.goto(`${origin}${APP.onboarding('administrators')}`);
  await a1.page.locator(ONBOARDING_UI.adminInviteEmail).fill(email);
  await withStepUp(a1.page, a1.page.locator(ONBOARDING_UI.adminInviteSubmit));
  const a2 = await newPerson(person, email);
  await enrolByInvite(a2.page, origin, (await control.newest(email, 'admin_invitation')).link);
  const a2Account = await verifyOnIdentityPage(a2, control, origin, sameIdentityAs);
  return { a2, a2Account };
}

/**
 * `granter` grants signatory role `role` to `account` on the
 * Administrators step, with its own step-up (I-78), and sees the new
 * holder listed. A grant to one's own account is refused (SoD-07, NOTE 5),
 * so `granter` is a tenant admin other than `account`.
 */
export async function grantSignatory(
  granter: Person,
  origin: string,
  account: string,
  role: SignatoryRoleName,
): Promise<void> {
  const page = granter.page;
  await page.goto(`${origin}${APP.onboarding('administrators')}`);
  await expect(page.locator(ONBOARDING_UI.signatories)).toBeVisible();
  await page.locator(ONBOARDING_UI.signatoryAccount).selectOption(account);
  await page.locator(signatoryRoleChoice(role)).check();
  await withStepUp(page, page.locator(ONBOARDING_UI.signatoryGrant));
  await expect(page.locator(signatoryHolder(role, account))).toHaveCount(1);
}

/**
 * `granter` grants Financial signatory and Legal signatory to `account`,
 * so the Administrators step can validate (SoD-14, SoD-15). One account
 * may hold both (SoD-16).
 */
export async function grantSignatories(granter: Person, origin: string, account: string): Promise<void> {
  for (const role of SIGNATORY_ROLES) await grantSignatory(granter, origin, account, role);
}

/**
 * Activates the organisation on the summary page once onboarding is
 * complete: `requester` requests activation and `approver`, a different
 * tenant admin, approves it (SoD-18).
 */
export async function activateOrganisation(requester: Person, approver: Person, origin: string): Promise<void> {
  const state = (p: Person): Locator => p.page.locator(ONBOARDING_UI.activationState);
  await requester.page.goto(`${origin}${APP.onboardingSummary}`);
  await expect(state(requester)).toHaveAttribute('data-state', 'not_requested');
  await requester.page.locator(ONBOARDING_UI.activationRequest).click();
  await expect(state(requester)).toHaveAttribute('data-state', 'requested');
  await approver.page.goto(`${origin}${APP.onboardingSummary}`);
  await expect(state(approver)).toHaveAttribute('data-state', 'requested');
  await approver.page.locator(ONBOARDING_UI.activationApprove).click();
  await expect(state(approver)).toHaveAttribute('data-state', 'active');
}

/** Saves the Administrators step and completes onboarding on the summary page. */
export async function completeOnboarding(page: Page, origin: string): Promise<void> {
  await page.goto(`${origin}${APP.onboarding('administrators')}`);
  await expect(page.locator(`${ONBOARDING_UI.admins} li[data-account]`)).toHaveCount(2);
  await saveOnboardingStep(page, 'validated');
  await page.goto(`${origin}${APP.onboardingSummary}`);
  await page.locator(ONBOARDING_UI.complete).click();
  await expect(page.locator(ONBOARDING_UI.completeOutcome)).toHaveAttribute('data-outcome', 'completed');
}

/**
 * J0 through the pages: a fresh cell with a tenant whose onboarding
 * completed and whose organisation is active. A2 grants both signatory
 * roles to A1 (SoD-07, SoD-14, SoD-15). A1 requests activation and A2
 * approves it (SoD-18).
 */
export async function onboardedTenant(
  person: () => Promise<Page>,
  control: M4Control,
  opts: { readonly a2SameIdentityAsA1?: boolean } = {},
): Promise<Tenant> {
  const origin = control.cell.origin;
  const { a1, a1Account } = await firstAdmin(person, control);
  await walkStepsBeforeAdministrators(a1.page, origin);
  const { a2, a2Account } = await inviteSecondAdmin(
    person,
    control,
    a1,
    opts.a2SameIdentityAsA1 === true ? a1Account : undefined,
  );
  await grantSignatories(a2, origin, a1Account);
  await completeOnboarding(a1.page, origin);
  await activateOrganisation(a1, a2, origin);
  return { cell: control.cell, control, a1, a2, a1Account, a2Account };
}

/** The e2e cell `a` and its control client. */
export function cellA(request: ConstructorParameters<typeof M4Control>[0]): M4Control {
  return new M4Control(request, stack().cells.a);
}

// ---------------------------------------------------------------------------
// Creator flows (J1)
// ---------------------------------------------------------------------------

/** A1 opens a draft with step-up. Returns the programme id from the start page. */
export async function openDraft(a1: Person, origin: string): Promise<string> {
  await a1.page.goto(`${origin}${APP.creatorNew}`);
  await withStepUp(a1.page, a1.page.locator(CREATOR_UI.open));
  await expect(a1.page).toHaveURL((u) => u.origin === origin && /\/creator\/start$/.test(u.pathname));
  return programmeOf(a1.page);
}

/**
 * A1 invites M1 as programme manager on the draft. M1 accepts and
 * verifies. A1 grants the role with its own step-up (J1, J2).
 */
export async function addProgrammeManager(
  person: () => Promise<Page>,
  t: Tenant,
  p: string,
  sameIdentityAs?: string,
): Promise<{ m1: Person; m1Account: string }> {
  const origin = t.cell.origin;
  const m1 = await newPerson(person, syntheticEmail('m1'));
  await invite(t.a1.page, origin, p, m1.email, 'programme_manager');
  const m1Account = await acceptInvitation(m1, t.control, origin, sameIdentityAs);
  await grant(t.a1.page, origin, p, m1.email);
  return { m1, m1Account };
}

/** M1 applies the shipped SuperSAFE template on the starting point page. */
export async function applySuperSafeTemplate(m1: Person, origin: string, p: string): Promise<void> {
  await m1.page.goto(`${origin}${APP.creatorStart(p)}`);
  await m1.page.locator('[data-start="template"][data-template="1"]').click();
  await expect(m1.page).toHaveURL((u) => u.pathname === APP.creatorStep(p, 'funder'));
}

/**
 * Moves the test clock of the cell at `origin` past one H-07 window
 * (`rate.rs`, `DRY_RUN_VAULT_PER_ACCOUNT`, interim: 30 vault reads per
 * account per minute). The test clock moves only on request, so without
 * this a walk of every step reads the report more than 30 times in one
 * instant. No assertion depends on the instant.
 */
async function nextMinute(page: Page, origin: string): Promise<void> {
  const cell = Object.values(stack().cells).find((c) => c.origin === origin);
  if (cell === undefined) throw new Error(`no cell of the stack serves ${origin}`);
  const r = await page.request.post(`${cell.control}/test/clock/advance`, { data: { micros: String(61_000_000) } });
  expect(r.ok(), `the test clock advances: ${r.status()}`).toBe(true);
}

/**
 * M1 walks steps 1 to 10. On each step M1 accepts the template narrative,
 * enters every synthetic field from the fixture, saves, and expects no
 * failure among the step's checks. Returns the warnings seen per step.
 */
export async function walkCreatorSteps(
  m1: Person,
  origin: string,
  p: string,
  f: SuperSafe,
  onStep?: (step: CreatorStepName) => Promise<void>,
): Promise<Record<string, string[]>> {
  const warnings: Record<string, string[]> = {};
  for (const step of CREATOR_STEPS) {
    await nextMinute(m1.page, origin);
    await m1.page.goto(`${origin}${APP.creatorStep(p, step)}`);
    // The step renders its fields and narratives after the draft read, so
    // the walk waits for it before it counts the narratives to accept.
    await expect(m1.page.locator('main[data-ready="true"]')).toBeVisible();
    await acceptNarratives(m1.page);
    for (const key of stepFields(f, step)) {
      if (f.synthetic.includes(key)) {
        await setFieldValue(m1.page, key, fixtureValue(f, key));
      }
    }
    if (onStep !== undefined) {
      await onStep(step);
    }
    const r = await saveStep(m1.page);
    expect(r.failures, `step ${step}: no failing check after entering the fixture values`).toEqual([]);
    warnings[step] = r.warnings;
  }
  return warnings;
}

/**
 * The review page: acknowledges every warning, checks the previews and
 * requests activation. Returns the acknowledged warning checks.
 */
export async function reviewAndRequest(m1: Person, origin: string, p: string): Promise<string[]> {
  const page = m1.page;
  await nextMinute(page, origin);
  await page.goto(`${origin}${APP.creatorStep(p, 'review')}`);
  const report = page.locator(CREATOR_UI.report);
  await expect(report).toBeVisible();
  await expect(report.locator('li[data-check][data-severity="failure"]'), 'the report shows no failure').toHaveCount(0);
  const acked: string[] = [];
  const pending = report.locator('li[data-severity="warning"][data-acknowledged="false"]');
  for (let guard = 0; (await pending.count()) > 0; guard++) {
    expect(guard, 'acknowledging warnings ends').toBeLessThan(200);
    const it = pending.first();
    acked.push((await it.getAttribute('data-check')) ?? '');
    await it.locator('[data-action="acknowledge"]').click();
  }
  for (const id of [CREATOR_UI.previewGuide, CREATOR_UI.previewPublic, CREATOR_UI.previewContract]) {
    await expect(page.locator(id), `${id} renders`).not.toHaveText('');
  }
  await expect(page.locator(CREATOR_UI.previewGuide)).toContainText('SuperSAFE');
  await expect(page.locator(CREATOR_UI.requestActivation)).toBeEnabled();
  await page.locator(CREATOR_UI.requestActivation).click();
  await expect(page.locator(CREATOR_UI.activationStatus)).toHaveAttribute('data-status', 'requested');
  return acked;
}

// ---------------------------------------------------------------------------
// Accessibility and the footer (R-NF-03, R-WL-04, I-69)
// ---------------------------------------------------------------------------

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
}

/** Page structure and accessible names, as Chromium computes them. */
export async function structureProblems(page: Page, label: string): Promise<string[]> {
  const problems: string[] = [];
  const doc = await page.evaluate(() => ({
    lang: document.documentElement.lang,
    title: document.title.trim(),
    mains: document.querySelectorAll('main, [role="main"]').length,
    h1: document.querySelectorAll('h1').length,
    positiveTabindex: Array.from(document.querySelectorAll('[tabindex]')).filter(
      (e) => Number(e.getAttribute('tabindex')) > 0,
    ).length,
    unlabelledFields: Array.from(document.querySelectorAll('input:not([type="hidden"]), select, textarea')).filter(
      (e) => e instanceof HTMLElement && e.closest('[hidden]') === null && (e as HTMLInputElement).labels?.length === 0 &&
        !e.hasAttribute('aria-labelledby'),
    ).length,
  }));
  if (doc.lang === '') problems.push(`${label}: no document language`);
  if (doc.title === '') problems.push(`${label}: no title`);
  if (doc.mains !== 1) problems.push(`${label}: ${doc.mains} main landmarks, not 1`);
  if (doc.h1 < 1) problems.push(`${label}: no h1`);
  if (doc.positiveTabindex > 0) problems.push(`${label}: positive tabindex`);
  if (doc.unlabelledFields > 0) problems.push(`${label}: ${doc.unlabelledFields} form controls without a label element`);
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

/**
 * Text colour pairs that miss the AA ratio, in the current colour scheme:
 * 4.5:1, or 3:1 for large text. Colours are resolved by the browser's
 * canvas, so any CSS colour syntax works.
 */
export async function contrastProblems(page: Page, label: string): Promise<string[]> {
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
    const lum = (c: number[]): number => 0.2126 * lin(c[0] ?? 0) + 0.7152 * lin(c[1] ?? 0) + 0.0722 * lin(c[2] ?? 0);
    const out: string[] = [];
    for (const el of Array.from(document.body.querySelectorAll<HTMLElement>('*'))) {
      const own = Array.from(el.childNodes).some((n) => n.nodeType === Node.TEXT_NODE && (n.textContent ?? '').trim() !== '');
      if (!own || el.getClientRects().length === 0) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility !== 'visible' || el.closest(':disabled') !== null) continue;
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
      const need = size >= 24 || (bold && size >= 18.66) ? 3 : 4.5;
      if (ratio < need) {
        out.push(`${el.tagName} "${(el.textContent ?? '').trim().slice(0, 40)}" ratio ${ratio.toFixed(2)} < ${need}`);
      }
    }
    return out;
  });
  return found.map((x) => `${label}: ${x}`);
}

/** Contrast problems in both colour schemes. */
export async function contrastBothThemes(page: Page, label: string): Promise<string[]> {
  const out: string[] = [];
  for (const colorScheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme });
    out.push(...(await contrastProblems(page, `${label} (${colorScheme})`)));
  }
  await page.emulateMedia({ colorScheme: null });
  return out;
}

/** Missing mandatory footer elements (R-WL-04, P-68, I-69 seam). */
export async function footerProblems(page: Page, label: string, tenantAdmin: boolean): Promise<string[]> {
  const keys: string[] = [...FOOTER.everyPage, ...(tenantAdmin ? FOOTER.tenantAdmin : [])];
  const problems: string[] = [];
  const footers = page.locator('footer');
  if ((await footers.count()) !== 1) {
    return [`${label}: ${await footers.count()} footer elements, not 1`];
  }
  for (const k of keys) {
    const el = footers.locator(`[data-mandatory="${k}"]`);
    if ((await el.count()) !== 1) {
      problems.push(`${label}: footer element ${k} is missing`);
    } else if (!(await el.isVisible()) || (await el.innerText()).trim() === '') {
      problems.push(`${label}: footer element ${k} is not visible text`);
    }
  }
  return problems;
}

/** Every page check of this lane: structure, names, contrast in both themes, the footer. */
export async function pageProblems(page: Page, label: string, tenantAdmin: boolean): Promise<string[]> {
  return [
    ...(await structureProblems(page, label)),
    ...(await contrastBothThemes(page, label)),
    ...(await footerProblems(page, label, tenantAdmin)),
  ];
}

/** Presses Tab until `selector` has focus, and checks that the focus is visible there. */
export async function tabTo(page: Page, selector: string, max = 80): Promise<void> {
  // A page renders after its reads, so the target must exist before Tab can reach it.
  await page.locator(selector).first().waitFor({ state: 'attached' });
  for (let i = 0; i < max; i++) {
    const at = await page.evaluate((s) => {
      const a = document.activeElement;
      if (!(a instanceof HTMLElement) || !a.matches(s)) return null;
      const cs = getComputedStyle(a);
      return (cs.outlineStyle !== 'none' && cs.outlineWidth !== '0px') || cs.boxShadow !== 'none';
    }, selector);
    if (at !== null) {
      expect(at, `focus is visible on ${selector}`).toBe(true);
      return;
    }
    await page.keyboard.press('Tab');
  }
  throw new Error(`${selector} is not reachable by Tab within ${max} presses`);
}
