/**
 * The page contract, the e2e cell contract and the shared helpers of the
 * applicant specs (M4 design sections 2.2 J4, 3.9, 8.7 and 13 row W4b,
 * ADR-014).
 *
 * This file is not a spec. Playwright collects `*.spec.ts` files only.
 *
 * # Page contract (lane W4b, `web/src/calls` and `web/src/applicant`)
 *
 * Every `/app/` path serves the one shell (`fstp-web`), and the client
 * router mounts the page. [`APP`] lists the applicant paths and [`AUI`]
 * the element ids the specs drive. Interim, pending the W4b implementer
 * and the lead: these ids and paths are the test author's reading of
 * journey J4. A page may add elements, but each id here keeps its role.
 *
 * - A proposal page shows its state in `#proposal-state`, whose
 *   `data-state` attribute holds the state's spec name, such as `DRAFT`
 *   or `NOT_SELECTED` (`SPEC/02-domain/state-machine.md`).
 * - An action the state does not allow has no control on the page. It is
 *   absent, never only disabled (design section 8.7, `roles/<role>`).
 * - A refusal shows an element with `role="alert"` (as in M3).
 * - A save shows its outcome in a status element. `data-status="saved"`
 *   marks a save the server accepted.
 * - Amounts are ADR-006 strings, shown and sent byte for byte. The
 *   browser never computes money (design section 3.9).
 * - Free text is set through `textContent` only (ADR-014 "DOM").
 * - Q24 (interim, pending Daniel): no proposal attachments in M4, so no
 *   applicant page has a file input.
 *
 * # E2e cell contract (lanes W3b and W5, `fstp-e2e-cell`)
 *
 * The specs reach the cell through the stack manifest of
 * `e2e/playwright.config.ts` (`FSTP_E2E_STACK`), cell `a`. Interim,
 * pending the lead: `fstp-e2e-cell` writes that manifest and serves the
 * M3 devstack control routes the config names (`/test/reset`,
 * `/test/mailbox`, `/test/clock/advance`, `/test/account`). It adds one
 * route, [`ApplicantControl.scenario`], which seeds a proposal in a given
 * state through production commands. Without a manifest every spec here
 * fails at its first step with [`StackMissing`]. No spec is skipped.
 */

import { expect, type APIRequestContext, type Page, type Request, type Response } from '@playwright/test';
import {
  Control,
  StackMissing,
  VirtualAuthenticator,
  enrolByInvite,
  pageCdp,
  signUp,
  stack,
  syntheticEmail,
  type CellEndpoints,
} from '../playwright.config';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** The applicant pages on the cell origin (`web/src/{calls,applicant}`). */
export const APP = {
  /** Open calls (`calls.list_open`). */
  calls: '/app/calls',
  /** One call (`calls.get`), with the button that starts a proposal. */
  call: (call: string): string => `/app/calls/${call}`,
  /** The call's Guide for Applicants (`calls.guide`). */
  guide: (call: string): string => `/app/calls/${call}/guide`,
  /** The caller's own proposals (`proposal.list_own`). */
  proposals: '/app/proposals',
  /** One proposal (`proposal.view`): state, withdrawal, copy request. */
  proposal: (p: string): string => `/app/proposals/${p}`,
  /** The private workspace with autosave (`proposal.save_workspace`). */
  workspace: (p: string): string => `/app/proposals/${p}/workspace`,
  /** The plan editor (`proposal.record_plan`). */
  plan: (p: string): string => `/app/proposals/${p}/plan`,
  /** Country and declared affiliations, to the vault only. */
  eligibility: (p: string): string => `/app/proposals/${p}/eligibility`,
  /** The data protection notice, the ethics declaration and submission. */
  submit: (p: string): string => `/app/proposals/${p}/submit`,
  /** Stage 2 questions, answers and the revised plan. */
  stage2: (p: string): string => `/app/proposals/${p}/stage2`,
  /** The negotiation landing (`negotiation.view`). */
  negotiation: (p: string): string => `/app/proposals/${p}/negotiation`,
  /** The guardian page (`guardian.begin_consent`). */
  guardian: (p: string): string => `/app/proposals/${p}/guardian`,
  /** The team: invite members in DRAFT, add a guardian (`proposal.add_member`, `proposal.add_guardian`). */
  team: (p: string): string => `/app/proposals/${p}/team`,
  /** The caller's notices (`me.notices`). */
  notices: '/app/notices',
} as const;

/**
 * The web routes the applicant pages call, from the registry
 * (`web/src/gen/api.ts`, lane W3a). The specs watch these requests.
 */
export const API = {
  listOpen: '/api/v1/calls',
  call: (c: string): string => `/api/v1/calls/${c}`,
  create: (c: string): string => `/api/v1/calls/${c}/proposals`,
  listOwn: '/api/v1/me/proposals',
  view: (p: string): string => `/api/v1/proposals/${p}`,
  workspace: (p: string): string => `/api/v1/proposals/${p}/workspace`,
  plan: (p: string): string => `/api/v1/proposals/${p}/plan`,
  team: (p: string): string => `/api/v1/proposals/${p}/team`,
  guardian: (p: string): string => `/api/v1/proposals/${p}/guardian`,
  country: (p: string): string => `/api/v1/proposals/${p}/vault/country`,
  affiliations: (p: string): string => `/api/v1/proposals/${p}/vault/affiliations`,
  submission: (p: string): string => `/api/v1/proposals/${p}/submission`,
  copy: (p: string): string => `/api/v1/proposals/${p}/copy`,
  withdrawal: (p: string): string => `/api/v1/proposals/${p}/withdrawal`,
  stage2: (p: string): string => `/api/v1/proposals/${p}/stage2`,
  stage2Answers: (p: string): string => `/api/v1/proposals/${p}/stage2/answers`,
  stage2Revision: (p: string): string => `/api/v1/proposals/${p}/stage2/revision`,
  guardianConsent: (p: string): string => `/api/v1/proposals/${p}/guardian/consent`,
  negotiation: (p: string): string => `/api/v1/proposals/${p}/negotiation`,
  negotiationNotice: (p: string): string => `/api/v1/proposals/${p}/negotiation/notice`,
  notices: '/api/v1/me/notices',
} as const;

/** The element ids of the page contract. */
export const AUI = {
  calls: { list: '#calls-list' },
  call: {
    title: '#call-title',
    /** Holds a `time[datetime]` with the RFC 3339 instant, and the zone name. */
    deadline: '#call-deadline',
    amounts: '#call-amounts',
    aiDisclosure: '#call-ai-disclosure',
    guideLink: '#call-guide-link',
    start: '#proposal-start',
  },
  guide: { body: '#guide' },
  proposals: { list: '#proposals-list' },
  proposal: {
    title: '#proposal-title',
    state: '#proposal-state',
    withdraw: '#proposal-withdraw',
    withdrawDialog: '#withdraw-dialog',
    withdrawConfirm: '#withdraw-confirm',
    withdrawCancel: '#withdraw-cancel',
    copyEmail: '#copy-email',
    copyRequest: '#copy-request',
    copyStatus: '#copy-status',
  },
  workspace: {
    title: '#ws-title',
    /** The neutral summary, length-limited (Q9 interim A). */
    summary: '#ws-summary',
    narrative: '#ws-narrative',
    status: '#ws-status',
  },
  plan: {
    /** The first milestone of the first task: its amount, start day and due day. */
    amount: '#plan-t1-m1-amount',
    start: '#plan-t1-m1-start',
    due: '#plan-t1-m1-due',
    /** The fields of milestone `m` of task `t`, numbered from 1 in the order added. */
    milestone: (t: number, m: number): { amount: string; start: string; due: string } => ({
      amount: `#plan-t${t}-m${m}-amount`,
      start: `#plan-t${t}-m${m}-start`,
      due: `#plan-t${t}-m${m}-due`,
    }),
    addTask: '#plan-add-task',
    addMilestone: (t: number): string => `#plan-t${t}-add-milestone`,
    description: '#plan-description',
    save: '#plan-save',
    status: '#plan-status',
    /** The error summary, `role="alert"`, with a link to each field. */
    errors: '#plan-errors',
  },
  eligibility: {
    country: '#elig-country',
    countrySave: '#elig-country-save',
    affiliations: '#elig-affiliations',
    affiliationsSave: '#elig-affiliations-save',
    status: '#elig-status',
  },
  submit: {
    /** The notice; `data-notice-version` names the version shown. */
    notice: '#submit-notice',
    noticeRead: '#submit-notice-read',
    /** The ethics `fieldset`. Its `aria-describedby` names the group's error. */
    ethics: '#submit-ethics',
    /** The first radio of the ethics group: "no ethics issue". */
    ethicsNone: '#ethics-none',
    ethicsDeclared: '#ethics-declared',
    ethicsDetails: '#ethics-details',
    confirm: '#submit-confirm',
    /** The error summary, `role="alert"`, with a link to each field. */
    errors: '#submit-errors',
  },
  stage2: {
    /** One `li` per question, each with `data-handle` and a `time[datetime]`. */
    questions: '#stage2-questions',
    answer: '#stage2-answer',
    answerSend: '#stage2-answer-send',
    /** The revised plan: the first milestone of the first task, and the work plan text. */
    planAmount: '#stage2-plan-t1-m1-amount',
    planStart: '#stage2-plan-t1-m1-start',
    planDue: '#stage2-plan-t1-m1-due',
    planDescription: '#stage2-plan-description',
    revise: '#stage2-revise',
    status: '#stage2-status',
  },
  notices: { list: '#notices-list' },
  negotiation: {
    notice: '#negotiation-notice',
    acknowledge: '#negotiation-acknowledge',
    acknowledged: '#negotiation-acknowledged',
    nextSteps: '#negotiation-next-steps',
  },
  guardian: { consentStart: '#guardian-consent-start' },
  team: {
    memberEmail: '#team-member-email',
    memberSend: '#team-member-send',
    memberStatus: '#team-member-status',
    guardianEmail: '#team-guardian-email',
    guardianSend: '#team-guardian-send',
    guardianStatus: '#team-guardian-status',
  },
} as const;

/** Every proposal state, by its spec name (`state-machine.md`). */
export const STATES = [
  'DRAFT',
  'SUBMITTED',
  'INELIGIBLE',
  'STAGE1',
  'NOT_SELECTED',
  'STAGE2',
  'RANKED',
  'IRC_REVIEW',
  'DEFERRED',
  'DECLINED',
  'NEGOTIATION',
  'WITHDRAWN',
  'GRANTED',
  'IN_EXECUTION',
  'COMPLETED',
  'TERMINATED',
] as const;

/** A proposal state. */
export type State = (typeof STATES)[number];

/**
 * The states with a withdrawal exit, from `state-machine.md` NOTE 10:
 * "Withdrawal is open in DRAFT, SUBMITTED, STAGE1, STAGE2, RANKED,
 * IRC_REVIEW, DEFERRED and NEGOTIATION." This is the reference of R-SB-03,
 * written from the spec text.
 */
export const WITHDRAWABLE: ReadonlySet<State> = new Set<State>([
  'DRAFT',
  'SUBMITTED',
  'STAGE1',
  'STAGE2',
  'RANKED',
  'IRC_REVIEW',
  'DEFERRED',
  'NEGOTIATION',
]);

// ---------------------------------------------------------------------------
// The e2e cell's applicant scenarios
// ---------------------------------------------------------------------------

/**
 * The states a scenario seeds. `OPEN_CALL` seeds a published, open call
 * and no proposal. `IRC_REVIEW_MINOR` seeds a proposal whose every
 * reviewing IRC member validated it, whose lead has no adult attestation,
 * and that has a guardian added (state-machine NOTE 14).
 * `DEFERRED_AFTER_CONCERN` seeds an IRC concern with a later call
 * published (NOTE 7).
 */
export type ScenarioAt =
  | 'OPEN_CALL'
  | 'STAGE2'
  | 'IRC_REVIEW_MINOR'
  | 'NEGOTIATION'
  | 'NOT_SELECTED'
  | 'DEFERRED_AFTER_CONCERN'
  | 'INELIGIBLE';

/** What the specs need to know about the seeded call. */
export interface CallFacts {
  readonly id: string;
  readonly title: string;
  /** The deadline instant, RFC 3339. */
  readonly deadline: string;
  /** The IANA zone the call states its deadline in. */
  readonly time_zone: string;
  /** The ADR-006 amount texts the call page shows (P-04, P-05, budget). */
  readonly amounts: readonly string[];
  /**
   * Microseconds from the cell clock's now to the deadline. For
   * `OPEN_CALL` it is below one hour, so a spec can pass the deadline
   * without outliving a session (P-72).
   */
  readonly until_deadline_micros: number;
}

/** A synthetic person and the one-time link that enrols their passkey. */
export interface PersonLink {
  readonly email: string;
  /** `<origin>/auth/invite#<token>`, as M3 invitations are. */
  readonly enrol_url: string;
}

/** What `POST /test/scenario/applicant {at}` seeds and returns. */
export interface ApplicantScenario {
  readonly at: ScenarioAt;
  readonly call: CallFacts;
  /** The seeded proposal. Null for `OPEN_CALL`. */
  readonly proposal: string | null;
  /** Its title. Null for `OPEN_CALL`. */
  readonly title: string | null;
  /** Its lead. Null for `OPEN_CALL`. */
  readonly lead: PersonLink | null;
  /** The added guardian. Set for `IRC_REVIEW_MINOR` only. */
  readonly guardian: PersonLink | null;
  /**
   * For `STAGE2`: the P-11 handles of the questions' authors, and
   * canaries of the reviewers' identities (display names, emails, account
   * ids) that no applicant page may show (TH-08). Null otherwise.
   */
  readonly stage2: { readonly handles: readonly string[]; readonly hidden: readonly string[] } | null;
}

function fail(what: string): never {
  throw new StackMissing(`e2e cell scenario: ${what}`);
}

function strOf(v: unknown, what: string): string {
  if (typeof v !== 'string' || v.length === 0) fail(`${what} must be a non-empty string`);
  return v;
}

function strOrNull(v: unknown, what: string): string | null {
  return v === null ? null : strOf(v, what);
}

function strings(v: unknown, what: string): string[] {
  if (!Array.isArray(v)) fail(`${what} must be an array of strings`);
  return v.map((x, i) => strOf(x, `${what}[${i}]`));
}

function obj(v: unknown, what: string): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) fail(`${what} must be an object`);
  return v as Record<string, unknown>;
}

function personOf(v: unknown, what: string, origin: string): PersonLink | null {
  if (v === null) return null;
  const o = obj(v, what);
  const enrol_url = strOf(o['enrol_url'], `${what}.enrol_url`);
  const u = new URL(enrol_url);
  if (u.origin !== origin || u.search !== '' || u.hash.length < 2) {
    fail(`${what}.enrol_url must be a cell-origin link with its token in the fragment`);
  }
  return { email: strOf(o['email'], `${what}.email`), enrol_url };
}

/** Reads a scenario reply, refusing any shape outside the contract. */
export function readScenario(v: unknown, at: ScenarioAt, origin: string): ApplicantScenario {
  const o = obj(v, 'reply');
  if (o['at'] !== at) fail(`reply.at must be ${at}`);
  const c = obj(o['call'], 'call');
  const until = c['until_deadline_micros'];
  if (typeof until !== 'number' || !Number.isSafeInteger(until) || until <= 0) {
    fail('call.until_deadline_micros must be a positive safe integer');
  }
  const deadline = strOf(c['deadline'], 'call.deadline');
  if (Number.isNaN(Date.parse(deadline))) fail('call.deadline must be an RFC 3339 instant');
  const call: CallFacts = {
    id: strOf(c['id'], 'call.id'),
    title: strOf(c['title'], 'call.title'),
    deadline,
    time_zone: strOf(c['time_zone'], 'call.time_zone'),
    amounts: strings(c['amounts'], 'call.amounts'),
    until_deadline_micros: until,
  };
  for (const a of call.amounts) {
    if (!/^(0|[1-9][0-9]*)\.[0-9]{2}$/.test(a)) fail(`call.amounts holds ${a}, not an ADR-006 EUR text`);
  }
  const s2 = o['stage2'];
  const stage2 =
    s2 === null || s2 === undefined
      ? null
      : {
          handles: strings(obj(s2, 'stage2')['handles'], 'stage2.handles'),
          hidden: strings(obj(s2, 'stage2')['hidden'], 'stage2.hidden'),
        };
  const proposal = strOrNull(o['proposal'] ?? null, 'proposal');
  const scenario: ApplicantScenario = {
    at,
    call,
    proposal,
    title: strOrNull(o['title'] ?? null, 'title'),
    lead: personOf(o['lead'] ?? null, 'lead', origin),
    guardian: personOf(o['guardian'] ?? null, 'guardian', origin),
    stage2,
  };
  if (at !== 'OPEN_CALL' && (scenario.proposal === null || scenario.lead === null)) {
    fail(`${at} must seed a proposal and its lead`);
  }
  if (at === 'IRC_REVIEW_MINOR' && scenario.guardian === null) fail('IRC_REVIEW_MINOR must seed a guardian');
  if (at === 'STAGE2' && (stage2 === null || stage2.handles.length === 0 || stage2.hidden.length === 0)) {
    fail('STAGE2 must seed questions, their handles and the hidden reviewer canaries');
  }
  return scenario;
}

/** The M3 devstack control routes plus the applicant scenario route. */
export class ApplicantControl extends Control {
  constructor(
    private readonly req: APIRequestContext,
    cell: CellEndpoints,
  ) {
    super(req, cell);
  }

  /**
   * `POST /test/scenario/applicant {at}`: a published SuperSAFE call and,
   * unless `at` is `OPEN_CALL`, one proposal in state `at`, each built
   * from genesis through production commands, as M3's scenario routes
   * are. Test only: the route exists in `fstp-e2e-cell` and never in the
   * shipped `fstp-cell`.
   */
  async scenario(at: ScenarioAt): Promise<ApplicantScenario> {
    const r = await this.req.post(`${this.cell.control}/test/scenario/applicant`, { data: { at } });
    if (!r.ok()) {
      throw new StackMissing(`e2e cell control scenario ${at} answered ${r.status()} (lanes W3b and W5)`);
    }
    return readScenario(await r.json(), at, this.cell.origin);
  }
}

/** The cell and its control, reset to a fresh state. */
export async function freshCell(request: APIRequestContext): Promise<{
  readonly origin: string;
  readonly vault: string;
  readonly control: ApplicantControl;
}> {
  const cell = stack().cells.a;
  const control = new ApplicantControl(request, cell);
  await control.reset();
  return { origin: cell.origin, vault: cell.vault_origin, control };
}

/** The non-null value of a scenario member, or a contract failure. */
export function must<T>(v: T | null, what: string): T {
  if (v === null) fail(`${what} is missing`);
  return v;
}

// ---------------------------------------------------------------------------
// People
// ---------------------------------------------------------------------------

/**
 * A new applicant: a fresh browser context with a platform authenticator,
 * self-registered through M3 (email proof, then a passkey). Ends on the
 * account page, signed in. The applicant has no adult attestation, so
 * any proposal of theirs is minor-flagged (state-machine NOTE 14).
 */
export async function newApplicant(
  person: () => Promise<Page>,
  control: Control,
  origin: string,
  tag: string,
): Promise<{ readonly page: Page; readonly email: string }> {
  const page = await person();
  await VirtualAuthenticator.attach(page);
  const email = syntheticEmail(tag);
  await signUp(page, control, origin, email);
  return { page, email };
}

/** A seeded person, signed in through their enrolment link. */
export async function seededPerson(person: () => Promise<Page>, origin: string, link: PersonLink): Promise<Page> {
  const page = await person();
  await VirtualAuthenticator.attach(page);
  await enrolByInvite(page, origin, link.enrol_url);
  return page;
}

// ---------------------------------------------------------------------------
// Journey steps
// ---------------------------------------------------------------------------

/** Waits until the proposal page shows `state` in `#proposal-state`. */
export async function expectState(page: Page, origin: string, proposal: string, state: State): Promise<void> {
  await page.goto(`${origin}${APP.proposal(proposal)}`);
  await expect(page.locator(AUI.proposal.state)).toHaveAttribute('data-state', state);
  await expect(page.locator(AUI.proposal.state)).not.toHaveText('');
}

/**
 * Finds the call in the open-call list, opens it and starts a proposal.
 * Returns the new proposal's id, from the workspace URL the page lands on.
 */
export async function startProposal(page: Page, origin: string, call: CallFacts): Promise<string> {
  await page.goto(`${origin}${APP.calls}`);
  const entry = page.locator(`${AUI.calls.list} li`).filter({ hasText: call.title });
  await expect(entry).toHaveCount(1);
  await entry.locator(`a[href="${APP.call(call.id)}"]`).click();
  await expect(page).toHaveURL((u) => u.origin === origin && u.pathname === APP.call(call.id));
  const created = page.waitForResponse(
    (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === API.create(call.id),
  );
  await page.locator(AUI.call.start).click();
  expect((await created).ok(), 'the cell creates the draft').toBe(true);
  await expect(page).toHaveURL((u) => u.origin === origin && /^\/app\/proposals\/[^/]+\/workspace$/.test(u.pathname));
  const id = new URL(page.url()).pathname.split('/')[3];
  if (id === undefined || id === '') throw new Error('the workspace URL names no proposal');
  return id;
}

/** Types into a field and waits until the page reports the save as stored. */
export async function fillAndAutosave(page: Page, selector: string, text: string, status: string): Promise<void> {
  const saved = page.waitForResponse(
    (r) => r.request().method() === 'PUT' && new URL(r.url()).pathname.endsWith('/workspace') && r.ok(),
  );
  await page.locator(selector).fill(text);
  await saved;
  await expect(page.locator(status)).toHaveAttribute('data-status', 'saved');
}

/** Writes a complete draft: title, neutral summary and narrative. */
export async function writeDraft(page: Page, origin: string, proposal: string, title: string): Promise<void> {
  await page.goto(`${origin}${APP.workspace(proposal)}`);
  await fillAndAutosave(page, AUI.workspace.title, title, AUI.workspace.status);
  await fillAndAutosave(page, AUI.workspace.summary, 'A synthetic neutral summary.', AUI.workspace.status);
  await fillAndAutosave(page, AUI.workspace.narrative, 'A synthetic narrative of the planned work.', AUI.workspace.status);
}

/**
 * Synthetic milestone days for a plan. `RecordPlanVersion` needs a start
 * and a due day on every milestone (`fstp-domain` `proposal/intake.rs`
 * `check_tasks`). These days lie after every seeded call deadline.
 */
export const PLAN_DAYS = { start: '2027-03-01', due: '2027-06-30' } as const;

/**
 * Records a plan version of one task with one milestone, whose amount is
 * the ADR-006 string `amount` (`RecordPlanVersion`).
 */
export async function recordPlan(page: Page, origin: string, proposal: string, amount: string): Promise<void> {
  await page.goto(`${origin}${APP.plan(proposal)}`);
  await page.locator(AUI.plan.amount).fill(amount);
  await page.locator(AUI.plan.start).fill(PLAN_DAYS.start);
  await page.locator(AUI.plan.due).fill(PLAN_DAYS.due);
  await page.locator(AUI.plan.description).fill('A synthetic work plan.');
  const put = page.waitForResponse(
    (r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === API.plan(proposal),
  );
  await page.locator(AUI.plan.save).click();
  expect((await put).ok(), 'the cell records the plan version').toBe(true);
  await expect(page.locator(AUI.plan.status)).toHaveAttribute('data-status', 'saved');
}

/**
 * Submits from the submit page: reads the notice, declares no ethics
 * issue and confirms. Returns the notice version the page showed.
 */
export async function submitDraft(page: Page, origin: string, proposal: string): Promise<{
  readonly version: string;
  readonly response: Response;
}> {
  await page.goto(`${origin}${APP.submit(proposal)}`);
  const notice = page.locator(AUI.submit.notice);
  await expect(notice).toBeVisible();
  const version = await notice.getAttribute('data-notice-version');
  if (version === null || version === '') throw new Error('the notice names no version');
  await page.locator(AUI.submit.noticeRead).check();
  await page.locator(AUI.submit.ethicsNone).check();
  const sent = page.waitForResponse(
    (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === API.submission(proposal),
  );
  await page.locator(AUI.submit.confirm).click();
  return { version, response: await sent };
}

/** A fresh applicant with a complete draft in the seeded open call. */
export async function draftedProposal(
  person: () => Promise<Page>,
  control: ApplicantControl,
  origin: string,
  tag: string,
): Promise<{ readonly page: Page; readonly proposal: string; readonly call: CallFacts; readonly title: string }> {
  const s = await control.scenario('OPEN_CALL');
  const { page } = await newApplicant(person, control, origin, tag);
  const proposal = await startProposal(page, origin, s.call);
  const title = `Synthetic proposal ${tag}`;
  await writeDraft(page, origin, proposal, title);
  await recordPlan(page, origin, proposal, '1500.00');
  return { page, proposal, call: s.call, title };
}

// ---------------------------------------------------------------------------
// Request and response capture
// ---------------------------------------------------------------------------

/** One API request the page sent. */
export interface Sent {
  readonly method: string;
  readonly origin: string;
  readonly path: string;
  readonly body: string | null;
}

/** One API response the page received. */
export interface Received {
  readonly method: string;
  readonly path: string;
  readonly status: number;
  readonly body: string;
}

/** Records every request, and every response body, of `page`. */
export class Traffic {
  readonly sent: Sent[] = [];
  readonly received: Received[] = [];
  private readonly pending: Promise<void>[] = [];

  constructor(page: Page) {
    page.on('request', (r: Request) => {
      const u = new URL(r.url());
      this.sent.push({ method: r.method(), origin: u.origin, path: u.pathname, body: r.postData() });
    });
    page.on('response', (r: Response) => {
      const u = new URL(r.url());
      if (!u.pathname.startsWith('/api/')) return;
      this.pending.push(
        r.text().then(
          (body) => {
            this.received.push({ method: r.request().method(), path: u.pathname, status: r.status(), body });
          },
          () => undefined,
        ),
      );
    });
  }

  /** Waits until every response body seen so far has been read. */
  async settle(): Promise<void> {
    await Promise.all(this.pending);
  }

  /** The requests to `path` with `method`. */
  to(method: string, path: string): Sent[] {
    return this.sent.filter((s) => s.method === method && s.path === path);
  }
}

/** Every leaf of a JSON value: strings and numbers as text, plus member names. */
export function jsonLeaves(v: unknown): { readonly strings: string[]; readonly numbers: string[]; readonly keys: string[] } {
  const out = { strings: [] as string[], numbers: [] as string[], keys: [] as string[] };
  const walk = (x: unknown): void => {
    if (typeof x === 'string') out.strings.push(x);
    else if (typeof x === 'number') out.numbers.push(String(x));
    else if (Array.isArray(x)) x.forEach(walk);
    else if (typeof x === 'object' && x !== null) {
      for (const [k, y] of Object.entries(x)) {
        out.keys.push(k);
        walk(y);
      }
    }
  };
  walk(v);
  return out;
}

/** The parsed JSON of a body, or null when it is not JSON. */
export function parsedOrNull(body: string | null): unknown {
  if (body === null || body === '') return null;
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// R-SB-01: fields a submission form must not have
// ---------------------------------------------------------------------------

/** What the R-SB-01 predicate sees of one form control. */
export interface ControlFacts {
  readonly tag: string;
  readonly type: string;
  readonly id: string;
  readonly name: string;
  readonly autocomplete: string;
  /** The label text: `<label>` elements, `aria-label` and `aria-labelledby`. */
  readonly label: string;
}

const DOB_WORDS = /\b(date of birth|birth ?date|birthday|dob|born|age)\b/i;
const IDENTITY_WORDS = /\b(passport|identity (card|document|number)|id (card|document|number)|national id|social security|tax id)\b/i;
const PAYMENT_WORDS = /\b(iban|bic|swift|bank|card number|cvv|cvc|payment|account number|sort code|routing number)\b/i;

/**
 * Why a control must not be on an applicant form before negotiation, or
 * null when it may be. R-SB-01: "no submission form contains identity
 * document, date of birth or payment fields". Q24 (interim, pending
 * Daniel): no attachments in M4, so a file input is refused too. Under
 * the Q23 answer (M3 Q13 A), age is an over-18 attestation on the vault
 * origin, never a field here.
 */
export function forbiddenField(c: ControlFacts): string | null {
  const words = `${c.id} ${c.name} ${c.label}`.replace(/[-_]/g, ' ');
  const ac = c.autocomplete.toLowerCase().split(/\s+/);
  if (c.tag === 'input' && c.type === 'file') return 'attachment (Q24)';
  if (ac.some((t) => t.startsWith('bday')) || (c.tag === 'input' && c.type === 'date') || DOB_WORDS.test(words)) {
    return 'date of birth';
  }
  if (ac.some((t) => t.startsWith('cc-') || t.startsWith('transaction-')) || PAYMENT_WORDS.test(words)) {
    return 'payment';
  }
  if (IDENTITY_WORDS.test(words)) return 'identity document';
  return null;
}

/** The facts of every form control on the page, labels resolved. */
export async function controlsOf(page: Page): Promise<ControlFacts[]> {
  return page.evaluate(() => {
    const text = (e: Element | null): string => (e === null ? '' : (e.textContent ?? '').trim());
    return Array.from(document.querySelectorAll('input, select, textarea')).map((e) => {
      const el = e as HTMLInputElement;
      const labels = Array.from(el.labels ?? []).map((l) => text(l));
      const by = (el.getAttribute('aria-labelledby') ?? '')
        .split(/\s+/)
        .filter((x) => x !== '')
        .map((id) => text(document.getElementById(id)));
      return {
        tag: el.tagName.toLowerCase(),
        type: (el.getAttribute('type') ?? '').toLowerCase(),
        id: el.id,
        name: el.getAttribute('name') ?? '',
        autocomplete: el.getAttribute('autocomplete') ?? '',
        label: [...labels, el.getAttribute('aria-label') ?? '', ...by].join(' ').trim(),
      };
    });
  });
}

/** The R-SB-01 problems of the page, each naming the control. */
export async function forbiddenFieldsOn(page: Page, label: string): Promise<string[]> {
  const out: string[] = [];
  for (const c of await controlsOf(page)) {
    const why = forbiddenField(c);
    if (why !== null) out.push(`${label}: ${c.tag}#${c.id} "${c.label}" is a ${why} field`);
  }
  return out;
}

// ---------------------------------------------------------------------------
// R-NF-03: structure and accessible names
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

/**
 * The R-NF-03 structure problems of a page: a language, a title, one
 * `main` landmark, an `h1`, no positive tabindex, and an accessible name
 * on every control, as Chromium computes it.
 */
export async function structureProblems(page: Page, label: string): Promise<string[]> {
  const problems: string[] = [];
  const doc = await page.evaluate(() => ({
    lang: document.documentElement.lang,
    title: document.title.trim(),
    mains: document.querySelectorAll('main, [role="main"]').length,
    h1: document.querySelectorAll('h1').length,
    positive: Array.from(document.querySelectorAll('[tabindex]')).filter((e) => Number(e.getAttribute('tabindex')) > 0)
      .length,
  }));
  if (doc.lang === '') problems.push(`${label}: no document language`);
  if (doc.title === '') problems.push(`${label}: no title`);
  if (doc.mains !== 1) problems.push(`${label}: ${doc.mains} main landmarks, not 1`);
  if (doc.h1 < 1) problems.push(`${label}: no h1`);
  if (doc.positive > 0) problems.push(`${label}: positive tabindex`);
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

/** Presses Tab until `selector` has focus. Fails after `max` presses. */
export async function tabTo(page: Page, selector: string, max = 60): Promise<void> {
  for (let i = 0; i < max; i++) {
    if (await page.evaluate((s) => document.activeElement?.matches(s) === true, selector)) return;
    await page.keyboard.press('Tab');
  }
  throw new Error(`${selector} is not reachable by Tab within ${max} presses`);
}

/** The ids a control's `aria-describedby` and `aria-errormessage` name, with visible text. */
export async function visibleErrorTexts(page: Page, selector: string): Promise<string[]> {
  const refs = await page.locator(selector).evaluate((e) =>
    `${e.getAttribute('aria-describedby') ?? ''} ${e.getAttribute('aria-errormessage') ?? ''}`
      .split(/\s+/)
      .filter((x) => x !== ''),
  );
  const texts: string[] = [];
  for (const id of refs) {
    const el = page.locator(`[id="${id}"]`);
    if ((await el.count()) === 1 && (await el.isVisible())) {
      const t = (await el.innerText()).trim();
      if (t !== '') texts.push(t);
    }
  }
  return texts;
}

// ---------------------------------------------------------------------------
// Small values
// ---------------------------------------------------------------------------

/** A generated canary string, as design section 8.1 shapes them. */
export function canary(kind: string): string {
  const b = new Uint8Array(4);
  globalThis.crypto.getRandomValues(b);
  return `CANARY-${kind}-${Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')}`;
}

/** Microseconds in one second. */
export const SECOND_MICROS = 1_000_000;
