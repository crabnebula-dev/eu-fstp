/**
 * The page contract of the creator, onboarding and people pages (M4 lane
 * W4a), and the e2e cell routes the specs of this lane need.
 *
 * The specs were written before the pages. This file is the contract the
 * page agent of lane W4a builds to, and the e2e cell agent of lane W5
 * serves. Every selector, route and response shape here is an interim
 * reading, pending Daniel and the generated `web/src/gen/api.ts` of lane
 * W3a. A later answer replaces it here, in one place.
 *
 * Sources: M4 design sections 2 (J0 to J2), 3.2, 3.3, 3.5, 3.9 and 8.7;
 * `SPEC/02-domain/programme-creator.md`; ADR-014.
 *
 * # Conventions every page of this lane follows
 *
 * - Each high-risk action opens the M3 step-up dialog `dialog#stepup`.
 *   Its confirm button is `#stepup-confirm`, and Escape cancels it
 *   (`e2e/playwright.config.ts` `UI.stepup`).
 * - A refusal shows an element with `role="alert"`. Its `data-rule`
 *   attribute holds the refusal's `rule`, such as `I-67`, when the API
 *   named one.
 * - Every page has one `main`, an `h1`, a document language and title,
 *   and a `footer` with the mandatory elements of [`FOOTER`].
 * - Every visible string comes from the feature's message catalogue,
 *   `web/src/<feature>/messages.en.ts`, which exports `CATALOGUE` in the
 *   `CatalogueInput` form of `web/src/core/i18n.ts`.
 */

import { expect, type APIRequestContext } from '@playwright/test';
import { StackMissing, type CellEndpoints } from '../playwright.config';

// ---------------------------------------------------------------------------
// Application routes on the cell origin
// ---------------------------------------------------------------------------

/**
 * The onboarding steps in the order of the onboarding table of
 * `programme-creator.md`, spelled as `fstp_tenant::OnboardingStep::name`
 * spells them in routes.
 */
export const ONBOARDING_STEPS = [
  'organisation',
  'agreements',
  'branding',
  'domains_and_email',
  'identity',
  'inference',
  'payments',
  'channels',
  'administrators',
] as const;

export type OnboardingStepName = (typeof ONBOARDING_STEPS)[number];

/**
 * The creator steps 1 to 10 of `programme-creator.md`, spelled as
 * `fstp_programme::Step::name` spells the step members of the spec JSON,
 * then the review (step 11), which holds no field.
 */
export const CREATOR_STEPS = [
  'funder',
  'identity',
  'eligibility',
  'funding',
  'evaluation',
  'money',
  'contract',
  'support',
  'people',
  'comms',
] as const;

export type CreatorStepName = (typeof CREATOR_STEPS)[number];

/** The review step's route segment. */
export const REVIEW_STEP = 'review';

/**
 * Page routes. Design section 2.2 names `/app/admin/onboarding/{step}`.
 * The other `/app` paths are interim readings of this lane.
 */
export const APP = {
  onboarding: (step: OnboardingStepName): string => `/app/admin/onboarding/${step}`,
  onboardingSummary: '/app/admin/onboarding/summary',
  /** The signed-in person's identity verification page (J0, `me.begin_verification`). */
  identity: '/app/me/identity',
  /** One tenant setting page, such as `p71` (J0, `tenant.set_*`). */
  setting: (param: 'p20' | 'p69' | 'p70' | 'p71' | 'p72' | 'p74'): string => `/app/admin/settings/${param}`,
  /** Opening a draft (J1, `creator.open_draft`). */
  creatorNew: '/app/creator/new',
  /** The starting point page (J1, `creator.apply_start`, `import.upload`). */
  creatorStart: (p: string): string => `/app/programmes/${p}/creator/start`,
  creatorStep: (p: string, step: CreatorStepName | typeof REVIEW_STEP): string =>
    `/app/programmes/${p}/creator/${step}`,
  /** The import review page (J1, `import.resolve`). */
  creatorImports: (p: string): string => `/app/programmes/${p}/creator/imports`,
  /** The people admin page where roles are granted (J1, J2, `roles.grant`). */
  people: (p: string): string => `/app/programmes/${p}/people`,
  /** The approval inbox of tenant admins (J1, `creator.approve_activation`). */
  approvals: '/app/admin/approvals',
  /** The invitation landing. Invitation mails link here with the token in the fragment. */
  invitation: '/app/invitation',
} as const;

/** The pattern of a programme's creator page path, capturing the programme id. */
export const CREATOR_PATH = /^\/app\/programmes\/([0-9A-Za-z_-]+)\/creator\/([a-z_]+)$/;

// ---------------------------------------------------------------------------
// API reads the specs make (design sections 2.2 and 8.2)
// ---------------------------------------------------------------------------

/**
 * Read routes. Their paths are those of design section 2.2 and 8.2. The
 * response shapes are interim readings:
 *
 * - `draft`: `{ "spec": <fstp.programme/1 spec JSON>, "revision": "<opaque>",
 *   "status": "draft" | "active" }`. Every member of the spec is present,
 *   with `null` for a gap, as `fstp_programme::encode_spec` writes it.
 * - `report`: `{ "revision": "<opaque>", "results": [{ "check": "<CheckId>",
 *   "severity": "failure" | "warning", "acknowledged": boolean }] }`.
 * - `onboardingStep`: `{ "step": "<name>", "status": "locked" | "open" |
 *   "saved" | "validated" | "skipped" | "unavailable" }`.
 */
export const API = {
  draft: (p: string): string => `/api/v1/programmes/${p}/draft`,
  report: (p: string): string => `/api/v1/programmes/${p}/draft/report`,
  onboardingStep: (step: OnboardingStepName): string => `/api/v1/admin/onboarding/${step}`,
  /** The POST that starts identity verification of the signed-in admin (J0). */
  meVerification: '/api/v1/me/verification',
  /** `{ "signatories": [{ "account", "role", "handle" }] }`, the tenant-wide signatory bindings (NOTE 5). */
  signatories: '/api/v1/admin/signatories',
  /** `{ "state", "request", "requested_by", "approved_by" }`, the organisation's activation (SoD-18). */
  activation: '/api/v1/admin/activation',
} as const;

/** The tenant-wide signatory roles (NOTE 5 of `roles-and-sod.md`), as the wire spells them. */
export const SIGNATORY_ROLES = ['financial_signatory', 'legal_signatory'] as const;

/** One signatory role. */
export type SignatoryRoleName = (typeof SIGNATORY_ROLES)[number];

// ---------------------------------------------------------------------------
// Element contract
// ---------------------------------------------------------------------------

/**
 * The footer's mandatory elements (design section 3.9, R-WL-04, P-68 and
 * the I-69 seam). Each is an element inside the page's `footer` with the
 * attribute `data-mandatory` set to the key, and visible text. The Data Act
 * information is required on pages a tenant admin sees.
 */
export const FOOTER = {
  everyPage: ['privacy_notice', 'accessibility_statement', 'platform_attribution'],
  tenantAdmin: ['data_act_information'],
} as const;

/** The step-up dialog of M3, as `e2e/playwright.config.ts` names it. */
export const STEPUP = { dialog: '#stepup', confirm: '#stepup-confirm' } as const;

/**
 * Onboarding pages (`/app/admin/onboarding/{step}`).
 *
 * - `#onboarding-steps` is a `nav` holding one `li[data-step]` per step in
 *   order, with `data-status` set to the step's status. A locked step's
 *   item holds no link.
 * - Each step page has one `form#onboarding-form`. Its controls carry the
 *   `name` of the value member they edit (see `ONBOARDING_VALUES`).
 * - `#onboarding-save` saves and validates the step. `#onboarding-outcome`
 *   (`role="status"`) then carries `data-outcome="validated"` or the step
 *   failure's code, spelled as `fstp-tenant` spells it, such as
 *   `too_few_admins`.
 * - `#onboarding-next` is a link to the next step. It exists only once the
 *   step is validated.
 * - A step page opened while locked shows `#onboarding-locked` and no form.
 * - The summary page has `#onboarding-complete`. Its result is
 *   `#onboarding-complete-outcome` with `data-outcome="completed"`, or a
 *   refusal alert.
 * - The Administrators step has `#signatories` (SoD-14, SoD-15). It holds
 *   one `section[data-signatory-role]` per signatory role, listing each
 *   holder as `li[data-account]`, or `[data-empty="true"]` with no holder.
 *   `#signatory-missing` names the roles still without a holder. A grant
 *   picks an account in `#signatory-account` and a role radio, then
 *   `#signatory-grant` sends it with a step-up (I-78).
 * - The summary page has `#activation` (SoD-18). `#activation-state`
 *   carries `data-state` set to `not_requested`, `requested` or
 *   `active`. `#activation-request` requests activation, and
 *   `#activation-approve` approves an open request.
 * - A refusal shows in the page alert, `main [role="alert"]`, with
 *   `data-rule` set to the rule it names, such as `SoD-07`.
 */
export const ONBOARDING_UI = {
  steps: '#onboarding-steps',
  form: '#onboarding-form',
  save: '#onboarding-save',
  outcome: '#onboarding-outcome',
  next: '#onboarding-next',
  locked: '#onboarding-locked',
  complete: '#onboarding-complete',
  completeOutcome: '#onboarding-complete-outcome',
  /** The P-20 control of the Payments step and its save button, a high-risk setting change. */
  p20: 'input[type="radio"][name="p20"]',
  p20Save: '#setting-p20-save',
  /** The Administrators step: invite an admin (high-risk) and the admin list. */
  adminInviteEmail: '#admin-invite-email',
  adminInviteSubmit: '#admin-invite-submit',
  admins: '#admins',
  /** The Administrators step: the signatory holders and the grant form (SoD-14, SoD-15). */
  signatories: '#signatories',
  signatoryMissing: '#signatory-missing',
  signatoryAccount: '#signatory-account',
  signatoryGrant: '#signatory-grant',
  /** The summary: the organisation's activation (SoD-18). */
  activationState: '#activation-state',
  activationMissing: '#activation-missing',
  activationRequest: '#activation-request',
  activationApprove: '#activation-approve',
  /** The page alert, which names a refused rule in `data-rule`. */
  alert: 'main [role="alert"]',
} as const;

/** The radio of signatory role `role` in the grant form of the Administrators step. */
export function signatoryRoleChoice(role: SignatoryRoleName): string {
  return `input[type="radio"][name="signatory-role"][value="${role}"]`;
}

/** The holder `account` of signatory role `role` on the Administrators step. */
export function signatoryHolder(role: SignatoryRoleName, account: string): string {
  return `#signatories section[data-signatory-role="${role}"] li[data-account="${account}"]`;
}

/**
 * Tenant setting pages (`/app/admin/settings/{param}`). `#setting-value`
 * is the control, `#setting-save` the high-risk save, and
 * `#setting-current` shows the value in force.
 */
export const SETTING_UI = {
  value: '#setting-value',
  save: '#setting-save',
  current: '#setting-current',
} as const;

/**
 * The identity page (`/app/me/identity`). `#verify-identity` starts the
 * vault flow. `#identity-status` carries `data-status` set to
 * `unverified`, `pending` or `verified`.
 */
export const IDENTITY_UI = {
  verify: '#verify-identity',
  status: '#identity-status',
} as const;

/**
 * Creator pages.
 *
 * - `/app/creator/new`: `#creator-open` opens a draft with the default
 *   funder profile (high-risk). The page then shows the starting point
 *   page of the new programme.
 * - Starting point page: one button per option, `[data-start="blank"]`,
 *   `[data-start="clone"]`, `[data-start="import"]`, and one
 *   `[data-start="template"][data-template="<id>"]` per template, where the
 *   shipped SuperSAFE template has id `1` (`fstp_programme::SUPERSAFE_TEMPLATE`).
 *   The import option opens a file input `#import-file` and `#import-upload`.
 * - Step pages: `#creator-steps` is a `nav` with one `li[data-step]` per
 *   step. Each field of the step is one element `[data-field="<key>"]`,
 *   where the key is `<step member>.<field member>` of the spec JSON, such
 *   as `money.p05_recipient_cap`. Its value controls follow the field value
 *   contract of `support.ts` (`setFieldValue`). A narrative field whose
 *   text came from a template and is not yet accepted holds a button
 *   `[data-action="accept-narrative"]`.
 * - `#creator-step-save` saves the step. `#creator-step-status` then
 *   carries `data-state="saved"`, and `#creator-step-checks` lists the
 *   step's check results as `li[data-check][data-severity]`.
 * - `#creator-step-next` links to the next step.
 * - Review page: `#report` lists `li[data-check][data-severity]
 *   [data-acknowledged]`. A warning not yet acknowledged holds
 *   `[data-action="acknowledge"]`. `#preview-guide`, `#preview-public` and
 *   `#preview-contract` are regions holding the previews.
 *   `#request-activation` is disabled while the report is not clean.
 *   `#activation-status` carries `data-status="requested"` once requested.
 */
export const CREATOR_UI = {
  open: '#creator-open',
  steps: '#creator-steps',
  stepSave: '#creator-step-save',
  stepStatus: '#creator-step-status',
  stepChecks: '#creator-step-checks',
  stepNext: '#creator-step-next',
  report: '#report',
  previewGuide: '#preview-guide',
  previewPublic: '#preview-public',
  previewContract: '#preview-contract',
  requestActivation: '#request-activation',
  activationStatus: '#activation-status',
  importFile: '#import-file',
  importUpload: '#import-upload',
} as const;

/**
 * The creator's People step (step 9) and the people admin page.
 *
 * - `#invite-form` with `#invite-email`, `#invite-role` (a `select` whose
 *   option values are the role keys of [`ROLE_KEYS`]) and `#invite-submit`.
 * - `#invitations` lists `li[data-invitation][data-email]`. `data-sod` is
 *   `pass`, `fail` or `unchecked` (the live SoD check, D3), and
 *   `data-state` is `invited`, `accepted`, `verified` or `granted`.
 * - On the people admin page, the item of an invitee who accepted the
 *   terms and verified identity (`data-state="verified"`, SoD-09) holds
 *   `[data-action="grant"]`, a high-risk action. While the programme is a
 *   draft, only a programme manager invitation offers it (D1).
 */
export const PEOPLE_UI = {
  form: '#invite-form',
  email: '#invite-email',
  role: '#invite-role',
  submit: '#invite-submit',
  invitations: '#invitations',
} as const;

/** The role keys of the invitation form, one per `fstp_domain::roles::Role` this lane invites. */
export const ROLE_KEYS = {
  programmeManager: 'programme_manager',
  callDrafter: 'call_drafter',
  coordinator: 'fstp_coordinator',
  committeeMember: 'committee_member',
  committeeChair: 'committee_chair',
  ircMember: 'irc_member',
} as const;

/**
 * The invitation landing (`/app/invitation#<token>`). `#invitation-terms`
 * holds the confidentiality terms as approved text. `#invitation-accept`
 * accepts them, and first enrols a passkey when the browser has no
 * session. `#invitation-status` then carries `data-status="accepted"`.
 * `#invitation-verify` starts identity verification for SoD-09.
 */
export const INVITATION_UI = {
  terms: '#invitation-terms',
  accept: '#invitation-accept',
  status: '#invitation-status',
  verify: '#invitation-verify',
} as const;

/**
 * The approval inbox (`/app/admin/approvals`). Each pending approval is
 * `li[data-approval="activation"][data-programme="<p>"]` with
 * `[data-action="approve"]`, a high-risk action. A tenant admin's grant
 * of a role to their own account (SoD-07) is
 * `li[data-approval="self_grant"][data-id="<approval>"]`, approved the
 * same way by a second admin. A refusal shows `#approval-error` with
 * `role="alert"` and `data-rule`.
 */
export const APPROVAL_UI = {
  error: '#approval-error',
  item: (p: string): string => `li[data-approval="activation"][data-programme="${p}"]`,
  selfGrant: (a: string): string => `li[data-approval="self_grant"][data-id="${a}"]`,
} as const;

/**
 * The import review page. Each proposal is `li[data-proposal]` with
 * `data-field` set to the field key and `data-flagged="true"` when it
 * conflicts with the funder profile. It shows the proposed value in
 * `[data-role="value"]`, whose `data-json` attribute holds the value's
 * canonical JSON (RFC 8785), and its evidence span in
 * `[data-role="evidence"]`. Both are shown as text, never as markup.
 * Its actions are `[data-action="confirm"]`, `[data-action="edit"]` (which
 * reveals the field's value controls inside the item and
 * `[data-action="save-edit"]`) and `[data-action="dismiss"]`. A flagged
 * proposal holds `input[type="checkbox"][data-role="conflict-ack"]`.
 * A resolved item carries `data-resolution` set to `confirmed`, `edited`
 * or `dismissed`.
 */
export const IMPORT_UI = {
  proposals: '#proposals',
  item: 'li[data-proposal]',
} as const;

// ---------------------------------------------------------------------------
// e2e cell control routes (lane W5, `fstp-e2e-cell`)
// ---------------------------------------------------------------------------

/** One outbox message as the e2e cell captured it. */
export interface CellMail {
  readonly kind: string;
  readonly link: string;
}

/**
 * The loopback control routes of `fstp-e2e-cell` that this lane needs,
 * beyond the M3 routes of `Control` in `e2e/playwright.config.ts`
 * (`/test/reset`, `/test/mailbox`, `/test/account`, `/test/clock/advance`).
 *
 * Contract for lane W5, interim pending Daniel:
 *
 * - `GET /test/mailbox?to=` also returns the kinds `admin_invitation`
 *   (a tenant admin invitation, linking to the M3 `/auth/invite` page) and
 *   `invitation` (a programme role invitation, linking to
 *   `/app/invitation#<token>`).
 * - `POST /test/vault/verify {"account": "<id>"}` makes the synthetic
 *   vault hold a completed identity verification for the account, as a
 *   wallet or document check would. With `"same_identity_as": "<id>"` the
 *   new verification names the same person as that account's, which is
 *   the Sybil case of I-67. It answers `{}`.
 * - After `POST /test/reset`, the cell's fake control plane holds accepted
 *   agreements at version 1 each, its prober passes every probe, its
 *   pre-check port exists, it loads the synthetic legal-wording profile,
 *   and its vault knows the P-13 classes of the SuperSAFE fixture.
 * - Its import proposer is `FakeProposer`. For the annex
 *   `e2e/creator/fixtures/synthetic-annex.md` it proposes at least
 *   `money.p05_recipient_cap` with a value above the P-58 ceiling (flagged
 *   against the profile, L-10), `funder.action_number` and
 *   `identity.scope`, each with an evidence span.
 */
export class M4Control {
  constructor(
    private readonly request: APIRequestContext,
    readonly cell: CellEndpoints,
  ) {}

  private url(path: string): string {
    return `${this.cell.control}${path}`;
  }

  private async ok(r: Awaited<ReturnType<APIRequestContext['get']>>, what: string): Promise<unknown> {
    if (!r.ok()) {
      throw new StackMissing(`e2e cell control ${what} answered ${r.status()}`);
    }
    return r.json();
  }

  /** `POST /test/reset`: the cell at first start, with the first admin's invitation. */
  async reset(): Promise<{ readonly url: string; readonly email: string }> {
    const v = (await this.ok(await this.request.post(this.url('/test/reset')), 'reset')) as {
      first_admin?: { url?: unknown; email?: unknown };
    };
    const url = v.first_admin?.url;
    const email = v.first_admin?.email;
    if (typeof url !== 'string' || typeof email !== 'string') {
      throw new StackMissing('e2e cell control reset: expected {first_admin: {url, email}}');
    }
    expect(new URL(url).origin).toBe(this.cell.origin);
    return { url, email };
  }

  /** The newest message of `kind` to `to`. Fails when there is none. */
  async newest(to: string, kind: string): Promise<CellMail> {
    const r = await this.request.get(this.url('/test/mailbox'), { params: { to } });
    const v = (await this.ok(r, 'mailbox')) as { messages?: unknown };
    if (!Array.isArray(v.messages)) {
      throw new StackMissing('e2e cell control mailbox: expected {messages: [...]}');
    }
    const all = (v.messages as CellMail[]).filter((m) => m.kind === kind);
    const last = all[all.length - 1];
    if (last === undefined) {
      throw new Error(`no ${kind} message to ${to}`);
    }
    expect(new URL(last.link).origin, 'mail links point at the cell origin').toBe(this.cell.origin);
    return last;
  }

  /** `GET /test/account?email=`: the account id with that login email. */
  async account(email: string): Promise<string> {
    const r = await this.request.get(this.url('/test/account'), { params: { email } });
    const v = (await this.ok(r, 'account')) as { account?: unknown };
    if (typeof v.account !== 'string') {
      throw new StackMissing('e2e cell control account: expected {account}');
    }
    return v.account;
  }

  /** `POST /test/vault/verify`: a completed verification in the synthetic vault. */
  async verify(account: string, sameIdentityAs?: string): Promise<void> {
    const data: Record<string, string> = { account };
    if (sameIdentityAs !== undefined) {
      data['same_identity_as'] = sameIdentityAs;
    }
    await this.ok(await this.request.post(this.url('/test/vault/verify'), { data }), 'vault verify');
  }
}
