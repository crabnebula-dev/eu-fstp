// The page logic of tenant onboarding (R-TN-01, SoD-07; M4 design
// section 3.5, `SPEC/02-domain/programme-creator.md` "Tenant onboarding").
//
// This module is pure: it touches no DOM, so Node can load it. The
// response readers are the interim readings of this lane, pending Daniel
// and the generated validators of `web/src/gen/api.ts` (lane W3a).

/**
 * The onboarding steps in the order of the onboarding table, spelled as
 * `fstp_tenant::OnboardingStep::name` spells them in routes.
 */
export const ONBOARDING_STEPS = [
  "organisation",
  "agreements",
  "branding",
  "domains_and_email",
  "identity",
  "inference",
  "payments",
  "channels",
  "administrators",
] as const;

/** One onboarding step. */
export type OnboardingStep = (typeof ONBOARDING_STEPS)[number];

/** A step status as `fstp_tenant::StepStatus` names it. */
export type StepStatus = "locked" | "open" | "saved" | "validated" | "skipped" | "unavailable";

const STATUSES: ReadonlySet<string> = new Set(["locked", "open", "saved", "validated", "skipped", "unavailable"]);

/** Whether `s` names an onboarding step. */
export function isOnboardingStep(s: string): s is OnboardingStep {
  return (ONBOARDING_STEPS as readonly string[]).includes(s);
}

/** Whether a step with status `s` lets the next step open. */
export function passes(s: StepStatus | undefined): boolean {
  return s === "validated" || s === "skipped";
}

/**
 * The steps a person may open, in order: the first step, and each later
 * step whose every earlier step is validated, or skipped as Agreements is
 * in a self-hosted cell (R-TN-01: "Each step validates before the next
 * opens"). The server enforces the same order on every save.
 */
export function openableSteps(statuses: Readonly<Record<string, StepStatus>>): readonly OnboardingStep[] {
  const out: OnboardingStep[] = [];
  for (const s of ONBOARDING_STEPS) {
    out.push(s);
    if (!passes(Object.hasOwn(statuses, s) ? statuses[s] : undefined)) break;
  }
  return out;
}

/** The step after `step`, or null after Administrators. */
export function nextOnboardingStep(step: OnboardingStep): OnboardingStep | null {
  const i = ONBOARDING_STEPS.indexOf(step);
  return ONBOARDING_STEPS[i + 1] ?? null;
}

/** `v` as a plain object, or null. */
export function record(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Readonly<Record<string, unknown>>) : null;
}

/** One step as `GET /api/v1/admin/onboarding/{step}` answers it. */
export interface StepView {
  readonly step: OnboardingStep;
  readonly status: StepStatus;
  /** The tenant revision a save names as its base. */
  readonly revision: string;
  /** The latest saved values, in the `fstp-tenant` codec form, or null. */
  readonly values: Readonly<Record<string, unknown>> | null;
  /** The outcome of the latest save, such as `validated` or `too_few_admins`. */
  readonly outcome: string | null;
  /**
   * For the Agreements step: the versions the control plane recorded as
   * accepted (`TenantQuery::Agreements`), or null.
   */
  readonly accepted: Readonly<Record<string, unknown>> | null;
}

/**
 * Reads `{step, status, revision, values?, outcome?, accepted?}`. Null
 * otherwise.
 *
 * Interim, pending Daniel: the e2e contract names `step` and `status`.
 * `revision`, `values`, `outcome` and `accepted` are this lane's reading of
 * `TenantCommand::SaveStep { base }` and the `StepSaved` record.
 */
export function readStep(body: unknown): StepView | null {
  const o = record(body);
  if (o === null) return null;
  const step = o["step"];
  const status = o["status"];
  const revision = o["revision"];
  if (typeof step !== "string" || !isOnboardingStep(step)) return null;
  if (typeof status !== "string" || !STATUSES.has(status)) return null;
  if (typeof revision !== "string") return null;
  const v = o["values"];
  const values = v === undefined || v === null ? null : record(v);
  if (v !== undefined && v !== null && values === null) return null;
  const outcome = o["outcome"];
  if (outcome !== undefined && outcome !== null && typeof outcome !== "string") return null;
  const a = o["accepted"];
  const accepted = a === undefined || a === null ? null : record(a);
  if (a !== undefined && a !== null && accepted === null) return null;
  return {
    step,
    status: status as StepStatus,
    revision,
    values,
    outcome: typeof outcome === "string" ? outcome : null,
    accepted,
  };
}

/** Reads the answer of a step save: `{status, outcome}`. Null otherwise. */
export function readSaved(body: unknown): { readonly status: StepStatus; readonly outcome: string } | null {
  const o = record(body);
  const status = o?.["status"];
  const outcome = o?.["outcome"];
  if (typeof status !== "string" || !STATUSES.has(status) || typeof outcome !== "string" || outcome === "") return null;
  return { status: status as StepStatus, outcome };
}

/** A failure code as `fstp-tenant` spells a step outcome. */
const OUTCOME = /^[a-z][a-z0-9_]{0,63}$/;

/** Whether `s` can be shown as a step outcome code. */
export function isOutcome(s: string): boolean {
  return OUTCOME.test(s);
}

/** One tenant admin as the Administrators step lists it. */
export interface AdminRow {
  readonly account: string;
  /** The pseudonymous display handle, never an email (`Accounts::display_handle`). */
  readonly handle: string;
  readonly verified: boolean;
}

/** Reads `{admins: [{account, handle, verified}]}`. Null otherwise. */
export function readAdmins(body: unknown): AdminRow[] | null {
  const list = record(body)?.["admins"];
  if (!Array.isArray(list)) return null;
  const out: AdminRow[] = [];
  for (const x of list as unknown[]) {
    const r = record(x);
    const account = r?.["account"];
    const handle = r?.["handle"];
    const verified = r?.["verified"];
    if (typeof account !== "string" || !/^[0-9]{1,39}$/.test(account)) return null;
    if (typeof handle !== "string" || typeof verified !== "boolean") return null;
    out.push({ account, handle, verified });
  }
  return out;
}

/**
 * The tenant-wide signatory roles (NOTE 5 of `roles-and-sod.md`), spelled
 * as `fstp_access::role_wire_name` spells them, Financial first.
 */
export const SIGNATORY_ROLES = ["financial_signatory", "legal_signatory"] as const;

/** One signatory role. */
export type SignatoryRole = (typeof SIGNATORY_ROLES)[number];

/** Whether `s` names a signatory role. */
export function isSignatoryRole(s: unknown): s is SignatoryRole {
  return typeof s === "string" && (SIGNATORY_ROLES as readonly string[]).includes(s);
}

/** One signatory binding as `GET /api/v1/admin/signatories` lists it. It names no programme. */
export interface SignatoryRow {
  readonly account: string;
  readonly role: SignatoryRole;
  /** The pseudonymous display handle, never an email. */
  readonly handle: string;
}

/** Reads `{signatories: [{account, role, handle}]}`. Null otherwise. */
export function readSignatories(body: unknown): SignatoryRow[] | null {
  const list = record(body)?.["signatories"];
  if (!Array.isArray(list)) return null;
  const out: SignatoryRow[] = [];
  for (const x of list as unknown[]) {
    const r = record(x);
    const account = r?.["account"];
    const role = r?.["role"];
    const handle = r?.["handle"];
    if (typeof account !== "string" || !/^[0-9]{1,39}$/.test(account)) return null;
    if (!isSignatoryRole(role) || typeof handle !== "string") return null;
    out.push({ account, role, handle });
  }
  return out;
}

/** The signatory roles with no holder in `rows`, Financial first (SoD-14, SoD-15). */
export function missingSignatories(rows: readonly SignatoryRow[]): SignatoryRole[] {
  return SIGNATORY_ROLES.filter((r) => !rows.some((x) => x.role === r));
}

/** The activation state of the organisation (SoD-18). */
export type ActivationState = "not_requested" | "requested" | "active";

/** The organisation's activation as `GET /api/v1/admin/activation` answers it. */
export interface ActivationView {
  readonly state: ActivationState;
  /** The open or approved request, or null before any request. */
  readonly request: string | null;
  readonly requestedBy: string | null;
  readonly approvedBy: string | null;
}

/** An account id or null, as the activation read gives it; undefined for any other value. */
function idOrNull(v: unknown): string | null | undefined {
  if (v === null) return null;
  return typeof v === "string" && /^[0-9]{1,39}$/.test(v) ? v : undefined;
}

/**
 * Reads `{state, request, requested_by, approved_by}`. Null for any other
 * shape, or for members that do not fit the state: a request and its
 * requester exist from `requested` on, and an approver only once `active`.
 */
export function readActivation(body: unknown): ActivationView | null {
  const r = record(body);
  if (r === null) return null;
  const state = r["state"];
  const request = idOrNull(r["request"]);
  const requestedBy = idOrNull(r["requested_by"]);
  const approvedBy = idOrNull(r["approved_by"]);
  if (request === undefined || requestedBy === undefined || approvedBy === undefined) return null;
  switch (state) {
    case "not_requested":
      return request === null && requestedBy === null && approvedBy === null
        ? { state, request, requestedBy, approvedBy }
        : null;
    case "requested":
      return request !== null && requestedBy !== null && approvedBy === null
        ? { state, request, requestedBy, approvedBy }
        : null;
    case "active":
      return request !== null && requestedBy !== null && approvedBy !== null
        ? { state, request, requestedBy, approvedBy }
        : null;
    default:
      return null;
  }
}

/** The identity verification state of the signed-in person. */
export type VerificationStatus = "unverified" | "pending" | "verified";

/** Reads `{status}` of `GET /api/v1/me/verification`. Null otherwise. */
export function readVerification(body: unknown): VerificationStatus | null {
  const s = record(body)?.["status"];
  return s === "unverified" || s === "pending" || s === "verified" ? s : null;
}

/** The tenant settings the cell may change in M4 (`fstp_tenant::TenantParam`). */
export const SETTINGS = ["p20", "p69", "p70", "p71", "p72", "p74"] as const;

/** One tenant setting. */
export type SettingParam = (typeof SETTINGS)[number];

/** Whether `s` names a tenant setting. */
export function isSetting(s: string): s is SettingParam {
  return (SETTINGS as readonly string[]).includes(s);
}

/** The P-20 payment modes. */
export const PAYMENT_MODES = ["record_only", "execution"] as const;
/** The P-70 login methods. Passkeys are always on. */
export const LOGIN_METHODS = ["passkey", "eudi_wallet", "opaque", "magic_link"] as const;

/**
 * Reads `{p20, p69, p70, p71, p72, p74}` of `GET /api/v1/admin/settings`,
 * each in the `fstp-tenant` codec form or null when unset. Null when the
 * body is not an object.
 */
export function readSettings(body: unknown): Readonly<Record<SettingParam, unknown>> | null {
  const o = record(body);
  if (o === null) return null;
  const out: Record<string, unknown> = {};
  for (const p of SETTINGS) {
    out[p] = Object.hasOwn(o, p) ? o[p] : null;
  }
  return out as Readonly<Record<SettingParam, unknown>>;
}

/** A whole number of seconds, as a person enters it. */
const SECONDS = /^(0|[1-9][0-9]{0,11})$/;

/**
 * Microseconds as a decimal string, from whole seconds typed by a
 * person. Null for anything else. Integer arithmetic only.
 */
export function secondsToMicros(text: string): string | null {
  const t = text.trim();
  if (!SECONDS.test(t)) return null;
  return (BigInt(t) * 1_000_000n).toString();
}

/**
 * Whole seconds from a microsecond decimal string, or null when the
 * value is not a whole number of seconds.
 */
export function microsToSeconds(v: unknown): string | null {
  if (typeof v !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(v)) return null;
  const us = BigInt(v);
  return us % 1_000_000n === 0n ? (us / 1_000_000n).toString() : null;
}

/** Compares two strings by UTF-16 code unit, as `fstp-tenant` compares ASCII names. */
function byCodeUnit(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * The names of a checkbox group as a `fstp-tenant` name set: strictly
 * ascending by code unit, each name once. The codec (`take_name_set`)
 * refuses any other order, so every set a page sends goes through here.
 */
export function nameSet(names: Iterable<string>): string[] {
  const out: string[] = [];
  for (const n of [...names].sort(byCodeUnit)) {
    if (out[out.length - 1] !== n) out.push(n);
  }
  return out;
}

/** An account id as the codec takes it: decimal digits with no leading zero. */
const ACCOUNT = /^(0|[1-9][0-9]{0,38})$/;

/**
 * Account ids as a `fstp-tenant` account set: strictly ascending by
 * numeric value, each id once (`take_accounts`). Null when an id is not
 * a decimal account id, so a page never sends a set the codec refuses.
 */
export function accountSet(ids: Iterable<string>): string[] | null {
  const all = [...ids];
  if (!all.every((x) => ACCOUNT.test(x))) return null;
  const nums = all.map((x) => BigInt(x)).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const out: string[] = [];
  for (const n of nums) {
    const s = n.toString();
    if (out[out.length - 1] !== s) out.push(s);
  }
  return out;
}

/**
 * One key per `fstp_domain::roles::Role`, in the order of `Role::ALL`.
 * P-74 limits the MCP server to some of these roles. The key names the
 * role's label and control id. The wire spelling is `roleSpecName(key)`.
 */
export const MCP_ROLES = [
  "programme_manager",
  "call_drafter",
  "fstp_coordinator",
  "committee_member",
  "committee_chair",
  "irc_member",
  "applicant",
  "applicant_team_member",
  "guardian",
  "tenant_admin",
  "finance_approver",
  "payment_releaser",
  "contract_signatory",
  "financial_signatory",
  "legal_signatory",
  "auditor",
] as const;

/** One role of `MCP_ROLES`. */
export type McpRole = (typeof MCP_ROLES)[number];

/** The words of a role key that `Role::spec_name` spells in capitals. */
const ACRONYMS: ReadonlySet<string> = new Set(["fstp", "irc"]);

/**
 * The spelling `fstp_domain::roles::Role::spec_name` gives the role of
 * `key`, which the `fstp-tenant` codec uses for P-74 roles: words apart,
 * the first capitalised, the acronyms FSTP and IRC in capitals.
 */
export function roleSpecName(key: McpRole): string {
  return key
    .split("_")
    .map((w, i) => (ACRONYMS.has(w) ? w.toUpperCase() : i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(" ");
}

/** The role key whose spec name is `name`, or null for a name no role has. */
export function roleOfSpecName(name: string): McpRole | null {
  return MCP_ROLES.find((k) => roleSpecName(k) === name) ?? null;
}

/** The P-74 value as the page edits it (`fstp_tenant::McpSettings`). */
export interface McpValue {
  readonly enabled: boolean;
  readonly public_tools: boolean;
  /** Null means every role. A list, even an empty one, limits the server to those roles. */
  readonly roles: readonly string[] | null;
}

/**
 * The P-74 value to send. `everyRole` is the person's explicit choice:
 * true sends `roles: null`, false sends the chosen roles as a name set,
 * possibly empty. No other input is ever read as every role.
 */
export function mcpValue(enabled: boolean, publicTools: boolean, everyRole: boolean, roles: Iterable<string>): McpValue {
  return { enabled, public_tools: publicTools, roles: everyRole ? null : nameSet(roles) };
}
