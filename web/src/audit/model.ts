// The audit log of a programme (R-AU-01, I-24, ADR-007, ADR-022,
// ADR-023): the reply checks and the pure helpers of the page.
//
// - `audit.entries` gives the programme's ledger entries, newest first,
//   to its auditor. A row names texts by id only (ADR-007), and an
//   account by its id and its role in the programme.
// - `audit.unmasks` gives the unmask records to the auditor and the
//   tenant admins (ADR-023 reading 11).
// - `audit.vault_outcomes` gives the vault answers the programme's
//   decisions used, by digest and answer bit only (overview NOTE 5).

import { isBool, isId, isText, list, nullable, oneOf, record, type Guard } from "../reviewer/kit.js";

/** The side of a ledger entry. */
export type Side = "core" | "finding" | "creator" | "import" | "onboarding" | "contract" | "report";

/** What an audit row acts on. */
export type ObjectType = "proposal" | "call" | "assignment" | "binding" | "request" | "decision" | "programme";

/** One ledger entry of the audit log. */
export interface AuditRow {
  readonly seq: string;
  readonly at: string;
  readonly side: Side;
  readonly kind: string;
  readonly actor: string | null;
  readonly actor_role: string;
  readonly object_type: ObjectType | null;
  readonly object: string | null;
  readonly texts: readonly string[];
  readonly hash: string;
}

/** `audit.entries`. */
export interface AuditLog {
  readonly programme: string;
  readonly entries: readonly AuditRow[];
}

/** One unmask record of `audit.unmasks` (ADR-023). */
export interface UnmaskRow {
  readonly party: string;
  readonly subject_type: string;
  readonly subject: string;
  readonly by: string;
  readonly purpose: string;
  readonly at: string;
}

/** `audit.unmasks`. */
export interface Unmasks {
  readonly unmasks: readonly UnmaskRow[];
}

/** One vault answer of `audit.vault_outcomes`. */
export interface OutcomeRow {
  readonly seq: string;
  readonly at: string;
  readonly query: string;
  readonly digest: string;
  readonly holds: boolean;
  readonly epoch: string;
}

/** `audit.vault_outcomes`. */
export interface Outcomes {
  readonly programme: string;
  readonly outcomes: readonly OutcomeRow[];
}

const isSide = oneOf<Side>("core", "finding", "creator", "import", "onboarding", "contract", "report");
const isObjectType = oneOf<ObjectType>("proposal", "call", "assignment", "binding", "request", "decision", "programme");

export const isAuditLog: Guard<AuditLog> = record<AuditLog>({
  programme: isId,
  entries: list(
    record<AuditRow>({
      seq: isId,
      at: isId,
      side: isSide,
      kind: isText,
      actor: nullable(isId),
      actor_role: isText,
      object_type: nullable(isObjectType),
      object: nullable(isId),
      texts: list(isId),
      hash: isText,
    }),
  ),
});

export const isUnmasks: Guard<Unmasks> = record<Unmasks>({
  unmasks: list(
    record<UnmaskRow>({
      party: isText,
      subject_type: isText,
      subject: isId,
      by: isId,
      purpose: isText,
      at: isId,
    }),
  ),
});

export const isOutcomes: Guard<Outcomes> = record<Outcomes>({
  programme: isId,
  outcomes: list(
    record<OutcomeRow>({
      seq: isId,
      at: isId,
      query: isText,
      digest: isText,
      holds: isBool,
      epoch: isId,
    }),
  ),
});

/** The record kinds the page names in words. Any other kind shows as its record name. */
export const KIND_LABELS: Readonly<Record<string, string>> = Object.freeze({
  BindingGranted: "audit.kind.binding_granted",
  BindingEnded: "audit.kind.binding_ended",
  BindingSuspended: "audit.kind.binding_suspended",
  BindingReinstated: "audit.kind.binding_reinstated",
  BindingVoided: "audit.kind.binding_voided",
  ActivationRequested: "audit.kind.activation_requested",
  ActivationApproved: "audit.kind.activation_approved",
  ActivationOverridden: "audit.kind.activation_overridden",
  ProgrammeActivated: "audit.kind.programme_activated",
  PartyUnmasked: "audit.kind.party_unmasked",
  Transitioned: "audit.kind.transitioned",
  ScoreRecorded: "audit.kind.score_recorded",
  ConflictDeclared: "audit.kind.conflict_declared",
  ContentRead: "audit.kind.content_read",
  CallDrafted: "audit.kind.call_drafted",
  CallApproved: "audit.kind.call_approved",
  CallPublished: "audit.kind.call_published",
  PolicyVersionRecorded: "audit.kind.policy_version",
  PaymentRequested: "audit.kind.payment_requested",
  PaymentApproved: "audit.kind.payment_approved",
  PaymentReleased: "audit.kind.payment_released",
});

/** The UTC minute of `micros`, a decimal of UTC microseconds, as `2026-11-01 09:12 UTC`, or null. */
export function utcMinute(micros: string): string | null {
  if (!/^-?[0-9]{1,16}$/.test(micros)) {
    return null;
  }
  const ms = Math.floor(Number(micros) / 1000);
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) {
    return null;
  }
  const iso = d.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

/** The first eight characters of a hex hash and an ellipsis, as the prototype shows it. */
export function shortHash(hash: string): string {
  return hash.length > 8 ? `${hash.slice(0, 8)}…` : hash;
}

/** The distinct record kinds of `rows`, sorted, for the event type filter. */
export function kindsOf(rows: readonly AuditRow[]): readonly string[] {
  return [...new Set(rows.map((r) => r.kind))].sort();
}

/** The rows of `kind`, or every row for the empty kind, in the order given. */
export function filterRows(rows: readonly AuditRow[], kind: string): readonly AuditRow[] {
  return kind === "" ? rows : rows.filter((r) => r.kind === kind);
}
