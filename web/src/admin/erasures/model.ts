// The pure part of the tenant admin's erasure page (P-41, ADR-007;
// Daniel, 2026-11-15 late; lane m5/retention).
//
// - `admin.erasures` answers `{erasures, retention_ended}`: each erased
//   text with its cause, the grant it served and its times, and each
//   grant whose funder retention ended. Ids, causes and instants only
//   (I-27). An instant is a decimal string of UTC microseconds.
// - `admin.request_erasure` takes `{cause, grant}`. The cell refuses a
//   grant whose retention has not ended (P-41), and asks for a step-up.

/** The erasure causes of ADR-007, as `fstp_access::ERASURE_CAUSES` names them. */
export const ERASURE_CAUSES = ["retention_expiry", "erasure_request", "cell_erasure", "verification_completed"] as const;

/** One cause. */
export type ErasureCause = (typeof ERASURE_CAUSES)[number];

/** What an erased text held, as `fstp_access::ERASURE_KINDS` names them (ADR-007, lanes L33 and L37). */
export const ERASURE_KINDS = ["text", "display_name", "document"] as const;

/** One kind. */
export type ErasureKind = (typeof ERASURE_KINDS)[number];

/** One erasure-log row. */
export interface ErasureEntry {
  readonly text: string;
  readonly cause: ErasureCause;
  readonly grant: string | null;
  readonly requestedAt: string;
  readonly completedAt: string | null;
  /** What the text held (lane L33). */
  readonly kind: ErasureKind;
  /** The root epoch whose destruction completed the erasure, once known (I-81). */
  readonly destroyedEpoch: string | null;
}

/** One grant whose retention ended. */
export interface RetentionEnded {
  readonly grant: string;
  readonly programme: string;
  readonly start: string;
  readonly end: string;
}

/** The `admin.erasures` reply. */
export interface ErasuresReply {
  readonly erasures: readonly ErasureEntry[];
  readonly retentionEnded: readonly RetentionEnded[];
}

const ID = /^(0|[1-9][0-9]{0,38})$/;

function isId(v: unknown): v is string {
  return typeof v === "string" && ID.test(v);
}

function isCause(v: unknown): v is ErasureCause {
  return typeof v === "string" && (ERASURE_CAUSES as readonly string[]).includes(v);
}

function record(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Readonly<Record<string, unknown>>) : null;
}

function entry(v: unknown): ErasureEntry | null {
  const o = record(v);
  if (o === null) return null;
  const { text, cause, grant, requested_at: requestedAt, completed_at: completedAt, kind, destroyed_epoch: destroyedEpoch } = o;
  if (!isId(text) || !isCause(cause) || !isId(requestedAt)) return null;
  if (grant !== null && !isId(grant)) return null;
  if (completedAt !== null && !isId(completedAt)) return null;
  if (typeof kind !== "string" || !(ERASURE_KINDS as readonly string[]).includes(kind)) return null;
  if (destroyedEpoch !== null && !isId(destroyedEpoch)) return null;
  return Object.freeze({ text, cause, grant, requestedAt, completedAt, kind: kind as ErasureKind, destroyedEpoch });
}

function ended(v: unknown): RetentionEnded | null {
  const o = record(v);
  if (o === null) return null;
  const { grant, programme, start, end } = o;
  if (!isId(grant) || !isId(programme) || !isId(start) || !isId(end)) return null;
  return Object.freeze({ grant, programme, start, end });
}

/** The `admin.erasures` reply, or null when it has another shape. */
export function decodeErasures(v: unknown): ErasuresReply | null {
  const o = record(v);
  if (o === null || !Array.isArray(o["erasures"]) || !Array.isArray(o["retention_ended"])) return null;
  const erasures = (o["erasures"] as unknown[]).map(entry);
  const retentionEnded = (o["retention_ended"] as unknown[]).map(ended);
  if (erasures.some((e) => e === null) || retentionEnded.some((e) => e === null)) return null;
  return Object.freeze({
    erasures: Object.freeze(erasures as ErasureEntry[]),
    retentionEnded: Object.freeze(retentionEnded as RetentionEnded[]),
  });
}

/** The `admin.request_erasure` body, or null for an unknown cause or a grant that is no id. */
export function requestBody(cause: string, grant: string): { readonly cause: ErasureCause; readonly grant: string } | null {
  if (!isCause(cause) || !isId(grant)) return null;
  return Object.freeze({ cause, grant });
}

/** `YYYY-MM-DD` of an instant in UTC microseconds, or the decimal text when it is out of range. */
export function dayOf(micros: string): string {
  const ms = Number(BigInt(micros) / 1000n);
  const d = new Date(ms);
  return Number.isFinite(d.getTime()) ? d.toISOString().slice(0, 10) : micros;
}
