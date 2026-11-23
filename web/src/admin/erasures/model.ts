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

/** Who authorised an erasure, as `fstp_access::ERASURE_AUTHORISERS` names them (ADR-007, Daniel 2026-11-23, lane L39). Never which account (R-CF-03). */
export const ERASURE_AUTHORISERS = ["system", "account"] as const;

/** One authoriser. */
export type ErasureAuthoriser = (typeof ERASURE_AUTHORISERS)[number];

/** The media types of an import document, as `fstp_access::IMPORT_MEDIA` names them. */
export const IMPORT_MEDIA = ["text/plain", "text/markdown"] as const;

/** The longest stated reason, in characters (`fstp_api_core::erasure::MAX_REASON`, lane L39). */
export const MAX_REASON = 500;

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
  /** Whether the system or an account authorised it (lane L39). */
  readonly authoriser: ErasureAuthoriser;
  /** The reason a tenant admin stated, if any (lane L39). */
  readonly reason: string | null;
}

/** One grant whose retention ended. */
export interface RetentionEnded {
  readonly grant: string;
  readonly programme: string;
  readonly start: string;
  readonly end: string;
}

/** One import document a tenant admin may erase (lane L39). */
export interface DocumentRow {
  readonly document: string;
  readonly programme: string;
  readonly media: string;
  readonly erased: boolean;
}

/** The `admin.erasures` reply. */
export interface ErasuresReply {
  readonly erasures: readonly ErasureEntry[];
  readonly retentionEnded: readonly RetentionEnded[];
  readonly documents: readonly DocumentRow[];
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
  const { text, cause, grant, requested_at: requestedAt, completed_at: completedAt, kind, destroyed_epoch: destroyedEpoch, authoriser, reason } = o;
  if (!isId(text) || !isCause(cause) || !isId(requestedAt)) return null;
  if (grant !== null && !isId(grant)) return null;
  if (completedAt !== null && !isId(completedAt)) return null;
  if (typeof kind !== "string" || !(ERASURE_KINDS as readonly string[]).includes(kind)) return null;
  if (destroyedEpoch !== null && !isId(destroyedEpoch)) return null;
  if (typeof authoriser !== "string" || !(ERASURE_AUTHORISERS as readonly string[]).includes(authoriser)) return null;
  if (reason !== null && typeof reason !== "string") return null;
  return Object.freeze({
    text,
    cause,
    grant,
    requestedAt,
    completedAt,
    kind: kind as ErasureKind,
    destroyedEpoch,
    authoriser: authoriser as ErasureAuthoriser,
    reason,
  });
}

function documentRow(v: unknown): DocumentRow | null {
  const o = record(v);
  if (o === null) return null;
  const { document, programme, media, erased } = o;
  if (!isId(document) || !isId(programme) || typeof erased !== "boolean") return null;
  if (typeof media !== "string" || !(IMPORT_MEDIA as readonly string[]).includes(media)) return null;
  return Object.freeze({ document, programme, media, erased });
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
  if (o === null || !Array.isArray(o["erasures"]) || !Array.isArray(o["retention_ended"]) || !Array.isArray(o["documents"])) return null;
  const erasures = (o["erasures"] as unknown[]).map(entry);
  const retentionEnded = (o["retention_ended"] as unknown[]).map(ended);
  const documents = (o["documents"] as unknown[]).map(documentRow);
  if (erasures.some((e) => e === null) || retentionEnded.some((e) => e === null) || documents.some((d) => d === null)) return null;
  return Object.freeze({
    erasures: Object.freeze(erasures as ErasureEntry[]),
    retentionEnded: Object.freeze(retentionEnded as RetentionEnded[]),
    documents: Object.freeze(documents as DocumentRow[]),
  });
}

/** The `admin.request_erasure` body, or null for an unknown cause or a grant that is no id. */
export function requestBody(cause: string, grant: string): { readonly cause: ErasureCause; readonly grant: string } | null {
  if (!isCause(cause) || !isId(grant)) return null;
  return Object.freeze({ cause, grant });
}

/**
 * The `admin.erase_document` body (ADR-007, Daniel 2026-11-23, lane L39): the
 * reason trimmed, of 1 to MAX_REASON characters with no control character,
 * or null.
 */
export function eraseBody(reason: string): { readonly reason: string } | null {
  const t = reason.trim();
  const n = [...t].length;
  if (n < 1 || n > MAX_REASON || /\p{Cc}/u.test(t)) return null;
  return Object.freeze({ reason: t });
}

/** `YYYY-MM-DD` of an instant in UTC microseconds, or the decimal text when it is out of range. */
export function dayOf(micros: string): string {
  const ms = Number(BigInt(micros) / 1000n);
  const d = new Date(ms);
  return Number.isFinite(d.getTime()) ? d.toISOString().slice(0, 10) : micros;
}
