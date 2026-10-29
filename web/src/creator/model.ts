// The page logic of the programme creator (R-PG-01, R-PG-03, I-66; M4
// design sections 3.2 and 3.9).
//
// This module is pure: it touches no DOM, so Node can load it. The pages
// in `pages/` call it, and the Node specs of `e2e/creator` test it.
//
// The response readers below are the interim readings of this lane,
// pending Daniel and the generated validators of `web/src/gen/api.ts`
// (lane W3a). Each one accepts exactly the members a page uses and
// refuses a body without them, so a page never acts on a shape it does
// not know.

import { fieldOf, type FieldStep } from "./fields.js";

/** A step of the creator, with its route segment and its number in the spec table. */
export interface CreatorStep {
  readonly id: FieldStep | "review";
  readonly number: number;
}

/** Steps 1 to 10 of `programme-creator.md`, then the review (step 11). */
export const CREATOR_STEPS: readonly CreatorStep[] = [
  { id: "funder", number: 1 },
  { id: "identity", number: 2 },
  { id: "eligibility", number: 3 },
  { id: "funding", number: 4 },
  { id: "evaluation", number: 5 },
  { id: "money", number: 6 },
  { id: "contract", number: 7 },
  { id: "support", number: 8 },
  { id: "people", number: 9 },
  { id: "comms", number: 10 },
  { id: "review", number: 11 },
];

/** The route segment of the review step, which holds no field. */
export const REVIEW_STEP = "review";

/** Whether `s` is the route segment of a creator step, the review included. */
export function isCreatorStep(s: string): s is CreatorStep["id"] {
  return CREATOR_STEPS.some((x) => x.id === s);
}

/** The step after `step`, or null after the review. */
export function nextStep(step: string): CreatorStep["id"] | null {
  const i = CREATOR_STEPS.findIndex((x) => x.id === step);
  const n = i < 0 ? undefined : CREATOR_STEPS[i + 1];
  return n === undefined ? null : n.id;
}

/** The step id of field `<step>.<member>`, or null for a key that names no field. */
export function stepOfField(key: string): string | null {
  return typeof key === "string" ? (fieldOf(key)?.step ?? null) : null;
}

/** One validation result as the review page consumes it. */
export interface GateResult {
  readonly severity: "failure" | "warning";
  readonly acknowledged: boolean;
}

/**
 * Whether the review page offers the activation request (I-66): no
 * failure, and every warning acknowledged. An acknowledgement never
 * clears a failure. The server decides again at the request and at the
 * approval, so this only keeps the page honest.
 */
export function activationGate(results: readonly GateResult[]): {
  readonly canRequest: boolean;
  readonly failures: number;
  readonly unacknowledged: number;
} {
  let failures = 0;
  let unacknowledged = 0;
  for (const r of results) {
    if (r.severity === "failure") {
      failures += 1;
    } else if (r.acknowledged !== true) {
      unacknowledged += 1;
    }
  }
  return { canRequest: failures === 0 && unacknowledged === 0, failures, unacknowledged };
}

/**
 * The step whose page shows a check that names no field or step: the
 * step that holds the values it reads. A check outside this table and
 * without a subject shows on the review page only.
 *
 * Interim, pending Daniel: design section 3.2 gives each check a subject
 * but no wire form for it. This table follows the check catalogue of
 * that section.
 */
const CHECK_HOME: Readonly<Record<string, FieldStep>> = {
  CapAboveCeiling: "money",
  P04MaxAboveP05: "money",
  P39AboveP03: "evaluation",
  ActionDatesInconsistent: "funder",
  ExclusionClassUnknown: "eligibility",
  PrecheckUnavailable: "evaluation",
  AiActReassessment: "evaluation",
  FlowDownMissing: "contract",
  InviteeRefused: "people",
  InviteeWithoutAccount: "people",
  RosterShort: "people",
  ProximityListMissing: "comms",
  ChannelUnreachable: "comms",
};

/** One result of the validation report. */
export interface ReportResult {
  readonly check: string;
  readonly severity: "failure" | "warning";
  readonly acknowledged: boolean;
  /** The key an acknowledgement names. Defaults to the check id. */
  readonly key: string;
  /** The field the result is about, when it names one. */
  readonly field: string | null;
  /** The step the result is about, when it names one. */
  readonly step: string | null;
  /** The values the result names, such as the P-05 and P-58 amounts of `CapAboveCeiling`. */
  readonly values: readonly string[];
}

/** The validation report of one draft revision. */
export interface Report {
  readonly revision: string;
  readonly results: readonly ReportResult[];
}

/** The step page that shows `r`, or null for the review page only. */
export function stepOfResult(r: ReportResult): string | null {
  if (r.field !== null) {
    const s = stepOfField(r.field);
    if (s !== null) return s;
  }
  if (r.step !== null && isCreatorStep(r.step) && r.step !== REVIEW_STEP) {
    return r.step;
  }
  return Object.hasOwn(CHECK_HOME, r.check) ? (CHECK_HOME[r.check] ?? null) : null;
}

/** `v` as a plain object, or null. */
export function record(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Readonly<Record<string, unknown>>) : null;
}

/** An optional string member: absent or null is null, anything else but a string refuses. */
function optString(o: Readonly<Record<string, unknown>>, k: string): string | null | undefined {
  const v = o[k];
  if (v === undefined || v === null) return null;
  return typeof v === "string" ? v : undefined;
}

/**
 * Reads `{revision, results: [{check, severity, acknowledged, key?,
 * field?, step?, detail?}]}`. `detail` is an object of string values,
 * shown as text. Null when the body has another shape.
 */
export function readReport(body: unknown): Report | null {
  const o = record(body);
  if (o === null || typeof o["revision"] !== "string" || !Array.isArray(o["results"])) return null;
  const results: ReportResult[] = [];
  for (const x of o["results"] as unknown[]) {
    const r = record(x);
    if (r === null) return null;
    const check = r["check"];
    const severity = r["severity"];
    const acknowledged = r["acknowledged"];
    if (typeof check !== "string" || check === "") return null;
    if (severity !== "failure" && severity !== "warning") return null;
    if (typeof acknowledged !== "boolean") return null;
    const key = optString(r, "key");
    const field = optString(r, "field");
    const step = optString(r, "step");
    if (key === undefined || field === undefined || step === undefined) return null;
    const values: string[] = [];
    const detail = r["detail"];
    if (detail !== undefined && detail !== null) {
      const d = record(detail);
      if (d === null) return null;
      for (const k of Object.keys(d).sort()) {
        const v = d[k];
        if (typeof v !== "string") return null;
        values.push(v);
      }
    }
    results.push({ check, severity, acknowledged, key: key ?? check, field, step, values });
  }
  return { revision: o["revision"], results };
}

/** The draft as the creator pages read it. */
export interface Draft {
  /** The `fstp.programme/1` spec, with `null` for a gap. */
  readonly spec: Readonly<Record<string, unknown>>;
  readonly revision: string;
  readonly status: "draft" | "active";
  /**
   * Template narrative not yet accepted, by field key (TH-49). The spec
   * holds `null` for such a field until a person accepts or edits it.
   */
  readonly pendingNarratives: Readonly<Record<string, string>>;
  /** Whether an activation request stands at the current revision. */
  readonly activationRequested: boolean;
}

/**
 * Reads `{spec, revision, status, pending_narratives?, activation?}`,
 * where `activation` is `"requested"` while a request stands. Null when
 * the body has another shape.
 *
 * Interim, pending Daniel: `pending_narratives` and `activation` are this
 * lane's names. The spec, revision and status follow the e2e contract.
 */
export function readDraft(body: unknown): Draft | null {
  const o = record(body);
  if (o === null) return null;
  const spec = record(o["spec"]);
  const revision = o["revision"];
  const status = o["status"];
  if (spec === null || typeof revision !== "string" || (status !== "draft" && status !== "active")) return null;
  const pending: Record<string, string> = {};
  const p = o["pending_narratives"];
  if (p !== undefined && p !== null) {
    const r = record(p);
    if (r === null) return null;
    for (const k of Object.keys(r)) {
      const v = r[k];
      if (typeof v !== "string" || fieldOf(k) === null) return null;
      pending[k] = v;
    }
  }
  const activation = o["activation"];
  if (activation !== undefined && activation !== null && typeof activation !== "string") return null;
  return { spec, revision, status, pendingNarratives: pending, activationRequested: activation === "requested" };
}

/** The value of field `key` in a draft spec. A gap or a missing member is null. */
export function draftValue(d: Draft, key: string): unknown {
  const f = fieldOf(key);
  if (f === null) return null;
  const step = record(d.spec[f.step]);
  const v = step === null ? undefined : step[f.member];
  return v === undefined ? null : v;
}

/** A programme id as the routes carry it. */
export const PROGRAMME_ID = /^[0-9A-Za-z_-]{1,64}$/;

/** Whether `s` is a programme id. */
export function isProgrammeId(s: string): boolean {
  return PROGRAMME_ID.test(s);
}

/** A shipped or tenant template the starting point page offers. */
export interface TemplateRow {
  readonly id: string;
  readonly version: number;
  readonly name: string;
}

/** Reads `{templates: [{id, version, name}]}`. Null otherwise. */
export function readTemplates(body: unknown): TemplateRow[] | null {
  const list = record(body)?.["templates"];
  if (!Array.isArray(list)) return null;
  const out: TemplateRow[] = [];
  for (const x of list as unknown[]) {
    const r = record(x);
    const id = r?.["id"];
    const version = r?.["version"];
    const name = r?.["name"];
    if (typeof id !== "string" || !/^[0-9A-Za-z_-]{1,64}$/.test(id)) return null;
    if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) return null;
    if (typeof name !== "string") return null;
    out.push({ id, version, name });
  }
  return out;
}

/** A programme of the tenant, as the clone choice lists it. */
export interface ProgrammeRow {
  readonly id: string;
  readonly name: string;
}

/** Reads `{programmes: [{id, name}]}`. Null otherwise. */
export function readProgrammes(body: unknown): ProgrammeRow[] | null {
  const list = record(body)?.["programmes"];
  if (!Array.isArray(list)) return null;
  const out: ProgrammeRow[] = [];
  for (const x of list as unknown[]) {
    const r = record(x);
    const id = r?.["id"];
    const name = r?.["name"];
    if (typeof id !== "string" || !isProgrammeId(id) || typeof name !== "string") return null;
    out.push({ id, name });
  }
  return out;
}

/** Reads `{programme}` from the answer of opening a draft. Null otherwise. */
export function readOpened(body: unknown): string | null {
  const p = record(body)?.["programme"];
  return typeof p === "string" && isProgrammeId(p) ? p : null;
}

/** One block of a preview document. */
export interface PreviewBlock {
  readonly kind: "heading" | "paragraph" | "item";
  readonly text: string;
}

/**
 * Reads a preview: `{blocks: [{kind, text}]}` with kind `heading`,
 * `paragraph` or `item`, or `{text}`, whose lines become paragraphs. The
 * page shows every block as text, never as markup. Null otherwise.
 */
export function readPreview(body: unknown): PreviewBlock[] | null {
  const o = record(body);
  if (o === null) return null;
  if (typeof o["text"] === "string") {
    return o["text"]
      .split("\n")
      .map((t) => t.trim())
      .filter((t) => t !== "")
      .map((text) => ({ kind: "paragraph" as const, text }));
  }
  const blocks = o["blocks"];
  if (!Array.isArray(blocks)) return null;
  const out: PreviewBlock[] = [];
  for (const x of blocks as unknown[]) {
    const r = record(x);
    const kind = r?.["kind"];
    const text = r?.["text"];
    if ((kind !== "heading" && kind !== "paragraph" && kind !== "item") || typeof text !== "string") return null;
    out.push({ kind, text });
  }
  return out;
}

/** One pending approval of the approval inbox. */
export interface ApprovalRow {
  readonly kind: string;
  readonly programme: string;
  /** The revision the request names, when the list carries it. */
  readonly revision: string | null;
  /**
   * Whether the viewer may approve it. A builder may not (I-67), and an
   * admin may not approve a grant of their own (SoD-07).
   */
  readonly approvable: boolean;
  readonly name: string | null;
  /** The approval id of a self-grant, which `admin.approve_self_grant` names. */
  readonly approval: string | null;
  /** The role a self-grant asks for, as the server spells it. */
  readonly role: string | null;
  /** The pseudonymous handle of the admin who asks for it, never an email. */
  readonly grantee: string | null;
}

/** The approval id of a self-grant row: 1 to 64 URL-safe characters. */
const APPROVAL_ID = /^[0-9A-Za-z_-]{1,64}$/;

/**
 * Reads `{approvals: [{kind, programme, revision?, approvable, name?,
 * approval?, role?, grantee?}]}`. Null otherwise. A `self_grant` row
 * must carry `approval`, `role` and `grantee`.
 *
 * Interim, pending Daniel and lane W3a: the self-grant members are this
 * lane's reading of `TenantCommand::ApproveSelfGrant` and the route
 * `POST /admin/approvals/{a}` (design section 2.2, J2).
 */
export function readApprovals(body: unknown): ApprovalRow[] | null {
  const list = record(body)?.["approvals"];
  if (!Array.isArray(list)) return null;
  const out: ApprovalRow[] = [];
  for (const x of list as unknown[]) {
    const r = record(x);
    if (r === null) return null;
    const kind = r["kind"];
    const programme = r["programme"];
    const approvable = r["approvable"];
    const revision = optString(r, "revision");
    const name = optString(r, "name");
    if (typeof kind !== "string" || typeof programme !== "string" || !isProgrammeId(programme)) return null;
    if (typeof approvable !== "boolean" || revision === undefined || name === undefined) return null;
    const approval = optString(r, "approval");
    const role = optString(r, "role");
    const grantee = optString(r, "grantee");
    if (approval === undefined || role === undefined || grantee === undefined) return null;
    if (approval !== null && !APPROVAL_ID.test(approval)) return null;
    if (kind === "self_grant" && (approval === null || role === null || grantee === null)) return null;
    out.push({ kind, programme, revision, approvable, name, approval, role, grantee });
  }
  return out;
}

/** One evidence span of an import proposal, as text. */
export interface Evidence {
  readonly text: string;
}

/** One import proposal as the import review page shows it. */
export interface ProposalRow {
  readonly id: string;
  readonly field: string;
  readonly value: unknown;
  /** The server's digest of the stored value, which a resolution names as shown. */
  readonly digest: string;
  readonly evidence: readonly Evidence[];
  /** Whether the value conflicts with the funder profile (flagged, never adjusted). */
  readonly flagged: boolean;
  readonly resolution: "confirmed" | "edited" | "dismissed" | null;
}

/**
 * Reads `{proposals: [{id, field, value, digest, evidence: [{text}],
 * flagged, resolution}]}`. Null otherwise. A proposal for a field the
 * schema does not know refuses the whole body.
 */
export function readProposals(body: unknown): ProposalRow[] | null {
  const list = record(body)?.["proposals"];
  if (!Array.isArray(list)) return null;
  const out: ProposalRow[] = [];
  for (const x of list as unknown[]) {
    const r = record(x);
    if (r === null) return null;
    const id = r["id"];
    const field = r["field"];
    const digest = r["digest"];
    const flagged = r["flagged"];
    const resolution = r["resolution"];
    const evidence = r["evidence"];
    if (typeof id !== "string" || !/^[0-9A-Za-z_-]{1,64}$/.test(id)) return null;
    if (typeof field !== "string" || fieldOf(field) === null) return null;
    if (typeof digest !== "string" || typeof flagged !== "boolean" || !Object.hasOwn(r, "value")) return null;
    if (resolution !== null && resolution !== "confirmed" && resolution !== "edited" && resolution !== "dismissed") {
      return null;
    }
    if (!Array.isArray(evidence)) return null;
    const spans: Evidence[] = [];
    for (const e of evidence as unknown[]) {
      const t = record(e)?.["text"];
      if (typeof t !== "string") return null;
      spans.push({ text: t });
    }
    out.push({ id, field, value: r["value"], digest, evidence: spans, flagged, resolution });
  }
  return out;
}

/** Unresolved proposals first, each group in server order. */
export function proposalOrder(rows: readonly ProposalRow[]): ProposalRow[] {
  return [...rows.filter((r) => r.resolution === null), ...rows.filter((r) => r.resolution !== null)];
}

/**
 * The RFC 8785 canonical text of a JSON value of the kinds the creator
 * sends and shows: null, booleans, strings, safe integers, arrays and
 * plain objects. Null for anything else.
 */
export function canonicalJson(v: unknown): string | null {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") return Number.isSafeInteger(v) ? JSON.stringify(v) : null;
  if (Array.isArray(v)) {
    const parts: string[] = [];
    for (const x of v as unknown[]) {
      const c = canonicalJson(x);
      if (c === null) return null;
      parts.push(c);
    }
    return `[${parts.join(",")}]`;
  }
  const o = record(v);
  if (o === null) return null;
  const parts: string[] = [];
  for (const k of Object.keys(o).sort()) {
    const c = canonicalJson(o[k]);
    if (c === null) return null;
    parts.push(`${JSON.stringify(k)}:${c}`);
  }
  return `{${parts.join(",")}}`;
}
