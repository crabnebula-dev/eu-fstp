// The model of the platform mailbox (lane m6/mailbox,
// `docs/handoff/mailbox-design.md`): the closed reader of the
// `me.mailbox` reply, the route of each kind and the label of each
// message.
//
// A message carries ids, a kind, optional instants, a flag and a path
// under `/app/` (I-27, I-86). The page shows a label from the catalogue
// for its kind and links to the path. It never shows text from the
// server, so no proposal content can reach the mailbox page.
//
// This module is pure: it reads values that `JSON.parse` produced and
// builds plain data. It holds no DOM code and no network code.

/** The kinds of a message, as `fstp_access::MAILBOX_KINDS` spells them. */
export const MAIL_KINDS = [
  "pending.confirm",
  "proposal.submit",
  "stage2.respond",
  "negotiation.acknowledge",
  "review.declare",
  "review.score",
  "irc.declare",
  "irc.review",
  "intake.knock_out",
  "round.vote",
  "admin.approve_activation",
  "contract.sign",
  "payment.review",
  "payment.approve",
  "payment.release",
  "payment.confirm",
  "notice.outcome",
  "notice.irc_concern",
] as const;

/** One kind. */
export type MailKind = (typeof MAIL_KINDS)[number];

/**
 * The page of each kind, as `fstp_api_core::mailbox::MAILBOX_ROUTES`
 * names it. Each `{name}` is an id of the message.
 */
export const MAILBOX_ROUTES: Readonly<Record<MailKind, string>> = Object.freeze({
  "pending.confirm": "/app/pending/{pending}",
  "proposal.submit": "/app/proposals/{proposal}/submit",
  "stage2.respond": "/app/proposals/{proposal}/stage2",
  "negotiation.acknowledge": "/app/proposals/{proposal}/negotiation",
  "review.declare": "/app/assignments/{assignment}",
  "review.score": "/app/assignments/{assignment}",
  "irc.declare": "/app/irc-assignments/{assignment}",
  "irc.review": "/app/irc-assignments/{assignment}",
  "intake.knock_out": "/app/calls/{call}/intake",
  "round.vote": "/app/cut-off-rounds/{round}",
  "admin.approve_activation": "/app/admin/approvals",
  "contract.sign": "/app/grants/{proposal}/contract",
  "payment.review": "/app/operations",
  "payment.approve": "/app/operations",
  "payment.release": "/app/operations",
  "payment.confirm": "/app/operations",
  "notice.outcome": "/app/notices",
  "notice.irc_concern": "/app/notices",
});

/**
 * The M5 pages that were not mounted when the mailbox was built (MB-D7).
 * Lane `m5/ui` has merged, so every mailbox route must now be mounted.
 */
export const M5_ROUTES: readonly string[] = Object.freeze([]);

/** The mailbox page and the pending action page. */
export const MAILBOX_PATHS = Object.freeze({
  mailbox: "/app/mailbox",
  pending: (id: string): string => `/app/pending/${id}`,
});

/** The ids a message may name. */
export const ID_MEMBERS = [
  "proposal",
  "call",
  "assignment",
  "round",
  "contract",
  "request",
  "pending",
  "programme",
] as const;

/** One id member. */
export type IdMember = (typeof ID_MEMBERS)[number];

/** One message. */
export interface MailMessage {
  readonly id: string;
  readonly kind: MailKind;
  readonly action: boolean;
  readonly href: string;
  /** When the work arrived, in microseconds, when known. */
  readonly since: string | null;
  /** When it is due or expires, in microseconds, when known. */
  readonly due: string | null;
  /** A notice's own read mark (MB-Q1, ADR-020); null for a work message. */
  readonly read: boolean | null;
  readonly ids: Readonly<Partial<Record<IdMember, string>>>;
}

/** The `me.mailbox` reply. */
export interface Mailbox {
  readonly open: number;
  readonly messages: readonly MailMessage[];
}

type Rec = Readonly<Record<string, unknown>>;

const ID = /^(0|[1-9][0-9]{0,38})$/;

function isId(v: unknown): v is string {
  return typeof v === "string" && ID.test(v);
}

function rec(v: unknown): Rec | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Rec) : null;
}

function isKind(v: unknown): v is MailKind {
  return typeof v === "string" && (MAIL_KINDS as readonly string[]).includes(v);
}

const REQUIRED = ["id", "kind", "action", "href"];
const OPTIONAL = ["since", "due", "read", ...ID_MEMBERS];

/**
 * Whether `href` is the route `pattern` with each `{name}` filled by the
 * message's id of that name.
 */
export function fills(href: string, pattern: string, ids: Readonly<Partial<Record<string, string>>>): boolean {
  const a = href.split("/");
  const b = pattern.split("/");
  if (a.length !== b.length) {
    return false;
  }
  return b.every((seg, i) => {
    const got = a[i];
    if (seg.startsWith("{") && seg.endsWith("}")) {
      const want = ids[seg.slice(1, -1)];
      return want !== undefined && got === want;
    }
    return got === seg;
  });
}

function message(v: unknown): MailMessage | null {
  const o = rec(v);
  if (o === null) {
    return null;
  }
  for (const k of REQUIRED) {
    if (!Object.hasOwn(o, k)) {
      return null;
    }
  }
  if (!Object.keys(o).every((k) => REQUIRED.includes(k) || OPTIONAL.includes(k))) {
    return null;
  }
  const { id, kind, action, href } = o;
  if (typeof id !== "string" || !isKind(kind) || typeof action !== "boolean" || typeof href !== "string") {
    return null;
  }
  const ids: Partial<Record<IdMember, string>> = {};
  for (const k of ID_MEMBERS) {
    if (Object.hasOwn(o, k)) {
      const x = o[k];
      if (!isId(x)) {
        return null;
      }
      ids[k] = x;
    }
  }
  const instant = (k: string): string | null | undefined => {
    if (!Object.hasOwn(o, k)) {
      return null;
    }
    const x = o[k];
    return isId(x) ? x : undefined;
  };
  const since = instant("since");
  const due = instant("due");
  if (since === undefined || due === undefined) {
    return null;
  }
  // MB-Q1, ADR-020: a notice carries its read mark, a work message none.
  const read = Object.hasOwn(o, "read") ? o["read"] : null;
  if (action ? read !== null : typeof read !== "boolean") {
    return null;
  }
  // The page must be the route of the kind, filled with the message's
  // own ids, so no reply can send a person elsewhere.
  if (!fills(href, MAILBOX_ROUTES[kind], ids)) {
    return null;
  }
  return Object.freeze({ id, kind, action, href, since, due, read: read as boolean | null, ids: Object.freeze(ids) });
}

/**
 * The `me.mailbox` reply, or null when `v` does not fit its closed
 * shape: `{open, messages}`, every message closed, every id decimal,
 * every page the route of its kind, and `open` the number of messages to
 * act on.
 */
export function readMailbox(v: unknown): Mailbox | null {
  const o = rec(v);
  if (o === null || Object.keys(o).length !== 2 || !Object.hasOwn(o, "open") || !Object.hasOwn(o, "messages")) {
    return null;
  }
  const open = o["open"];
  const list = o["messages"];
  if (typeof open !== "number" || !Number.isSafeInteger(open) || open < 0 || !Array.isArray(list)) {
    return null;
  }
  const out: MailMessage[] = [];
  for (const x of list as readonly unknown[]) {
    const m = message(x);
    if (m === null) {
      return null;
    }
    out.push(m);
  }
  if (out.filter((m) => m.action).length !== open) {
    return null;
  }
  return Object.freeze({ open, messages: Object.freeze(out) });
}

/** The catalogue key of a message's label: `mailbox.kind.<kind>`. */
export function labelKey(kind: MailKind): string {
  return `mailbox.kind.${kind}`;
}

/**
 * The catalogue arguments of a message's label: the ids that `template`
 * names as `{name}`, and no other, since the catalogue refuses an
 * argument its message does not use.
 */
export function labelArgs(m: MailMessage, template: string): Readonly<Record<string, string>> {
  const args: Record<string, string> = {};
  for (const k of ID_MEMBERS) {
    const v = m.ids[k];
    if (v !== undefined && template.includes(`{${k}}`)) {
      args[k] = v;
    }
  }
  return Object.freeze(args);
}

/** The work messages and the notices, each in reply order. */
export function split(b: Mailbox): { readonly work: readonly MailMessage[]; readonly notices: readonly MailMessage[] } {
  return {
    work: Object.freeze(b.messages.filter((m) => m.action)),
    notices: Object.freeze(b.messages.filter((m) => !m.action)),
  };
}

/** The UTC day `YYYY-MM-DD` of an instant in microseconds, or null. */
export function dayOf(micros: string | null): string | null {
  if (micros === null) {
    return null;
  }
  const ms = Number(BigInt(micros) / 1000n);
  if (!Number.isFinite(ms)) {
    return null;
  }
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}
