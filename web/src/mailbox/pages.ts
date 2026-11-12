// The mailbox page `/app/mailbox` and the prepared action page
// `/app/pending/{id}` (lane m6/mailbox, `docs/handoff/mailbox-design.md`
// sections 1 to 4).
//
// The mailbox lists the caller's work first, then the notices. Each item
// is a catalogue label built from its kind and ids, and one link to the
// page where the work happens. Nothing the server sends is shown as
// text, only ids, so no proposal content reaches this page (I-27).
//
// The prepared action page shows one action an agent prepared (I-85):
// its operation name, the canonical request exactly as a confirmation
// replays it, as untrusted plain text (TW-9), and its expiry. Confirm
// sends the digest the person saw and runs the step-up dialog of the
// creator pages; Discard closes it. Every element is built with `h`, so
// no string reaches an HTML parser (ADR-014).

import { frame, run, showFailure, type Frame } from "../applicant/ui.js";
import type { Failure } from "../applicant/client.js";
import { createApi, type ApiClient, type ApiOutcome } from "../core/api.js";
import { h } from "../core/dom.js";
import { createI18n, type I18n, type Label } from "../core/i18n.js";
import { anyObject, call as command } from "../creator/ops.js";
import { OPERATIONS, VALIDATORS } from "../gen/api.js";
import { MAILBOX_LABELS } from "./messages.en.js";
import { type MailMessage, type Mailbox, MAILBOX_PATHS, dayOf, labelArgs, labelKey, readMailbox, split } from "./model.js";

let catalogue: I18n | null = null;

/** The mailbox interface string `id`. */
export function mailboxLabel(id: string, args?: Readonly<Record<string, string>>): Label {
  catalogue ??= createI18n({ catalogues: [{ locale: "en", labels: MAILBOX_LABELS, approved: {} }], locale: "en" });
  return catalogue.label(id, args);
}

let client: ApiClient | null = null;

function api(): ApiClient {
  client ??= createApi({ fetch: (input, init) => globalThis.fetch(input, init) });
  return client;
}

type Read<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly failure: Failure };

function failureOf(o: ApiOutcome): Failure {
  switch (o.kind) {
    case "refused":
      return { kind: "refused", code: o.code, rule: o.rule };
    case "failed":
      return { kind: "failed", reason: o.reason };
    case "step_up_required":
    case "strong_method_required":
      return { kind: "step_up" };
    case "pending":
      return { kind: "pending" };
    default:
      return { kind: "failed", reason: "invalid_response" };
  }
}

/** Calls read `name` and decodes its reply through the generated validator and `decode`. It never throws. */
async function read<T>(name: "me.mailbox" | "pending.list", decode: (v: unknown) => T | null): Promise<Read<T>> {
  const op = OPERATIONS.find((o) => o.name === name);
  const check = VALIDATORS[name];
  if (op === undefined || op.base === "page" || check === undefined) {
    return { ok: false, failure: { kind: "unavailable" } };
  }
  const box: { value: T | null } = { value: null };
  let o: ApiOutcome;
  try {
    o = await api().call(op, {}, undefined, (v) => {
      box.value = check(v) ? decode(v) : null;
      return box.value !== null;
    });
  } catch {
    return { ok: false, failure: { kind: "failed", reason: "network" } };
  }
  return o.kind === "done" && box.value !== null ? { ok: true, value: box.value } : { ok: false, failure: failureOf(o) };
}

/** The caller's mailbox. It never throws. */
export function readMyMailbox(): Promise<Read<Mailbox>> {
  return read("me.mailbox", readMailbox);
}

let counted: Promise<number | null> | null = null;

/** The number of messages to act on, read once per page load, or null. */
export function mailboxCount(): Promise<number | null> {
  counted ??= readMyMailbox()
    .then((r) => (r.ok ? r.value.open : null))
    .catch(() => null);
  return counted;
}

/** One message as a list item. */
function item(m: MailMessage): HTMLElement {
  const meta: string[] = [];
  const since = dayOf(m.since);
  if (since !== null) {
    meta.push(mailboxLabel("mailbox.since", { day: since }));
  }
  const due = dayOf(m.due);
  if (due !== null) {
    meta.push(mailboxLabel("mailbox.due", { day: due }));
  }
  const kids: HTMLElement[] = [
    h("p", { class: "mailbox-what" }, [h("a", { href: m.href, "data-mail-link": m.kind }, [mailboxLabel(labelKey(m.kind), labelArgs(m, MAILBOX_LABELS[labelKey(m.kind)] ?? ""))])]),
  ];
  if (meta.length > 0) {
    kids.push(h("p", { class: "fstp-meta" }, [meta.join(" · ")]));
  }
  return h("li", { "data-mail": m.id, "data-kind": m.kind, class: m.action ? "mailbox-item mailbox-item--work" : "mailbox-item" }, kids);
}

/** Mounts the mailbox page. */
export function mountMailbox(): void {
  const f = frame(mailboxLabel("mailbox.title"));
  f.main.append(h("p", { class: "muted" }, [mailboxLabel("mailbox.intro")]));
  run(f, async () => {
    const r = await readMyMailbox();
    if (!r.ok) {
      showFailure(f, r.failure);
      return;
    }
    const { work, notices } = split(r.value);
    f.main.append(
      h("section", { id: "mailbox-work", "aria-labelledby": "mailbox-work-title" }, [
        h("h2", { id: "mailbox-work-title" }, [mailboxLabel("mailbox.work"), " ", h("span", { class: "badge badge--info", "data-open": String(r.value.open) }, [String(r.value.open)])]),
        work.length === 0
          ? h("p", { id: "mailbox-empty" }, [mailboxLabel("mailbox.empty")])
          : h("ul", { id: "mailbox-list", class: "fstp-list" }, work.map(item)),
      ]),
      h("section", { id: "mailbox-notices", "aria-labelledby": "mailbox-notices-title" }, [
        h("h2", { id: "mailbox-notices-title" }, [mailboxLabel("mailbox.notices")]),
        notices.length === 0
          ? h("p", {}, [mailboxLabel("mailbox.no_notices")])
          : h("ul", { id: "mailbox-notice-list", class: "fstp-list" }, notices.map(item)),
      ]),
    );
  });
}

// ---------------------------------------------------------------------------
// The prepared action page
// ---------------------------------------------------------------------------

/** One pending action as `pending.list` gives it, to its own account. */
export interface PendingAction {
  readonly id: string;
  readonly op: string;
  readonly request: string;
  readonly digest: string;
  readonly expires: string;
  readonly status: "open" | "confirmed" | "expired" | "discarded";
}

const STATUSES = ["open", "confirmed", "expired", "discarded"] as const;

/** The `pending.list` reply, or null when it does not fit. */
export function readPendingList(v: unknown): readonly PendingAction[] | null {
  if (!Array.isArray(v)) {
    return null;
  }
  const out: PendingAction[] = [];
  for (const x of v as readonly unknown[]) {
    if (typeof x !== "object" || x === null || Array.isArray(x)) {
      return null;
    }
    const o = x as Readonly<Record<string, unknown>>;
    const { id, op, request, digest, expires, status } = o;
    if (
      typeof id !== "string" ||
      typeof op !== "string" ||
      typeof request !== "string" ||
      typeof digest !== "string" ||
      !/^[0-9a-f]{64}$/.test(digest) ||
      typeof expires !== "string" ||
      typeof status !== "string" ||
      !(STATUSES as readonly string[]).includes(status)
    ) {
      return null;
    }
    out.push(Object.freeze({ id, op, request, digest, expires, status: status as PendingAction["status"] }));
  }
  return Object.freeze(out);
}

function back(): HTMLElement {
  return h("p", {}, [h("a", { href: MAILBOX_PATHS.mailbox, "data-mail-back": "" }, [mailboxLabel("pending.back")])]);
}

function say(f: Frame, key: string): void {
  f.alert.textContent = mailboxLabel(key);
  f.alert.hidden = false;
}

/** Mounts the page of pending action `id`. */
export function mountPendingAction(id: string): void {
  const f = frame(mailboxLabel("pending.title"));
  f.main.append(h("p", { class: "muted" }, [mailboxLabel("pending.intro")]));
  run(f, async () => {
    const r = await read("pending.list", readPendingList);
    if (!r.ok) {
      showFailure(f, r.failure);
      return;
    }
    const a = r.value.find((x) => x.id === id);
    if (a === undefined) {
      say(f, "pending.not_found");
      f.main.append(back());
      return;
    }
    const status = h("p", { id: "pending-status", role: "status", "data-status": a.status }, [a.status]);
    // TW-9: the request is untrusted text, shown as text only.
    const request = h("pre", { id: "pending-request", class: "pending-request" }, [a.request]);
    const details = h("dl", { class: "pending-details" }, [
      h("dt", {}, [mailboxLabel("pending.op")]),
      h("dd", { id: "pending-op" }, [a.op]),
      h("dt", {}, [mailboxLabel("pending.expires")]),
      h("dd", {}, [dayOf(a.expires) ?? a.expires]),
      h("dt", {}, [mailboxLabel("pending.status")]),
      h("dd", {}, [status]),
    ]);
    f.main.append(details, h("h2", {}, [mailboxLabel("pending.request")]), request);
    if (a.status !== "open") {
      say(f, "pending.closed");
      f.main.append(back());
      return;
    }
    const confirm = h("button", { type: "button", class: "btn btn--primary", "data-pending": "confirm" }, [mailboxLabel("pending.confirm")]);
    const discard = h("button", { type: "button", class: "btn", "data-pending": "discard" }, [mailboxLabel("pending.discard")]);
    const finish = (key: string, next: string): void => {
      confirm.remove();
      discard.remove();
      status.textContent = next;
      status.setAttribute("data-status", next);
      say(f, key);
    };
    confirm.addEventListener("click", () => {
      void command("pending.confirm", [a.id], { shown: a.digest }, anyObject).then((o) => {
        if (o.kind === "done") {
          finish("pending.done", "confirmed");
        } else {
          say(f, "pending.failed");
        }
      });
    });
    discard.addEventListener("click", () => {
      void command("pending.discard", [a.id], {}, anyObject).then((o) => {
        if (o.kind === "done") {
          finish("pending.discarded", "discarded");
        } else {
          say(f, "pending.failed");
        }
      });
    });
    f.main.append(h("p", { class: "btn-row" }, [confirm, " ", discard]), back());
  });
}
