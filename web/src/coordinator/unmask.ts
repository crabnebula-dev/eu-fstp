// The coordinator unmask (ADR-023, I-17 as amended 2026-11-15).
//
// - The FSTP coordinator of a programme may see who any party of it is:
//   the lead, a team member, the guardian, the person behind a reviewer
//   or IRC handle, and staff. Every other role stays masked.
// - Each unmask asks for a purpose, needs a passkey step-up (I-78) and is
//   a ledger record the auditor reads. The page says so before the form.
// - The identity opens on the vault origin only. This page never holds
//   an identity attribute: the cell answers with the vault's release
//   page, and the page opens it only when it is this cell's vault origin.

import { h, type Child } from "../core/dom.js";
import type { I18n } from "../core/i18n.js";
import { ceremony } from "../creator/stepup.js";
import type { ApiOutcome } from "../core/api.js";
import { withStepUp } from "../core/stepup.js";
import {
  buttonEl,
  formEl,
  guarded,
  opRef,
  isId,
  isText,
  list,
  oneOf,
  record,
  textArea,
  whileBusy,
  type Frame,
  type Guard,
  type PageEnv,
  type Problem,
} from "../reviewer/kit.js";

/** The longest purpose, in characters (ADR-023 reading 4). */
export const PURPOSE_LIMIT = 500;

/** A party kind, as the cell spells it. */
export type PartyKind = "applicant" | "team_member" | "guardian" | "reviewer" | "irc" | "staff";

/** How a party is named: by its role binding or its reviewer assignment. */
export type SubjectType = "binding" | "assignment";

/** One party the coordinator may unmask. It names no identity attribute. */
export interface PartyRow {
  readonly party: PartyKind;
  readonly subject_type: SubjectType;
  readonly subject: string;
  readonly role: string;
  readonly label: string;
}

/** `identity.parties`: the parties of one proposal and the staff of its programme. */
export interface Parties {
  readonly programme: string;
  readonly proposal: string;
  readonly parties: readonly PartyRow[];
}

const isParty = oneOf<PartyKind>("applicant", "team_member", "guardian", "reviewer", "irc", "staff");
const isSubjectType = oneOf<SubjectType>("binding", "assignment");

export const isParties: Guard<Parties> = record<Parties>({
  programme: isId,
  proposal: isId,
  parties: list(
    record<PartyRow>({
      party: isParty,
      subject_type: isSubjectType,
      subject: isId,
      role: isText,
      label: isText,
    }),
  ),
});

/** Whether `s` is an admissible purpose: not blank, at most 500 characters. */
export function purposeOk(s: string): boolean {
  return s.trim() !== "" && [...s].length <= PURPOSE_LIMIT;
}

/**
 * The body of `identity.unmask` for the party `kind`/`id` and the
 * purpose `purpose`, or null for a purpose the cell would refuse.
 */
export function unmaskBody(kind: SubjectType, id: string, purpose: string): unknown {
  if (!purposeOk(purpose)) {
    return null;
  }
  // Members in canonical (RFC 8785) order, as the cell's digest reads them.
  const subject = kind === "binding" ? { binding: id, type: "Binding" } : { assignment: id, type: "Assignment" };
  return { purpose, subject };
}

/** Whether `to` is this cell's vault origin: `id.<cell host>` on the page's scheme and port, `/r` with a ticket. */
export function isVaultUrl(to: string, here: { readonly protocol: string; readonly hostname: string; readonly port: string }): boolean {
  let u: URL;
  try {
    u = new URL(to);
  } catch {
    return false;
  }
  return (
    u.protocol === here.protocol &&
    u.username === "" &&
    u.password === "" &&
    u.hostname === `id.${here.hostname}` &&
    u.port === here.port &&
    u.pathname === "/r" &&
    u.search === "" &&
    u.hash.length > 1
  );
}

/** The `{redirect}` of `identity.unmask`, or null. */
function redirectOf(v: unknown): string | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return null;
  }
  const r = (v as Readonly<Record<string, unknown>>)["redirect"];
  return typeof r === "string" ? r : null;
}

/**
 * Sends `identity.unmask` for `programme` with `body`. The cell asks for
 * a step-up (I-78), which the M3 ceremony completes, and the call is sent
 * once more. The answer is the vault origin's release page.
 */
async function sendUnmask(
  env: PageEnv,
  programme: string,
  body: unknown,
): Promise<{ readonly ok: true; readonly to: string } | { readonly ok: false; readonly problem: Problem }> {
  const op = opRef("identity.unmask");
  if (op === null) {
    return { ok: false, problem: { kind: "unavailable" } };
  }
  const box: { to: string | null } = { to: null };
  const validate = (v: unknown): boolean => {
    box.to = redirectOf(v);
    return box.to !== null;
  };
  let o: ApiOutcome;
  try {
    o = await withStepUp(() => env.api.call(op, { programme }, body, validate), {
      ceremony,
      addPasskey: () => env.navigate("/auth/account"),
    });
  } catch {
    return { ok: false, problem: { kind: "failed", reason: "request" } };
  }
  if (o.kind === "done" && box.to !== null) {
    return { ok: true, to: box.to };
  }
  if (o.kind === "done") {
    return { ok: false, problem: { kind: "failed", reason: "invalid_response" } };
  }
  if (o.kind === "refused") {
    return { ok: false, problem: { kind: "refused", code: o.code, rule: o.rule } };
  }
  if (o.kind === "failed") {
    return { ok: false, problem: { kind: "failed", reason: o.reason } };
  }
  return { ok: false, problem: { kind: "unexpected" } };
}

/** The element id stem of the party `kind`/`id`. */
function stem(kind: SubjectType, id: string): string {
  return `unmask-${kind}-${id}`;
}

/**
 * An "Unmask" control for one party. It opens a short form with the
 * purpose and a passkey confirmation, then opens the vault origin's
 * release page in this tab.
 */
export function unmaskControl(
  env: PageEnv,
  t: I18n,
  f: Frame,
  programme: string,
  kind: SubjectType,
  id: string,
  who: string,
): HTMLElement {
  const s = stem(kind, id);
  const open = buttonEl(s, "button", t.label("coord.unmask.open", { who }));
  const holder = h("div", { class: "fstp-unmask", id: `${s}-panel` }, [open]);
  open.addEventListener("click", () => {
    const purpose = textArea(`${s}-purpose`, t.label("coord.unmask.purpose"));
    purpose.control.setAttribute("maxlength", String(PURPOSE_LIMIT));
    const submit = buttonEl(`${s}-submit`, "submit", t.label("coord.unmask.submit"));
    const error = h("p", { id: `${s}-error`, class: "fstp-error", hidden: true });
    const form = formEl(`${s}-form`, [
      h("p", { class: "fstp-hint" }, [t.label("coord.unmask.intro")]),
      purpose.root,
      error,
      submit,
    ]);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      void guarded(f, () =>
        whileBusy(submit, async () => {
          const body = unmaskBody(kind, id, purpose.control.value);
          if (body === null) {
            error.textContent = t.label("coord.unmask.err_purpose", { limit: String(PURPOSE_LIMIT) });
            error.hidden = false;
            purpose.control.focus();
            return;
          }
          error.hidden = true;
          f.clearAlert();
          const r = await sendUnmask(env, programme, body);
          if (!r.ok) {
            f.problem(r.problem);
            return;
          }
          if (!isVaultUrl(r.to, location)) {
            f.alert(t.label("coord.unmask.bad_redirect"));
            return;
          }
          f.status(t.label("coord.unmask.opening"));
          location.assign(r.to);
        }),
      );
    });
    holder.replaceChildren(form);
    purpose.control.focus();
  });
  return holder;
}

/** The plain name of a party row, such as "Applicant (lead)" or a reviewer's handle. */
export function partyName(t: I18n, p: PartyRow, n: number): string {
  if ((p.party === "reviewer" || p.party === "irc") && p.label !== "") {
    return t.label(`coord.unmask.kind_${p.party}_named`, { label: p.label });
  }
  if (p.party === "staff") {
    return t.label("coord.unmask.kind_staff", { role: t.label(`coord.unmask.role_${p.role}`) });
  }
  if (p.party === "applicant" || p.party === "guardian") {
    return t.label(`coord.unmask.kind_${p.party}`);
  }
  return t.label(`coord.unmask.kind_${p.party}`, { n: String(n) });
}

/** The table of `parties`, with an Unmask control on each row. */
export function partiesTable(env: PageEnv, t: I18n, f: Frame, v: Parties): Child[] {
  const counts = new Map<PartyKind, number>();
  const rows = v.parties.map((p) => {
    const n = (counts.get(p.party) ?? 0) + 1;
    counts.set(p.party, n);
    const name = partyName(t, p, n);
    return h("tr", { "data-party": p.party, "data-subject": `${p.subject_type}:${p.subject}` }, [
      h("th", { scope: "row" }, [name]),
      h("td", {}, [unmaskControl(env, t, f, v.programme, p.subject_type, p.subject, name)]),
    ]);
  });
  return [
    h("p", {}, [t.label("coord.unmask.page_intro")]),
    h("table", { id: "parties-table" }, [
      h("caption", {}, [t.label("coord.unmask.caption")]),
      h("thead", {}, [h("tr", {}, [h("th", { scope: "col" }, [t.label("coord.unmask.col_party")]), h("th", { scope: "col" }, [t.label("coord.col_action")])])]),
      h("tbody", {}, rows),
    ]),
    ...(rows.length === 0 ? [h("p", {}, [t.label("coord.unmask.none")])] : []),
  ];
}
