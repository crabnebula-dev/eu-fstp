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
import { act, isVaultUrl } from "../grant/kit.js";
import { decodeRedirect } from "../grant/models.js";
import {
  buttonEl,
  formEl,
  guarded,
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
  const subject = kind === "binding" ? { type: "Binding", binding: id } : { type: "Assignment", assignment: id };
  return { purpose, subject };
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
          const r = await act(env, "identity.unmask", { programme }, body, decodeRedirect);
          if (!r.ok) {
            f.problem(r.problem);
            return;
          }
          if (!isVaultUrl(r.data, location)) {
            f.alert(t.label("coord.unmask.bad_redirect"));
            return;
          }
          f.status(t.label("coord.unmask.opening"));
          location.assign(r.data);
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
