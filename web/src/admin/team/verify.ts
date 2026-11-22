// "Record verification" on the member page (ADR-008 and ADR-004 record of
// lane L13b, decided by Daniel on 2026-11-21).
//
// A verified tenant admin chooses it next to a person. The page asks the
// cell for a verification ticket for that person
// (`POST /api/v1/verifications {account, command_id}`), then opens the
// vault origin's form, where only the person's identity details are typed.
// The cell never sees them (I-17). The cell decides every rule again: who
// may record, and for whom.

import { h } from "../../core/dom.js";
import type { I18n } from "../../core/i18n.js";
import { post, record } from "../../auth/api.js";
import { randomHex } from "../../auth/encoding.js";
import { buttonEl, guarded, whileBusy, type Frame } from "../../reviewer/kit.js";

/** The cell route that issues a verification ticket. */
export const VERIFICATIONS = "/api/v1/verifications";

/** The body of a ticket request for `account`, with a fresh command id, and for an applicant the proposal. */
export function verificationRequest(
  account: string,
  commandId: string,
  proposal: string | null = null,
): Readonly<Record<string, string>> {
  return proposal === null ? { account, command_id: commandId } : { account, command_id: commandId, proposal };
}

/** The cell route that lists the applicants a tenant admin may verify. */
export const VERIFICATION_PEOPLE = "/api/v1/verification-people";

/** One person a tenant admin may verify: an account of a proposal in NEGOTIATION or later, or a staff member who asked (no proposal). */
export interface PersonRow {
  readonly account: string;
  readonly proposal: string | null;
  readonly requested: boolean;
  readonly role: string;
}

const ID = /^(?:0|[1-9][0-9]{0,38})$/;

/** The `{people}` reply of the cell, or null for any other shape. */
export function decodePeople(v: unknown): readonly PersonRow[] | null {
  const o = record(v);
  const people = o === null ? undefined : o["people"];
  if (o === null || Object.keys(o).length !== 1 || !Array.isArray(people)) return null;
  const out: PersonRow[] = [];
  for (const x of people as readonly unknown[]) {
    const r = record(x);
    if (r === null || Object.keys(r).length !== 4) return null;
    const { account, proposal, requested, role } = r;
    const proposalOk = proposal === null || (typeof proposal === "string" && ID.test(proposal));
    if (typeof account !== "string" || !ID.test(account) || !proposalOk || typeof requested !== "boolean" || typeof role !== "string") {
      return null;
    }
    out.push(Object.freeze({ account, proposal: proposal as string | null, requested, role }));
  }
  return Object.freeze(out);
}

/** Whether `to` is this cell's vault origin write page: `id.<cell host>` on the page's scheme and port, `/w` with a ticket. */
export function isVaultWriteUrl(to: string, here: { readonly protocol: string; readonly hostname: string; readonly port: string }): boolean {
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
    u.pathname === "/w" &&
    u.search === "" &&
    u.hash.length > 1
  );
}

/** The "Record verification" control of the person `account`, for an applicant of `proposal`. */
export function verifyControl(t: I18n, f: Frame, account: string, proposal: string | null = null): HTMLElement {
  const id = proposal === null ? `verify-${account}` : `verify-${proposal}-${account}`;
  const button = buttonEl(id, "button", t.label("team.verify.open"));
  button.addEventListener("click", () => {
    void guarded(f, () =>
      whileBusy(button, async () => {
        f.clearAlert();
        const r = await post(VERIFICATIONS, verificationRequest(account, randomHex(16), proposal));
        const url = record(r.body)?.["url"];
        if (r.status !== 200 || typeof url !== "string") {
          f.alert(t.label("team.verify.refused"));
          return;
        }
        if (!isVaultWriteUrl(url, location)) {
          f.alert(t.label("team.verify.refused"));
          return;
        }
        f.status(t.label("team.verify.opening"));
        location.assign(url);
      }),
    );
  });
  return h("div", { class: "fstp-verify" }, [button]);
}
