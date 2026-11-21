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

/** The body of a ticket request for `account`, with a fresh command id. */
export function verificationRequest(account: string, commandId: string): { readonly account: string; readonly command_id: string } {
  return { account, command_id: commandId };
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

/** The "Record verification" control of the person `account`. */
export function verifyControl(t: I18n, f: Frame, account: string): HTMLElement {
  const button = buttonEl(`verify-${account}`, "button", t.label("team.verify.open"));
  button.addEventListener("click", () => {
    void guarded(f, () =>
      whileBusy(button, async () => {
        f.clearAlert();
        const r = await post(VERIFICATIONS, verificationRequest(account, randomHex(16)));
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
