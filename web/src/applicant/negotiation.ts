// The negotiation landing (`negotiation.view`,
// `negotiation.acknowledge_notice`; R-NG-06 at negotiation) and the
// guardian page (`guardian.begin_consent`; I-18, R-NG-01, state-machine
// NOTE 14).
//
// M4 shows the negotiation read only: the data protection notice with
// its version, its acknowledgement and the next steps. The guardian gives
// consent on the vault origin, so the guardian page asks for no identity
// attribute. It hands over to the vault's write page, whose ticket
// travels in the fragment.

import { h } from "../core/dom.js";
import { navigate } from "../core/router.js";
import { activityNav } from "../journey/links.js";
import { call } from "./client.js";
import { loadProposal } from "./load.js";
import { NOTICE_VERSIONS } from "./messages.en.js";
import { guardianConsentOpen, leadActionsOffered, negotiationOpen, teamReadsOffered } from "./rules.js";
import { APP, type Frame, approved, button, clearAlert, frame, run, showAlert, showFailure, t } from "./ui.js";
import { decodeAccepted, decodeNegotiation, decodeRedirect } from "./wire.js";

function acknowledged(): HTMLElement {
  return h("p", { id: "negotiation-acknowledged", class: "fstp-done" }, [t("negotiation.acknowledged")]);
}

function acknowledge(f: Frame, id: string, slot: HTMLElement): void {
  const b = button("negotiation-acknowledge", t("negotiation.acknowledge"));
  b.addEventListener("click", () => {
    clearAlert(f);
    b.disabled = true;
    run(f, async () => {
      const r = await call(
        "negotiation.acknowledge_notice",
        { proposal: id },
        { notice_version: NOTICE_VERSIONS.negotiation },
        decodeAccepted,
      );
      if (!r.ok) {
        b.disabled = false;
        showFailure(f, r.failure);
        return;
      }
      slot.replaceChildren(acknowledged());
    });
  });
  slot.replaceChildren(b);
}

/** Mounts the negotiation landing of proposal `id`. */
export function mountNegotiation(id: string): void {
  const f = frame(t("negotiation.title"));
  f.main.append(h("p", {}, [h("a", { href: APP.proposal(id) }, [t("proposal.back")])]));
  run(f, async () => {
    const p = await loadProposal(f, id);
    if (p === null) {
      return;
    }
    if (!negotiationOpen(p.state) || !teamReadsOffered(p.role)) {
      showAlert(f, t("negotiation.closed"));
      return;
    }
    const n = await call("negotiation.view", { proposal: id }, undefined, decodeNegotiation);
    if (!n.ok) {
      showFailure(f, n.failure);
      return;
    }
    f.heading.replaceChildren(t("negotiation.title"), " ", h("span", { class: "state-name fstp-visually-hidden" }, [`(${p.state})`]));
    const slot = h("div", {});
    if (n.value.acknowledged) {
      slot.append(acknowledged());
    } else if (leadActionsOffered(p.role)) {
      acknowledge(f, id, slot);
    } else {
      slot.append(h("p", {}, [t("negotiation.lead_acknowledges")]));
    }
    f.main.append(
      h(
        "section",
        {
          id: "negotiation-notice",
          "data-notice-version": NOTICE_VERSIONS.negotiation,
          "aria-labelledby": "negotiation-notice-heading",
        },
        [
          h("h2", { id: "negotiation-notice-heading" }, [t("negotiation.notice.heading")]),
          h("p", {}, [approved("notice.negotiation")]),
          slot,
        ],
      ),
      h("section", { id: "negotiation-next-steps", "aria-labelledby": "negotiation-next-heading" }, [
        h("h2", { id: "negotiation-next-heading" }, [t("negotiation.next.heading")]),
        h("ol", {}, [
          h("li", {}, [t("negotiation.next.identity")]),
          h("li", {}, [t("negotiation.next.guardian")]),
          h("li", {}, [t("negotiation.next.amount"), " ", h("a", { id: "negotiation-grant-link", href: `/app/grants/${id}` }, [t("negotiation.next.grant_link")])]),
          h("li", {}, [t("negotiation.next.contract"), " ", h("a", { id: "negotiation-contract-link", href: `/app/grants/${id}/contract` }, [t("negotiation.next.contract_link")])]),
        ]),
      ]),
    );
  });
}

/** The path of the vault's write page (M3 design section 6.5). */
const VAULT_WRITE = "/w";

/**
 * Whether `to` is the vault write page of this cell: the cell page's own
 * scheme, which is `https:` on every deployed cell, the host
 * `id.<cell host>` on the cell's port, the path `/w`, no query, no
 * credentials, and a ticket in the fragment. Anything else is refused,
 * so a reply can never send the guardian elsewhere. The loopback e2e
 * cell is plain `http:` under `.localhost` (lane mapp), so the scheme is
 * the page's, never a downgrade from it.
 */
export function isVaultWrite(
  to: string,
  here: { readonly protocol: string; readonly hostname: string; readonly port: string },
): boolean {
  let u: URL;
  try {
    u = new URL(to);
  } catch {
    return false;
  }
  return (
    (here.protocol === "https:" || here.protocol === "http:") &&
    u.protocol === here.protocol &&
    u.username === "" &&
    u.password === "" &&
    u.hostname === `id.${here.hostname}` &&
    u.port === here.port &&
    u.pathname === VAULT_WRITE &&
    u.search === "" &&
    u.hash.length > 1
  );
}

/** Mounts the guardian page of proposal `id`. */
export function mountGuardian(id: string): void {
  const f = frame(t("guardian.title"));
  run(f, async () => {
    const p = await loadProposal(f, id);
    if (p === null) {
      return;
    }
    // O-60: the guardian's own consent steps are in the activity log.
    f.main.append(activityNav(id));
    // Only the guardian gives consent (registry GUARDIAN), and consent
    // opens at the last IRC validation and in NEGOTIATION (NOTE 14).
    if (p.role !== "guardian" || !guardianConsentOpen(p.state)) {
      f.main.append(h("p", {}, [t("guardian.closed")]));
      return;
    }
    consent(f, id);
  });
}

/** The guardian's consent start: it hands over to the vault's write page. */
function consent(f: Frame, id: string): void {
  const start = button("guardian-consent-start", t("guardian.start"));
  start.addEventListener("click", () => {
    clearAlert(f);
    start.disabled = true;
    run(f, async () => {
      const r = await call("guardian.begin_consent", { proposal: id }, {}, decodeRedirect);
      if (!r.ok) {
        start.disabled = false;
        showFailure(f, r.failure);
        return;
      }
      if (!isVaultWrite(r.value, location)) {
        start.disabled = false;
        showAlert(f, t("guardian.bad_redirect"));
        return;
      }
      navigate(r.value);
    });
  });
  f.main.append(h("p", {}, [t("guardian.intro")]), h("p", {}, [start]));
}
