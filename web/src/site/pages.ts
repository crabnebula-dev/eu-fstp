// The pages of lane m4/site that no older feature folder holds: the
// profile page `/app/me` (`docs/design/06-profile-page.md`, prototype
// `profile.html`; R-NF-03, R-NF-04, R-CF-03, I-83, I-86).
//
// One page with two parts, Profile and Security, and an in-page
// navigation "On this page" to both:
//
// - Profile: the verification status (`me.get_verification`) as a chip
//   with its text, and the roles held (`me.roles`) in words. Name,
//   organisation and affiliations are never shown (R-CF-03, I-83); they
//   live in the vault.
// - Security: the caller's sessions (`me.sessions`, R-LG-04) as a
//   table, and the links to the M3 page that adds and removes passkeys
//   and ends sessions with a step-up (`/auth/account`) and to recovery.
//
// Interim, pending the lead: the design's display name, language, theme
// and time zone preferences have no operation in this release, so they
// are left out rather than shown with nothing behind them. The passkey
// table has no read operation either, so its management stays on the M3
// page this page links.

import { frame } from "../applicant/ui.js";
import { type Child, h } from "../core/dom.js";
import { type I18n, type Label, createI18n } from "../core/i18n.js";
import { createRouter, type Router } from "../core/router.js";
import { myRoles } from "../home/session.js";
import { homeLabel } from "../home/nav.js";
import { type Guard, browserEnv, isId, isText, list, oneOf, readOp, record } from "../reviewer/kit.js";
import { SITE_LABELS } from "./messages.en.js";

let catalogue: I18n | null = null;

/** The site catalogue. Interim, pending the lead: English, no overrides yet. */
function site(): I18n {
  catalogue ??= createI18n({ catalogues: [{ locale: "en", labels: SITE_LABELS, approved: {} }], locale: "en" });
  return catalogue;
}

/** A label of the site catalogue. */
function t(id: string, args?: Readonly<Record<string, string>>): Label {
  return site().label(id, args);
}

type Verification = "unverified" | "pending" | "verified";

const isVerification: Guard<{ readonly status: Verification }> = record({
  status: oneOf<Verification>("unverified", "pending", "verified"),
});

type Method = "passkey" | "magic_link" | "opaque" | "eudi_wallet";

interface SessionRow {
  readonly session: string;
  readonly method: Method;
  readonly started: string;
}

const isSessions: Guard<readonly SessionRow[]> = list(
  record<SessionRow>({ session: isId, method: oneOf<Method>("passkey", "magic_link", "opaque", "eudi_wallet"), started: isText }),
);

/** A UTC microsecond instant: a decimal string, as the cell writes it (`auth/pages/account.ts`). */
function micros(v: string): bigint | null {
  return /^-?(?:0|[1-9][0-9]{0,18})$/.test(v) ? BigInt(v) : null;
}

let dates: Intl.DateTimeFormat | null = null;

/**
 * The start of a session as a date and time in the catalogue locale,
 * as the M3 account page shows it (R-LG-04, `06-profile-page.md`). A
 * value that is not an instant reads as not known, never as raw digits.
 */
function sessionStart(started: string): Child {
  const us = micros(started);
  const ms = us === null ? Number.NaN : Number(us / 1000n);
  const at = new Date(ms);
  if (Number.isNaN(at.getTime())) {
    return t("me.security.started_unknown");
  }
  dates ??= new Intl.DateTimeFormat(site().locale, { dateStyle: "medium", timeStyle: "short" });
  return h("time", { datetime: at.toISOString() }, [dates.format(at)]);
}

/** The chip of a verification status, with its glyph and text (R-NF-03). */
function verificationChip(v: Verification | null): HTMLElement {
  const tone = v === "verified" ? "badge--success" : v === "pending" ? "badge--warning" : "badge--neutral";
  return h("span", { id: "me-verification", class: `badge ${tone}`, "data-status": v ?? "unknown" }, [
    t(`me.profile.verification.${v ?? "unknown"}`),
  ]);
}

/** Mounts the profile page `/app/me`. */
function mountProfile(): void {
  const f = frame(t("me.title"));
  const env = browserEnv(document.body);
  const verification = h("dd", {}, [h("span", { "aria-busy": "true" }, [t("me.loading")])]);
  const roles = h("dd", {}, []);
  const sessions = h("div", {}, [h("p", { "aria-busy": "true" }, [t("me.loading")])]);

  f.main.append(
    h("nav", { class: "on-this-page", "aria-label": t("me.on_this_page") }, [
      h("ul", {}, [
        h("li", {}, [h("a", { href: "#profile-heading" }, [t("me.profile.title")])]),
        h("li", {}, [h("a", { href: "#security-heading" }, [t("me.security.title")])]),
      ]),
    ]),
    h("section", { id: "me-profile", "aria-labelledby": "profile-heading" }, [
      h("h2", { id: "profile-heading" }, [t("me.profile.title")]),
      h("div", { class: "card" }, [
        h("dl", { class: "facts" }, [
          h("dt", {}, [t("me.profile.verification")]),
          verification,
          h("dt", {}, [t("me.profile.roles")]),
          roles,
        ]),
        h("p", { class: "text-sm" }, [t("me.profile.vault_note")]),
      ]),
    ]),
    h("section", { id: "me-security", "aria-labelledby": "security-heading" }, [
      h("h2", { id: "security-heading" }, [t("me.security.title")]),
      h("h3", {}, [t("me.security.sessions")]),
      sessions,
      h("h3", {}, [t("me.security.passkeys")]),
      h("p", {}, [t("me.security.passkeys.intro")]),
      h("p", { class: "stepup-note" }, [t("me.security.stepup_note")]),
      h("p", {}, [h("a", { href: "/auth/account", "data-nav-link": "passkeys" }, [t("me.security.passkeys.link")])]),
      h("h3", {}, [t("me.security.recovery")]),
      h("p", {}, [t("me.security.recovery.intro")]),
      h("p", {}, [h("a", { href: "/auth/recovery" }, [t("me.security.recovery.link")])]),
    ]),
  );

  void readOp(env, "me.get_verification", {}, isVerification).then((v) => {
    const status = v.ok ? v.data.status : null;
    const parts: HTMLElement[] = [verificationChip(status)];
    if (status !== "verified") {
      parts.push(h("span", { class: "fstp-hint" }, [t("me.profile.unverified_note")]));
      parts.push(h("a", { href: "/app/me/identity" }, [t("me.profile.verify")]));
    }
    verification.replaceChildren(...parts);
  });

  void myRoles().then((a) => {
    if (a.kind !== "roles") {
      roles.replaceChildren(t("me.failed"));
      return;
    }
    const items: HTMLElement[] = [];
    if (a.roles.tenantAdmin) {
      items.push(h("li", {}, [t("me.profile.tenant_admin")]));
    }
    for (const b of a.roles.roles) {
      const role = homeLabel(`role.${b.role}`);
      items.push(
        h("li", {}, [
          b.proposal === null
            ? t("me.profile.role", { role, programme: b.programme })
            : t("me.profile.role_proposal", { role, proposal: b.proposal, programme: b.programme }),
        ]),
      );
    }
    roles.replaceChildren(items.length === 0 ? h("p", {}, [t("me.profile.roles.none")]) : h("ul", {}, items));
  });

  void readOp(env, "me.sessions", {}, isSessions).then((s) => {
    if (!s.ok) {
      sessions.replaceChildren(h("p", { role: "status" }, [t("me.security.sessions.failed")]));
      return;
    }
    if (s.data.length === 0) {
      sessions.replaceChildren(h("p", { id: "sessions-list" }, [t("me.security.sessions.none")]));
      return;
    }
    sessions.replaceChildren(
      h("table", {}, [
        h("caption", { class: "sr-only" }, [t("me.security.sessions.caption")]),
        h("thead", {}, [
          h("tr", {}, [
            h("th", { scope: "col" }, [t("me.security.sessions")]),
            h("th", { scope: "col" }, [t("me.security.method")]),
            h("th", { scope: "col" }, [t("me.security.started")]),
          ]),
        ]),
        h(
          "tbody",
          { id: "sessions-list" },
          s.data.map((r) =>
            h("tr", { "data-session": r.session }, [
              h("td", { class: "pid" }, [t("me.security.session", { id: r.session })]),
              h("td", {}, [t(`me.security.method.${r.method}`)]),
              h("td", {}, [sessionStart(r.started)]),
            ]),
          ),
        ),
      ]),
    );
  });
}

/** The site pages, each with its route. */
const PAGES: readonly { readonly name: string; readonly pattern: string; readonly mount: () => void }[] = [
  { name: "site.profile", pattern: "/app/me", mount: mountProfile },
];

let router: Router | null = null;

/** Mounts the site page of `path`. False when none has the path. */
export function mountSite(path: string): boolean {
  router ??= createRouter(PAGES.map((p) => ({ name: p.name, pattern: p.pattern, segments: {} })));
  const m = router.match(path);
  const page = m === null ? undefined : PAGES.find((p) => p.name === m.name);
  if (page === undefined) {
    return false;
  }
  page.mount();
  return true;
}
