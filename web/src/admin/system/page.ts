// The tenant admins' System page, `/app/admin/system` (ADR-028 record of
// lane L20; Daniel, 2026-11-21: the platform must be runnable by one
// technical and one non-technical person, and anything the second needs
// is on a web page).
//
// - It reads `tenant.system`: the cell clock, the vault, outgoing mail and
//   the host status file that `fstp-admin` writes. The page gate admits a
//   tenant admin only, by the same read (SA-09, `fstp_access::PAGES`).
// - It reads `tenant.list_admins` for each admin with "checked" or not,
//   and links to the onboarding checklist of lane L18 rather than repeat
//   it.
// - Each row is green, amber, red or unknown, as a badge with a glyph and
//   a word, so colour is never the only cue (R-NF-03). A row that is not
//   green says who acts and what to tell them.
//
// No name, address or account number is shown: handles only (I-27).

import { h, type Child } from "../../core/dom.js";
import type { I18n, Label } from "../../core/i18n.js";
import type { RouteDef } from "../../core/router.js";
import { link, section } from "../../grant/kit.js";
import { readAdmins, type AdminRow } from "../../onboarding/model.js";
import { frame, pageI18n, readOp, type Frame, type JudgingPage, type PageEnv } from "../../reviewer/kit.js";
import { SYSTEM_LABELS } from "./messages.en.js";
import { decodeSystem, hostNext, overall, rows, type Light, type Row, type SystemReply } from "./model.js";

/** The paths of the page. */
export const SYSTEM_PATHS = Object.freeze({
  system: "/app/admin/system",
  checklist: "/app/admin/onboarding/summary",
  home: "/app/",
});

const BADGE: Readonly<Record<Light, string>> = {
  green: "badge badge--success",
  amber: "badge badge--warning",
  red: "badge badge--error",
  unknown: "badge badge--neutral",
};

function labels(env: PageEnv): I18n {
  return pageI18n(env, SYSTEM_LABELS);
}

const isReply = (v: unknown): v is unknown => decodeSystem(v) !== null;
const isAdmins = (v: unknown): v is unknown => readAdmins(v) !== null;

/** The sentence of a row, with an age in words where it has one. */
function sentence(t: I18n, r: Row): Label {
  const params: Record<string, string> = { ...r.params };
  const unit = params["unit"];
  if (unit !== undefined && params["age"] !== undefined) {
    params["age"] = t.label(unit, { n: params["age"] });
    delete params["unit"];
  }
  return t.label(r.text, params);
}

/** One row as a list item: name, light, sentence, and who acts. */
function rowItem(t: I18n, r: Row): HTMLElement {
  const parts: Child[] = [
    h("strong", {}, [t.label(`system.name.${r.id}`)]),
    " ",
    h("span", { class: BADGE[r.light], "data-light": r.light }, [t.label(`system.light.${r.light}`)]),
    " ",
    h("span", { class: "system-sentence" }, [sentence(t, r)]),
  ];
  if (r.actor !== null) {
    const who = h("p", { class: "system-actor", "data-actor": r.actor }, [t.label(`system.actor.${r.actor}`)]);
    if (r.tell !== null) who.append(" ", h("q", {}, [t.label(r.tell)]));
    parts.push(who);
  }
  return h("li", { "data-row": r.id, "data-light": r.light }, parts);
}

function rowList(id: string, t: I18n, rs: readonly Row[]): HTMLElement {
  return h("ul", { id, class: "system-rows" }, rs.map((r) => rowItem(t, r)));
}

/** The admins, each with "checked" or not, and the link to the checklist. */
function adminsSection(t: I18n, admins: readonly AdminRow[] | null): HTMLElement {
  const body: Child[] = [h("p", {}, [t.label("system.admins.intro")])];
  if (admins === null) {
    body.push(h("p", { id: "system-admins-unavailable" }, [t.label("system.admins.unavailable")]));
  } else if (admins.length === 0) {
    body.push(h("p", { id: "system-admins-none" }, [t.label("system.admins.none")]));
  } else {
    body.push(
      h(
        "ul",
        { id: "system-admins" },
        admins.map((a) =>
          h("li", { "data-verified": a.verified ? "true" : "false" }, [
            h("span", { class: a.verified ? BADGE.green : BADGE.amber }, [
              t.label(a.verified ? "system.light.green" : "system.light.amber"),
            ]),
            " ",
            t.label(a.verified ? "system.admins.row.verified" : "system.admins.row.unverified", { handle: a.handle }),
          ]),
        ),
      ),
    );
  }
  body.push(h("p", {}, [link(SYSTEM_PATHS.checklist, t.label("system.admins.checklist"))]));
  return section("system-admins-section", t.label("system.admins.heading"), body);
}

/** The page body of one reply. */
export function systemBody(t: I18n, r: SystemReply, admins: readonly AdminRow[] | null): Child[] {
  const all = rows(r);
  const top = all.filter((x) => ["report", "cell", "vault", "services", "edge", "mail"].includes(x.id));
  const care = all.filter((x) => ["backups", "archive", "keys", "snapshots", "certificates"].includes(x.id));
  const light = overall(all);
  const out: Child[] = [
    h("p", {}, [t.label("system.intro")]),
    h("p", { id: "system-overall", class: "callout", "data-light": light }, [
      h("span", { class: BADGE[light] }, [t.label(`system.light.${light}`)]),
      " ",
      t.label(`system.overall.${light}`),
    ]),
  ];
  const next = hostNext(r);
  if (next !== null) {
    out.push(
      section("system-next", t.label("system.next.heading"), [
        h("p", { id: "system-next-text", "data-actor": next.actor }, [t.label(next.text)]),
      ]),
    );
  }
  out.push(
    section("system-parts", t.label("system.parts.heading"), [rowList("system-parts-rows", t, top)]),
    section("system-care", t.label("system.backups.heading"), [rowList("system-care-rows", t, care)]),
    adminsSection(t, admins),
  );
  return out;
}

async function mountSystem(env: PageEnv): Promise<void> {
  const t = labels(env);
  const f: Frame = frame(env, t, t.label("system.title"));
  const refresh = h("button", { id: "system-refresh", type: "button" }, [t.label("system.refresh")]);
  const load = async (): Promise<void> => {
    const r = await readOp(env, "tenant.system", {}, isReply);
    if (!r.ok) {
      f.problem(r.problem);
      f.show([h("p", {}, [link(SYSTEM_PATHS.home, t.label("system.back"))])]);
      return;
    }
    const data = decodeSystem(r.data);
    if (data === null) {
      f.problem({ kind: "failed", reason: "invalid_response" });
      return;
    }
    const a = await readOp(env, "tenant.list_admins", {}, isAdmins);
    const admins = a.ok ? readAdmins(a.data) : null;
    f.clearAlert();
    f.show([...systemBody(t, data, admins), h("p", {}, [refresh]), h("p", {}, [link(SYSTEM_PATHS.home, t.label("system.back"))])]);
  };
  refresh.addEventListener("click", () => {
    void (async () => {
      refresh.setAttribute("disabled", "");
      await load();
      refresh.removeAttribute("disabled");
      f.status(t.label("system.checked"));
    })();
  });
  await load();
}

const route = (name: string, pattern: string): RouteDef => ({ name, pattern, segments: {} });

/** The System page. */
export const SYSTEM_PAGES: readonly JudgingPage[] = [
  { route: route("admin.system", SYSTEM_PATHS.system), mount: (env) => mountSystem(env) },
];

/** Mounts the System page for `path`. False, and nothing rendered, for any other path. */
export async function mountSystemPage(env: PageEnv, path: string): Promise<boolean> {
  const p = path.endsWith("/") && path.length > 1 ? path.slice(0, -1) : path;
  const page = SYSTEM_PAGES.find((x) => x.route.pattern === p);
  if (page === undefined) {
    return false;
  }
  await page.mount(env, {});
  return true;
}
