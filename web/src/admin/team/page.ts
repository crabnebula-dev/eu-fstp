// The team page `/app/programmes/{programme}/team` and the member page
// `/app/admin/members` (SA-11, Daniel 2026-11-15 night;
// `docs/design/spec-amendments.md`).
//
// - The team page reads `team.list`: every Drafting, Judging and
//   Operations role of the programme, open invitations included. Its
//   readers are the programme's manager and the tenant admins, and the
//   page gate admits them by the same read (SA-09).
// - The member page reads `admin.members`: every member account of the
//   organisation with its roles across programmes. Tenant admins only.
// - Each row shows the display name, or "no name set", and the
//   invitation or login email. The display name is shown on these two
//   pages only (I-17, P-11, I-27).
// - The pages offer the actions the reply's `actions` names, row by row
//   (`roleActions`): grant, end and reinstate, each high-risk, so the
//   cell asks for a step-up (`act`). The team page also invites a person
//   (`creator.invite`) while the programme has a creator draft. The
//   server decides every action again.
// - Applicants and their teams are never listed: the reply admits no
//   Receiving role (`TEAM_ROLES`).

import { h, type Child } from "../../core/dom.js";
import { labelWithHelp } from "../../help/help.js";
import type { I18n, Label } from "../../core/i18n.js";
import { createRouter, type RouteDef } from "../../core/router.js";
import { act, anyObject, buttonEl, formEl, link, onSubmit, section } from "../../grant/kit.js";
import { ROLES, plausibleEmail } from "../../people/model.js";
import { frame, idRoute, inputEl, pageI18n, readOp, selectEl, type Frame, type JudgingPage, type PageEnv } from "../../reviewer/kit.js";
import { TEAM_LABELS } from "./messages.en.js";
import { get } from "../../auth/api.js";
import { VERIFICATION_PEOPLE, decodePeople, verifyControl, type PersonRow } from "./verify.js";
import {
  TEAM_PATHS,
  dayOf,
  decodeMembers,
  decodeTeam,
  roleActions,
  type MembersReply,
  type RoleRow,
  type TeamAction,
  type TeamReply,
} from "./model.js";

function labels(env: PageEnv): I18n {
  return pageI18n(env, TEAM_LABELS);
}

function roleText(t: I18n, role: string): Label {
  return t.label(`team.role.${role}`);
}

function statusText(t: I18n, r: RoleRow): Label {
  const status = t.label(`team.status.${r.status}`);
  return r.rule === null ? status : t.label("team.status.rule", { status, rule: r.rule });
}

function datesText(t: I18n, r: RoleRow): Label {
  if (r.start === null) return t.label("team.dates.none");
  const start = dayOf(r.start);
  return r.end === null ? t.label("team.dates.from", { start }) : t.label("team.dates.from_until", { start, end: dayOf(r.end) });
}

/** A key that names one role of a page: its binding or its invitation. */
function keyOf(r: RoleRow): string {
  return r.binding !== null ? `binding-${r.binding}` : `invitation-${r.invitation ?? "none"}`;
}

/**
 * The action controls of one role. Each runs its operation through
 * `act`, which answers the cell's step-up, then reloads the page.
 */
function controls(
  env: PageEnv,
  t: I18n,
  f: Frame,
  r: RoleRow,
  actions: readonly TeamAction[],
  reload: () => Promise<void>,
): Child[] {
  const p = r.programme;
  if (p === null) return [];
  const out: Child[] = [];
  const key = keyOf(r);
  for (const a of roleActions(r, actions)) {
    if (a === "grant" && r.invitation !== null) {
      const invitation = r.invitation;
      const b = buttonEl(`grant-${key}`, "button", t.label("team.action.grant"));
      b.setAttribute("data-action", "grant");
      b.addEventListener("click", () => {
        void (async () => {
          f.clearAlert();
          const done = await act(env, "roles.grant", { programme: p }, { invitation }, anyObject);
          if (!done.ok) return f.problem(done.problem);
          await reload();
          f.status(t.label("team.action.granted"));
        })();
      });
      out.push(b);
    } else if (a === "end" && r.binding !== null) {
      const binding = r.binding;
      const b = buttonEl(`end-${key}`, "button", t.label("team.action.end"));
      b.setAttribute("data-action", "end");
      b.addEventListener("click", () => {
        void (async () => {
          f.clearAlert();
          const done = await act(env, "roles.end", { programme: p, binding }, {}, anyObject);
          if (!done.ok) return f.problem(done.problem);
          await reload();
          f.status(t.label("team.action.ended"));
        })();
      });
      out.push(b);
    } else if (a === "reinstate" && r.binding !== null) {
      const binding = r.binding;
      const reason = inputEl({ id: `reason-${key}`, type: "text", autocomplete: "off" });
      const b = buttonEl(`reinstate-${key}`, "button", t.label("team.action.reinstate"));
      b.setAttribute("data-action", "reinstate");
      b.addEventListener("click", () => {
        void (async () => {
          f.clearAlert();
          const why = reason.value.trim();
          if (why === "") {
            f.alert(t.label("team.action.reason_missing"));
            reason.focus();
            return;
          }
          const done = await act(env, "roles.reinstate", { programme: p, binding }, { reason: why }, anyObject);
          if (!done.ok) return f.problem(done.problem);
          await reload();
          f.status(t.label("team.action.reinstated"));
        })();
      });
      out.push(h("span", { class: "fstp-control" }, [h("label", { for: `reason-${key}` }, [t.label("team.action.reason")]), reason]), b);
    }
  }
  return out;
}

function nameCell(t: I18n, name: string | null): Child {
  return name === null ? h("span", { class: "fstp-hint" }, [t.label("team.no_name")]) : name;
}

function emailCell(t: I18n, email: string | null): Child {
  return email === null ? h("span", { class: "fstp-hint" }, [t.label("team.no_email")]) : h("span", { class: "fstp-email" }, [email]);
}

function head(t: I18n, cols: readonly string[]): HTMLElement {
  return h("thead", {}, [h("tr", {}, cols.map((c) => h("th", { scope: "col" }, [t.label(c)])))]);
}

/** The table of the team page. */
function teamTable(env: PageEnv, t: I18n, f: Frame, p: string, r: TeamReply, reload: () => Promise<void>): Child {
  if (r.rows.length === 0) {
    return h("p", { id: "team-none" }, [t.label("team.none")]);
  }
  return h("table", { id: "team-rows", class: "fstp-table" }, [
    h("caption", {}, [t.label("team.table.caption", { programme: p })]),
    head(t, ["team.col.name", "team.col.email", "team.col.role", "team.col.status", "team.col.dates", "team.col.actions"]),
    h(
      "tbody",
      {},
      r.rows.map((row) =>
        h("tr", { "data-key": keyOf(row), "data-account": row.account ?? "", "data-status": row.status, "data-role": row.role }, [
          h("td", {}, [nameCell(t, row.displayName)]),
          h("td", {}, [emailCell(t, row.email)]),
          h("td", {}, [roleText(t, row.role)]),
          h("td", {}, [statusText(t, row)]),
          h("td", {}, [datesText(t, row)]),
          h("td", {}, controls(env, t, f, row, r.actions, reload)),
        ]),
      ),
    ),
  ]);
}

/** The invitation form of the team page (`creator.invite`). */
function inviteForm(env: PageEnv, t: I18n, f: Frame, p: string, reload: () => Promise<void>): HTMLElement {
  const email = inputEl({ id: "team-invite-email", type: "email", autocomplete: "off", spellcheck: "false" });
  const role = selectEl(
    { id: "team-invite-role", name: "team-invite-role" },
    ROLES.map((r) => h("option", { value: r }, [roleText(t, r)])),
  );
  const submit = buttonEl("team-invite-submit", "submit", t.label("team.invite.submit"));
  const form = formEl("team-invite-form", [
    h("div", { class: "fstp-field" }, [...labelWithHelp("team-invite-email", t.label("team.invite.email"), "help.invite.email"), email]),
    h("div", { class: "fstp-field" }, [...labelWithHelp("team-invite-role", t.label("team.invite.role"), "help.invite.role"), role]),
    submit,
  ]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const address = email.value.trim();
    if (!plausibleEmail(address)) {
      f.alert(t.label("team.invite.email_invalid"));
      email.focus();
      return;
    }
    const done = await act(env, "creator.invite", { programme: p }, { email: address, role: role.value }, anyObject);
    if (!done.ok) {
      f.problem(done.problem);
      return;
    }
    await reload();
    f.status(t.label("team.invite.sent", { email: address }));
  });
  return form;
}

async function mountTeam(env: PageEnv, p: string): Promise<void> {
  const t = labels(env);
  const f = frame(env, t, t.label("team.title"));
  const load = async (): Promise<void> => {
    const r = await readOp(env, "team.list", { programme: p }, (v): v is unknown => decodeTeam(v, p) !== null);
    if (!r.ok) {
      f.problem(r.problem);
      f.show([h("p", {}, [link(TEAM_PATHS.home, t.label("team.back"))])]);
      return;
    }
    const data = decodeTeam(r.data, p);
    if (data === null) {
      f.problem({ kind: "failed", reason: "invalid_response" });
      return;
    }
    const body: Child[] = [h("p", {}, [t.label("team.intro", { programme: p })])];
    if (data.actions.some((a) => a !== "invite")) {
      body.push(h("p", { class: "fstp-hint" }, [t.label("team.action.step_up")]));
    }
    body.push(teamTable(env, t, f, p, data, load));
    if (data.actions.includes("invite")) {
      body.push(section("team-invite", t.label("team.invite.heading"), [inviteForm(env, t, f, p, load)]));
    }
    body.push(
      h("p", {}, [link(TEAM_PATHS.members, t.label("team.members_link"))]),
      h("p", {}, [link(TEAM_PATHS.account, t.label("team.account_link"))]),
      h("p", {}, [link(TEAM_PATHS.home, t.label("team.back"))]),
    );
    f.show(body);
  };
  await load();
}

/** The roles of one member, each with its controls and a link to its programme's team page. */
function memberRoles(env: PageEnv, t: I18n, f: Frame, roles: readonly RoleRow[], actions: readonly TeamAction[], reload: () => Promise<void>): Child {
  if (roles.length === 0) return "";
  return h(
    "ul",
    {},
    roles.map((r) => {
      const status = statusText(t, r);
      const role = roleText(t, r.role);
      if (r.programme === null) {
        return h("li", { "data-key": keyOf(r), "data-status": r.status }, [t.label("team.member.tenant_role", { role, status })]);
      }
      return h("li", { "data-key": keyOf(r), "data-status": r.status, "data-programme": r.programme }, [
        t.label("team.member.role", { role, programme: r.programme, status, dates: datesText(t, r) }),
        " ",
        link(TEAM_PATHS.team(r.programme), t.label("team.member.team_link", { programme: r.programme })),
        " ",
        ...controls(env, t, f, r, actions, reload),
      ]);
    }),
  );
}

function membersTable(env: PageEnv, t: I18n, f: Frame, r: MembersReply, reload: () => Promise<void>): Child {
  if (r.members.length === 0) {
    return h("p", { id: "members-none" }, [t.label("team.members.none")]);
  }
  return h("table", { id: "members-rows", class: "fstp-table" }, [
    h("caption", {}, [t.label("team.members.caption")]),
    head(t, ["team.col.name", "team.col.email", "team.col.roles"]),
    h(
      "tbody",
      {},
      r.members.map((m) =>
        h("tr", { "data-account": m.account }, [
          h("td", {}, [nameCell(t, m.displayName)]),
          h("td", {}, [emailCell(t, m.email)]),
          h("td", {}, [
            ...(m.tenantAdmin ? [h("p", {}, [t.label("team.tenant_admin")])] : []),
            memberRoles(env, t, f, m.roles, r.actions, reload),
            verifyControl(t, f, m.account),
          ]),
        ]),
      ),
    ),
  ]);
}

/** The applicants a tenant admin may verify, each with its control. Empty for anyone the cell refuses. */
function applicantsSection(t: I18n, f: Frame, people: readonly PersonRow[]): Child[] {
  if (people.length === 0) return [];
  const roleOf = (r: string): Label => {
    const known = ["applicant", "applicant_team_member", "guardian"].includes(r);
    return t.label(known ? `team.verify.role.${r}` : "team.verify.role.other");
  };
  return [
    h("h2", { id: "verify-applicants" }, [t.label("team.verify.applicants")]),
    h("p", {}, [t.label("team.verify.applicants_intro")]),
    h(
      "ul",
      { id: "verify-applicant-list", class: "fstp-list" },
      people.map((p) =>
        h("li", { "data-account": p.account, "data-proposal": p.proposal ?? "", "data-requested": String(p.requested) }, [
          p.proposal === null
            ? t.label("team.verify.staff_person", { account: p.account })
            : t.label("team.verify.person", { proposal: p.proposal, role: roleOf(p.role), account: p.account }),
          ...(p.requested ? [" ", h("strong", { class: "fstp-badge" }, [t.label("team.verify.asked")])] : []),
          " ",
          verifyControl(t, f, p.account, p.proposal),
        ]),
      ),
    ),
  ];
}

async function mountMembers(env: PageEnv): Promise<void> {
  const t = labels(env);
  const f = frame(env, t, t.label("team.members_title"));
  const load = async (): Promise<void> => {
    const r = await readOp(env, "admin.members", {}, (v): v is unknown => decodeMembers(v) !== null);
    if (!r.ok) {
      f.problem(r.problem);
      f.show([h("p", {}, [link(TEAM_PATHS.home, t.label("team.back"))])]);
      return;
    }
    const data = decodeMembers(r.data);
    if (data === null) {
      f.problem({ kind: "failed", reason: "invalid_response" });
      return;
    }
    const peopleReply = await get(VERIFICATION_PEOPLE);
    const people = peopleReply.status === 200 ? (decodePeople(peopleReply.body) ?? []) : [];
    f.show([
      h("p", {}, [t.label("team.members_intro")]),
      h("p", { class: "fstp-hint" }, [t.label("team.action.step_up")]),
      membersTable(env, t, f, data, load),
      ...applicantsSection(t, f, people),
      h("p", {}, [link(TEAM_PATHS.account, t.label("team.account_link"))]),
      h("p", {}, [link(TEAM_PATHS.home, t.label("team.back"))]),
    ]);
  };
  await load();
}

const plain = (name: string, pattern: string): RouteDef => ({ name, pattern, segments: {} });

/** The team and member pages. */
export const TEAM_PAGES: readonly JudgingPage[] = [
  {
    route: idRoute("admin.team", "/app/programmes/{programme}/team", ["programme"]),
    mount: (env, params) => mountTeam(env, params["programme"] ?? ""),
  },
  { route: plain("admin.members", TEAM_PATHS.members), mount: (env) => mountMembers(env) },
];

/** Mounts the team or member page for `path`. False, and nothing rendered, for any other path. */
export async function mountTeamPages(env: PageEnv, path: string): Promise<boolean> {
  const m = createRouter(TEAM_PAGES.map((p) => p.route)).match(path);
  const page = m === null ? undefined : TEAM_PAGES.find((p) => p.route.name === m.name);
  if (m === null || page === undefined) {
    return false;
  }
  await page.mount(env, m.params);
  return true;
}
