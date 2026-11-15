// The tenant admin's funder profiles page, `/app/admin/funder-profiles`
// (Daniel, 2026-11-15 late: "A tenant may copy one into a tenant-owned
// profile and edit it. A programme pins one, as today.").
//
// - It reads `tenant.funder_profiles`. The page gate admits a tenant admin
//   only, by the same read (SA-09, `fstp_access::PAGES`).
// - A copy and a save are high-risk, so the cell asks for a step-up, and a
//   cancelled step-up changes nothing. Each save records a new version.

import { h, type Child } from "../../core/dom.js";
import type { I18n } from "../../core/i18n.js";
import type { RouteDef } from "../../core/router.js";
import { act, anyObject, buttonEl, formEl, link, onSubmit, section, textArea, textField } from "../../grant/kit.js";
import { frame, pageI18n, readOp, selectEl, type Frame, type JudgingPage, type PageEnv } from "../../reviewer/kit.js";
import { ADMIN_PROFILE_LABELS } from "./messages.en.js";
import { copyBody, decodeProfiles, latestTenant, saveBody, type ProfileRow } from "./model.js";

/** The path of the page. */
export const ADMIN_PROFILE_PATHS = Object.freeze({
  profiles: "/app/admin/funder-profiles",
  home: "/app/",
});

function labels(env: PageEnv): I18n {
  return pageI18n(env, ADMIN_PROFILE_LABELS);
}

const isReply = (v: unknown): v is readonly ProfileRow[] => decodeProfiles(v) !== null;

function table(t: I18n, rows: readonly ProfileRow[]): HTMLElement {
  return h("table", { id: "profiles-table" }, [
    h("caption", {}, [t.label("admin.profiles.list.caption")]),
    h("thead", {}, [
      h("tr", {}, [
        h("th", { scope: "col" }, [t.label("admin.profiles.col.id")]),
        h("th", { scope: "col" }, [t.label("admin.profiles.col.version")]),
        h("th", { scope: "col" }, [t.label("admin.profiles.col.owner")]),
        h("th", { scope: "col" }, [t.label("admin.profiles.col.source")]),
      ]),
    ]),
    h(
      "tbody",
      {},
      rows.map((r) =>
        h("tr", { "data-profile": r.id, "data-version": r.version, "data-owner": r.owner }, [
          h("th", { scope: "row" }, [r.id]),
          h("td", {}, [r.version]),
          h("td", {}, [t.label(`admin.profiles.owner.${r.owner}`)]),
          h("td", {}, [r.source === null ? t.label("admin.profiles.source.none") : t.label("admin.profiles.source.row", r.source)]),
        ]),
      ),
    ),
  ]);
}

function copyForm(env: PageEnv, t: I18n, f: Frame, rows: readonly ProfileRow[], reload: () => Promise<void>): HTMLElement {
  const from = selectEl(
    { id: "profile-copy-from", name: "profile-copy-from" },
    rows.map((r, i) => h("option", { value: String(i) }, [`${r.id} ${r.version}`])),
  );
  const id = textField("profile-copy-id", t.label("admin.profiles.copy.id"));
  const submit = buttonEl("profile-copy-submit", "submit", t.label("admin.profiles.copy.submit"));
  submit.disabled = rows.length === 0;
  const form = formEl("profile-copy-form", [
    h("div", { class: "fstp-field" }, [h("label", { for: "profile-copy-from" }, [t.label("admin.profiles.copy.from")]), from]),
    id.root,
    submit,
  ]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const source = rows[Number(from.value)];
    const body = source === undefined ? null : copyBody(id.control.value.trim(), source);
    if (body === null) {
      f.alert(t.label("admin.profiles.copy.invalid"));
      return;
    }
    const done = await act(env, "tenant.funder_profile.copy", {}, body, anyObject);
    if (!done.ok) {
      f.problem(done.problem);
      return;
    }
    await reload();
    f.status(t.label("admin.profiles.copy.done", { id: body["id"] ?? "" }));
  });
  return form;
}

function editForm(env: PageEnv, t: I18n, f: Frame, rows: readonly ProfileRow[], reload: () => Promise<void>): Child[] {
  const mine = latestTenant(rows);
  if (mine.length === 0) {
    return [h("p", { id: "profile-edit-none" }, [t.label("admin.profiles.edit.none")])];
  }
  const which = selectEl(
    { id: "profile-edit-which", name: "profile-edit-which" },
    mine.map((r, i) => h("option", { value: String(i) }, [`${r.id} ${r.version}`])),
  );
  const text = textArea("profile-edit-text", t.label("admin.profiles.edit.text"));
  text.control.rows = 16;
  text.control.value = mine[0]?.text ?? "";
  which.addEventListener("change", () => {
    text.control.value = mine[Number(which.value)]?.text ?? "";
  });
  const submit = buttonEl("profile-edit-submit", "submit", t.label("admin.profiles.edit.submit"));
  const form = formEl("profile-edit-form", [
    h("div", { class: "fstp-field" }, [h("label", { for: "profile-edit-which" }, [t.label("admin.profiles.edit.which")]), which]),
    text.root,
    submit,
  ]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const target = mine[Number(which.value)];
    const body = target === undefined ? null : saveBody(target.id, text.control.value);
    if (body === null || target === undefined) {
      f.alert(t.label("admin.profiles.edit.invalid"));
      return;
    }
    const done = await act(env, "tenant.funder_profile.save", {}, body, anyObject);
    if (!done.ok) {
      f.problem(done.problem);
      return;
    }
    await reload();
    f.status(t.label("admin.profiles.edit.done", { id: target.id }));
  });
  return [form];
}

async function mountProfiles(env: PageEnv): Promise<void> {
  const t = labels(env);
  const f: Frame = frame(env, t, t.label("admin.profiles.title"));
  const load = async (): Promise<void> => {
    const r = await readOp(env, "tenant.funder_profiles", {}, isReply);
    const rows = r.ok ? decodeProfiles(r.data) : null;
    if (!r.ok || rows === null) {
      if (!r.ok) f.problem(r.problem);
      f.show([h("p", {}, [link(ADMIN_PROFILE_PATHS.home, t.label("admin.profiles.back"))])]);
      return;
    }
    f.show([
      h("p", {}, [t.label("admin.profiles.intro")]),
      section("profiles-list", t.label("admin.profiles.list.heading"), [table(t, rows)]),
      section("profiles-copy", t.label("admin.profiles.copy.heading"), [copyForm(env, t, f, rows, load)]),
      section("profiles-edit", t.label("admin.profiles.edit.heading"), editForm(env, t, f, rows, load)),
    ]);
  };
  await load();
}

const route = (name: string, pattern: string): RouteDef => ({ name, pattern, segments: {} });

/** The funder profiles page. */
export const ADMIN_PROFILE_PAGES: readonly JudgingPage[] = [
  { route: route("admin.funder_profiles", ADMIN_PROFILE_PATHS.profiles), mount: (env) => mountProfiles(env) },
];

/** Mounts the funder profiles page for `path`. False, and nothing rendered, for any other path. */
export async function mountAdminProfiles(env: PageEnv, path: string): Promise<boolean> {
  const p = path.endsWith("/") && path.length > 1 ? path.slice(0, -1) : path;
  const page = ADMIN_PROFILE_PAGES.find((x) => x.route.pattern === p);
  if (page === undefined) {
    return false;
  }
  await page.mount(env, {});
  return true;
}
