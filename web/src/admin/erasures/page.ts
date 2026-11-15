// The tenant admin's erasure page, `/app/admin/erasures` (P-41, ADR-007;
// Daniel, 2026-11-15 late, `docs/handoff/m3-exit-audit.md` section 9;
// lane m5/retention).
//
// - It reads `admin.erasures`: the grants whose funder retention ended
//   and the erasure log. The page gate admits a tenant admin only, by the
//   same read (SA-09, `fstp_access::PAGES`).
// - A tenant admin requests the erasure of one grant's texts with its
//   cause through `admin.request_erasure`. The request is high-risk, so
//   the cell asks for a step-up, and a cancelled step-up changes nothing.
//   The cell refuses a grant whose retention has not ended (P-41).
// - The mailbox notice `admin.retention_ended` links here. The tenant
//   admin's home and navigation link here too.
//
// Ids, causes and dates only (I-27): no text, no name, no account.

import { h, type Child } from "../../core/dom.js";
import type { I18n } from "../../core/i18n.js";
import type { RouteDef } from "../../core/router.js";
import { act, anyObject, buttonEl, formEl, link, onSubmit, section } from "../../grant/kit.js";
import { frame, pageI18n, readOp, selectEl, type Frame, type JudgingPage, type PageEnv } from "../../reviewer/kit.js";
import { ADMIN_ERASURE_LABELS } from "./messages.en.js";
import { ERASURE_CAUSES, dayOf, decodeErasures, requestBody, type ErasuresReply } from "./model.js";

/** The path of the page. */
export const ADMIN_ERASURE_PATHS = Object.freeze({
  erasures: "/app/admin/erasures",
  home: "/app/",
});

function labels(env: PageEnv): I18n {
  return pageI18n(env, ADMIN_ERASURE_LABELS);
}

const isReply = (v: unknown): v is ErasuresReply => decodeErasures(v) !== null;

/** The grants whose retention ended, one line each. */
function endedList(t: I18n, r: ErasuresReply): Child[] {
  if (r.retentionEnded.length === 0) {
    return [h("p", { id: "erasures-ended-none" }, [t.label("admin.erasures.ended.none")])];
  }
  return [
    h(
      "ul",
      { id: "erasures-ended" },
      r.retentionEnded.map((e) =>
        h("li", { "data-grant": e.grant }, [
          t.label("admin.erasures.ended.row", {
            grant: e.grant,
            programme: e.programme,
            start: dayOf(e.start),
            end: dayOf(e.end),
          }),
        ]),
      ),
    ),
  ];
}

/** The erasure log, one line per erased text. */
function logList(t: I18n, r: ErasuresReply): Child[] {
  if (r.erasures.length === 0) {
    return [h("p", { id: "erasures-log-none" }, [t.label("admin.erasures.log.none")])];
  }
  return [
    h(
      "ul",
      { id: "erasures-log" },
      r.erasures.map((e) =>
        h("li", { "data-text": e.text, "data-cause": e.cause }, [
          t.label("admin.erasures.log.row", {
            text: e.text,
            grant: e.grant ?? t.label("admin.erasures.log.no_grant"),
            cause: t.label(`admin.erasures.cause.${e.cause}`),
            requested: dayOf(e.requestedAt),
            completed: e.completedAt === null ? t.label("admin.erasures.log.pending") : dayOf(e.completedAt),
          }),
        ]),
      ),
    ),
  ];
}

/** The request form: a grant whose retention ended, and a cause. */
function requestForm(env: PageEnv, t: I18n, f: Frame, r: ErasuresReply, reload: () => Promise<void>): HTMLElement {
  const grant = selectEl(
    { id: "erasure-grant", name: "erasure-grant" },
    r.retentionEnded.map((e) => h("option", { value: e.grant }, [e.grant])),
  );
  const cause = selectEl(
    { id: "erasure-cause", name: "erasure-cause" },
    ERASURE_CAUSES.map((c) => h("option", { value: c }, [t.label(`admin.erasures.cause.${c}`)])),
  );
  const submit = buttonEl("erasure-submit", "submit", t.label("admin.erasures.request.submit"));
  submit.className = "fstp-primary";
  submit.disabled = r.retentionEnded.length === 0;
  const form = formEl("erasure-form", [
    h("div", { class: "fstp-field" }, [h("label", { for: "erasure-grant" }, [t.label("admin.erasures.request.grant")]), grant]),
    h("div", { class: "fstp-field" }, [h("label", { for: "erasure-cause" }, [t.label("admin.erasures.request.cause")]), cause]),
    submit,
  ]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const body = requestBody(cause.value, grant.value);
    if (body === null) {
      f.alert(t.label("admin.erasures.request.invalid"));
      return;
    }
    const done = await act(env, "admin.request_erasure", {}, body, anyObject);
    if (!done.ok) {
      f.problem(done.problem);
      return;
    }
    await reload();
    f.status(t.label("admin.erasures.request.done", { grant: body.grant }));
  });
  return form;
}

async function mountErasures(env: PageEnv): Promise<void> {
  const t = labels(env);
  const f: Frame = frame(env, t, t.label("admin.erasures.title"));
  const load = async (): Promise<void> => {
    const r = await readOp(env, "admin.erasures", {}, isReply);
    if (!r.ok) {
      f.problem(r.problem);
      f.show([h("p", {}, [link(ADMIN_ERASURE_PATHS.home, t.label("admin.erasures.back"))])]);
      return;
    }
    const data = decodeErasures(r.data);
    if (data === null) {
      f.problem({ kind: "failed", reason: "invalid_response" });
      return;
    }
    f.show([
      h("p", {}, [t.label("admin.erasures.intro")]),
      section("erasures-retention", t.label("admin.erasures.ended.heading"), [
        h("p", {}, [t.label("admin.erasures.ended.intro")]),
        ...endedList(t, data),
      ]),
      section("erasures-request", t.label("admin.erasures.request.heading"), [
        h("p", {}, [t.label("admin.erasures.request.intro")]),
        requestForm(env, t, f, data, load),
      ]),
      section("erasures-log-section", t.label("admin.erasures.log.heading"), logList(t, data)),
      h("p", {}, [link(ADMIN_ERASURE_PATHS.home, t.label("admin.erasures.back"))]),
    ]);
  };
  await load();
}

const route = (name: string, pattern: string): RouteDef => ({ name, pattern, segments: {} });

/** The erasure page. */
export const ADMIN_ERASURE_PAGES: readonly JudgingPage[] = [
  { route: route("admin.erasures", ADMIN_ERASURE_PATHS.erasures), mount: (env) => mountErasures(env) },
];

/** Mounts the erasure page for `path`. False, and nothing rendered, for any other path. */
export async function mountAdminErasures(env: PageEnv, path: string): Promise<boolean> {
  const p = path.endsWith("/") && path.length > 1 ? path.slice(0, -1) : path;
  const page = ADMIN_ERASURE_PAGES.find((x) => x.route.pattern === p);
  if (page === undefined) {
    return false;
  }
  await page.mount(env, {});
  return true;
}
