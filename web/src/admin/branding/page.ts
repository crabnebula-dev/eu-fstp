// The tenant admin's branding and terminology screens (M9 lane P2;
// R-WL-03, R-WL-05, I-68, I-70, I-72; M9 design section 2.2).
//
// - `/app/admin/branding`: the tenant name and the brand colour family in
//   light and dark. "Check contrast" asks `tenant.branding.check` and
//   lists each failing pair of the I-70 table. Saving checks first and
//   sends `tenant.branding.set` only when every pair passes. The cell
//   decides again and refuses under I-70 (high risk, so it asks for a
//   step-up).
// - `/app/admin/terminology`: one field per interface label of the closed
//   list, with the platform label beside it, and the Voyage switch. Keys
//   of fixed wording show without a field. `tenant.terminology.set`
//   replaces the tenant pack (I-72).
//
// Both screens are linked from the tenant admin's Home ("Organisation
// settings"). Interim, pending Daniel: no read gives the tokens or the
// labels in force, so the screens start from the platform values.

import { h, type Child } from "../../core/dom.js";
import type { I18n, Label } from "../../core/i18n.js";
import type { RouteDef } from "../../core/router.js";
import { act, anyObject, buttonEl, formEl, link, onSubmit, section, textField } from "../../grant/kit.js";
import { checkbox, frame, pageI18n, type Frame, type JudgingPage, type PageEnv } from "../../reviewer/kit.js";
import { FIXED_LABEL_KEYS, PLAIN_LABELS } from "../../vocab/plain.js";
import { ADMIN_BRANDING_LABELS } from "./messages.en.js";
import {
  COLOUR_KEYS,
  MODES,
  PLATFORM,
  brandingBody,
  decodeCheck,
  editableKeys,
  fieldId,
  splitPair,
  terminologyBody,
  type BrandingCheck,
  type Mode,
} from "./model.js";

/** The paths of the two screens. */
export const ADMIN_BRAND_PATHS = Object.freeze({
  branding: "/app/admin/branding",
  terminology: "/app/admin/terminology",
  home: "/app/",
});

function labels(env: PageEnv): I18n {
  return pageI18n(env, ADMIN_BRANDING_LABELS);
}

/** The readable name of a pair, such as "Dark mode: text on the brand fill". */
function pairName(t: I18n, name: string): Label {
  const p = splitPair(name);
  if (p === null) {
    return t.label("admin.branding.pair", { mode: name, pair: "" });
  }
  return t.label("admin.branding.pair", {
    mode: t.label(`admin.branding.mode.${p.mode}`),
    pair: t.label(`admin.branding.pair.${p.kind}`),
  });
}

/** The result of a contrast check. */
function checkResult(t: I18n, c: BrandingCheck): Child[] {
  if (c.accepted) {
    return [h("p", { id: "branding-pass", "data-accepted": "true" }, [t.label("admin.branding.checks.pass")])];
  }
  return [
    h("p", { "data-accepted": "false" }, [t.label("admin.branding.checks.fail")]),
    h(
      "ul",
      { id: "branding-failing" },
      c.failing.map((p) => h("li", { "data-pair": p }, [pairName(t, p)])),
    ),
  ];
}

async function mountBranding(env: PageEnv): Promise<void> {
  const t = labels(env);
  const f: Frame = frame(env, t, t.label("admin.branding.title"));
  const name = textField("branding-name", t.label("admin.branding.name"), { spellcheck: "false" });
  const colours: Record<Mode, Record<string, HTMLInputElement>> = { light: {}, dark: {} };
  const sets = MODES.map((mode) => {
    const fields = COLOUR_KEYS.map((key) => {
      const field = textField(`branding-${mode}-${key}`, t.label(`admin.branding.colour.${key}`), {
        type: "color",
        value: PLATFORM[mode][key],
      });
      colours[mode][key] = field.control;
      return field.root;
    });
    return h("fieldset", { id: `branding-${mode}` }, [h("legend", {}, [t.label(`admin.branding.mode.${mode}`)]), ...fields]);
  });
  const result = h("div", { id: "branding-check-result" }, [h("p", {}, [t.label("admin.branding.checks.none")])]);
  const read = (m: Mode): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const [k, c] of Object.entries(colours[m])) {
      out[k] = c.value;
    }
    return out;
  };
  const body = (): ReturnType<typeof brandingBody> =>
    brandingBody({ name: name.control.value.trim(), light: read("light"), dark: read("dark") });

  /** Asks the cell for the failing pairs and shows them. Null when the check did not complete. */
  const check = async (): Promise<BrandingCheck | null> => {
    f.clearAlert();
    const b = body();
    if (b === null) {
      f.alert(t.label("admin.branding.invalid"));
      return null;
    }
    const r = await act(env, "tenant.branding.check", {}, b, decodeCheck);
    if (!r.ok) {
      f.problem(r.problem);
      return null;
    }
    result.replaceChildren(...checkResult(t, r.data));
    return r.data;
  };

  const checkButton = buttonEl("branding-check", "button", t.label("admin.branding.check"));
  checkButton.addEventListener("click", () => {
    checkButton.disabled = true;
    check()
      .catch(() => f.problem({ kind: "failed", reason: "request" }))
      .finally(() => {
        checkButton.disabled = false;
      });
  });
  const save = buttonEl("branding-save", "submit", t.label("admin.branding.save"));
  save.className = "fstp-primary";
  const form = formEl("branding-form", [name.root, ...sets, checkButton, save]);
  onSubmit(f, form, save, async () => {
    // I-70: the pairs are checked first, so a failing set is never sent.
    const c = await check();
    if (c === null) {
      return;
    }
    if (!c.accepted) {
      f.alert(t.label("admin.branding.not_saved"));
      return;
    }
    const b = body();
    if (b === null) {
      return;
    }
    const r = await act(env, "tenant.branding.set", {}, b, anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    f.status(t.label("admin.branding.saved"));
  });
  f.show([
    h("p", {}, [t.label("admin.branding.intro")]),
    h("p", {}, [t.label("admin.branding.start")]),
    form,
    section("branding-checks", t.label("admin.branding.checks.heading"), [result]),
    h("p", { class: "text-sm" }, [t.label("admin.branding.footer_note")]),
    h("p", {}, [link(ADMIN_BRAND_PATHS.home, t.label("admin.branding.back"))]),
  ]);
}

async function mountTerminology(env: PageEnv): Promise<void> {
  const t = labels(env);
  const f: Frame = frame(env, t, t.label("admin.terminology.title"));
  const voyage = checkbox("terminology-voyage", "terminology-voyage", t.label("admin.terminology.voyage"));
  const fields = editableKeys().map((key) => {
    const field = textField(fieldId(key), t.label("admin.terminology.default", { text: PLAIN_LABELS[key] ?? key }), {
      "data-key": key,
      maxlength: "200",
    });
    return { key, field };
  });
  const list = h("fieldset", { id: "terminology-labels" }, [
    h("legend", {}, [t.label("admin.terminology.labels")]),
    ...fields.map((x) => x.field.root),
  ]);
  const fixed = section("terminology-fixed", t.label("admin.terminology.fixed.heading"), [
    h("p", {}, [t.label("admin.terminology.fixed.intro")]),
    h(
      "ul",
      {},
      FIXED_LABEL_KEYS.map((k) => h("li", { "data-key": k }, [PLAIN_LABELS[k] ?? k])),
    ),
  ]);
  const save = buttonEl("terminology-save", "submit", t.label("admin.terminology.save"));
  save.className = "fstp-primary";
  const form = formEl("terminology-form", [voyage.root, list, save]);
  onSubmit(f, form, save, async () => {
    f.clearAlert();
    const entries: Record<string, string> = {};
    for (const x of fields) {
      x.field.control.removeAttribute("aria-invalid");
      entries[x.key] = x.field.control.value;
    }
    const built = terminologyBody(entries, voyage.control.checked);
    if (!built.ok) {
      for (const x of fields) {
        if (built.invalid.includes(x.key)) {
          x.field.control.setAttribute("aria-invalid", "true");
        }
      }
      f.alert(t.label("admin.terminology.invalid"));
      return;
    }
    const r = await act(env, "tenant.terminology.set", {}, built.body, anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    f.status(t.label("admin.terminology.saved"));
  });
  f.show([
    h("p", {}, [t.label("admin.terminology.intro")]),
    h("p", {}, [t.label("admin.terminology.scope")]),
    h("p", {}, [t.label("admin.terminology.start")]),
    form,
    fixed,
    h("p", {}, [link(ADMIN_BRAND_PATHS.home, t.label("admin.branding.back"))]),
  ]);
}

const route = (name: string, pattern: string): RouteDef => ({ name, pattern, segments: {} });

/** The two screens. */
export const ADMIN_BRANDING_PAGES: readonly JudgingPage[] = [
  { route: route("admin.branding", ADMIN_BRAND_PATHS.branding), mount: (env) => mountBranding(env) },
  { route: route("admin.terminology", ADMIN_BRAND_PATHS.terminology), mount: (env) => mountTerminology(env) },
];

/** Mounts the screen of `path`. False, and nothing rendered, when it is neither. */
export async function mountAdminBranding(env: PageEnv, path: string): Promise<boolean> {
  const p = path.endsWith("/") && path.length > 1 ? path.slice(0, -1) : path;
  const page = ADMIN_BRANDING_PAGES.find((x) => x.route.pattern === p);
  if (page === undefined) {
    return false;
  }
  await page.mount(env, {});
  return true;
}
