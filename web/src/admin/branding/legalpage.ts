// The tenant's legal details on the admin branding page (ADR-037; Daniel,
// 2026-11-22, `legal/README.md` Q4). The legal pages behind every footer
// (privacy notice, accessibility statement, imprint, terms of use, Data Act
// information) fill their blanks from these values. A non-technical admin
// fills them here: one plain label and one short hint per field, and any
// field may stay empty, which the pages show as "[not set: ...]".
// `tenant.set_legal_details` is high-risk, so it asks for a step-up, as the
// funding card defaults do.

import { h } from "../../core/dom.js";
import type { I18n } from "../../core/i18n.js";
import { act, anyObject, buttonEl, formEl, onSubmit, section, textField } from "../../grant/kit.js";
import type { Frame, PageEnv } from "../../reviewer/kit.js";

/** The longest value, in bytes, as `fstp_brand::legal::MAX_LEGAL_BYTES`. */
export const MAX_LEGAL_BYTES = 300;

/** The path of the set legal details, as JSON (ADR-037). */
export const LEGAL_DETAILS_PATH = "/legal/details";

/** The field keys, in form order, as `fstp_brand::legal::LegalField::KEYS`. */
export const LEGAL_KEYS: readonly string[] = Object.freeze([
  "legal_name",
  "address",
  "registered_address",
  "privacy_contact",
  "dpo_name",
  "dpo_contact",
  "supervisory_authority",
  "accessibility_contact",
  "company_number",
  "vat_number",
  "transparency_register",
  "governing_law",
]);

/** Whether `s` may be a set value: 1 to 300 bytes, no control character, no angle bracket (I-68). `s` is trimmed. */
export function plainLegalValue(s: string): boolean {
  return s !== "" && new TextEncoder().encode(s).length <= MAX_LEGAL_BYTES && !/[\u0000-\u001f\u007f-\u009f<>]/.test(s);
}

/**
 * The request body of `tenant.set_legal_details`: every key, each value
 * trimmed, an empty string for an empty field. Null names the first key
 * whose value is not plain text.
 */
export function legalDetailsBody(values: Readonly<Record<string, string>>): { body: Record<string, string> | null; bad: string | null } {
  const body: Record<string, string> = {};
  for (const k of LEGAL_KEYS) {
    const v = (values[k] ?? "").trim();
    if (v !== "" && !plainLegalValue(v)) {
      return { body: null, bad: k };
    }
    body[k] = v;
  }
  return { body, bad: null };
}

/** Reads the set legal details, or an empty record when they cannot be read. */
export function decodeLegalDetails(x: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (typeof x !== "object" || x === null || Array.isArray(x)) {
    return out;
  }
  for (const k of LEGAL_KEYS) {
    const v = (x as Record<string, unknown>)[k];
    if (typeof v === "string") {
      out[k] = v;
    }
  }
  return out;
}

/** The "Legal details" section of the branding page. */
export function legalSection(env: PageEnv, t: I18n, f: Frame): HTMLElement {
  const fields = LEGAL_KEYS.map((k) => {
    const id = `legal-${k.replaceAll("_", "-")}`;
    const hintId = `${id}-hint`;
    const field = textField(id, t.label(`admin.branding.legal.${k}`), {
      maxlength: String(MAX_LEGAL_BYTES),
      "aria-describedby": hintId,
    });
    field.root.append(h("span", { id: hintId, class: "fstp-hint" }, [t.label(`admin.branding.legal.${k}.hint`)]));
    return { key: k, field };
  });
  void (async () => {
    try {
      const r = await fetch(LEGAL_DETAILS_PATH, { credentials: "same-origin", cache: "no-store", redirect: "error" });
      const d = r.ok ? decodeLegalDetails(await r.json()) : {};
      for (const { key, field } of fields) {
        const v = d[key];
        if (v !== undefined && field.control.value === "") {
          field.control.value = v;
        }
      }
    } catch {
      // No values shown: the admin types them.
    }
  })();
  const save = buttonEl("legal-save", "submit", t.label("admin.branding.legal.save"));
  save.className = "fstp-primary";
  const form = formEl("legal-form", [...fields.map((x) => x.field.root), save]);
  onSubmit(f, form, save, async () => {
    const values: Record<string, string> = {};
    for (const { key, field } of fields) {
      values[key] = field.control.value;
    }
    const { body, bad } = legalDetailsBody(values);
    if (body === null) {
      f.alert(t.label("admin.branding.legal.invalid", { field: t.label(`admin.branding.legal.${bad ?? "legal_name"}`) }));
      return;
    }
    const r = await act(env, "tenant.set_legal_details", {}, body, anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    f.status(t.label("admin.branding.legal.saved"));
  });
  return section("legal-details", t.label("admin.branding.legal.heading"), [
    h("p", {}, [t.label("admin.branding.legal.intro")]),
    h("p", {}, [t.label("admin.branding.legal.empty")]),
    form,
  ]);
}
