// The funding card defaults on the tenant admin's branding page (ADR-034;
// I-69). Each programme's funding card names its coordinator and the
// coordinator's contact. These defaults fill an empty coordinator field of
// a new programme, and back the card of a programme activated before the
// contact field existed. `tenant.set_funding_defaults` is high-risk, so it
// asks for a step-up, as the brand colours do.

import { h } from "../../core/dom.js";
import { type I18n, createI18n } from "../../core/i18n.js";
import { act, anyObject, buttonEl, formEl, onSubmit, section, textField } from "../../grant/kit.js";
import type { Frame, PageEnv } from "../../reviewer/kit.js";
import { FUNDING_PATH, type FundingCard, decodeFunding } from "../../shell/funding.js";
import { ADMIN_BRANDING_LABELS } from "./messages.en.js";

/** The longest default, in bytes, as `fstp_brand::funding::MAX_DEFAULT_BYTES`. */
export const MAX_DEFAULT_BYTES = 200;

/** Whether `s` may be a default: 1 to 200 bytes, no control character, no angle bracket, no outer white space (I-68). */
export function plainDefault(s: string): boolean {
  return (
    s !== "" &&
    new TextEncoder().encode(s).length <= MAX_DEFAULT_BYTES &&
    s.trim() === s &&
    !/[\u0000-\u001f\u007f-\u009f<>]/.test(s)
  );
}

/** The request body of `tenant.set_funding_defaults`, or null when a value is not plain text. */
export function fundingDefaultsBody(name: string, contact: string): { name: string; contact: string } | null {
  const n = name.trim();
  const c = contact.trim();
  return plainDefault(n) && plainDefault(c) ? { name: n, contact: c } : null;
}

/** The "Funding card" section of the branding page. */
export function fundingSection(env: PageEnv, t: I18n, f: Frame): HTMLElement {
  const name = textField("funding-name", t.label("admin.branding.funding.name"), { maxlength: "200" });
  const contact = textField("funding-contact", t.label("admin.branding.funding.contact"), { maxlength: "200" });
  const hintList = h("ul", { id: "funding-ack-hints", class: "hint" }, []);
  hintList.hidden = true;
  void (async () => {
    try {
      const r = await fetch(FUNDING_PATH, { credentials: "same-origin", cache: "no-store", redirect: "error" });
      const answer = r.ok ? decodeFunding(await r.json()) : null;
      const d = answer?.defaults ?? null;
      // L-08 (ADR-036): say which programme lacks the funding sentence, and why.
      const hints = ackHints(answer?.cards ?? [], t);
      hintList.replaceChildren(...hints.map((s) => h("li", {}, [s])));
      hintList.hidden = hints.length === 0;
      if (d !== null) {
        name.control.value = name.control.value === "" ? d.name : name.control.value;
        contact.control.value = contact.control.value === "" ? d.contact : contact.control.value;
      }
    } catch {
      // No defaults shown: the admin types them.
    }
  })();
  const save = buttonEl("funding-save", "submit", t.label("admin.branding.funding.save"));
  save.className = "fstp-primary";
  const form = formEl("funding-form", [name.root, contact.root, save]);
  onSubmit(f, form, save, async () => {
    const body = fundingDefaultsBody(name.control.value, contact.control.value);
    if (body === null) {
      f.alert(t.label("admin.branding.funding.invalid"));
      return;
    }
    const r = await act(env, "tenant.set_funding_defaults", {}, body, anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    f.status(t.label("admin.branding.funding.saved"));
  });
  return section("funding-defaults", t.label("admin.branding.funding.heading"), [
    h("p", {}, [t.label("admin.branding.funding.intro")]),
    h("p", {}, [t.label("admin.branding.funding.role")]),
    hintList,
    form,
  ]);
}

/** The English labels of this section, for callers without a page. */
function englishLabels(): I18n {
  return createI18n({ catalogues: [{ locale: "en", labels: ADMIN_BRANDING_LABELS, approved: {} }], locale: "en" });
}

/**
 * One plain line per programme whose funding sentence does not show
 * (L-08, ADR-036): it names the programme and the values to fill in, and
 * where. Usability: the non-technical operator sees why the sentence is
 * missing without reading any code.
 */
export function ackHints(cards: readonly FundingCard[], t: I18n = englishLabels()): string[] {
  const out: string[] = [];
  for (const c of cards) {
    if (c.acknowledgement !== null || c.acknowledgementMissing.length === 0) {
      continue;
    }
    if (c.acknowledgementMissing.includes("profile")) {
      out.push(String(t.label("admin.branding.funding.ack.profile", { name: c.name })));
      continue;
    }
    const values = c.acknowledgementMissing.map((m) => String(t.label(`admin.branding.funding.ack.${m}`)));
    const joined =
      values.length <= 1
        ? (values[0] ?? "")
        : `${values.slice(0, -1).join(", ")} ${String(t.label("admin.branding.funding.ack.and"))} ${values[values.length - 1] ?? ""}`;
    out.push(String(t.label("admin.branding.funding.ack.missing", { name: c.name, values: joined })));
  }
  return out;
}
