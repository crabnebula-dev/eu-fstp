// The legal pages behind every footer and the legal details form
// (ADR-037; Daniel, 2026-11-22, Q4 and Q6; I-68, I-69).

import { ADMIN_BRANDING_LABELS } from "../src/admin/branding/messages.en.js";
import { LEGAL_KEYS, decodeLegalDetails, legalDetailsBody } from "../src/admin/branding/legalpage.js";
import { defaultMandatoryElements, footer } from "../src/creator/frame.js";
import { shellFooter } from "../src/shell/brand.js";
import { LEGAL_LINKS, footerItem } from "../src/shell/legal.js";
import { assert, eq, test } from "./support/harness.js";
import { FakeElement, freshDom } from "./support/fakedom.js";

/** The `href` of the link keyed `key` in `root`, or null. */
function hrefOf(root: FakeElement, key: string): string | null {
  for (const a of root.getElementsByTagName("a")) {
    if (a.getAttribute("data-mandatory") === key) {
      return a.getAttribute("href");
    }
  }
  return null;
}

/** I-69, ADR-037: the app footers link every legal page under its mandatory key, signed in or out. */
test("i69_adr037_app_footers_link_the_legal_pages", () => {
  freshDom();
  const roots = [
    shellFooter() as unknown as FakeElement,
    footer(defaultMandatoryElements()) as unknown as FakeElement,
  ];
  for (const root of roots) {
    for (const l of LEGAL_LINKS) {
      eq(hrefOf(root, l.key), l.path, `${l.key} links its page`);
    }
  }
  eq(LEGAL_LINKS.length, 5, "five legal pages");
  assert(LEGAL_LINKS.every((l) => l.path.startsWith("/legal/")), "every page is under /legal/");
});

/** I-69: any other footer element stays a keyed span. */
test("i69_adr037_other_footer_elements_stay_spans", () => {
  freshDom();
  const li = footerItem("platform_attribution", "Runs on the FSTP platform.") as unknown as FakeElement;
  eq(li.getElementsByTagName("a").length, 0, "no link");
  eq(li.getElementsByTagName("span")[0]?.getAttribute("data-mandatory"), "platform_attribution", "keyed");
});

/** I-68, ADR-037: the form sends every key, trimmed, empty when not set, and refuses markup. */
test("i68_adr037_legal_details_body_is_plain_text", () => {
  const { body, bad } = legalDetailsBody({ legal_name: " Synthetic Org Ltd ", vat_number: "" });
  eq(bad, null, "valid");
  eq(Object.keys(body ?? {}), [...LEGAL_KEYS], "every key in form order");
  eq(body?.["legal_name"], "Synthetic Org Ltd", "trimmed");
  eq(body?.["address"], "", "an empty field is sent empty");
  eq(legalDetailsBody({ address: "<b>x</b>" }).bad, "address", "markup is refused");
  eq(legalDetailsBody({ address: "x".repeat(301) }).bad, "address", "too long");
  eq(decodeLegalDetails({ legal_name: "A", other: "B", vat_number: 7 }), { legal_name: "A" }, "decodes known string members");
  eq(decodeLegalDetails(null), {}, "nothing to decode");
});

/** ADR-037 usability rule: each field has a plain label and a short hint. */
test("adr037_every_legal_field_has_a_label_and_a_hint", () => {
  for (const k of LEGAL_KEYS) {
    const label = ADMIN_BRANDING_LABELS[`admin.branding.legal.${k}`];
    const hint = ADMIN_BRANDING_LABELS[`admin.branding.legal.${k}.hint`];
    assert(label !== undefined && label.length > 0, `${k} label`);
    assert(hint !== undefined && hint.length > 0 && hint.length <= 120, `${k} hint`);
  }
});
