// forms.ts: labelled controls and amount fields (R-NF-03, ADR-006; M4
// design section 3.9). A field never rewrites what the user typed.

import type { FormField } from "./support/contract.js";
import { FakeElement, asFake, freshDom, sinkUses } from "./support/fakedom.js";
import { assert, eq, show, test, thrown } from "./support/harness.js";
import { core } from "./support/load.js";

function labelOf(f: FormField): FakeElement {
  const labels = asFake(f.root).getElementsByTagName("label");
  eq(labels.length, 1, "one label in the field");
  const l = labels[0];
  assert(l !== undefined, "label exists");
  return l;
}

/** R-NF-03: each field's label is bound to its control by `for` and id, and holds the label as text. */
test("r_nf_03_field_label_is_bound_to_its_control", async () => {
  freshDom();
  const forms = await core("forms");
  const f = forms.field({ id: "title", label: "Title <i>of</i> the proposal", kind: "text", required: true });
  const control = asFake(f.control);
  eq(control.getAttribute("id"), "title", "control id");
  assert(asFake(f.root).contains(control), "the control is inside the field");
  const label = labelOf(f);
  eq(label.getAttribute("for"), "title", "label for");
  eq(label.textContent, "Title <i>of</i> the proposal", "label text");
  eq(label.descendants().filter((e) => e.localName !== "span").length, 0, "no element parsed from the label");
  eq(sinkUses, [], "no HTML sink reached");
});

/** ADR-006: an amount field reads only canonical EUR strings and never rewrites the input. */
test("adr006_amount_field_reads_canonical_strings_only", async () => {
  freshDom();
  const forms = await core("forms");
  const f = forms.field({ id: "cap", label: "Cap", kind: "amount", required: true });
  const cases: readonly [string, boolean][] = [
    ["1234.50", true],
    ["0.00", true],
    ["1234.5", false],
    ["1 234,50", false],
    ["€1234.50", false],
    ["-5.00", false],
    ["1e3", false],
    [" 1234.50", false],
  ];
  for (const [typed, ok] of cases) {
    asFake(f.control).value = typed;
    const got = f.read();
    eq(asFake(f.control).value, typed, `the control still holds ${show(typed)}`);
    if (ok) {
      eq(got, { ok: true, value: typed }, `read of ${show(typed)}`);
    } else {
      eq(got, { ok: false, reason: "amount" }, `read of ${show(typed)}`);
    }
  }
});

/** R-NF-03: an empty required field reports `required`, and an optional one reads as empty. */
test("r_nf_03_required_field_reports_a_missing_value", async () => {
  freshDom();
  const forms = await core("forms");
  const required = forms.field({ id: "a", label: "A", kind: "text", required: true });
  eq(required.read(), { ok: false, reason: "required" }, "required and empty");
  assert(asFake(required.control).hasAttribute("required") || asFake(required.control).getAttribute("aria-required") === "true", "the control is marked required");
  const optional = forms.field({ id: "b", label: "B", kind: "text", required: false });
  eq(optional.read(), { ok: true, value: "" }, "optional and empty");
  const amount = forms.field({ id: "c", label: "C", kind: "amount", required: true });
  eq(amount.read(), { ok: false, reason: "required" }, "required amount and empty");
});

/** ADR-014 (DOM clobbering): a field id that would shadow a form member is refused. */
test("adr014_field_id_that_shadows_a_form_member_is_refused", async () => {
  freshDom();
  const forms = await core("forms");
  for (const id of ["submit", "action", "elements", "reset", "method"]) {
    thrown(() => forms.field({ id, label: "X", kind: "text", required: false }), `field id ${show(id)}`);
  }
  eq(asFake(forms.field({ id: "P-04", label: "Cap", kind: "amount", required: true }).control).getAttribute("name"), "P-04", "a safe id passes");
});
