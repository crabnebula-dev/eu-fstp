// Field help in the wizard and the Programme editor (SA-13, Daniel
// 2026-11-15 night; `docs/design/spec-amendments.md` SA-13).
//
// - Every field of the creator catalogue (`creator/fields.ts`) has a help
//   text, and a parameter field names its P- id, as the label check does
//   for labels (R-PG-01, R-NF-04).
// - Every label of the wizard, invitation and import forms comes with its
//   help, and every help id those pages spell is in the help catalogue.
// - The "i" control is a real button named "About <field label>", with
//   `aria-expanded` and `aria-controls`. Its help region sits under the
//   label, hidden until a click (R-NF-03).
// - The field editors put the control beside the field's label or legend.
//
// Every value is synthetic.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { fieldEditor } from "../src/creator/editor.js";
import { FIELDS, fieldOf } from "../src/creator/fields.js";
import { HELP_CATALOGUE } from "../src/help/messages.en.js";
import { attachHelp, fieldHelpId, helpText, labelWithHelp } from "../src/help/help.js";
import { asFake, freshDom, type FakeElement } from "./support/fakedom.js";
import { assert, eq, test } from "./support/harness.js";
import { WEB_DIR } from "./support/paths.js";

/** The label, the "i" button and the help region that `labelWithHelp` returns. */
function parts(id: string, label: string, helpId: string): { label: FakeElement; button: FakeElement; region: FakeElement } {
  const out = labelWithHelp(id, label, helpId).map(asFake);
  eq(out.length, 3, "a label, its button and its region");
  const [l, b, r] = out;
  assert(l !== undefined && b !== undefined && r !== undefined, "three parts");
  return { label: l, button: b, region: r };
}

/** Runs `fn` with the form control classes the editor tests for, which the fake DOM leaves out. */
function withControlClasses(fn: () => void): void {
  const g = globalThis as unknown as Record<string, unknown>;
  const names = ["HTMLTextAreaElement", "HTMLSelectElement"];
  const added = names.filter((n) => g[n] === undefined);
  for (const n of added) g[n] = class {};
  try {
    fn();
  } finally {
    for (const n of added) delete g[n];
  }
}

/** The P- id a field key spells in its member name, such as "P-53", or null. */
function pId(member: string): string | null {
  const m = /^p(\d\d)_/.exec(member);
  return m === null ? null : `P-${m[1] ?? ""}`;
}

/** R-PG-01, R-NF-04, SA-13: every catalogue field has a help text, and a parameter field names its P- id. */
test("r_pg_01_sa13_every_catalogue_field_has_a_help_text", () => {
  const missing: string[] = [];
  const unnamed: string[] = [];
  for (const f of FIELDS) {
    const text = helpText(fieldHelpId(f.key));
    if (text === null || text.trim() === "") {
      missing.push(f.key);
      continue;
    }
    const p = pId(f.member);
    if (p !== null && !text.includes(p)) unnamed.push(`${f.key} (${p})`);
  }
  eq(missing, [], "fields without a help text");
  eq(unnamed, [], "parameter fields whose help does not name the P- id");
  // No help text for a field the catalogue does not have.
  const keys = new Set(FIELDS.map((f) => fieldHelpId(f.key)));
  const extra = Object.keys(HELP_CATALOGUE.labels).filter((id) => id.startsWith("help.field.") && !keys.has(id));
  eq(extra, [], "help texts of fields the catalogue does not have");
});

/**
 * The pages in SA-13's scope outside the field editors, and the labels
 * in them that name an option or an action reason, not a field.
 */
const FORM_PAGES: readonly (readonly [string, RegExp | null])[] = [
  ["setup/pages.ts", /for: `setup-role-\$\{role\}`/],
  ["people/invite.ts", null],
  ["admin/team/page.ts", /for: `reason-\$\{key\}`/],
  ["creator/pages/start.ts", null],
  ["creator/pages/imports.ts", null],
];

/** R-NF-04, SA-13: every field label of the wizard, invitation and import forms comes with its help. */
test("r_nf_04_sa13_every_wizard_invitation_and_import_field_has_a_help_text", () => {
  const problems: string[] = [];
  const used = new Set<string>();
  for (const [file, exempt] of FORM_PAGES) {
    const src = readFileSync(join(WEB_DIR, "src", file), "utf8");
    src.split("\n").forEach((line, i) => {
      if (/h\("label"/.test(line) && (exempt === null || !exempt.test(line))) {
        problems.push(`${file}:${i + 1}: a label without its help (use labelWithHelp)`);
      }
    });
    const ids = [...src.matchAll(/"(help\.[a-z_.]+)"/g)].map((m) => m[1] ?? "");
    if (ids.length === 0) problems.push(`${file}: no help id`);
    for (const id of ids) {
      used.add(id);
      if (helpText(id) === null) problems.push(`${file}: help id ${id} is not in the catalogue`);
    }
  }
  eq(problems, [], "labels and help ids of the form pages");
  for (const id of [
    "help.wizard.programme_name",
    "help.wizard.manager_email",
    "help.wizard.team_email",
    "help.wizard.role",
    "help.wizard.organisation",
    "help.wizard.role_start",
    "help.wizard.role_end",
    "help.invite.email",
    "help.invite.role",
    "help.invite.organisation",
    "help.import.file",
    "help.import.clone_source",
    "help.import.conflict_ack",
  ]) {
    assert(used.has(id), `a page uses ${id}`);
  }
});

/** R-NF-03, SA-13: the "i" control is a real button named "About <label>", collapsed, controlling a hidden region. */
test("r_nf_03_sa13_help_button_is_a_named_collapsed_disclosure", () => {
  freshDom();
  const { label, button, region } = parts("setup-name", "Programme name", "help.wizard.programme_name");
  eq(label.localName, "label", "the label comes first");
  eq(label.getAttribute("for"), "setup-name", "the label names its control");
  eq(label.textContent, "Programme name", "the label keeps its text");
  eq(button.localName, "button", "a real button");
  eq(button.getAttribute("type"), "button", "never a submit button");
  eq(button.getAttribute("aria-label"), "About Programme name", "the accessible name");
  eq(button.getAttribute("aria-expanded"), "false", "collapsed at first");
  eq(button.textContent, "", "the glyph comes from the style sheet, so no text competes with the name");
  const regionId = region.getAttribute("id");
  assert(regionId !== null && regionId !== "", "the region has an id");
  eq(button.getAttribute("aria-controls"), regionId, "the button controls the region");
  assert(region.hasAttribute("hidden"), "the help is hidden by default");
  eq(region.textContent, helpText("help.wizard.programme_name"), "the region holds the help text");
});

/** R-NF-03, SA-13: a click shows the help and a second click hides it again. */
test("r_nf_03_sa13_help_button_toggles_its_region", () => {
  freshDom();
  const { button, region } = parts("invite-email", "Email address", "help.invite.email");
  button.click();
  eq(button.getAttribute("aria-expanded"), "true", "expanded after a click");
  assert(!region.hasAttribute("hidden"), "the help shows after a click");
  button.click();
  eq(button.getAttribute("aria-expanded"), "false", "collapsed after a second click");
  assert(region.hasAttribute("hidden"), "the help hides again");
});

/** R-NF-03, SA-13: on a legend the button sits inside it, and the group keeps the legend text as its name. */
test("r_nf_03_sa13_help_on_a_legend_keeps_the_group_name", () => {
  freshDom();
  const legend = asFake(document.createElement("legend"));
  legend.append("Role");
  const fieldset = asFake(document.createElement("fieldset"));
  fieldset.append(legend, document.createElement("div") as unknown as FakeElement);
  const help = attachHelp(legend as unknown as HTMLElement, "setup-team-role", "help.wizard.role");
  assert(help !== null, "the help is attached");
  const button = asFake(help.button);
  const region = asFake(help.region);
  const name = legend.children[0];
  assert(name !== undefined, "the legend text sits in a span");
  eq(name.textContent, "Role", "the span holds the legend text");
  eq(fieldset.getAttribute("aria-labelledby"), name.getAttribute("id"), "the group is named by the span alone");
  eq(legend.children[1], button, "the button sits beside the text in the legend");
  eq(button.getAttribute("aria-label"), "About Role", "the button's name");
  eq(fieldset.children[1], region, "the region follows the legend");
  assert(region.hasAttribute("hidden"), "hidden by default");
});

/** R-PG-01, R-NF-03, SA-13: a field editor puts the button beside the field label, for a scalar and for a list field. */
test("r_pg_01_sa13_field_editor_puts_help_beside_the_field_label", () => {
  freshDom();
  withControlClasses(() => {
    const name = fieldOf("identity.name");
    assert(name !== null, "identity.name is in the catalogue");
    const scalar = asFake(fieldEditor(name, "Synthetic Programme", { mark: true, prefix: "f.identity.name" }).root);
    const control = scalar.children[0];
    assert(control !== undefined, "the control block");
    const kids = control.children;
    eq(kids.map((k) => k.localName), ["label", "button", "div", "input"], "label, button, region, then the input");
    const button = kids[1];
    const region = kids[2];
    assert(button !== undefined && region !== undefined, "button and region");
    eq(button.getAttribute("aria-label"), "About Programme name", "named after the field label");
    eq(button.getAttribute("aria-controls"), region.getAttribute("id"), "controls the region");
    eq(region.textContent, helpText(fieldHelpId("identity.name")), "the field's help");
    assert(region.hasAttribute("hidden"), "hidden by default");

    const ko = fieldOf("evaluation.p09_knock_outs");
    assert(ko !== null, "P-09 is in the catalogue");
    const list = asFake(fieldEditor(ko, [{ id: "1", text: "Synthetic criterion" }], { mark: true, prefix: "ko" }).root);
    const group = list.children[0];
    assert(group !== undefined && group.localName === "fieldset", "a list field is a fieldset");
    const legend = group.children[0];
    assert(legend !== undefined && legend.localName === "legend", "its legend comes first");
    eq(legend.textContent, "Knock-out criteria (P-09)", "the legend text is unchanged");
    const koButton = legend.children[1];
    assert(koButton !== undefined && koButton.localName === "button", "the button sits in the legend");
    eq(koButton.getAttribute("aria-label"), "About Knock-out criteria (P-09)", "named after the field label");
    eq(group.getAttribute("aria-labelledby"), legend.children[0]?.getAttribute("id") ?? "", "the group keeps its name");
    // Only the field label carries help: no member or item does.
    const buttons = group.descendants().filter((e) => e.getAttribute("aria-controls")?.endsWith("-help") === true);
    eq(buttons.length, 1, "one help button per field");
  });
});

/** The help texts that wait for a legal explanation, each marked TODO(legal) for Daniel. */
const LEGAL_PENDING = [
  "help.field.contract.flow_down",
  "help.field.contract.p30_signature_cascade",
  "help.field.contract.p44_payment_nature",
  "help.field.contract.p47_seal_level",
  "help.field.eligibility.minors",
  "help.field.eligibility.p19_document_retention",
  "help.field.evaluation.p77_mcp_binding_actions",
  "help.field.funder.p41_funder_retention",
  "help.field.funder.p46_switch_retrieval_period",
];

/** R-NF-04, SA-13: the help texts follow the prose rules, and exactly the listed ones wait for legal text. */
test("r_nf_04_sa13_help_texts_follow_the_prose_rules_and_mark_legal_gaps", () => {
  const problems: string[] = [];
  const marked: string[] = [];
  for (const [id, text] of Object.entries(HELP_CATALOGUE.labels)) {
    if (text.includes("—")) problems.push(`${id}: an em dash`);
    for (const s of text.split(/(?<=[.!?])\s+/)) {
      const words = s.split(/\s+/).filter((w) => w !== "").length;
      if (words >= 40) problems.push(`${id}: a sentence of ${words} words`);
    }
    if (text.includes("TODO(legal)")) marked.push(id);
  }
  eq(problems, [], "prose rules");
  eq(marked.sort(), [...LEGAL_PENDING].sort(), "the help texts marked TODO(legal)");
});
