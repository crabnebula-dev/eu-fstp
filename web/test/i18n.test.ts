// i18n.ts: catalogues per locale and message placeholders (R-NF-04), with
// interface strings as `Label` and approved wording as `ApprovedText`,
// never overridable (I-72 seam). M4 design section 3.9, ADR-014.

import { readExpectations } from "../fuzz/harness.js";
import type { CatalogueInput, I18nModule, I18nOptions } from "./support/contract.js";
import { messageish } from "./support/gen.js";
import { assert, eq, forAll, show, test, thrown } from "./support/harness.js";
import { core } from "./support/load.js";
import { placeholderNames, refFormat, refParseMessage } from "./reference/message_ref.js";

const EN: CatalogueInput = {
  locale: "en",
  labels: {
    "nav.calls": "Calls",
    "call.count": "{count} proposals in {call}",
    "role.reviewer": "Reviewer",
    "braces": "Use {{braces}} for {thing}",
  },
  approved: {
    "notice.ai": "This page uses an AI assessor. Synthetic approved wording for tests.",
    "terms.reviewer": "As a {role} you accept these terms. Synthetic approved wording for tests.",
  },
};

const DE: CatalogueInput = {
  locale: "de",
  labels: {
    "nav.calls": "Ausschreibungen",
    "call.count": "{count} Vorschläge in {call}",
    "role.reviewer": "Gutachter",
    "braces": "{thing} mit {{Klammern}}",
  },
  approved: {
    "notice.ai": "Diese Seite nutzt einen KI-Assistenten. Synthetic approved wording for tests.",
    "terms.reviewer": "Als {role} akzeptieren Sie diese Bedingungen. Synthetic approved wording for tests.",
  },
};

function refusedBy(i18n: I18nModule, fn: () => unknown, what: string): void {
  const e = thrown(fn, what);
  assert(e instanceof i18n.I18nError, `${what}: threw ${show(String(e))}, not an I18nError`);
}

/** R-NF-04: the placeholder parser accepts and refuses the shared corpus as listed, with the reference parts. */
test("r_nf_04_parse_message_matches_the_corpus", async () => {
  const i18n = await core("i18n");
  for (const e of readExpectations("message_format")) {
    const got = i18n.parseMessage(e.input);
    eq(got.ok, e.verdict === "accept", `line ${e.line}: ${show(e.input)}`);
    const want = refParseMessage(e.input);
    if (got.ok && want.ok) {
      eq(got.parts, want.parts, `line ${e.line}: parts`);
    }
  }
});

/** R-NF-04: on strings near the grammar, the parser agrees with the reference and never throws. */
test("r_nf_04_parse_message_agrees_with_reference", async () => {
  const i18n = await core("i18n");
  forAll(
    messageish,
    (s) => {
      const got = i18n.parseMessage(s);
      const want = refParseMessage(s);
      eq(got.ok, want.ok, `acceptance of ${show(s)}`);
      if (got.ok && want.ok) {
        eq(got.parts, want.parts, `parts of ${show(s)}`);
      }
    },
    { runs: 2000 },
  );
});

/** R-NF-04: each locale's catalogue answers for that locale. */
test("r_nf_04_label_selects_the_locale_catalogue", async () => {
  const i18n = await core("i18n");
  const en = i18n.createI18n({ catalogues: [EN, DE], locale: "en" });
  const de = i18n.createI18n({ catalogues: [EN, DE], locale: "de" });
  eq(en.locale, "en", "en locale");
  eq(de.locale, "de", "de locale");
  eq(en.label("nav.calls"), "Calls", "en label");
  eq(de.label("nav.calls"), "Ausschreibungen", "de label");
  eq(de.label("call.count", { count: "3", call: "SuperSAFE 1" }), "3 Vorschläge in SuperSAFE 1", "de args");
  eq(en.label("braces", { thing: "x" }), "Use {braces} for x", "escaped braces");
});

/** R-NF-04: arguments are inserted as text and never parsed as placeholders or markup. */
test("r_nf_04_arguments_are_inserted_as_text_only", async () => {
  const i18n = await core("i18n");
  const en = i18n.createI18n({ catalogues: [EN], locale: "en" });
  eq(
    en.label("call.count", { count: "{call}", call: "<img src=x onerror=alert(1)>" }),
    "{call} proposals in <img src=x onerror=alert(1)>",
    "arguments kept verbatim",
  );
  eq(en.label("call.count", { count: "{{", call: "}}" }), "{{ proposals in }}", "brace arguments kept verbatim");
});

/** R-NF-04: a missing argument, an extra argument or an unknown id is refused, never shown as a key. */
test("r_nf_04_missing_extra_and_unknown_are_refused", async () => {
  const i18n = await core("i18n");
  const en = i18n.createI18n({ catalogues: [EN], locale: "en" });
  refusedBy(i18n, () => en.label("call.count", { count: "3" }), "missing argument");
  refusedBy(i18n, () => en.label("call.count"), "no arguments");
  refusedBy(i18n, () => en.label("nav.calls", { extra: "x" }), "extra argument");
  refusedBy(i18n, () => en.label("call.count", { count: "3", call: "c", more: "m" }), "extra argument beside the right ones");
  refusedBy(i18n, () => en.label("no.such.id"), "unknown label id");
  refusedBy(i18n, () => en.approved("no.such.id"), "unknown approved id");
  refusedBy(i18n, () => en.label("notice.ai"), "an approved id read as a label");
  refusedBy(i18n, () => en.approved("nav.calls"), "a label id read as approved text");
});

/** R-NF-04: an unknown locale, or a catalogue message that does not parse, is refused at creation. */
test("r_nf_04_unknown_locale_and_malformed_catalogue_refused", async () => {
  const i18n = await core("i18n");
  refusedBy(i18n, () => i18n.createI18n({ catalogues: [EN], locale: "fr" }), "unknown locale");
  refusedBy(i18n, () => i18n.createI18n({ catalogues: [], locale: "en" }), "no catalogue");
  const bad: CatalogueInput = { locale: "en", labels: { x: "Hello {Name}" }, approved: {} };
  refusedBy(i18n, () => i18n.createI18n({ catalogues: [bad], locale: "en" }), "malformed label");
  const badApproved: CatalogueInput = { locale: "en", labels: {}, approved: { x: "unclosed {" } };
  refusedBy(i18n, () => i18n.createI18n({ catalogues: [badApproved], locale: "en" }), "malformed approved text");
});

/** R-NF-04: over generated messages and arguments, formatting equals the reference. */
test("r_nf_04_format_agrees_with_reference", async () => {
  const i18n = await core("i18n");
  forAll(
    (r) => {
      const msg = messageish(r);
      const args: Record<string, string> = {};
      const parsed = refParseMessage(msg);
      if (parsed.ok) {
        for (const n of placeholderNames(parsed.parts)) {
          args[n] = r.pick(["", "x", "{name}", "<b>", "}}", "é"]);
        }
      }
      return { msg, args };
    },
    ({ msg, args }) => {
      const parsed = refParseMessage(msg);
      const cat: CatalogueInput = { locale: "en", labels: { m: msg }, approved: { a: msg } };
      if (!parsed.ok) {
        refusedBy(i18n, () => i18n.createI18n({ catalogues: [cat], locale: "en" }), `malformed ${show(msg)}`);
        return;
      }
      const t = i18n.createI18n({ catalogues: [cat], locale: "en" });
      const want = refFormat(parsed.parts, args);
      eq(t.label("m", args), want, `label of ${show(msg)}`);
      eq(t.approved("a", args), want, `approved text of ${show(msg)}`);
    },
    { runs: 1000 },
  );
});

/** I-72: an override of approved wording is refused, so notices and terms keep their wording. */
test("i72_override_of_approved_text_refused", async () => {
  const i18n = await core("i18n");
  for (const id of Object.keys(EN.approved)) {
    const opts: I18nOptions = { catalogues: [EN], locale: "en", overrides: { [id]: "Changed wording" } };
    refusedBy(i18n, () => i18n.createI18n(opts), `override of approved ${id}`);
  }
});

/** I-72: terminology overrides change interface labels only; approved text stays as approved. */
test("i72_label_override_changes_labels_only", async () => {
  const i18n = await core("i18n");
  const t = i18n.createI18n({
    catalogues: [EN],
    locale: "en",
    overrides: { "role.reviewer": "Evaluator", "nav.calls": "Open calls" },
  });
  eq(t.label("role.reviewer"), "Evaluator", "overridden label");
  eq(t.label("nav.calls"), "Open calls", "second overridden label");
  eq(t.label("call.count", { count: "1", call: "c" }), "1 proposals in c", "other labels unchanged");
  eq(
    t.approved("terms.reviewer", { role: t.label("role.reviewer") }),
    "As a Evaluator you accept these terms. Synthetic approved wording for tests.",
    "approved wording unchanged around a bound label",
  );
  eq(t.approved("notice.ai"), EN.approved["notice.ai"], "approved text unchanged");
});

/** I-72: an override of an unknown label, or one that does not parse, is refused. */
test("i72_override_of_unknown_label_or_malformed_override_refused", async () => {
  const i18n = await core("i18n");
  refusedBy(i18n, () => i18n.createI18n({ catalogues: [EN], locale: "en", overrides: { "no.such": "x" } }), "unknown label");
  refusedBy(
    i18n,
    () => i18n.createI18n({ catalogues: [EN], locale: "en", overrides: { "nav.calls": "Calls {" } }),
    "malformed override",
  );
});

/** I-72: an id that is both a label and approved text is refused, so no override can reach approved wording. */
test("i72_id_in_both_labels_and_approved_refused", async () => {
  const i18n = await core("i18n");
  const both: CatalogueInput = { locale: "en", labels: { x: "Label" }, approved: { x: "Approved" } };
  refusedBy(i18n, () => i18n.createI18n({ catalogues: [both], locale: "en" }), "id in both namespaces");
});
