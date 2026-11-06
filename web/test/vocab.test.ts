// The vocabulary packs in the web app (`SPEC/12-journey-ui.md` section 4,
// `docs/design/07-vocabulary-pack.md`; O-55, I-72, I-94, I-96, R-WL-05).
//
// The plain label is the catalogue label and always leads. A tenant that
// switches Voyage on gets the Voyage label as a secondary line. Approved
// wording never takes a pack label, and formal state names stay visible.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { APPLICANT_APPROVED, FOOTER_APPROVED } from "../src/applicant/messages.en.js";
import { CALLS_APPROVED } from "../src/calls/messages.en.js";
import { CATALOGUE as CREATOR } from "../src/creator/messages.en.js";
import { createI18n, I18nError } from "../src/core/i18n.js";
import { HOME_LABELS } from "../src/home/messages.en.js";
import { JOURNEY_LABELS } from "../src/journey/messages.en.js";
import { CATALOGUE as PEOPLE } from "../src/people/messages.en.js";
import { stateWithVoyage, vocabOptions, labelWithVoyage } from "../src/vocab/label.js";
import { VOYAGE_LABELS } from "../src/vocab/voyage.js";
import { asFake, freshDom } from "./support/fakedom.js";
import { assert, eq, show, test, thrown } from "./support/harness.js";
import { REPO_DIR } from "./support/paths.js";

interface PackFile {
  readonly vocab_pack_version: number;
  readonly pack: string;
  readonly labels: Readonly<Record<string, string>>;
}

function packFile(name: string): PackFile {
  const path = join(REPO_DIR, "crates", "fstp-journey", "vocab", name);
  return JSON.parse(readFileSync(path, "utf8")) as PackFile;
}

const PLAIN = packFile("plain.v1.json");
const VOYAGE = packFile("voyage.v1.json");

const APPROVED: Readonly<Record<string, string>> = {
  ...APPLICANT_APPROVED,
  ...FOOTER_APPROVED,
  ...CALLS_APPROVED,
  ...CREATOR.approved,
  ...PEOPLE.approved,
};

const LABELS = { ...HOME_LABELS, ...JOURNEY_LABELS };

function i18n(on: boolean) {
  return createI18n({
    catalogues: [{ locale: "en", labels: LABELS, approved: {} }],
    locale: "en",
    ...vocabOptions(on ? "voyage" : "plain"),
  });
}

test("adr015_web_voyage_pack_equals_the_shipped_pack", () => {
  eq(VOYAGE.pack, "voyage", "the pack file");
  eq({ ...VOYAGE_LABELS }, { ...VOYAGE.labels }, "web/src/vocab/voyage.ts repeats vocab/voyage.v1.json");
  eq(PLAIN.pack, "plain", "the plain pack file");
});

// Lane j3 gave `journey.withdraw.action` the link text "Withdraw on the
// proposal page" and put design 07's "Withdraw this proposal" under
// `journey.withdraw.title`. Lane vocab may not edit that catalogue, so the
// one difference is listed here and reported. The list must stay exact.
const DIVERGES: readonly string[] = ["journey.withdraw.action"];

test("r_wl_05_web_catalogue_labels_are_the_plain_pack", () => {
  let shared = 0;
  const differ: string[] = [];
  for (const [key, text] of Object.entries(PLAIN.labels)) {
    const label = LABELS[key];
    if (label !== undefined) {
      if (label !== text) {
        differ.push(key);
      }
      shared += 1;
    }
  }
  eq(differ, DIVERGES, "O-55: catalogue labels that differ from the plain pack");
  assert(shared >= 16, `the check has teeth: ${shared} shared keys`);
});

test("i72_no_pack_key_is_approved_wording", () => {
  for (const key of [...Object.keys(PLAIN.labels), ...Object.keys(VOYAGE.labels)]) {
    assert(!(key in APPROVED), `I-72: ${key} is approved wording`);
  }
});

test("i72_a_secondary_label_for_approved_wording_is_refused", () => {
  const e = thrown(
    () =>
      createI18n({
        catalogues: [{ locale: "en", labels: { "nav.home": "Home" }, approved: { "notice.ai": "Synthetic approved wording." } }],
        locale: "en",
        secondary: { "notice.ai": "Chart room" },
      }),
    "a Voyage label for approved wording",
  );
  assert(e instanceof I18nError && e.message.includes("I-72"), show(e));
  const placeholder = thrown(
    () =>
      createI18n({
        catalogues: [{ locale: "en", labels: { "nav.home": "Home" }, approved: {} }],
        locale: "en",
        secondary: { "nav.home": "Harbour {name}" },
      }),
    "a Voyage label with a placeholder its label lacks",
  );
  assert(placeholder instanceof I18nError, show(placeholder));
});

test("r_jv_09_web_approved_texts_hold_no_voyage_label", () => {
  for (const [key, label] of Object.entries(VOYAGE.labels)) {
    if (PLAIN.labels[key] === label) {
      continue;
    }
    for (const [id, text] of Object.entries(APPROVED)) {
      assert(!text.includes(label), `I-94: approved ${id} holds the Voyage label ${label}`);
    }
  }
});

test("i72_voyage_line_shows_only_when_switched_on", () => {
  const off = i18n(false);
  const on = i18n(true);
  for (const key of Object.keys(LABELS)) {
    eq(off.secondary(key), null, `O-55: ${key} without the switch`);
  }
  eq(on.label("journey.node.stage1"), "Stage 1 evaluation", "O-55: the plain label leads");
  eq(on.secondary("journey.node.stage1"), "Crossing", "O-55: the Voyage line");
  eq(on.secondary("nav.my_applications"), "My voyages", "O-55: navigation");
  eq(on.secondary("journey.node.not_selected"), "Route ended", "I-72: fixed respectful wording");
  eq(on.secondary("nav.home"), null, "no Voyage label for Home");
  thrown(() => on.secondary("no.such.label"), "an unknown id");
});

test("i96_web_state_label_keeps_the_formal_name", () => {
  freshDom();
  for (const on of [false, true]) {
    const el = asFake(stateWithVoyage(i18n(on), "journey.node.stage2", "STAGE2"));
    const parts = el.children;
    eq(parts[0]?.getAttribute("class"), "plain-label", "the plain label leads");
    eq(parts[0]?.textContent, "Stage 2 questions", "the plain label");
    eq(parts[1]?.getAttribute("class"), "state-name", "I-96: the formal name");
    eq(parts[1]?.textContent, "STAGE2", "I-96: the formal name");
    const voyage = parts.filter((p) => p.getAttribute("class") === "voyage-label");
    eq(voyage.length, on ? 1 : 0, `O-55: Voyage line with the switch ${on ? "on" : "off"}`);
    if (on) {
      eq(voyage[0]?.textContent, "Ascent: questions from the scouts", "the Voyage label");
      eq(parts.indexOf(voyage[0]!), parts.length - 1, "the Voyage line comes last");
    }
  }
});

test("r_wl_05_web_label_shows_the_voyage_line_beside_the_plain_label", () => {
  freshDom();
  const off = asFake(labelWithVoyage(i18n(false), "nav.programme_setup"));
  eq(off.textContent, "Programme set-up", "O-55: plain only");
  const on = asFake(labelWithVoyage(i18n(true), "nav.programme_setup"));
  eq(on.children[0]?.textContent, "Programme set-up", "O-55: the plain label leads");
  eq(on.children[on.children.length - 1]?.getAttribute("class"), "voyage-label", "the secondary line");
  eq(on.children[on.children.length - 1]?.textContent, "Planning Studio", "the Voyage label");
});
