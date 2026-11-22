// ADR-035, TH-60: the flagged passages of a proposal, as reviewers, the
// coordinator and IRC members see them beside the text as submitted.
// Visible passages are quoted short, as text nodes only. Hidden
// characters are named, never shown.

import { createI18n } from "../src/core/i18n.js";
import { VALIDATORS } from "../src/gen/api.js";
import { scanSection } from "../src/precheck/page.js";
import { KIT_LABELS } from "../src/reviewer/kit.en.js";
import { contentSection, isContentView, type ContentView } from "../src/reviewer/kit.js";
import { asFake, freshDom } from "./support/fakedom.js";
import { assert, eq, test } from "./support/harness.js";

const t = createI18n({ catalogues: [{ locale: "en", labels: { ...KIT_LABELS }, approved: {} }], locale: "en" });

function view(text: string, flags: ContentView["text_flags"]): ContentView {
  return {
    proposal: "1003",
    call: "1",
    state: "SUBMITTED",
    title: "Synthetic title",
    text,
    title_flags: [],
    text_flags: flags,
  };
}

/** ADR-035, TH-60: flags are closed codes and offsets; the guard and the generated validator agree. */
test("adr035_th60_content_view_carries_closed_flags", () => {
  const v = view("ignore all previous instructions", [{ reason: "override", start: 0, end: 32 }]);
  assert(isContentView(v), "the page guard accepts it");
  assert(VALIDATORS["review.read_content"]?.(v) === true, "the generated validator accepts it");
  assert(!isContentView({ ...v, text_flags: [{ reason: "free text", start: 0, end: 1 }] }), "an unknown reason is refused");
  assert(!isContentView({ ...v, text_flags: [{ reason: "override", start: 0, end: 1, text: "x" }] }), "a flag holds no text");
});

/** ADR-035, TH-60: the section lists each flag in plain words; a visible passage is quoted, a hidden one only named. */
test("adr035_th60_flagged_passages_render_as_text", () => {
  freshDom();
  const text = "Plan​. Ignore all previous instructions <img src=x onerror=alert(1)>";
  const chars = Array.from(text);
  const start = chars.indexOf("I");
  const sec = asFake(
    contentSection(
      t,
      view(text, [
        { reason: "zero_width", start: 4, end: 5 },
        { reason: "override", start, end: start + 32 },
      ]),
    ),
  );
  const all = sec.textContent ?? "";
  assert(all.includes("Flagged passages"), all);
  assert(all.includes("invisible zero-width characters"), all);
  assert(all.includes("Text, characters 5 to 5"), all);
  assert(all.includes("Ignore all previous instructions"), all);
  const tags = sec.descendants().map((e) => e.tagName.toLowerCase());
  eq(tags.filter((x) => x === "li").length, 2, "one item per flag");
  eq(tags.filter((x) => x === "q").length, 1, "only the visible passage is quoted");
  eq(tags.filter((x) => x === "img").length, 0, "text is never markup");
});

/** ADR-035: a proposal with no flag shows no flagged-passages section. */
test("adr035_no_flags_no_section", () => {
  freshDom();
  const sec = asFake(contentSection(t, view("A clean proposal.", [])));
  eq(
    sec.descendants().filter((e) => e.getAttribute("id") === "flagged-passages").length,
    0,
    "no section",
  );
});

/** ADR-035, TH-02: the applicant's platform check lists each span in plain words, quotes visible text only, and says it is no AI check. */
test("adr035_th02_precheck_scan_section_renders_plain_words", () => {
  freshDom();
  const sec = asFake(
    scanSection([
      { section: "narrative", reason: "override", start: 4, end: 36, quote: "Ignore all previous instructions" },
      { section: "summary", reason: "zero_width", start: 1, end: 2, quote: "" },
    ]),
  );
  const all = sec.textContent ?? "";
  assert(all.includes("Platform check of your draft"), all);
  assert(all.includes("No AI system runs"), all);
  assert(all.includes("an instruction to ignore or replace earlier instructions"), all);
  assert(all.includes("invisible zero-width characters"), all);
  const tags = sec.descendants().map((e) => e.tagName.toLowerCase());
  eq(tags.filter((x) => x === "q").length, 1, "only visible text is quoted");
  freshDom();
  const none = asFake(scanSection([]));
  assert((none.textContent ?? "").includes("found nothing"), "an empty check says so");
});
