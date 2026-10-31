// a11y.ts: live regions, error links and reduced motion (R-NF-03, WCAG 2.2
// level AA; M4 design section 3.9, ADR-014 "Accessibility").

import { FakeElement, asFake, fakeDocument, freshDom, mediaAnswers, sinkUses } from "./support/fakedom.js";
import { assert, eq, show, test, thrown } from "./support/harness.js";
import { core } from "./support/load.js";

function liveRegions(politeness: string): FakeElement[] {
  return fakeDocument.documentElement.descendants().filter((e) => e.getAttribute("aria-live") === politeness);
}

function element(tag: string, id: string | null): HTMLElement {
  const e = new FakeElement(tag);
  if (id !== null) {
    e.setAttribute("id", id);
  }
  fakeDocument.body.appendChild(e);
  return e as unknown as HTMLElement;
}

/** R-NF-03: announcements go as text into one live region per politeness, created on first use. */
test("r_nf_03_announce_puts_text_in_a_live_region", async () => {
  freshDom();
  const a11y = await core("a11y");
  a11y.announce("Saved <b>draft</b>", "polite");
  const polite = liveRegions("polite");
  eq(polite.length, 1, "one polite live region");
  const region = polite[0];
  assert(region !== undefined, "region exists");
  assert(fakeDocument.body.contains(region), "the region is in the page");
  eq(region.textContent, "Saved <b>draft</b>", "message as text");
  eq(region.descendants().length, 0, "no element parsed from the message");
  a11y.announce("Submitted", "polite");
  eq(liveRegions("polite").length, 1, "the polite region is reused");
  eq(liveRegions("polite")[0]?.textContent, "Submitted", "latest message");
  a11y.announce("Session ends in 1 minute", "assertive");
  eq(liveRegions("assertive").length, 1, "one assertive live region");
  eq(liveRegions("assertive")[0]?.textContent, "Session ends in 1 minute", "assertive message");
  eq(sinkUses, [], "no HTML sink reached");
});

/** R-NF-03: an error is linked to its field by aria-invalid and aria-describedby, keeping other ids. */
test("r_nf_03_link_error_marks_control_and_keeps_described_by", async () => {
  freshDom();
  const a11y = await core("a11y");
  const control = element("input", "cap");
  asFake(control).setAttribute("aria-describedby", "cap-hint");
  const error = element("p", "cap-error");
  a11y.linkError(control, error);
  eq(asFake(control).getAttribute("aria-invalid"), "true", "aria-invalid");
  const ids = (asFake(control).getAttribute("aria-describedby") ?? "").split(/\s+/).filter((s) => s !== "");
  eq([...ids].sort(), ["cap-error", "cap-hint"], "described-by ids");
  a11y.linkError(control, error);
  const again = (asFake(control).getAttribute("aria-describedby") ?? "").split(/\s+/).filter((s) => s !== "");
  eq(again.filter((s) => s === "cap-error").length, 1, "linking twice adds the id once");
  a11y.clearError(control, error);
  const after = asFake(control).getAttribute("aria-invalid");
  assert(after === null || after === "false", `aria-invalid after clearing: ${show(after)}`);
  eq(asFake(control).getAttribute("aria-describedby"), "cap-hint", "the hint id stays");
});

/** R-NF-03: an error element without an id cannot be linked, so no field points at nothing. */
test("r_nf_03_link_error_needs_an_error_id", async () => {
  freshDom();
  const a11y = await core("a11y");
  const control = element("input", "cap");
  const error = element("p", null);
  thrown(() => a11y.linkError(control, error), "linking an error without an id");
  eq(asFake(control).getAttribute("aria-invalid"), null, "the control is unchanged");
});

/** R-NF-03: reduced motion follows the `prefers-reduced-motion` media query. */
test("r_nf_03_reduced_motion_follows_the_media_query", async () => {
  freshDom();
  const a11y = await core("a11y");
  eq(a11y.prefersReducedMotion(), false, "no preference");
  mediaAnswers.set("(prefers-reduced-motion: reduce)", true);
  eq(a11y.prefersReducedMotion(), true, "reduce");
});

function nextTask(): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
}

/**
 * R-NF-03 (WCAG 2.2 SC 4.1.3): `installLiveRegions` puts both regions in
 * the page empty, so a later announcement changes a region already there.
 */
test("r_nf_03_install_live_regions_creates_empty_regions_first", async () => {
  freshDom();
  const a11y = await core("a11y");
  a11y.installLiveRegions();
  a11y.installLiveRegions();
  eq(liveRegions("polite").length, 1, "one polite region");
  eq(liveRegions("assertive").length, 1, "one assertive region");
  eq(liveRegions("polite")[0]?.textContent, "", "polite region starts empty");
  eq(liveRegions("assertive")[0]?.textContent, "", "assertive region starts empty");
  const before = liveRegions("polite")[0];
  a11y.announce("Saved", "polite");
  eq(liveRegions("polite").length, 1, "announce reuses the installed region");
  assert(liveRegions("polite")[0] === before, "the same element");
  eq(before?.textContent, "Saved", "message");
});

/**
 * R-NF-03 (WCAG 2.2 SC 4.1.3): when `announce` has to create a region, it
 * writes the message again one task later, unless a newer one replaced it.
 */
test("r_nf_03_first_announcement_is_written_again_after_one_task", async () => {
  freshDom();
  const a11y = await core("a11y");
  a11y.announce("Saved", "polite");
  const region = liveRegions("polite")[0];
  assert(region !== undefined, "region exists");
  const first = region.childNodes[0];
  await nextTask();
  eq(region.textContent, "Saved", "message after one task");
  assert(region.childNodes[0] !== first, "the text was written again into the region already in the page");
  a11y.announce("Error", "assertive");
  a11y.announce("Error twice", "assertive");
  await nextTask();
  eq(liveRegions("assertive")[0]?.textContent, "Error twice", "a newer message is not replaced by the delayed rewrite");
});
