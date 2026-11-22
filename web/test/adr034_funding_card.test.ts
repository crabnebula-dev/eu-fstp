// The funding card of every footer (ADR-034; I-68, I-69, R-NF-04), the
// plain messages for its missing values, and the defaults form.

import { fundingDefaultsBody } from "../src/admin/branding/fundingpage.js";
import { mailtoHref as authMailto } from "../src/auth/dom.js";
import { mailtoHref as coreMailto } from "../src/core/dom.js";
import { decodeCards } from "../src/auth/funding.js";
import { checkText } from "../src/creator/pages/common.js";
import { cardsFor, decodeFunding, fundingCard, fundingPart } from "../src/shell/funding.js";
import { assert, eq, test } from "./support/harness.js";
import { FakeElement, freshDom } from "./support/fakedom.js";

const ANSWER = {
  cards: [
    {
      programme: "7",
      name: "Synthetic programme A",
      grant_number: "SYNTHETIC-000000000",
      coordinator_name: "Synthetic coordinator org",
      coordinator_contact: "role@example.org",
    },
    { programme: "8", name: "Synthetic programme B", grant_number: null, coordinator_name: null, coordinator_contact: null },
  ],
  defaults: { name: "Synthetic coordinator org", contact: "role@example.org" },
};

/** ADR-034: the answer of `/brand/funding` decodes strictly. */
test("adr034_funding_answer_decodes", () => {
  const a = decodeFunding(ANSWER);
  assert(a !== null, "decodes");
  eq(a?.cards.length, 2, "two cards");
  eq(a?.cards[1]?.grantNumber, null, "a gap stays a gap");
  eq(a?.defaults?.contact, "role@example.org", "defaults");
  eq(decodeFunding({ cards: "x" }), null, "not an answer");
  eq(decodeFunding({ cards: [{ programme: 7 }] }), null, "a bad card");
  eq(decodeCards(ANSWER)?.length, 2, "the sign-in pages decode it too");
});

/** I-69: a programme page shows its own card; any other page shows every card. */
test("i69_programme_page_shows_its_own_card", () => {
  const a = decodeFunding(ANSWER);
  const cards = a?.cards ?? [];
  eq(cardsFor("7", cards).map((c) => c.programme), ["7"], "programme 7");
  eq(cardsFor(null, cards).length, 2, "tenant-wide");
  eq(cardsFor("9", cards).length, 2, "a programme without a card");
});

/** R-NF-04, I-69: the card is a labelled region with the logo's alt text and label and value pairs. */
test("r_nf_04_card_has_alt_text_and_labelled_values", () => {
  freshDom();
  const a = decodeFunding(ANSWER);
  const c = a?.cards[0];
  assert(c !== undefined, "a card");
  if (c === undefined) return;
  const el = fundingCard(c) as unknown as FakeElement;
  eq(el.getAttribute("aria-label"), "EU funding", "region name");
  const img = el.getElementsByTagName("img")[0];
  eq(img?.getAttribute("alt"), "Funded by the European Union", "alt text");
  eq(img?.getAttribute("src"), "/brand/funded-by-eu.svg", "the platform logo");
  const text = el.textContent ?? "";
  for (const s of ["Grant agreement number", "SYNTHETIC-000000000", "Coordinator", "Synthetic coordinator org", "Contact", "role@example.org"]) {
    assert(text.includes(s), s);
  }
  eq(el.getElementsByTagName("dt").length, 3, "label and value pairs");
  const gap = a?.cards[1];
  if (gap !== undefined) {
    assert((fundingCard(gap).textContent ?? "").includes("Not set yet"), "a gap says so");
  }
});

/** I-68: a value is text, never markup. */
test("i68_card_values_are_text", () => {
  freshDom();
  const el = fundingCard({
    programme: "7",
    name: "<img src=x>",
    grantNumber: "1",
    coordinatorName: "<b>x</b>",
    coordinatorContact: "c",
  }) as unknown as FakeElement;
  eq(el.getElementsByTagName("img").length, 1, "only the logo");
  eq(el.getElementsByTagName("b").length, 0, "no markup");
});

/** I-69: the footer part is keyed `funding_card` once, names its programmes, and holds one card each. */
test("i69_footer_part_is_keyed_once", () => {
  freshDom();
  const cards = decodeFunding(ANSWER)?.cards ?? [];
  const one = fundingPart(cardsFor("7", cards)) as unknown as FakeElement | null;
  eq(one?.getAttribute("data-mandatory"), "funding_card", "keyed");
  eq(one?.getAttribute("data-programmes"), "7", "its programme");
  eq(one?.getElementsByTagName("section").length, 1, "one card");
  const all = fundingPart(cardsFor(null, cards)) as unknown as FakeElement | null;
  eq(all?.getElementsByTagName("section").length, 2, "every card on a tenant-wide page");
  eq(fundingPart([]), null, "no card, no part");
});

/** I-69: a missing grant number or coordinator contact says in plain words what to fill in and where. */
test("i69_missing_card_values_have_plain_messages", () => {
  for (const f of ["funder.action_number", "funder.coordinator_name", "funder.coordinator_contact"]) {
    const m = String(checkText("FieldUnset", [], f));
    assert(m.startsWith("Fill in") && m.includes("step 1") && m.includes("funding card"), `${f}: ${m}`);
  }
  assert(String(checkText("FieldUnset", [], "funder.p56_fstp_budget")).includes("A value is missing."), "others keep the general message");
});

/** I-68: the defaults form sends plain text only. */
test("i68_funding_defaults_body_is_plain_text", () => {
  eq(fundingDefaultsBody(" Org ", "role@example.org"), { name: "Org", contact: "role@example.org" }, "trimmed");
  eq(fundingDefaultsBody("", "a"), null, "empty");
  eq(fundingDefaultsBody("<b>", "a"), null, "markup");
  eq(fundingDefaultsBody("x".repeat(201), "a"), null, "too long");
});

/** ADR-034 (lead decision), I-68: a contact that is one e-mail address is a `mailto:` link; nothing else is. */
test("adr034_contact_address_is_a_mailto_link", () => {
  freshDom();
  for (const f of [coreMailto, authMailto]) {
    eq(f("mailto:privacy@crabnebula.dev"), "mailto:privacy@crabnebula.dev", "one address");
    for (const bad of ["mailto:a@b", "mailto:a@example.org?bcc=x@example.org", "mailto:a@Example.org", "mailto:.a@example.org", "mailto:a@example.org,b@example.org", "mailto:a@1.2.3.4", "javascript:x"]) {
      eq(f(bad), null, bad);
    }
  }
  const c = decodeFunding(ANSWER)?.cards[0];
  if (c === undefined) return;
  const links = (fundingCard(c) as unknown as FakeElement).getElementsByTagName("a");
  eq(links.length, 1, "one link");
  eq(links[0]?.getAttribute("href"), "mailto:role@example.org", "the contact");
  const text = (fundingCard({ ...c, coordinatorContact: "Call +00 0000" }) as unknown as FakeElement).getElementsByTagName("a");
  eq(text.length, 0, "other contacts stay text");
});
