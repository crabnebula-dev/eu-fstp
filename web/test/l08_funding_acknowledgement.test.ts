// L-08 (ADR-036): the approved funding acknowledgement on the funding card
// of the `/app/` and sign-in footers, and the branding page's plain hint
// when a programme value keeps it from showing (I-68, I-69).

import { ackHints } from "../src/admin/branding/fundingpage.js";
import { decodeCards, fundingCard as authCard } from "../src/auth/funding.js";
import { decodeFunding, fundingCard } from "../src/shell/funding.js";
import { assert, eq, test } from "./support/harness.js";
import { FakeElement, freshDom } from "./support/fakedom.js";

const SENTENCE =
  "Synthetic programme A is funded by the European Union under the Horizon Europe grant agreement SYNTHETIC-000000000, SYN.";

const ANSWER = {
  cards: [
    {
      programme: "7",
      name: "Synthetic programme A",
      grant_number: "SYNTHETIC-000000000",
      coordinator_name: "Synthetic coordinator org",
      coordinator_contact: "role@example.org",
      acknowledgement: SENTENCE,
      acknowledgement_missing: [],
    },
    {
      programme: "8",
      name: "Synthetic programme B",
      grant_number: null,
      coordinator_name: null,
      coordinator_contact: null,
      acknowledgement: null,
      acknowledgement_missing: ["action_number", "action_acronym"],
    },
  ],
  defaults: null,
};

/** L-08: both decoders read the sentence and what keeps it from showing. */
test("adr036_l08_funding_answer_carries_the_acknowledgement", () => {
  const a = decodeFunding(ANSWER);
  eq(a?.cards[0]?.acknowledgement, SENTENCE, "the sentence");
  eq(a?.cards[1]?.acknowledgement, null, "no sentence");
  eq(a?.cards[1]?.acknowledgementMissing, ["action_number", "action_acronym"], "what is missing");
  eq(decodeCards(ANSWER)?.[0]?.acknowledgement, SENTENCE, "the sign-in pages");
  // An answer from before ADR-036 still decodes, with no sentence.
  const old = decodeFunding({ cards: [{ programme: "9", name: "Old" }], defaults: null });
  eq(old?.cards[0]?.acknowledgement, null, "older answer");
  eq(old?.cards[0]?.acknowledgementMissing, [], "older answer names nothing");
});

/** I-69, L-08: the card ends with the sentence; a card without it shows no sentence and no placeholder. */
test("i69_l08_card_shows_the_acknowledgement_or_nothing", () => {
  freshDom();
  const a = decodeFunding(ANSWER);
  const [one, two] = [a?.cards[0], a?.cards[1]];
  assert(one !== undefined && two !== undefined, "two cards");
  if (one === undefined || two === undefined) return;
  for (const make of [fundingCard, authCard]) {
    const el = make(one) as unknown as FakeElement;
    const text = el.textContent ?? "";
    assert(text.endsWith(SENTENCE), `the card ends with the sentence: ${text}`);
    assert(!text.includes("pending"), "no placeholder");
    const none = (make(two) as unknown as FakeElement).textContent ?? "";
    assert(!none.includes("funded by the European Union"), "no sentence");
    assert(!none.includes("pending"), "no placeholder");
  }
});

/** I-68: the sentence is text, never markup. */
test("i68_acknowledgement_is_text", () => {
  freshDom();
  const el = fundingCard({
    programme: "7",
    name: "x",
    grantNumber: "1",
    coordinatorName: "c",
    coordinatorContact: "c",
    acknowledgement: "<b>x</b> is funded",
    acknowledgementMissing: [],
  }) as unknown as FakeElement;
  eq(el.getElementsByTagName("b").length, 0, "no markup");
});

/** L-08, usability: the branding page names each programme without the sentence and the values to fill in, in plain words. */
test("adr036_l08_branding_page_says_why_the_sentence_is_missing", () => {
  const cards = decodeFunding(ANSWER)?.cards ?? [];
  const hints = ackHints(cards);
  eq(hints.length, 1, "one programme lacks it");
  const h = hints[0] ?? "";
  assert(h.startsWith("Synthetic programme B: "), h);
  assert(h.includes("grant agreement number") && h.includes("acronym") && h.includes("step 1"), h);
  const profile = ackHints([{ ...cards[1]!, acknowledgementMissing: ["profile"] }])[0] ?? "";
  assert(profile.includes("funder profile"), profile);
  const name = ackHints([{ ...cards[1]!, acknowledgementMissing: ["programme_name"] }])[0] ?? "";
  assert(name.includes("programme name") && name.includes("step 2"), name);
});

/** Every non-overlapping occurrence of `needle` in `s`. */
function occurrences(s: string, needle: string): number {
  return s.split(needle).length - 1;
}

/**
 * ADR-034 Q11 (Daniel, 2026-11-23): the Commission's emblem rules say not to
 * write the programme's name in conjunction with the EU emblem. The `/app/`
 * and sign-in cards show the logo with no name beside it. The name shows only
 * inside the acknowledgement sentence, and not at all without it.
 */
test("adr034_q11_card_names_the_programme_only_in_the_sentence", () => {
  freshDom();
  const a = decodeFunding(ANSWER);
  const [one, two] = [a?.cards[0], a?.cards[1]];
  assert(one !== undefined && two !== undefined, "two cards");
  if (one === undefined || two === undefined) return;
  for (const make of [fundingCard, authCard]) {
    const el = make(one) as unknown as FakeElement;
    eq(occurrences(el.textContent ?? "", one.name), 1, "only in the sentence");
    const ack = el.getElementsByTagName("p").filter((p) => p.getAttribute("class") === "funding-card-ack");
    eq(ack.length, 1, "one sentence");
    assert((ack[0]?.textContent ?? "").includes(one.name), "the name is in the sentence");
    const none = (make(two) as unknown as FakeElement).textContent ?? "";
    eq(occurrences(none, two.name), 0, "no sentence, no name");
  }
});
