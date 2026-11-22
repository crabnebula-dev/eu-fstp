// The typed registration code and the later passkey offer (Daniel,
// 2026-11-22, ADR-008 "Registration code" and "Later passkey"). Every
// value is synthetic.

import { AUTH_EN } from "../src/auth/messages.en.js";
import { DISMISSED_KEY, holdsNoPasskey } from "../src/auth/passkeyoffer.js";
import { assert, eq, test } from "./support/harness.js";

/** ADR-008 "Later passkey": only a devices reply with an empty list offers a passkey. */
test("adr008_passkey_offer_only_for_an_account_without_passkeys", () => {
  eq(holdsNoPasskey({ account: "1", devices: [] }), true, "no passkey");
  eq(holdsNoPasskey({ account: "1", devices: [{ id: "ab" }] }), false, "a passkey");
  for (const bad of [null, undefined, [], "x", { devices: "none" }, {}]) {
    eq(holdsNoPasskey(bad), false, `not a devices reply: ${JSON.stringify(bad)}`);
  }
  eq(DISMISSED_KEY, "fstp.passkeyoffer.dismissed", "the dismissal key");
});

/** ADR-008, writing style: the code and offer texts are plain, and the offer can be declined. */
test("adr008_registration_code_and_offer_texts_are_plain", () => {
  const m: Readonly<Record<string, string>> = AUTH_EN.messages;
  for (const id of ["signup.code.intro", "signup.code.label", "signup.code.submit", "signup.code.wrong", "offer.title", "offer.intro", "offer.send", "offer.later", "offer.sent"]) {
    const text = m[id];
    assert(typeof text === "string" && text.length > 0, `${id} exists`);
    assert(!(text ?? "").includes("—"), `${id} holds an em dash`);
  }
  eq(m["offer.later"], "Not now", "the offer can be declined");
  assert((m["signup.code.intro"] ?? "").includes("6-digit"), "the code is named as 6 digits");
});
