// The recorder's verification body of the vault write page (R-ID-02, I-17,
// ADR-004 record of lane L13b, row "Origin body"). The vault checks every
// body again; these tests pin the spelling `fstp_vault::codec` decodes.

import { canonical } from "../src/auth/encoding.js";
import {
  VERIFICATION_CHECKS,
  birthDateOk,
  identityNameOk,
  issuingStateOk,
  personOf,
  verificationBody,
} from "../src/vault/verification.js";
import { assert, eq, test } from "./support/harness.js";

/** R-ID-02: the body has the canonical members and labels of the vault. */
test("adr008_vault_verification_body_spelling", () => {
  const body = verificationBody("manual", "passport", ["photo_match", "document_authentic"], {
    familyNames: "Alpha",
    givenNames: "Synthetic",
    birthDate: "1990-02-28",
    issuingState: "deu",
  });
  assert(body !== null, "a valid entry was refused");
  eq(
    canonical(body),
    '{"checks":["document_authentic","photo_match"],"document_type":"passport","identity":{"birth_date":"1990-02-28","family_names":"Alpha","given_names":"Synthetic","issuing_state":"DEU"},"method":"manual"}',
    "the canonical body",
  );
  eq(
    [...VERIFICATION_CHECKS].join(","),
    "data_match,document_authentic,document_valid,photo_match",
    "the checks in label order",
  );
});

/** R-ID-02: the field bounds follow the vault's decoder. */
test("adr008_vault_verification_field_bounds", () => {
  assert(identityNameOk("Synthetic Alpha"), "plain name");
  assert(!identityNameOk(""), "empty");
  assert(!identityNameOk("   "), "blank");
  assert(!identityNameOk("a".repeat(201)), "too long");
  assert(!identityNameOk("tab\there"), "control character");
  assert(birthDateOk("2000-02-29"), "leap day");
  assert(!birthDateOk("1900-02-29"), "no leap day in 1900");
  assert(!birthDateOk("1899-12-31"), "before 1900");
  assert(!birthDateOk("1990-2-28"), "short month");
  assert(issuingStateOk("DEU"), "alpha-3");
  assert(!issuingStateOk("DE"), "alpha-2");
  assert(!issuingStateOk("D3U"), "digit");
  eq(
    verificationBody("manual", "passport", [], {
      familyNames: "Alpha",
      givenNames: "Synthetic",
      birthDate: "1990-02-28",
      issuingState: "DEU",
    }),
    null,
    "no check",
  );
  eq(personOf("person:501"), "501", "the person of the scope");
  eq(personOf("person:0501"), null, "a non-canonical account id");
  eq(personOf("programme:5"), null, "another scope");
});

/** ADR-004 record of lane L13b, row "Staff app": the member page asks for a ticket naming the person, and opens only this cell's vault write page. */
test("adr008_member_page_requests_the_person_ticket", async () => {
  const { verificationRequest, isVaultWriteUrl } = await import("../src/admin/team/verify.js");
  eq(
    canonical(verificationRequest("501", "00112233445566778899aabbccddeeff")),
    '{"account":"501","command_id":"00112233445566778899aabbccddeeff"}',
    "the request body",
  );
  const here = { protocol: "https:", hostname: "grants.example.eu", port: "" };
  assert(isVaultWriteUrl("https://id.grants.example.eu/w#ab12", here), "the vault write page");
  for (const bad of [
    "https://id.grants.example.eu/r#ab12",
    "https://id.evil.example/w#ab12",
    "http://id.grants.example.eu/w#ab12",
    "https://id.grants.example.eu/w",
    "https://id.grants.example.eu/w?x=1#ab12",
  ]) {
    assert(!isVaultWriteUrl(bad, here), `${bad} accepted`);
  }
});

/** R-NG-01, ADR-004 record of lane L13b, row "Staff app": an applicant's ticket request names the proposal, and the people list is read only in its exact shape. */
test("adr008_applicant_verification_names_the_proposal", async () => {
  const { verificationRequest, decodePeople } = await import("../src/admin/team/verify.js");
  eq(
    canonical(verificationRequest("301", "00112233445566778899aabbccddeeff", "1")),
    '{"account":"301","command_id":"00112233445566778899aabbccddeeff","proposal":"1"}',
    "the applicant's request body",
  );
  const people = decodePeople({ people: [{ account: "301", proposal: "1", requested: false, role: "applicant" }] });
  assert(people !== null && people.length === 1 && people[0]?.proposal === "1", "a valid list was refused");
  eq(decodePeople({ people: [] })?.length, 0, "an empty list");
  for (const bad of [
    null,
    { people: [{ account: "0301", proposal: "1", requested: false, role: "applicant" }] },
    { people: [{ account: "301", proposal: "1", requested: false, role: "applicant", name: "x" }] },
    { people: [], extra: 1 },
    { people: "301" },
  ]) {
    eq(decodePeople(bad), null, `accepted ${JSON.stringify(bad)}`);
  }
});

/** I-17, ADR-008 and ADR-026 record of lane L24 (decided by Daniel on 2026-11-22): the applicant reads plain words, staff see the open requests, and the shell counts them. */
test("adr008_identity_page_says_we_will_contact_you", async () => {
  const { CATALOGUE } = await import("../src/onboarding/messages.en.js");
  const pending = (CATALOGUE.labels as Readonly<Record<string, string>>)["onboarding.identity_page.pending"] ?? "";
  assert(pending.includes("We will contact you to check your ID"), "the identity page does not say we will contact you");
  const { decodePeople } = await import("../src/admin/team/verify.js");
  const people = decodePeople({
    people: [
      { account: "301", proposal: "1", requested: false, role: "applicant" },
      { account: "777", proposal: null, requested: true, role: "staff" },
    ],
  });
  assert(people !== null && people.length === 2, "a valid list was refused");
  eq(people?.[1]?.proposal ?? "none", "none", "a staff request names no proposal");
  eq(people?.[1]?.requested, true, "the open request is marked");
  const { openRequests } = await import("../src/auth/appshell.js");
  eq(openRequests({ people: [{ requested: true }, { requested: false }, { requested: true }] }), 2, "the shell count");
  eq(openRequests({}), 0, "no list, no count");
});
