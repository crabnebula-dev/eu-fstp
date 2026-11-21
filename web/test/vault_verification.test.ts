// The recorder's verification body of the vault write page (R-ID-02, I-17,
// ADR-004 record of lane L13b, row "Origin body"). The vault checks every
// body again; these tests pin the spelling `fstp_vault::codec` decodes.

import { canonical } from "../src/auth/encoding.js";
import {
  VERIFICATION_CHECKS,
  birthDateOk,
  identityNameOk,
  issuingStateOk,
  verificationBody,
} from "../src/vault/verification.js";
import { assert, eq, test } from "./support/harness.js";

/** R-ID-02: the body has the canonical members and labels of the vault. */
test("adr008_vault_verification_body_spelling", () => {
  const body = verificationBody("501", "manual", "passport", ["photo_match", "document_authentic"], {
    familyNames: "Alpha",
    givenNames: "Synthetic",
    birthDate: "1990-02-28",
    issuingState: "deu",
  });
  assert(body !== null, "a valid entry was refused");
  eq(
    canonical(body),
    '{"account":"501","checks":["document_authentic","photo_match"],"document_type":"passport","identity":{"birth_date":"1990-02-28","family_names":"Alpha","given_names":"Synthetic","issuing_state":"DEU"},"method":"manual"}',
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
    verificationBody("501", "manual", "passport", [], {
      familyNames: "Alpha",
      givenNames: "Synthetic",
      birthDate: "1990-02-28",
      issuingState: "DEU",
    }),
    null,
    "no check",
  );
  eq(
    verificationBody("0501", "manual", "passport", ["photo_match"], {
      familyNames: "Alpha",
      givenNames: "Synthetic",
      birthDate: "1990-02-28",
      issuingState: "DEU",
    }),
    null,
    "a non-canonical account id",
  );
});
