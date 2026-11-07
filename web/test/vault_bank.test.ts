// The bank and hardship bodies of the vault write page (I-33, I-86,
// R-PR-04, R-PR-05, M5 design 12.1). The vault checks every body again;
// these tests pin the spellings `fstp-vault-core` decodes.

import { canonical } from "../src/auth/encoding.js";
import {
  bankDetailsBody,
  bankDisputeBody,
  bankVerifiedBody,
  evidenceOf,
  hardshipBody,
  hardshipVerifiedBody,
  holderOk,
  ibanOk,
  normaliseIban,
  statementOk,
} from "../src/vault/bank.js";
import { assert, eq, test } from "./support/harness.js";

/** R-PR-05: the IBAN check is MOD 97-10, as `iban_ok` in the vault core. */
test("r_pr_05_vault_iban_check_matches_the_vault_core", () => {
  for (const good of ["DE89370400440532013000", "GB82WEST12345698765432"]) {
    assert(ibanOk(good), `${good} refused`);
  }
  for (const bad of ["DE89370400440532013001", "GB82WEST12345698765433", "de89370400440532013000", "DE8937040044", ""]) {
    assert(!ibanOk(bad), `${bad} accepted`);
  }
  eq(normaliseIban(" de89 3704 0044 0532 0130 00 "), "DE89370400440532013000", "normalised");
});

/** R-PR-05: holder names and statements follow the vault's bounds. */
test("r_pr_05_vault_holder_and_statement_bounds", () => {
  assert(holderOk("Synthetic Holder"), "plain name");
  assert(!holderOk(""), "empty");
  assert(!holderOk(" Leading"), "leading space");
  assert(!holderOk("a".repeat(141)), "too long");
  assert(statementOk("Line one\nLine two"), "line feed allowed");
  assert(!statementOk("tab\there"), "tab refused");
  assert(!statementOk("   "), "blank refused");
});

/**
 * I-33: the bodies are the canonical members the vault decodes. The
 * browser never names `at`, `version` or a hardship `evidence` on a
 * submission, since the vault stamps them.
 */
test("i33_vault_bank_bodies_leave_stamps_to_the_vault", () => {
  eq(
    canonical(bankDetailsBody("10", "77", "Synthetic Holder", "DE89370400440532013000")),
    '{"account":"10","grant":"77","holder":"Synthetic Holder","iban":"DE89370400440532013000"}',
    "bank details",
  );
  eq(
    canonical(bankVerifiedBody("20", "77", "bank_statement", ["iban_matches", "holder_matches"])),
    '{"checks":["holder_matches","iban_matches"],"grant":"77","method":"bank_statement","verifier":"20"}',
    "verification, checks in label order",
  );
  eq(canonical(bankDisputeBody("10", "77", true)), '{"account":"10","grant":"77","open":true}', "dispute");
  eq(
    canonical(hardshipBody("10", "77", "Synthetic")),
    '{"account":"10","grant":"77","statement":"Synthetic"}',
    "hardship",
  );
  eq(
    canonical(hardshipVerifiedBody("20", "77", "5")),
    '{"evidence":"5","grant":"77","verifier":"20"}',
    "hardship verification",
  );
});

/** I-86: the page reads only the evidence reference from a write reply. */
test("i86_vault_write_reply_yields_only_the_reference", () => {
  eq(evidenceOf('{"evidence":"42"}'), "42", "reference");
  eq(evidenceOf(""), null, "empty reply");
  eq(evidenceOf('{"evidence":"x"}'), null, "not an id");
});
