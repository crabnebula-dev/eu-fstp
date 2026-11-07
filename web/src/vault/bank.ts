// The bank and hardship entries of the vault origin (I-33, I-86, R-PR-04,
// R-PR-05, M5 design sections 5 and 12.1). Pure functions: the write page
// builds each fact body from them, and the vault checks every body again.
//
// The browser never sets `at`, `version` or a hardship `evidence` on a
// submission: the vault stamps them, and refuses a body that names one.

import type { Json } from '../auth/encoding.js';

/** The longest holder name, in characters (`MAX_HOLDER_CHARS`). */
export const MAX_HOLDER_CHARS = 140;

/** The longest hardship statement, in characters (`MAX_STATEMENT_CHARS`). */
export const MAX_STATEMENT_CHARS = 4000;

/** The IBAN in electronic form: no spaces, capitals. */
export function normaliseIban(s: string): string {
  return s.replace(/\s+/g, '').toUpperCase();
}

/**
 * Whether `s` is an IBAN in electronic form whose MOD 97-10 remainder is 1
 * (ISO 13616), as `fstp_vault_core::fact::iban_ok` decides.
 */
export function ibanOk(s: string): boolean {
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const c of moved) {
    const code = c.charCodeAt(0);
    const v = code >= 65 ? code - 55 : code - 48;
    rem = (rem * (v >= 10 ? 100 : 10) + v) % 97;
  }
  return rem === 1;
}

/** Whether `s` is a holder name the vault takes. */
export function holderOk(s: string): boolean {
  const n = [...s].length;
  return n >= 1 && n <= MAX_HOLDER_CHARS && s.trim() === s && !/[\u0000-\u001f\u007f-\u009f]/.test(s);
}

/** Whether `s` is a hardship statement the vault takes. */
export function statementOk(s: string): boolean {
  const n = [...s].length;
  return n >= 1 && n <= MAX_STATEMENT_CHARS && s.trim() !== '' && !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/.test(s);
}

/** The checks a verification may record, in label order. */
export const BANK_CHECKS = ['holder_matches', 'iban_matches'] as const;

/** The methods a verification may record. */
export const BANK_METHODS = ['bank_letter', 'bank_statement'] as const;

/** The body of a bank detail write by `account` for `grant`. */
export function bankDetailsBody(account: string, grant: string, holder: string, iban: string): Json {
  return { account, grant, holder, iban };
}

/** The body of a verification of the latest version, by `verifier`. */
export function bankVerifiedBody(
  verifier: string,
  grant: string,
  method: (typeof BANK_METHODS)[number],
  checks: readonly (typeof BANK_CHECKS)[number][],
): Json {
  const sorted = BANK_CHECKS.filter((c) => checks.includes(c));
  return { checks: sorted, grant, method, verifier };
}

/** The body that opens (`open`) or resolves a dispute. */
export function bankDisputeBody(account: string, grant: string, open: boolean): Json {
  return { account, grant, open };
}

/** The body of a hardship submission. The vault sets the reference. */
export function hardshipBody(account: string, grant: string, statement: string): Json {
  return { account, grant, statement };
}

/** The body of a hardship verification by `verifier`. */
export function hardshipVerifiedBody(verifier: string, grant: string, evidence: string): Json {
  return { evidence, grant, verifier };
}

/** The hardship reference in a write reply, or null. */
export function evidenceOf(reply: string): string | null {
  try {
    const v: unknown = JSON.parse(reply);
    if (typeof v !== 'object' || v === null) return null;
    const e = (v as Readonly<Record<string, unknown>>)['evidence'];
    return typeof e === 'string' && /^(?:0|[1-9][0-9]{0,38})$/.test(e) ? e : null;
  } catch {
    return null;
  }
}
