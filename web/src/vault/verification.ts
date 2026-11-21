// The recorder's verification entry of the vault origin (R-ID-02, I-17,
// ADR-008 "Manual identity checks", ADR-004 record of lane L13b). Pure
// functions: the write page builds the body from them, and the vault
// checks every body again (`fstp_vault::codec::decode_verification_write`).
//
// The four identity fields reach the vault only. It keeps them only as the
// sealed tuple of the identity. No document number and no image is asked
// for (R-ID-02).

import type { Json } from '../auth/encoding.js';

/** A decimal id as the claims spell it: no sign and no leading zero (`page.ts` `isId`). */
function isId(v: string): boolean {
  return /^(?:0|[1-9][0-9]{0,38})$/.test(v);
}

/** The longest name field, in characters (`MAX_NAME_CHARS`). */
export const MAX_NAME_CHARS = 200;

/** The verification methods, in label order. */
export const VERIFICATION_METHODS = ['manual'] as const;

/** The document types, in label order. */
export const DOCUMENT_TYPES = ['identity_card', 'passport', 'residence_permit'] as const;

/** The checks, in label order. */
export const VERIFICATION_CHECKS = ['data_match', 'document_authentic', 'document_valid', 'photo_match'] as const;

export type VerificationMethod = (typeof VERIFICATION_METHODS)[number];
export type DocumentType = (typeof DOCUMENT_TYPES)[number];
export type VerificationCheck = (typeof VERIFICATION_CHECKS)[number];

/** The four identity fields the recorder enters. */
export interface IdentityEntry {
  readonly familyNames: string;
  readonly givenNames: string;
  readonly birthDate: string;
  readonly issuingState: string;
}

/** Whether `s` is a name the vault takes: 1 to 200 characters, not blank, no control character. */
export function identityNameOk(s: string): boolean {
  const n = [...s].length;
  return n >= 1 && n <= MAX_NAME_CHARS && s.trim() !== '' && !/[\u0000-\u001f\u007f-\u009f]/.test(s);
}

/** Whether `s` is a calendar date `YYYY-MM-DD` from 1900-01-01 on. */
export function birthDateOk(s: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (m === null) return false;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  if (y < 1900 || mo < 1 || mo > 12 || d < 1) return false;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1] ?? 0;
  return d <= days;
}

/** Whether `s` is three capital letters, an ISO 3166-1 alpha-3 code. */
export function issuingStateOk(s: string): boolean {
  return /^[A-Z]{3}$/.test(s);
}

/**
 * The canonical body of a verification of `account`, or null when a field
 * is outside what the vault takes. The state is upper-cased and the checks
 * are put in label order.
 */
export function verificationBody(
  account: string,
  method: VerificationMethod,
  documentType: DocumentType,
  checks: readonly VerificationCheck[],
  identity: IdentityEntry,
): Json | null {
  const state = identity.issuingState.trim().toUpperCase();
  const picked = VERIFICATION_CHECKS.filter((c) => checks.includes(c));
  const ok =
    isId(account) &&
    picked.length > 0 &&
    identityNameOk(identity.familyNames) &&
    identityNameOk(identity.givenNames) &&
    birthDateOk(identity.birthDate) &&
    issuingStateOk(state);
  if (!ok) return null;
  return {
    account,
    checks: [...picked],
    document_type: documentType,
    identity: {
      birth_date: identity.birthDate,
      family_names: identity.familyNames,
      given_names: identity.givenNames,
      issuing_state: state,
    },
    method,
  };
}
