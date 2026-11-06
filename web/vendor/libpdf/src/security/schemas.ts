/**
 * Zod schemas for PDF encryption dictionary validation.
 *
 * These schemas provide type-safe parsing of encryption parameters
 * with proper validation and TypeScript type inference.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Core Encryption Schemas
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Valid encryption versions (V entry).
 *
 * - 1: 40-bit RC4 (PDF 1.1)
 * - 2: 40-128 bit RC4 (PDF 1.4)
 * - 3: Unpublished (rare)
 * - 4: AES-128 or RC4 with crypt filters (PDF 1.5)
 * - 5: AES-256 (PDF 2.0)
 */
export type EncryptionVersion = 1 | 2 | 3 | 4 | 5;

export const isEncryptionVersion = (version: unknown): version is EncryptionVersion => {
  return typeof version === "number" && version >= 1 && version <= 5;
};

/**
 * Valid encryption revisions (R entry).
 *
 * - 2: V=1, 40-bit RC4
 * - 3: V=2, 40-128 bit RC4
 * - 4: V=4, AES-128 or RC4
 * - 5: V=5, AES-256 (draft, Adobe Extension Level 3)
 * - 6: V=5, AES-256 (final, ISO 32000-2)
 */

export type EncryptionRevision = 2 | 3 | 4 | 5 | 6;

export const isEncryptionRevision = (revision: unknown): revision is EncryptionRevision => {
  return typeof revision === "number" && revision >= 2 && revision <= 6;
};

// ─────────────────────────────────────────────────────────────────────────────
// Crypt Filter Schemas (V4+)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Crypt filter methods (CFM entry).
 *
 * - None: Identity (no encryption)
 * - V2: RC4
 * - AESV2: AES-128
 * - AESV3: AES-256
 */
export type CryptFilterMethod = "None" | "V2" | "AESV2" | "AESV3";

export const isCryptFilterMethod = (method: unknown): method is CryptFilterMethod => {
  return typeof method === "string" && ["None", "V2", "AESV2", "AESV3"].includes(method);
};

/**
 * Authentication events (AuthEvent entry).
 *
 * - DocOpen: Authentication when document is opened
 * - EFOpen: Authentication when embedded file is accessed
 */
export type AuthEvent = "DocOpen" | "EFOpen";

export const isAuthEvent = (event: unknown): event is AuthEvent => {
  return typeof event === "string" && ["DocOpen", "EFOpen"].includes(event);
};

/**
 * Complete crypt filter configuration.
 */
export interface CryptFilter {
  cfm: CryptFilterMethod;
  authEvent?: AuthEvent;
  length?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm Schema
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Supported encryption algorithms.
 *
 * - RC4: Legacy stream cipher (R2-R4)
 * - AES-128: AES with 128-bit key (R4)
 * - AES-256: AES with 256-bit key (R5-R6)
 */
export type EncryptionAlgorithm = "RC4" | "AES-128" | "AES-256";

export const isEncryptionAlgorithm = (algorithm: unknown): algorithm is EncryptionAlgorithm => {
  return (
    typeof algorithm === "string" && ["RC4-40", "RC4-128", "AES-128", "AES-256"].includes(algorithm)
  );
};
