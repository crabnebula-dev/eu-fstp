/**
 * Credentials for decrypting PDF documents.
 *
 * Currently supports password-based authentication (Standard security handler).
 * Certificate-based authentication (Public Key handler) is planned for the future.
 */

/**
 * Password credential for Standard security handler.
 */
export interface PasswordCredential {
  type: "password";
  password: string;
}

/**
 * Certificate credential for Public Key security handler (future).
 */
export interface CertificateCredential {
  type: "certificate";
  certificate: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Credentials for decrypting a document.
 *
 * Can be provided as:
 * - A plain string (shorthand for password credential)
 * - A PasswordCredential object
 * - A CertificateCredential object (future support)
 */
export type DecryptionCredential = PasswordCredential | CertificateCredential;

/**
 * Input type that accepts either explicit credentials or string shorthand.
 */
export type CredentialInput = DecryptionCredential | string;

/**
 * Normalize credential input to a DecryptionCredential.
 *
 * @param input - Credential input (string or object)
 * @returns Normalized credential
 */
export function normalizeCredential(input: CredentialInput): DecryptionCredential {
  if (typeof input === "string") {
    return { type: "password", password: input };
  }

  return input;
}

/**
 * Check if the credential is a password credential.
 */
export function isPasswordCredential(
  credential: DecryptionCredential,
): credential is PasswordCredential {
  return credential.type === "password";
}

/**
 * Check if the credential is a certificate credential.
 */
export function isCertificateCredential(
  credential: DecryptionCredential,
): credential is CertificateCredential {
  return credential.type === "certificate";
}
