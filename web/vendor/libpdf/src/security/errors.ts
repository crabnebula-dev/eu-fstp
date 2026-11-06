/**
 * Error classes for PDF security operations.
 */

/**
 * Base class for security-related errors.
 */
export class SecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecurityError";
  }
}

/**
 * Error parsing the encryption dictionary.
 *
 * Thrown when the /Encrypt dictionary is malformed or contains
 * unsupported values.
 */
export class EncryptionDictError extends SecurityError {
  constructor(message: string) {
    super(message);
    this.name = "EncryptionDictError";
  }
}

/**
 * Error during password authentication.
 *
 * Thrown when password verification fails or required fields are missing.
 */
export class AuthenticationError extends SecurityError {
  constructor(message: string) {
    super(message);
    this.name = "AuthenticationError";
  }
}

/**
 * Error during decryption.
 *
 * Thrown when decryption fails due to invalid data or wrong key.
 */
export class DecryptionError extends SecurityError {
  constructor(message: string) {
    super(message);
    this.name = "DecryptionError";
  }
}

/**
 * Error codes for encryption-related failures.
 */
export type EncryptionErrorCode =
  | "NEED_CREDENTIALS"
  | "INVALID_CREDENTIALS"
  | "UNSUPPORTED_ENCRYPTION"
  | "UNSUPPORTED_CREDENTIALS";

/**
 * Error for unsupported encryption methods or credential types.
 *
 * Thrown when:
 * - The document uses an unsupported security handler (e.g., Adobe.PubSec)
 * - Certificate credentials are provided but not yet implemented
 * - An unknown encryption algorithm is encountered
 */
export class UnsupportedEncryptionError extends SecurityError {
  readonly code: EncryptionErrorCode;

  constructor(message: string, code: EncryptionErrorCode = "UNSUPPORTED_ENCRYPTION") {
    super(message);
    this.name = "UnsupportedEncryptionError";
    this.code = code;
  }
}

/**
 * Security error codes for permission and protection operations.
 */
export type SecurityErrorCode =
  | "PERMISSION_DENIED"
  | "NOT_AUTHENTICATED"
  | "INVALID_PASSWORD"
  | "UNSUPPORTED_ENCRYPTION";

/**
 * Error thrown when an operation requires permissions the user doesn't have.
 *
 * Examples:
 * - Calling removeProtection() without owner access or modify permission
 * - Calling setProtection() on an encrypted document without owner access
 */
export class PermissionDeniedError extends SecurityError {
  readonly code: SecurityErrorCode = "PERMISSION_DENIED";
  readonly requiredPermission?: string;

  constructor(message: string, requiredPermission?: string) {
    super(message);
    this.name = "PermissionDeniedError";
    this.requiredPermission = requiredPermission;
  }
}
