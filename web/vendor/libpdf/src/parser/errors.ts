/**
 * Error classes for PDF parsing operations.
 *
 * The error hierarchy is designed around recoverability:
 * - RecoverableParseError: Lenient mode can attempt brute-force recovery
 * - UnrecoverableParseError: Recovery was attempted but failed
 * - Other errors: Always propagate (no recovery possible)
 */

/**
 * Error thrown when recovery itself fails.
 *
 * This indicates we tried both normal parsing AND brute-force recovery,
 * but the document is too corrupted to parse. There's nothing left to try.
 */
export class UnrecoverableParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnrecoverableParseError";
  }
}

/**
 * Base class for recoverable parsing errors.
 *
 * When lenient mode is enabled, these errors trigger brute-force recovery
 * instead of failing immediately. Examples:
 * - Malformed xref tables
 * - Invalid object syntax
 * - Corrupted stream data
 *
 * Errors that are NOT recoverable (and should NOT extend this):
 * - UnsupportedEncryptionError (no fallback possible)
 * - Invalid credentials (user must provide correct password)
 * - Missing required files
 */
export class RecoverableParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RecoverableParseError";
  }
}

/**
 * Error when xref parsing fails.
 * Recoverable: brute-force parser can scan for objects.
 */
export class XRefParseError extends RecoverableParseError {
  constructor(message: string) {
    super(message);
    this.name = "XRefParseError";
  }
}

/**
 * Error when object parsing fails.
 * Recoverable: can skip malformed objects.
 */
export class ObjectParseError extends RecoverableParseError {
  constructor(message: string) {
    super(message);
    this.name = "ObjectParseError";
  }
}

/**
 * Error when stream decompression fails.
 * Recoverable: can return raw stream data.
 */
export class StreamDecodeError extends RecoverableParseError {
  constructor(message: string) {
    super(message);
    this.name = "StreamDecodeError";
  }
}

/**
 * Error when PDF structure is invalid.
 * Recoverable: brute-force can attempt to reconstruct structure.
 */
export class StructureError extends RecoverableParseError {
  constructor(message: string) {
    super(message);
    this.name = "StructureError";
  }
}
