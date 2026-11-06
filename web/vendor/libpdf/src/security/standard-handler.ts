/**
 * Standard security handler for PDF encryption.
 *
 * This handler implements password-based encryption for PDF documents
 * using the "Standard" security handler (the most common handler).
 *
 * Supports:
 * - R2-R4: MD5/RC4 based encryption (40-128 bit)
 * - R5-R6: SHA/AES-256 based encryption (256 bit)
 *
 * @see PDF 2.0 Specification, Section 7.6.4 (Standard Security Handler)
 */

import { type DecryptionCredential, isPasswordCredential } from "./credentials";
import {
  type EncryptionDict,
  getKeyLengthBytes,
  type EncryptionRevision,
  type EncryptionVersion,
} from "./encryption-dict";
import { UnsupportedEncryptionError } from "./errors";
import type { AbstractSecurityHandler } from "./handlers/abstract";
import { createHandlers, type HandlerConfig } from "./handlers/factory";
import { verifyOwnerPassword, verifyUserPassword } from "./key-derivation/md5-based";
import {
  verifyOwnerPasswordR56,
  verifyPermsEntry,
  verifyUserPasswordR56,
} from "./key-derivation/sha-based";
import type { Permissions } from "./permissions";

/**
 * Authentication result from password verification.
 */
export interface AuthResult {
  /** Whether authentication succeeded */
  authenticated: boolean;
  /** The type of password that was authenticated */
  passwordType?: "user" | "owner";
  /** Document permissions (for user password; owner has full access) */
  permissions: Permissions;
  /** Whether this user has owner-level access */
  isOwner: boolean;
}

/**
 * Standard security handler for PDF decryption.
 *
 * Usage:
 * 1. Create handler with encryption dictionary and file ID
 * 2. Call authenticate() with password (empty string for no password)
 * 3. If authenticated, use decryptString/decryptStream for each object
 */
export class StandardSecurityHandler {
  private encryptionKey: Uint8Array | null = null;
  private handlers: HandlerConfig | null = null;
  private authenticated = false;
  private isOwner = false;

  constructor(
    private readonly encryptDict: EncryptionDict,
    private readonly fileId: Uint8Array,
  ) {}

  /**
   * Get the encryption dictionary.
   */
  get encryption(): EncryptionDict {
    return this.encryptDict;
  }

  /**
   * Get the encryption version.
   */
  get version(): EncryptionVersion {
    return this.encryptDict.version;
  }

  /**
   * Get the encryption revision.
   */
  get revision(): EncryptionRevision {
    return this.encryptDict.revision;
  }

  /**
   * Get document permissions.
   */
  get permissions(): Permissions {
    return this.encryptDict.permissions;
  }

  /**
   * Check if the handler is authenticated.
   */
  get isAuthenticated(): boolean {
    return this.authenticated;
  }

  /**
   * Check if authenticated with owner password.
   */
  get hasOwnerAccess(): boolean {
    return this.isOwner;
  }

  /**
   * Get the string security handler (after authentication).
   */
  get stringHandler(): AbstractSecurityHandler | null {
    return this.handlers?.stringHandler ?? null;
  }

  /**
   * Get the stream security handler (after authentication).
   */
  get streamHandler(): AbstractSecurityHandler | null {
    return this.handlers?.streamHandler ?? null;
  }

  /**
   * Authenticate with a password.
   *
   * Tries both user and owner password validation.
   * Call with empty Uint8Array for documents with no password.
   *
   * @param password - UTF-8 encoded password bytes
   * @returns Authentication result
   */
  authenticate(password: Uint8Array): AuthResult {
    // Try user password first (most common)
    const userResult = this.tryUserPassword(password);
    if (userResult.authenticated) {
      return userResult;
    }

    // Try owner password
    const ownerResult = this.tryOwnerPassword(password);
    if (ownerResult.authenticated) {
      return ownerResult;
    }

    // Authentication failed
    return {
      authenticated: false,
      permissions: this.encryptDict.permissions,
      isOwner: false,
    };
  }

  /**
   * Authenticate with a string password (convenience method).
   */
  authenticateWithString(password: string): AuthResult {
    return this.authenticate(new TextEncoder().encode(password));
  }

  /**
   * Authenticate with a credential object.
   *
   * The Standard security handler only supports password credentials.
   * Certificate credentials require the Public Key handler (/Adobe.PubSec).
   *
   * @param credential - The credential to authenticate with
   * @returns Authentication result
   * @throws {UnsupportedEncryptionError} if credential type is not supported
   */
  authenticateWithCredential(credential: DecryptionCredential): AuthResult {
    if (isPasswordCredential(credential)) {
      return this.authenticateWithString(credential.password);
    }

    // Standard handler doesn't support certificate credentials
    throw new UnsupportedEncryptionError(
      "The Standard security handler only supports password credentials. " +
        "Certificate-based decryption requires the Public Key handler (/Adobe.PubSec), " +
        "which is not yet implemented.",
      "UNSUPPORTED_CREDENTIALS",
    );
  }

  /**
   * Try to authenticate with the user password.
   */
  private tryUserPassword(password: Uint8Array): AuthResult {
    const { revision } = this.encryptDict;

    if (revision >= 5) {
      return this.tryUserPasswordR56(password);
    }
    return this.tryUserPasswordR2R4(password);
  }

  /**
   * Try to authenticate with the owner password.
   */
  private tryOwnerPassword(password: Uint8Array): AuthResult {
    const { revision } = this.encryptDict;

    if (revision >= 5) {
      return this.tryOwnerPasswordR56(password);
    }
    return this.tryOwnerPasswordR2R4(password);
  }

  /**
   * Try user password for R2-R4 encryption.
   */
  private tryUserPasswordR2R4(password: Uint8Array): AuthResult {
    const result = verifyUserPassword(
      password,
      this.encryptDict.ownerHash,
      this.encryptDict.userHash,
      this.encryptDict.permissionsRaw,
      this.fileId,
      getKeyLengthBytes(this.encryptDict),
      this.encryptDict.revision,
      this.encryptDict.encryptMetadata,
    );

    if (result.isValid && result.encryptionKey) {
      this.setAuthenticated(result.encryptionKey, false);

      return {
        authenticated: true,
        passwordType: "user",
        permissions: this.encryptDict.permissions,
        isOwner: false,
      };
    }

    return {
      authenticated: false,
      permissions: this.encryptDict.permissions,
      isOwner: false,
    };
  }

  /**
   * Try owner password for R2-R4 encryption.
   */
  private tryOwnerPasswordR2R4(password: Uint8Array): AuthResult {
    const result = verifyOwnerPassword(
      password,
      this.encryptDict.ownerHash,
      this.encryptDict.userHash,
      this.encryptDict.permissionsRaw,
      this.fileId,
      getKeyLengthBytes(this.encryptDict),
      this.encryptDict.revision,
      this.encryptDict.encryptMetadata,
    );

    if (result.isValid && result.encryptionKey) {
      this.setAuthenticated(result.encryptionKey, true);

      return {
        authenticated: true,
        passwordType: "owner",
        permissions: this.encryptDict.permissions,
        isOwner: true,
      };
    }

    return {
      authenticated: false,
      permissions: this.encryptDict.permissions,
      isOwner: false,
    };
  }

  /**
   * Try user password for R5-R6 encryption.
   */
  private tryUserPasswordR56(password: Uint8Array): AuthResult {
    const { userHash, userEncryptionKey, revision, permsValue, permissionsRaw, encryptMetadata } =
      this.encryptDict;

    if (!userEncryptionKey) {
      return {
        authenticated: false,
        permissions: this.encryptDict.permissions,
        isOwner: false,
      };
    }

    const result = verifyUserPasswordR56(password, userHash, userEncryptionKey, revision);

    if (result.isValid && result.encryptionKey) {
      // For R6, verify Perms entry
      if (revision === 6 && permsValue) {
        const permsValid = verifyPermsEntry(
          result.encryptionKey,
          permsValue,
          permissionsRaw,
          encryptMetadata,
        );
        if (!permsValid) {
          return {
            authenticated: false,
            permissions: this.encryptDict.permissions,
            isOwner: false,
          };
        }
      }

      this.setAuthenticated(result.encryptionKey, false);

      return {
        authenticated: true,
        passwordType: "user",
        permissions: this.encryptDict.permissions,
        isOwner: false,
      };
    }

    return {
      authenticated: false,
      permissions: this.encryptDict.permissions,
      isOwner: false,
    };
  }

  /**
   * Try owner password for R5-R6 encryption.
   */
  private tryOwnerPasswordR56(password: Uint8Array): AuthResult {
    const {
      ownerHash,
      ownerEncryptionKey,
      userHash,
      revision,
      permsValue,
      permissionsRaw,
      encryptMetadata,
    } = this.encryptDict;

    if (!ownerEncryptionKey) {
      return {
        authenticated: false,
        permissions: this.encryptDict.permissions,
        isOwner: false,
      };
    }

    const result = verifyOwnerPasswordR56(
      password,
      ownerHash,
      ownerEncryptionKey,
      userHash,
      revision,
    );

    if (result.isValid && result.encryptionKey) {
      // For R6, verify Perms entry
      if (revision === 6 && permsValue) {
        const permsValid = verifyPermsEntry(
          result.encryptionKey,
          permsValue,
          permissionsRaw,
          encryptMetadata,
        );
        if (!permsValid) {
          return {
            authenticated: false,
            permissions: this.encryptDict.permissions,
            isOwner: false,
          };
        }
      }

      this.setAuthenticated(result.encryptionKey, true);

      return {
        authenticated: true,
        passwordType: "owner",
        permissions: this.encryptDict.permissions,
        isOwner: true,
      };
    }

    return {
      authenticated: false,
      permissions: this.encryptDict.permissions,
      isOwner: false,
    };
  }

  /**
   * Set authenticated state and create handlers.
   */
  private setAuthenticated(encryptionKey: Uint8Array, isOwner: boolean): void {
    this.encryptionKey = encryptionKey;
    this.authenticated = true;
    this.isOwner = isOwner;
    this.handlers = createHandlers(this.encryptDict, encryptionKey);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Encryption methods
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Encrypt a string.
   *
   * @param data - Plaintext string bytes
   * @param objectNumber - Object number containing the string
   * @param generationNumber - Generation number
   * @returns Encrypted string bytes
   * @throws {Error} if not authenticated
   */
  encryptString(data: Uint8Array, objectNumber: number, generationNumber: number): Uint8Array {
    if (!this.authenticated || !this.handlers) {
      throw new Error("Not authenticated");
    }

    return this.handlers.stringHandler.encryptString(data, objectNumber, generationNumber);
  }

  /**
   * Encrypt a stream.
   *
   * @param data - Plaintext stream bytes
   * @param objectNumber - Object number containing the stream
   * @param generationNumber - Generation number
   * @returns Encrypted stream bytes
   * @throws {Error} if not authenticated
   */
  encryptStream(data: Uint8Array, objectNumber: number, generationNumber: number): Uint8Array {
    if (!this.authenticated || !this.handlers) {
      throw new Error("Not authenticated");
    }

    return this.handlers.streamHandler.encryptStream(data, objectNumber, generationNumber);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Decryption methods
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Decrypt a string.
   *
   * @param data - Encrypted string bytes
   * @param objectNumber - Object number containing the string
   * @param generationNumber - Generation number
   * @returns Decrypted string bytes
   * @throws {Error} if not authenticated
   */
  decryptString(data: Uint8Array, objectNumber: number, generationNumber: number): Uint8Array {
    if (!this.authenticated || !this.handlers) {
      throw new Error("Not authenticated");
    }

    return this.handlers.stringHandler.decryptString(data, objectNumber, generationNumber);
  }

  /**
   * Decrypt a stream.
   *
   * @param data - Encrypted stream bytes
   * @param objectNumber - Object number containing the stream
   * @param generationNumber - Generation number
   * @returns Decrypted stream bytes
   * @throws {Error} if not authenticated
   */
  decryptStream(data: Uint8Array, objectNumber: number, generationNumber: number): Uint8Array {
    if (!this.authenticated || !this.handlers) {
      throw new Error("Not authenticated");
    }

    return this.handlers.streamHandler.decryptStream(data, objectNumber, generationNumber);
  }

  /**
   * Check if a specific stream should be encrypted.
   *
   * Some streams like XRef streams are never encrypted,
   * and metadata may be unencrypted if EncryptMetadata is false.
   *
   * @param streamType - The /Type of the stream (e.g., "XRef", "Metadata")
   * @returns Whether the stream should be encrypted
   */
  shouldEncryptStream(streamType?: string): boolean {
    // XRef streams are never encrypted
    if (streamType === "XRef") {
      return false;
    }

    // Metadata may be unencrypted
    if (streamType === "Metadata" && !this.encryptDict.encryptMetadata) {
      return false;
    }

    return true;
  }
}

/**
 * Try to authenticate with an empty password.
 *
 * Many encrypted PDFs use an empty user password but restrict
 * permissions. This is a convenience function for that common case.
 *
 * @param handler - The security handler
 * @returns Authentication result
 */
export function tryEmptyPassword(handler: StandardSecurityHandler): AuthResult {
  return handler.authenticate(new Uint8Array(0));
}
