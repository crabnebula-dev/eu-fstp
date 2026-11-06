/**
 * Abstract base class for PDF security handlers.
 *
 * Each handler encapsulates algorithm-specific logic for encrypting
 * and decrypting PDF strings and streams, including per-object key derivation.
 *
 * Subclasses implement the core encrypt/decrypt operations while this
 * base class provides the public API.
 */

export type Algorithm = "NONE" | "RC4" | "AES-128" | "AES-256";

export abstract class AbstractSecurityHandler {
  abstract readonly algorithm: Algorithm;

  constructor(readonly fileKey: Uint8Array) {}

  /**
   * Core encryption operation. Subclasses implement algorithm-specific logic.
   */
  protected abstract encrypt(data: Uint8Array, objNum: number, genNum: number): Uint8Array;

  /**
   * Core decryption operation. Subclasses implement algorithm-specific logic.
   */
  protected abstract decrypt(data: Uint8Array, objNum: number, genNum: number): Uint8Array;

  encryptString(data: Uint8Array, objNum: number, genNum: number): Uint8Array {
    return this.encrypt(data, objNum, genNum);
  }

  encryptStream(data: Uint8Array, objNum: number, genNum: number): Uint8Array {
    return this.encrypt(data, objNum, genNum);
  }

  decryptString(data: Uint8Array, objNum: number, genNum: number): Uint8Array {
    return this.decrypt(data, objNum, genNum);
  }

  decryptStream(data: Uint8Array, objNum: number, genNum: number): Uint8Array {
    return this.decrypt(data, objNum, genNum);
  }
}

/**
 * Identity handler for unencrypted content.
 *
 * Used when a crypt filter specifies "Identity" (no encryption),
 * or as a null object when no encryption is needed.
 */
export class IdentityHandler extends AbstractSecurityHandler {
  readonly algorithm = "NONE" as const;

  constructor() {
    super(new Uint8Array(0));
  }

  protected encrypt(data: Uint8Array, _objNum: number, _genNum: number): Uint8Array {
    return data;
  }

  protected decrypt(data: Uint8Array, _objNum: number, _genNum: number): Uint8Array {
    return data;
  }
}
