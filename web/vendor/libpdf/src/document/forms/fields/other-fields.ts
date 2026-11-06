/**
 * Other field types: Signature, Button, and Unknown.
 *
 * PDF Reference: Section 12.7.4.5 "Signature Fields"
 * PDF Reference: Section 12.7.4.2 "Button Fields"
 */

import { PdfDict } from "#src/objects/pdf-dict";

import { TerminalField } from "./base";

/**
 * Signature field.
 */
export class SignatureField extends TerminalField {
  readonly type = "signature" as const;

  /**
   * Check if field has been signed.
   */
  isSigned(): boolean {
    return this.dict.has("V");
  }

  /**
   * Get signature dictionary (if signed).
   */
  getSignatureDict(): PdfDict | null {
    return this.dict.getDict("V", this.registry.resolve.bind(this.registry)) ?? null;
  }

  /**
   * Signature fields don't have simple values.
   */
  getValue(): null {
    return null;
  }
}

/**
 * Push button field.
 */
export class ButtonField extends TerminalField {
  readonly type = "button" as const;

  /**
   * Push buttons don't have values.
   */
  getValue(): null {
    return null;
  }
}

/**
 * Unknown field type.
 */
export class UnknownField extends TerminalField {
  readonly type = "unknown" as const;

  getValue(): unknown {
    return this.getInheritable("V") ?? null;
  }
}
