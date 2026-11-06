/**
 * PDF permission flags parsing and representation.
 *
 * Permission flags are stored in the /P entry of the encryption dictionary
 * as a signed 32-bit integer. Each bit controls a specific permission.
 *
 * @see PDF 2.0 Specification, Table 22 (User access permissions)
 */

/**
 * Permission bit positions (1-indexed as per PDF spec).
 * Bits 1-2 must be 0, bits 7-8 must be 1.
 */
export const PermissionBits = {
  /** Bit 3: Print the document */
  PRINT: 3,
  /** Bit 4: Modify the contents of the document */
  MODIFY: 4,
  /** Bit 5: Copy or extract text and graphics */
  COPY: 5,
  /** Bit 6: Add or modify text annotations, fill form fields */
  ANNOTATE: 6,
  /** Bit 9: Fill in existing form fields */
  FILL_FORMS: 9,
  /** Bit 10: Extract text/graphics for accessibility */
  ACCESSIBILITY: 10,
  /** Bit 11: Assemble the document (insert, rotate, delete pages) */
  ASSEMBLE: 11,
  /** Bit 12: Print at high resolution */
  PRINT_HIGH_QUALITY: 12,
} as const;

/**
 * Parsed permission flags.
 *
 * All permissions default to true for unencrypted documents.
 */
export interface Permissions {
  /** Print the document (bit 3) */
  print: boolean;
  /** Print at full resolution (bit 12) - if false, only low-res printing */
  printHighQuality: boolean;
  /** Modify document contents (bit 4) */
  modify: boolean;
  /** Copy or extract text and graphics (bit 5) */
  copy: boolean;
  /** Add or modify annotations (bit 6) */
  annotate: boolean;
  /** Fill in existing form fields (bit 9) */
  fillForms: boolean;
  /** Extract text/graphics for accessibility (bit 10) */
  accessibility: boolean;
  /** Assemble: insert, rotate, delete pages (bit 11) */
  assemble: boolean;
}

/**
 * Default permissions (all allowed) for unencrypted documents.
 */
export const DEFAULT_PERMISSIONS: Permissions = {
  print: true,
  printHighQuality: true,
  modify: true,
  copy: true,
  annotate: true,
  fillForms: true,
  accessibility: true,
  assemble: true,
};

/**
 * Parse permission flags from the /P value.
 *
 * The /P value is a signed 32-bit integer where each bit controls
 * a specific permission. A set bit (1) means the action is ALLOWED.
 *
 * @param p - The /P value from the encryption dictionary
 * @returns Parsed permission flags
 */
export function parsePermissions(p: number): Permissions {
  // Helper to check if a bit is set (1-indexed)
  const hasBit = (bit: number): boolean => {
    return (p & (1 << (bit - 1))) !== 0;
  };

  return {
    print: hasBit(PermissionBits.PRINT),
    printHighQuality: hasBit(PermissionBits.PRINT_HIGH_QUALITY),
    modify: hasBit(PermissionBits.MODIFY),
    copy: hasBit(PermissionBits.COPY),
    annotate: hasBit(PermissionBits.ANNOTATE),
    fillForms: hasBit(PermissionBits.FILL_FORMS),
    accessibility: hasBit(PermissionBits.ACCESSIBILITY),
    assemble: hasBit(PermissionBits.ASSEMBLE),
  };
}

/**
 * Encode permissions as a /P value.
 *
 * @param permissions - Permission flags to encode
 * @returns Signed 32-bit integer for /P entry
 */
export function encodePermissions(permissions: Permissions): number {
  let p = 0;

  // Bits 7-8 must be 1 (required by spec)
  p |= 0b11000000; // bits 7 and 8

  // Set permission bits
  if (permissions.print) {
    p |= 1 << (PermissionBits.PRINT - 1);
  }

  if (permissions.modify) {
    p |= 1 << (PermissionBits.MODIFY - 1);
  }

  if (permissions.copy) {
    p |= 1 << (PermissionBits.COPY - 1);
  }

  if (permissions.annotate) {
    p |= 1 << (PermissionBits.ANNOTATE - 1);
  }

  if (permissions.fillForms) {
    p |= 1 << (PermissionBits.FILL_FORMS - 1);
  }

  if (permissions.accessibility) {
    p |= 1 << (PermissionBits.ACCESSIBILITY - 1);
  }

  if (permissions.assemble) {
    p |= 1 << (PermissionBits.ASSEMBLE - 1);
  }

  if (permissions.printHighQuality) {
    p |= 1 << (PermissionBits.PRINT_HIGH_QUALITY - 1);
  }

  // Set high bits for 32-bit representation (makes it negative)
  // This is typical for encrypted PDFs
  p |= 0xfffff000;

  // Convert to signed 32-bit
  return p | 0;
}

/**
 * Check if all permissions are granted.
 */
export function hasFullAccess(permissions: Permissions): boolean {
  return (
    permissions.print &&
    permissions.printHighQuality &&
    permissions.modify &&
    permissions.copy &&
    permissions.annotate &&
    permissions.fillForms &&
    permissions.accessibility &&
    permissions.assemble
  );
}
