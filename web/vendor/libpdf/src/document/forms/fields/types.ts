/**
 * Shared types and constants for form fields.
 *
 * PDF Reference: Section 12.7 "Interactive Forms"
 */

import type { TerminalField } from "./base";

/**
 * Interface for AcroForm-like objects that fields can reference.
 * Used to avoid circular dependencies.
 */
export interface AcroFormLike {
  defaultQuadding: number;
  updateFieldAppearance?(field: TerminalField): void;
}

/**
 * Field type identifiers.
 */
export type FieldType =
  | "text"
  | "checkbox"
  | "radio"
  | "dropdown"
  | "listbox"
  | "signature"
  | "button"
  | "unknown"
  | "non-terminal";

/**
 * Field flags from PDF spec Table 221.
 */
export const FieldFlags = {
  // Common flags (bits 1-3)
  READ_ONLY: 1 << 0,
  REQUIRED: 1 << 1,
  NO_EXPORT: 1 << 2,

  // Text field flags (bits 13-26)
  MULTILINE: 1 << 12,
  PASSWORD: 1 << 13,
  FILE_SELECT: 1 << 20,
  DO_NOT_SPELL_CHECK: 1 << 22,
  DO_NOT_SCROLL: 1 << 23,
  COMB: 1 << 24,
  RICH_TEXT: 1 << 25,

  // Button field flags (bits 15-17, 26)
  NO_TOGGLE_TO_OFF: 1 << 14,
  RADIO: 1 << 15,
  PUSHBUTTON: 1 << 16,
  RADIOS_IN_UNISON: 1 << 25, // Same bit as RICH_TEXT, different field type
  // Choice field flags (bits 18-27)
  COMBO: 1 << 17,
  EDIT: 1 << 18,
  SORT: 1 << 19,
  MULTI_SELECT: 1 << 21,
  COMMIT_ON_SEL_CHANGE: 1 << 26,
} as const;

/**
 * RGB color for text.
 */
export interface RgbColor {
  r: number;
  g: number;
  b: number;
}

/**
 * Choice option with export value and display text.
 */
export interface ChoiceOption {
  /** Export value (used in form data) */
  value: string;
  /** Display text (shown to user) */
  display: string;
}
