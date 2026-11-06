/**
 * Types for PDF file attachments.
 */

/**
 * Information about an embedded file attachment.
 */
export interface AttachmentInfo {
  /** The key name in the EmbeddedFiles tree */
  name: string;

  /** Original filename (from /UF, /F, or platform-specific keys) */
  filename: string;

  /** User-facing description */
  description?: string;

  /** MIME type (from /Subtype on the embedded file stream) */
  mimeType?: string;

  /** File size in bytes (uncompressed) */
  size?: number;

  /** Creation date */
  createdAt?: Date;

  /** Modification date */
  modifiedAt?: Date;
}

/**
 * Options for adding an attachment to a PDF.
 */
export interface AddAttachmentOptions {
  /** User-facing description */
  description?: string;

  /** MIME type (auto-detected from extension if not provided) */
  mimeType?: string;

  /** Creation date (defaults to now) */
  createdAt?: Date;

  /** Modification date (defaults to now) */
  modifiedAt?: Date;

  /** Overwrite if attachment with same name exists (default: false, throws) */
  overwrite?: boolean;
}
