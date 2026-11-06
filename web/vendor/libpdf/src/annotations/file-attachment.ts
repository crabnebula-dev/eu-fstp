/**
 * PDFFileAttachmentAnnotation - File attachment annotations.
 *
 * File attachment annotations display an icon representing an
 * embedded file attachment.
 *
 * PDF Reference: Section 12.5.6.15 "File Attachment Annotations"
 */

import { PdfDict } from "#src/objects/pdf-dict";
import { PdfName } from "#src/objects/pdf-name";
import type { PdfRef } from "#src/objects/pdf-ref";

import { PDFMarkupAnnotation } from "./markup";
import { isFileAttachmentIcon, type FileAttachmentIcon } from "./types";

/**
 * File attachment annotation - embedded file icon.
 */
export class PDFFileAttachmentAnnotation extends PDFMarkupAnnotation {
  /**
   * Icon to display.
   */
  get icon(): FileAttachmentIcon {
    const name = this.dict.getName("Name", this.registry.resolve.bind(this.registry));

    if (!name) {
      return "PushPin";
    }

    if (isFileAttachmentIcon(name.value)) {
      return name.value;
    }

    return "PushPin";
  }

  /**
   * Set the icon.
   */
  setIcon(icon: FileAttachmentIcon): void {
    this.dict.set("Name", PdfName.of(icon));
    this.markModified();
  }

  /**
   * Reference to the file specification.
   */
  get fileSpecRef(): PdfRef | null {
    const fs = this.dict.get("FS");

    return fs?.type === "ref" ? fs : null;
  }

  /**
   * Get the file specification dictionary.
   */
  getFileSpec(): PdfDict | null {
    return this.dict.getDict("FS", this.registry.resolve.bind(this.registry)) ?? null;
  }

  /**
   * Get the file name from the file specification.
   */
  getFileName(): string | null {
    const fs = this.getFileSpec();

    if (!fs) {
      return null;
    }

    // Try UF (Unicode file name) first, then F, then DOS/Unix names
    const uf = fs.getString("UF", this.registry.resolve.bind(this.registry));

    if (uf) {
      return uf.asString();
    }

    const f = fs.getString("F", this.registry.resolve.bind(this.registry));

    if (f) {
      return f.asString();
    }

    return null;
  }
}
