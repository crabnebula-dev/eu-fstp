import type { Scanner } from "../io/scanner.js";
import { PdfDict } from "../objects/pdf-dict.js";
import type { PdfObject } from "../objects/pdf-object.js";
import { PdfRef } from "../objects/pdf-ref.js";
import { PdfStream } from "../objects/pdf-stream.js";

import { RefusedError, StructureError } from "./errors.js";
import { IndirectObjectParser } from "./indirect-object-parser.js";
import { checkLimit, LIMITS } from "./limits.js";
import { type XRefEntry, XRefParser } from "./xref-parser.js";

/*
 * FSTP (ADR-016): this parser reads the server's own revisions and
 * nothing else, so it is strict. There is no lenient mode, no
 * brute-force recovery, no decryption and no object stream. An encrypted
 * file, a hybrid or stream cross-reference, an object stream and any
 * file beyond the hard limits of ./limits.js are refused with a typed
 * RefusedError. Every other defect throws its parse error.
 */

/**
 * Options for document parsing. FSTP (ADR-016): none; parsing is strict.
 */
export type ParseOptions = Record<string, never>;

/**
 * Parsed document result.
 */
export interface ParsedDocument {
  /** PDF version from header (e.g., "1.7", "2.0") */
  version: string;

  /** Combined trailer dictionary (merged from incremental updates) */
  trailer: PdfDict;

  /** Combined cross-reference entries */
  xref: Map<number, XRefEntry>;

  /** Warnings encountered during parsing */
  warnings: string[];

  /** Number of cross-reference sections in the /Prev chain */
  sections: number;

  // ─────────────────────────────────────────────────────────────────────────────
  // Object access
  // ─────────────────────────────────────────────────────────────────────────────

  /** Get an object by reference (with caching) */
  getObject(ref: PdfRef): PdfObject | null;

  /** Get the document catalog */
  getCatalog(): PdfDict | null;

  /**
   * Get the actual page count by walking the page tree.
   * This is more reliable than trusting /Count metadata for corrupted PDFs.
   */
  getPageCount(): number;

  /**
   * Get all page references by walking the page tree.
   * Returns an array of PdfRef for each reachable page, in document order.
   */
  getPages(): PdfRef[];
}

// PDF header signature: %PDF-
const PDF_HEADER = [0x25, 0x50, 0x44, 0x46, 0x2d]; // %PDF-

// Version pattern: X.Y where X is 1-9 and Y is 0-9
const VERSION_PATTERN = /^[1-9]\.\d$/;

/**
 * Top-level PDF document parser.
 *
 * Orchestrates header parsing, xref loading, trailer resolution, and object access.
 * Provides the main entry point for opening PDF files.
 *
 * @example
 * ```typescript
 * const parser = new DocumentParser(scanner);
 * const doc = await parser.parse();
 *
 * // Access catalog
 * const catalog = await doc.getCatalog();
 *
 * // Load an object by reference
 * const obj = await doc.getObject(PdfRef.of(1, 0));
 * ```
 */
export class DocumentParser {
  private readonly scanner: Scanner;
  private readonly warnings: string[] = [];

  constructor(scanner: Scanner, _options: ParseOptions = {}) {
    this.scanner = scanner;
  }

  /**
   * Parse the PDF document. FSTP (ADR-016): strict, no recovery.
   */
  parse(): ParsedDocument {
    checkLimit("a file of", this.scanner.bytes.length, LIMITS.maxFileBytes);

    // Phase 1: Parse header
    const version = this.parseHeader();

    // Phase 2: Find startxref
    const xrefParser = new XRefParser(this.scanner);

    const startXRef = xrefParser.findStartXRef();

    // Phase 3: Parse XRef chain (follow /Prev)
    const { xref, trailer, sections } = this.parseXRefChain(xrefParser, startXRef);

    // Phase 4: Build document with lazy object loading
    return this.buildDocument(version, xref, trailer, sections);
  }

  /**
   * Parse PDF header and extract version.
   *
   * FSTP (ADR-016): strict. The header starts the file, and the version
   * is one digit, a period and one digit.
   */
  parseHeader(): string {
    // FSTP (ADR-016): the header starts the file and names a valid version.
    if (!this.matchesAt(0, PDF_HEADER)) {
      throw new StructureError("PDF header not found at offset 0");
    }

    const bytes = this.scanner.bytes;
    let version = "";

    for (let i = PDF_HEADER.length; i < PDF_HEADER.length + 3 && i < bytes.length; i++) {
      version += String.fromCharCode(bytes[i]);
    }

    if (!VERSION_PATTERN.test(version)) {
      throw new StructureError(`Invalid PDF version: ${version}`);
    }

    return version;
  }

  /**
   * Parse the XRef chain, following /Prev links for incremental updates.
   *
   * FSTP (ADR-016): hybrid-reference files, whose trailer carries
   * /XRefStm, are refused. A loop or a chain above the section limit is
   * refused too. Public for the pdf_xref fuzz target of web/src/sign.
   */
  parseXRefChain(
    xrefParser: XRefParser,
    startOffset: number,
  ): { xref: Map<number, XRefEntry>; trailer: PdfDict; sections: number } {
    const combinedXRef = new Map<number, XRefEntry>();
    let firstTrailer: PdfDict | null = null;
    let sections = 0;

    // FSTP (ADR-016): a revisited offset is a loop and is refused, and the
    // chain is bounded by the hard section limit.
    const visited = new Set<number>();
    let offset: number | undefined = startOffset;

    while (offset !== undefined) {
      if (visited.has(offset)) {
        throw new StructureError(`Circular xref reference at offset ${offset}`);
      }

      visited.add(offset);
      sections++;
      checkLimit("an xref chain of", sections, LIMITS.maxXRefSections);

      const xrefData = xrefParser.parseAt(offset);

      // FSTP (ADR-016): hybrid files carry a supplementary xref stream.
      if (xrefData.trailer.has("XRefStm")) {
        throw new RefusedError("xref-stream", "a hybrid /XRefStm cross-reference");
      }

      // Merge table entries (first definition wins: newest revision first)
      for (const [objNum, entry] of xrefData.entries) {
        if (!combinedXRef.has(objNum)) {
          combinedXRef.set(objNum, entry);
        }
      }

      checkLimit("an xref chain with objects", combinedXRef.size, LIMITS.maxObjects);

      // Keep the first (most recent) trailer
      if (!firstTrailer) {
        firstTrailer = xrefData.trailer;
      }

      offset = xrefData.prev;
    }

    if (!firstTrailer) {
      throw new StructureError("No valid trailer found");
    }

    return { xref: combinedXRef, trailer: firstTrailer, sections };
  }

  /**
   * Build the final ParsedDocument with lazy object loading.
   */
  private buildDocument(
    version: string,
    xref: Map<number, XRefEntry>,
    trailer: PdfDict,
    sections: number,
  ): ParsedDocument {
    // Object cache: "objNum genNum" -> PdfObject
    const cache = new Map<string, PdfObject>();

    // FSTP (ADR-016): encrypted files are refused before any object loads.
    if (trailer.has("Encrypt")) {
      throw new RefusedError("encrypted", "an encrypted file");
    }

    const getObject = (ref: PdfRef): PdfObject | null => {
      const key = `${ref.objectNumber} ${ref.generation}`;

      // Check cache
      const cached = cache.get(key);

      if (cached !== undefined) {
        return cached;
      }

      // Look up in xref
      const entry = xref.get(ref.objectNumber);

      if (!entry) {
        return null;
      }

      switch (entry.type) {
        case "free":
          return null;

        case "compressed":
          throw new RefusedError("object-stream", `object ${ref.objectNumber} sits in an object stream`);

        case "uncompressed": {
          const parser = new IndirectObjectParser(this.scanner);

          const result = parser.parseObjectAt(entry.offset);

          // FSTP (ADR-016): the object at the offset is the one named.
          if (result.objNum !== ref.objectNumber || result.genNum !== ref.generation) {
            throw new StructureError(
              `Object at offset ${entry.offset} is ${result.objNum} ${result.genNum}, not ${key}`,
            );
          }

          const obj = result.value;

          // FSTP (ADR-016): object and xref streams are refused, also when
          // a classic table names them.
          if (obj instanceof PdfStream) {
            const type = obj.getName("Type")?.value;

            if (type === "ObjStm") {
              throw new RefusedError("object-stream", `object ${key} is an object stream`);
            }

            if (type === "XRef") {
              throw new RefusedError("xref-stream", `object ${key} is an xref stream`);
            }
          }

          cache.set(key, obj);

          return obj;
        }
      }
    };

    const getCatalog = (): PdfDict | null => {
      const rootRef = trailer.getRef("Root");

      if (!rootRef) {
        return null;
      }

      const root = getObject(rootRef);

      if (!root || (root.type !== "dict" && root.type !== "stream")) {
        return null;
      }

      return root as PdfDict;
    };

    /**
     * Walk the page tree and collect all page references.
     * Handles circular references and missing objects gracefully.
     */
    const getPages = (): PdfRef[] => {
      const pages: PdfRef[] = [];
      const visited = new Set<string>();

      const walkNode = (nodeOrRef: PdfObject | null, currentRef?: PdfRef): void => {
        // Handle references
        if (nodeOrRef instanceof PdfRef) {
          const key = `${nodeOrRef.objectNumber} ${nodeOrRef.generation}`;

          // FSTP (ADR-016): a page tree loop is refused.
          if (visited.has(key)) {
            throw new StructureError(`Circular reference in page tree: ${key}`);
          }

          visited.add(key);

          const resolved = getObject(nodeOrRef);

          walkNode(resolved, nodeOrRef);
          return;
        }

        // Must be a dictionary
        if (!(nodeOrRef instanceof PdfDict)) {
          return;
        }

        const type = nodeOrRef.getName("Type");

        if (type?.value === "Page") {
          // Leaf node - this is a page
          if (currentRef) {
            pages.push(currentRef);
          }
        } else if (type?.value === "Pages") {
          // Intermediate node - recurse into kids
          const kids = nodeOrRef.getArray("Kids", getObject);

          if (kids) {
            for (let i = 0; i < kids.length; i++) {
              const kid = kids.at(i);

              if (kid instanceof PdfRef) {
                walkNode(kid);
              } else if (kid instanceof PdfDict) {
                walkNode(kid);
              }
              // Skip null/invalid kids silently
            }
          }
        }
        // Ignore nodes without proper /Type
      };

      // Start from the catalog's Pages reference
      const catalog = getCatalog();

      if (!catalog) {
        return pages;
      }

      const pagesRef = catalog.getRef("Pages");

      if (pagesRef) {
        walkNode(pagesRef);
      }

      return pages;
    };

    const getPageCount = (): number => {
      const pages = getPages();

      return pages.length;
    };

    return {
      version,
      trailer,
      xref,
      warnings: this.warnings,
      sections,

      // Object access
      getObject,
      getCatalog,
      getPageCount,
      getPages,
    };
  }

  /**
   * Check if bytes at position match a pattern.
   */
  private matchesAt(pos: number, pattern: number[]): boolean {
    const bytes = this.scanner.bytes;

    for (let i = 0; i < pattern.length; i++) {
      if (pos + i >= bytes.length || bytes[pos + i] !== pattern[i]) {
        return false;
      }
    }

    return true;
  }
}
