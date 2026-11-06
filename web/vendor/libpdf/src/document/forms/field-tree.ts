/**
 * FieldTree - Safe iteration over the form field hierarchy.
 *
 * Provides cycle-safe, breadth-first iteration over form fields.
 * Based on PDFBox's PDFieldTree pattern.
 *
 * PDF Reference: Section 12.7.3.1 "Field Dictionaries"
 */

import { PdfDict } from "#src/objects/pdf-dict";
import { PdfRef } from "#src/objects/pdf-ref";

import type { ObjectRegistry } from "../object-registry";
import { createFormField, type FormField, NonTerminalField, TerminalField } from "./fields";

/**
 * Interface for AcroForm-like objects that can provide field tree iteration.
 */
export interface FieldTreeSource {
  getDict(): PdfDict;
  defaultQuadding: number;
  updateFieldAppearance?(field: TerminalField): void;
}

/**
 * FieldTree provides safe, synchronous iteration over the form field hierarchy.
 *
 * Features:
 * - Cycle detection prevents infinite loops from malformed PDFs
 * - Breadth-first iteration for predictable ordering
 * - Sets parent references during iteration
 * - Separate generators for all fields vs terminal-only
 *
 * Usage:
 * ```typescript
 * const tree = await FieldTree.load(acroForm, registry);
 *
 * // Iterate all fields (including non-terminal)
 * for (const field of tree) {
 *   console.log(field.name, field.type);
 * }
 *
 * // Iterate only terminal fields (value-holding)
 * for (const field of tree.terminalFields()) {
 *   console.log(field.name, field.getValue());
 * }
 * ```
 */
export class FieldTree implements Iterable<FormField> {
  private readonly fields: FormField[];

  private constructor(fields: FormField[]) {
    this.fields = fields;
  }

  /**
   * Load and build the field tree from an AcroForm.
   *
   * This performs async resolution of all field references and widget references,
   * then returns a FieldTree that can be iterated synchronously.
   *
   * @param acroForm The AcroForm to load fields from
   * @param registry The object registry for resolving references
   * @returns A fully-loaded FieldTree
   */
  static load(acroForm: FieldTreeSource, registry: ObjectRegistry): FieldTree {
    const dict = acroForm.getDict();
    const resolve = registry.resolve.bind(registry);
    const fieldsArray = dict.getArray("Fields", resolve);

    if (!fieldsArray) {
      return new FieldTree([]);
    }

    const visited = new Set<string>();
    const fields: FormField[] = [];

    // Process root fields breadth-first
    const queue: Array<{
      item: unknown;
      parentName: string;
      parent: FormField | null;
    }> = [];

    // Initialize queue with root fields
    for (let i = 0; i < fieldsArray.length; i++) {
      queue.push({
        item: fieldsArray.at(i),
        parentName: "",
        parent: null,
      });
    }

    // Process queue breadth-first
    while (queue.length > 0) {
      const entry = queue.shift();

      if (!entry) {
        continue;
      }

      const { parentName, parent } = entry;
      let { item } = entry;

      const ref = item instanceof PdfRef ? item : null;
      const refKey = ref ? `${ref.objectNumber}:${ref.generation}` : "";

      // Cycle detection
      if (refKey && visited.has(refKey)) {
        registry.addWarning(`Circular reference in form field tree: ${refKey}`);
        continue;
      }

      if (refKey) {
        visited.add(refKey);
      }

      // Resolve field dictionary
      let fieldDict: PdfDict | null = null;

      if (item instanceof PdfRef) {
        item = registry.resolve(item) ?? undefined;
      }

      if (item instanceof PdfDict) {
        fieldDict = item;
      }

      if (!fieldDict) {
        continue;
      }

      // Build fully-qualified name
      const partialName = fieldDict.getString("T", resolve)?.asString() ?? "";
      const fullName = parentName
        ? partialName
          ? `${parentName}.${partialName}`
          : parentName
        : partialName;

      // Check if terminal or non-terminal
      const isTerminal = checkIsTerminalField(fieldDict, registry);

      if (isTerminal) {
        // Create terminal field
        const field = createFormField(fieldDict, ref, registry, acroForm, fullName);

        field.resolveWidgets();

        field.parent = parent;
        fields.push(field);

        // Add to parent's children if parent is non-terminal
        if (parent instanceof NonTerminalField) {
          parent.addChild(field);
        }
      } else {
        // Create non-terminal field and queue its children
        const nonTerminal = new NonTerminalField(fieldDict, ref, registry, acroForm, fullName);

        nonTerminal.parent = parent;

        fields.push(nonTerminal);

        // Add to parent's children if parent is non-terminal
        if (parent instanceof NonTerminalField) {
          parent.addChild(nonTerminal);
        }

        // Queue children for processing
        const kids = fieldDict.getArray("Kids", resolve);

        if (kids) {
          for (let i = 0; i < kids.length; i++) {
            queue.push({
              item: kids.at(i),
              parentName: fullName,
              parent: nonTerminal,
            });
          }
        }
      }
    }

    return new FieldTree(fields);
  }

  /**
   * Iterate over all fields (terminal and non-terminal).
   * Fields are yielded in breadth-first order.
   */
  *[Symbol.iterator](): Generator<FormField> {
    for (const field of this.fields) {
      yield field;
    }
  }

  /**
   * Iterate over only terminal fields (those that hold values).
   */
  *terminalFields(): Generator<TerminalField> {
    for (const field of this.fields) {
      if (field instanceof TerminalField) {
        yield field;
      }
    }
  }

  /**
   * Get all fields as an array.
   */
  getAllFields(): FormField[] {
    return [...this.fields];
  }

  /**
   * Get all terminal fields as an array.
   */
  getTerminalFields(): TerminalField[] {
    return this.fields.filter(f => f instanceof TerminalField);
  }

  /**
   * Find a field by fully-qualified name.
   */
  findField(name: string): FormField | null {
    return this.fields.find(f => f.name === name) ?? null;
  }

  /**
   * Find a terminal field by name.
   */
  findTerminalField(name: string): TerminalField | null {
    const field = this.findField(name);

    if (field && field instanceof TerminalField) {
      return field;
    }

    return null;
  }

  /**
   * Get the number of fields (including non-terminal).
   */
  get size(): number {
    return this.fields.length;
  }

  /**
   * Check if tree is empty.
   */
  get isEmpty(): boolean {
    return this.fields.length === 0;
  }
}

/**
 * Check if a field dictionary represents a terminal field.
 *
 * A field is terminal if:
 * - It has no /Kids, OR
 * - Its /Kids contain widgets (no /T) rather than child fields (have /T)
 */
function checkIsTerminalField(dict: PdfDict, registry: ObjectRegistry): boolean {
  const resolve = registry.resolve.bind(registry);
  const kids = dict.getArray("Kids", resolve);

  if (!kids || kids.length === 0) {
    return true;
  }

  // Check the first kid - if it has /T, these are child fields (non-terminal)
  // If it has no /T, these are widgets (terminal)
  let firstKid = kids.at(0);

  if (!firstKid) {
    return true;
  }

  let firstKidDict: PdfDict | null = null;

  if (firstKid instanceof PdfRef) {
    firstKid = registry.resolve(firstKid) ?? undefined;
  }

  if (firstKid instanceof PdfDict) {
    firstKidDict = firstKid;
  }

  if (!firstKidDict) {
    return true;
  }

  // If first kid has /T, it's a child field → parent is non-terminal
  // If first kid has no /T, it's a widget → parent is terminal
  return !firstKidDict.has("T");
}
