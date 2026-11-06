/**
 * Form field factory function.
 *
 * Creates the appropriate field type based on /FT and /Ff values.
 */

import { PdfDict } from "#src/objects/pdf-dict";
import type { PdfRef } from "#src/objects/pdf-ref";

import type { ObjectRegistry } from "../../object-registry";
import type { TerminalField } from "./base";
import { CheckboxField } from "./checkbox-field";
import { DropdownField, ListBoxField } from "./choice-fields";
import { ButtonField, SignatureField, UnknownField } from "./other-fields";
import { RadioField } from "./radio-field";
import { TextField } from "./text-field";
import { type AcroFormLike, FieldFlags } from "./types";

/**
 * Create a terminal FormField instance based on /FT and /Ff.
 *
 * This factory creates only terminal fields (value-holding fields with widgets).
 * Non-terminal fields (containers) are created directly in AcroForm.
 */
export function createFormField(
  dict: PdfDict,
  ref: PdfRef | null,
  registry: ObjectRegistry,
  acroForm: AcroFormLike,
  name: string,
): TerminalField {
  const ft = getInheritableFieldName(dict, "FT", registry);
  const ff = getInheritableFieldNumber(dict, "Ff", registry);

  switch (ft) {
    case "Tx":
      return new TextField(dict, ref, registry, acroForm, name);

    case "Btn":
      if (ff & FieldFlags.PUSHBUTTON) {
        return new ButtonField(dict, ref, registry, acroForm, name);
      }

      if (ff & FieldFlags.RADIO) {
        return new RadioField(dict, ref, registry, acroForm, name);
      }

      return new CheckboxField(dict, ref, registry, acroForm, name);

    case "Ch":
      if (ff & FieldFlags.COMBO) {
        return new DropdownField(dict, ref, registry, acroForm, name);
      }

      return new ListBoxField(dict, ref, registry, acroForm, name);

    case "Sig":
      return new SignatureField(dict, ref, registry, acroForm, name);

    default:
      return new UnknownField(dict, ref, registry, acroForm, name);
  }
}

/**
 * Get inheritable name value from field hierarchy.
 */
function getInheritableFieldName(
  dict: PdfDict,
  key: string,
  registry: ObjectRegistry,
): string | null {
  let current: PdfDict | null = dict;
  const visited = new Set<PdfDict>();
  const resolve = registry.resolve.bind(registry);

  while (current) {
    if (visited.has(current)) {
      break;
    }

    visited.add(current);

    const value = current.getName(key, resolve);

    if (value) {
      return value.value;
    }

    const parent = current.getDict("Parent", resolve);

    if (!parent) {
      break;
    }

    current = parent;
  }

  return null;
}

/**
 * Get inheritable number value from field hierarchy.
 */
function getInheritableFieldNumber(dict: PdfDict, key: string, registry: ObjectRegistry): number {
  let current: PdfDict | null = dict;
  const visited = new Set<PdfDict>();
  const resolve = registry.resolve.bind(registry);

  while (current) {
    if (visited.has(current)) {
      break;
    }

    visited.add(current);

    const value = current.getNumber(key, resolve);

    if (value) {
      return value.value;
    }

    const parent = current.getDict("Parent", resolve);

    if (!parent) {
      break;
    }

    current = parent;
  }

  return 0;
}
