// Form fields (R-NF-03, ADR-006; M4 design section 3.9). Each control has
// a `<label>` bound to it. An amount field reads ADR-006 strings only. A
// field never rewrites what the user typed, so a wrong spelling stays
// visible for the user to correct.

import { h } from "./dom.js";
import type { Label } from "./i18n.js";
import { amountText, parseAmount } from "./money.js";

/** The options of one form field. */
export interface FieldOptions {
  /** The control's id, also its name. An HTML id without whitespace. */
  readonly id: string;
  /** The visible label, from a catalogue. */
  readonly label: Label;
  /** `amount` reads an ADR-006 EUR string. */
  readonly kind: "text" | "amount";
  readonly required: boolean;
}

/** What a field read gives. An amount is its ADR-006 text. */
export type FieldRead =
  | { readonly ok: true; readonly value: string }
  | { readonly ok: false; readonly reason: "required" | "amount" };

/** One built field: a root holding a bound `<label>` and the control. */
export interface FormField {
  readonly root: HTMLElement;
  readonly control: HTMLInputElement;
  /**
   * Reads the control and never writes it. An empty required field gives
   * `required`, and an empty optional one reads as `""`. An amount field
   * gives its ADR-006 text, or `amount`.
   */
  read(): FieldRead;
}

/** An HTML id that is safe in an id list: ASCII letters, digits, `-`, `_` and `.`. */
const FIELD_ID = /^[A-Za-z][A-Za-z0-9._-]*$/;

/** The class of a field's root element. */
export const FIELD_CLASS = "fstp-field";

/**
 * Builds a labelled text or amount field. It throws a `TypeError` for an
 * id that is not a plain HTML id or an unknown kind. An id that would
 * shadow a form member, such as `submit` or `action`, is refused by `h`
 * with a `DomRefusal`, since the id is also the control's name.
 */
export function field(opts: FieldOptions): FormField {
  if (typeof opts.id !== "string" || !FIELD_ID.test(opts.id)) {
    throw new TypeError("a field id is an ASCII letter, then letters, digits, '.', '-' or '_'");
  }
  if (opts.kind !== "text" && opts.kind !== "amount") {
    throw new TypeError("a field kind is text or amount");
  }
  const { id, kind, required } = opts;
  const attrs: Record<string, string | boolean> = {
    id,
    name: id,
    type: "text",
    required: required === true,
  };
  if (kind === "amount") {
    // An amount is a decimal string: offer the decimal keyboard, never a
    // number input, which would reformat or round what the user types.
    attrs["inputmode"] = "decimal";
    attrs["autocomplete"] = "off";
    attrs["spellcheck"] = "false";
  }
  const control = h("input", attrs);
  if (!(control instanceof HTMLInputElement)) {
    throw new TypeError("the document did not create an input element");
  }
  const label = h("label", { for: id }, [opts.label]);
  const root = h("div", { class: FIELD_CLASS }, [label, control]);
  return Object.freeze({
    root,
    control,
    read(): FieldRead {
      const typed = control.value;
      if (typed === "") {
        return required === true ? Object.freeze({ ok: false, reason: "required" }) : Object.freeze({ ok: true, value: "" });
      }
      if (kind === "text") {
        return Object.freeze({ ok: true, value: typed });
      }
      const parsed = parseAmount(typed, "EUR");
      return parsed.ok
        ? Object.freeze({ ok: true, value: amountText(parsed.amount) })
        : Object.freeze({ ok: false, reason: "amount" });
    },
  });
}
