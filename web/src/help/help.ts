// The "i" control of field help (SA-13, R-NF-03). One shared in-house
// component that every field editor in SA-13's scope uses.
//
// - The control is a real `<button type="button">` beside the field's
//   label, named "About <field label>". Its glyph comes from the style
//   sheet (`site/ui.css` `.fstp-info`), so no text node competes with
//   the name and no inline style is needed (CSP).
// - It follows the disclosure pattern: `aria-expanded` and
//   `aria-controls` point to the help region, which is hidden by default
//   and sits under the label, never as a tooltip. A click toggles it. A
//   native button turns Enter and Space into that click.
// - On a `legend`, the button sits inside it, beside the legend text.
//   The group is then named by that text alone through
//   `aria-labelledby`, so the button's name never joins the group's.
//
// The texts come from `help/messages.en.ts`. A missing text adds no
// control, so a page never breaks on it; the SA-13 completeness tests
// keep every text present.

import { h } from "../core/dom.js";
import { createI18n, type I18n, type Label } from "../core/i18n.js";
import { HELP_CATALOGUE } from "./messages.en.js";

/** The help catalogue. */
const ht: I18n = createI18n({ catalogues: [HELP_CATALOGUE], locale: HELP_CATALOGUE.locale });

/** The help text `id`, or null when the catalogue has none. */
export function helpText(id: string): Label | null {
  return Object.prototype.hasOwnProperty.call(HELP_CATALOGUE.labels, id) ? ht.label(id) : null;
}

/** The help id of creator field `key`, such as `help.field.identity.name`. */
export function fieldHelpId(key: string): string {
  return `help.field.${key}`;
}

/** An "i" button and the help region it shows and hides. */
export interface Help {
  readonly button: HTMLElement;
  readonly region: HTMLElement;
}

/**
 * The button and region of help text `text` for the field labelled
 * `field`. `base` is an identifier unique on the page; the region's id is
 * `<base>-help`.
 */
export function helpToggle(base: string, field: string, text: string): Help {
  const id = `${base}-help`;
  const region = h("div", { id, class: "fstp-help", hidden: true }, [h("p", {}, [text])]);
  const button = h("button", {
    type: "button",
    class: "fstp-info",
    "aria-label": ht.label("help.about", { field }),
    "aria-expanded": "false",
    "aria-controls": id,
  });
  button.addEventListener("click", () => {
    const open = button.getAttribute("aria-expanded") !== "true";
    button.setAttribute("aria-expanded", open ? "true" : "false");
    region.toggleAttribute("hidden", !open);
  });
  return { button, region };
}

/**
 * A label for control `id`, followed by its "i" button and help region,
 * for a page to place where the bare label went. Without a help text it
 * is the label alone.
 */
export function labelWithHelp(id: string, label: string, helpId: string): HTMLElement[] {
  const l = h("label", { for: id }, [label]);
  const text = helpText(helpId);
  if (text === null) return [l];
  const help = helpToggle(id, label, text);
  return [l, help.button, help.region];
}

/** Inserts `nodes` into `parent` after its child `ref`. */
function insertAfter(parent: Node, ref: Node, nodes: readonly Node[]): void {
  const kids: Node[] = Array.from(parent.childNodes);
  const next = kids[kids.indexOf(ref) + 1] ?? null;
  for (const n of nodes) parent.insertBefore(n, next);
}

/**
 * Puts help text `helpId` on `label`, a `label` or `legend` already in
 * its parent. A label gets the button and region after it. A legend
 * holds the button beside its text, its group is named by that text, and
 * the region follows the legend. `base` is an identifier unique on the
 * page. Returns null, and changes nothing, without a text or a parent.
 */
export function attachHelp(label: HTMLElement, base: string, helpId: string): Help | null {
  const text = helpText(helpId);
  const parent = label.parentElement;
  if (text === null || parent === null) return null;
  const help = helpToggle(base, label.textContent ?? "", text);
  if (label.localName === "legend") {
    const nameId = `${base}-name`;
    const name = h("span", { id: nameId }, Array.from(label.childNodes));
    label.replaceChildren(name, help.button);
    parent.setAttribute("aria-labelledby", nameId);
    insertAfter(parent, label, [help.region]);
  } else {
    insertAfter(parent, label, [help.button, help.region]);
  }
  return help;
}
