// Value editors of the creator step pages and the import review (R-PG-01,
// R-NF-03; M4 design section 3.9).
//
// Each field is built from its shape in `fields.ts`. Every leaf of the
// value has one labelled control whose `data-path` is the leaf's JSON
// pointer (RFC 6901) within the field value; a scalar field's control has
// `data-path=""`. This is the field value contract of
// `e2e/creator/support.ts` `setFieldValue`, an interim reading pending
// Daniel. Its rules:
//
// - A `select` holds an option value, and a checkbox a boolean.
// - Any other control holds the leaf's text: a string as it is, an
//   integer in decimal digits, an ADR-006 amount as its string. An empty
//   control is `null`.
// - A list is `[data-path][data-kind="list"]` with items
//   `[data-item="<ptr>/<i>"]` numbered from 0 and renumbered on removal,
//   and the buttons `[data-action="add"][data-for="<ptr>"]` and
//   `[data-action="remove"][data-for="<ptr>/<i>"]`.
// - A closed set of tokens is `[data-path][data-kind="set"]` holding one
//   checkbox per token, whose `value` is the token.
// - A numbered `id` member of a list item has no control.
//
// The editor never rewrites what a person typed. It reads values only on
// save, and the server decides what is valid.

import { clearError, linkError } from "../core/a11y.js";
import { h } from "../core/dom.js";
import type { Label } from "../core/i18n.js";
import { parseAmount } from "../core/money.js";
import type { FieldDef, Member, Shape } from "./fields.js";
import { labelOr, t } from "./i18n.js";
import { canonicalJson, record } from "./model.js";

/** A value a person entered that the page cannot send, tied to its control. */
export interface Problem {
  readonly control: HTMLElement;
  readonly message: Label;
}

/** The outcome of reading an editor. */
export type Read = { readonly ok: true; readonly value: unknown } | { readonly ok: false; readonly problems: readonly Problem[] };

/** One built value editor. */
interface Node {
  readonly el: HTMLElement;
  read(): Read;
}

/** What every control of one editor shares. */
interface Ctx {
  /** The id prefix, an identifier. */
  readonly prefix: string;
  /** Marks the editor touched after an add or a removal. */
  readonly touch: () => void;
}

/** The control id of the leaf at `ptr`. */
function idOf(ctx: Ctx, ptr: string): string {
  return ptr === "" ? ctx.prefix : `${ctx.prefix}${ptr.split("/").join(".")}`;
}

/** The label of a member, from the catalogue. */
export function memberLabel(name: string): Label {
  return labelOr(`creator.member.${name}`, () => t.label("creator.member.unnamed", { name }));
}

/** The label of an option token, from the catalogue. */
export function optionLabel(token: string): Label {
  return labelOr(`creator.option.${token}`, () => t.label("creator.option.unnamed", { token }));
}

/** The label of a field, from the catalogue. */
export function fieldLabel(key: string): Label {
  return labelOr(`creator.field.${key}`, () => t.label("creator.field.unnamed", { key }));
}

/** The hint of a leaf kind, or null. */
function hintOf(shape: Shape): Label | null {
  switch (shape.t) {
    case "amount":
      return t.label("creator.hint.amount");
    case "date":
      return t.label("creator.hint.date");
    case "int":
      return t.label("creator.hint.int");
    default:
      return null;
  }
}

const INTEGER = /^-?(0|[1-9][0-9]{0,15})$/;

function ok(value: unknown): Read {
  return { ok: true, value };
}

function bad(control: HTMLElement, message: Label): Read {
  return { ok: false, problems: [{ control, message }] };
}

/** Joins member reads, collecting every problem. */
function all(reads: readonly Read[]): { readonly values: unknown[]; readonly problems: Problem[] } {
  const values: unknown[] = [];
  const problems: Problem[] = [];
  for (const r of reads) {
    if (r.ok) {
      values.push(r.value);
    } else {
      problems.push(...r.problems);
    }
  }
  return { values, problems };
}

/** A text-like leaf: text, amount, integer or date. */
function leaf(shape: Shape, value: unknown, ptr: string, label: Label, ctx: Ctx): Node {
  const id = idOf(ctx, ptr);
  const attrs: Record<string, string | boolean> = { id, "data-path": ptr };
  const hint = hintOf(shape);
  const hintId = `${id}.hint`;
  if (hint !== null) {
    attrs["aria-describedby"] = hintId;
  }
  if (shape.t === "amount" || shape.t === "int") {
    attrs["inputmode"] = shape.t === "amount" ? "decimal" : "numeric";
    attrs["autocomplete"] = "off";
    attrs["spellcheck"] = "false";
  }
  const long = shape.t === "text" && shape.long;
  // A value this editor cannot show as text, such as a stored narrative
  // reference, is shown read-only and kept as it is.
  const shown = value === null || value === undefined ? "" : typeof value === "string" ? value : typeof value === "number" ? String(value) : null;
  if (shown === null) {
    attrs["readonly"] = true;
  }
  const control = long ? h("textarea", { ...attrs, rows: "4" }) : h("input", { ...attrs, type: "text" });
  if (control instanceof HTMLTextAreaElement || control instanceof HTMLInputElement) {
    control.value = shown ?? (canonicalJson(value) ?? "");
  }
  const children: HTMLElement[] = [h("label", { for: id }, [label]), control];
  if (hint !== null) {
    children.push(h("p", { id: hintId, class: "fstp-hint" }, [hint]));
  }
  const el = h("div", { class: "fstp-control" }, children);
  return {
    el,
    read(): Read {
      if (shown === null) {
        return ok(value);
      }
      const text = control instanceof HTMLTextAreaElement || control instanceof HTMLInputElement ? control.value : "";
      if (text === "") {
        return ok(null);
      }
      if (shape.t === "int") {
        const n = Number(text);
        return INTEGER.test(text) && Number.isSafeInteger(n) ? ok(n) : bad(control, t.label("creator.problem.int"));
      }
      if (shape.t === "amount") {
        return parseAmount(text, "EUR").ok ? ok(text) : bad(control, t.label("creator.problem.amount"));
      }
      return ok(text);
    },
  };
}

function checkbox(value: unknown, ptr: string, label: Label, ctx: Ctx): Node {
  const id = idOf(ctx, ptr);
  const box = h("input", { id, type: "checkbox", "data-path": ptr, checked: value === true });
  const el = h("div", { class: "fstp-check" }, [box, h("label", { for: id }, [label])]);
  return {
    el,
    read(): Read {
      return ok(box instanceof HTMLInputElement ? box.checked : false);
    },
  };
}

function choice(options: readonly string[], value: unknown, ptr: string, label: Label, ctx: Ctx, extra?: () => void): Node {
  const id = idOf(ctx, ptr);
  const opts = [h("option", { value: "" }, [t.label("creator.value.unset")])];
  for (const o of options) {
    opts.push(h("option", { value: o, selected: value === o }, [optionLabel(o)]));
  }
  // A value outside the closed list stays visible, so it is never lost.
  if (typeof value === "string" && value !== "" && !options.includes(value)) {
    opts.push(h("option", { value, selected: true }, [optionLabel(value)]));
  }
  const select = h("select", { id, "data-path": ptr }, opts);
  if (extra !== undefined) {
    select.addEventListener("change", extra);
  }
  const el = h("div", { class: "fstp-control" }, [h("label", { for: id }, [label]), select]);
  return {
    el,
    read(): Read {
      const v = select instanceof HTMLSelectElement ? select.value : "";
      return ok(v === "" ? null : v);
    },
  };
}

function tokenSet(options: readonly string[], value: unknown, ptr: string, label: Label, ctx: Ctx): Node {
  const chosen = new Set(Array.isArray(value) ? (value as unknown[]).filter((x): x is string => typeof x === "string") : []);
  const boxes: HTMLInputElement[] = [];
  const items: HTMLElement[] = [];
  const offered = [...options, ...[...chosen].filter((c) => !options.includes(c))];
  offered.forEach((o, i) => {
    const id = `${idOf(ctx, ptr)}.set${i}`;
    const box = h("input", { id, type: "checkbox", value: o, checked: chosen.has(o) });
    if (box instanceof HTMLInputElement) {
      boxes.push(box);
    }
    items.push(h("div", { class: "fstp-check" }, [box, h("label", { for: id }, [optionLabel(o)])]));
  });
  const el = h("fieldset", { "data-path": ptr, "data-kind": "set", class: "fstp-group" }, [h("legend", {}, [label]), ...items]);
  return {
    el,
    read(): Read {
      return ok(boxes.filter((b) => b.checked).map((b) => b.value));
    },
  };
}

/** The first form control inside `el`, or null. */
export function firstControl(el: HTMLElement): HTMLElement | null {
  for (const c of Array.from(el.querySelectorAll("*"))) {
    if (c instanceof HTMLInputElement || c instanceof HTMLSelectElement || c instanceof HTMLTextAreaElement) {
      return c;
    }
  }
  return null;
}

/** The largest decimal `id` among `items`, or 0. */
function largestId(ids: readonly string[]): number {
  let n = 0;
  for (const id of ids) {
    if (/^[1-9][0-9]{0,8}$/.test(id)) {
      n = Math.max(n, Number(id));
    }
  }
  return n;
}

function listOf(item: Shape, value: unknown, ptr: string, label: Label, ctx: Ctx): Node {
  const values: unknown[] = Array.isArray(value) ? [...(value as unknown[])] : [];
  // The numbered ids of keyed items. A loaded item keeps its id.
  const ids: string[] = values.map((v, i) => {
    const id = record(v)?.["id"];
    return typeof id === "string" ? id : String(i + 1);
  });
  let nodes: Node[] = [];
  const box = h("div", { class: "fstp-items" });
  const add = h("button", { type: "button", "data-action": "add", "data-for": ptr }, [t.label("creator.list.add", { field: label })]);
  const el = h("fieldset", { "data-path": ptr, "data-kind": "list", class: "fstp-group" }, [h("legend", {}, [label]), box, add]);

  /** The current values of the items, as their controls hold them. */
  const current = (): unknown[] => nodes.map((n, i) => {
    const r = n.read();
    return r.ok ? r.value : values[i];
  });

  const render = (): void => {
    nodes = values.map((v, i) => {
      const n = String(i + 1);
      const at = `${ptr}/${i}`;
      const node = build(item, v, at, t.label("creator.list.item", { field: label, n }), ctx, n, ids[i] ?? n);
      return node;
    });
    box.replaceChildren(
      ...nodes.map((node, i) => {
        const at = `${ptr}/${i}`;
        const remove = h("button", { type: "button", "data-action": "remove", "data-for": at }, [
          t.label("creator.list.remove", { field: label, n: String(i + 1) }),
        ]);
        remove.addEventListener("click", () => {
          const kept = current();
          kept.splice(i, 1);
          ids.splice(i, 1);
          values.splice(0, values.length, ...kept);
          ctx.touch();
          render();
          add.focus();
        });
        return h("div", { "data-item": at, class: "fstp-item" }, [node.el, remove]);
      }),
    );
  };

  add.addEventListener("click", () => {
    const kept = current();
    values.splice(0, values.length, ...kept, null);
    ids.push(String(largestId(ids) + 1));
    ctx.touch();
    render();
    const last = box.lastElementChild;
    const first = last instanceof HTMLElement ? firstControl(last) : null;
    first?.focus();
  });
  render();
  return {
    el,
    read(): Read {
      const { values: vs, problems } = all(nodes.map((n) => n.read()));
      return problems.length > 0 ? { ok: false, problems } : ok(vs);
    },
  };
}

function members(list: readonly Member[], value: unknown, ptr: string, ctx: Ctx, item: string | null, id: string | null): Node[] {
  const o = record(value);
  return list.map((x) => {
    if (x.auto) {
      const fixed = id;
      return {
        el: h("span", { hidden: true }),
        read: (): Read => ok(fixed),
      };
    }
    const label = item === null ? memberLabel(x.name) : t.label("creator.list.member", { member: memberLabel(x.name), n: item });
    return build(x.shape, o === null ? null : (o[x.name] ?? null), `${ptr}/${x.name}`, label, ctx, item, null);
  });
}

function objectOf(
  shape: Extract<Shape, { t: "object" }>,
  value: unknown,
  ptr: string,
  label: Label,
  ctx: Ctx,
  item: string | null,
  id: string | null,
): Node {
  const nodes = members(shape.members, value, ptr, ctx, item, id);
  const el = h("fieldset", { class: "fstp-group" }, [h("legend", {}, [label]), ...nodes.map((n) => n.el)]);
  return {
    el,
    read(): Read {
      const { values, problems } = all(nodes.map((n) => n.read()));
      if (problems.length > 0) return { ok: false, problems };
      const out: Record<string, unknown> = {};
      let any = false;
      shape.members.forEach((x, i) => {
        const v = values[i] ?? null;
        if (!x.auto && v !== null) any = true;
        if (!shape.sparse || v !== null) out[x.name] = v;
      });
      return ok(any ? out : null);
    },
  };
}

function taggedOf(
  shape: Extract<Shape, { t: "tagged" }>,
  value: unknown,
  ptr: string,
  label: Label,
  ctx: Ctx,
  item: string | null,
): Node {
  const o = record(value);
  const kindLabel = item === null ? memberLabel("kind") : t.label("creator.list.member", { member: memberLabel("kind"), n: item });
  const area = h("div", { class: "fstp-variant" });
  let nodes: Node[] = [];
  let kind = typeof o?.["kind"] === "string" ? (o["kind"] as string) : "";
  const fill = (from: unknown): void => {
    const v = shape.variants.find((x) => x.kind === kind);
    nodes = v === undefined ? [] : members(v.members, from, ptr, ctx, item, null);
    area.replaceChildren(...nodes.map((n) => n.el));
  };
  const select = choice(
    shape.variants.map((v) => v.kind),
    kind,
    `${ptr}/kind`,
    kindLabel,
    ctx,
    () => {
      const s = select.el.querySelector("select");
      kind = s instanceof HTMLSelectElement ? s.value : "";
      fill(null);
    },
  );
  fill(value);
  const el = h("fieldset", { class: "fstp-group" }, [h("legend", {}, [label]), select.el, area]);
  return {
    el,
    read(): Read {
      if (kind === "") return ok(null);
      const v = shape.variants.find((x) => x.kind === kind);
      const { values, problems } = all(nodes.map((n) => n.read()));
      if (problems.length > 0) return { ok: false, problems };
      const out: Record<string, unknown> = { kind };
      (v?.members ?? []).forEach((x, i) => {
        out[x.name] = values[i] ?? null;
      });
      return ok(out);
    },
  };
}

/**
 * Builds the editor of `shape` at `ptr`. `item` is the number of the
 * list item the editor sits in, for its labels, and `id` the numbered id
 * of that item.
 */
function build(shape: Shape, value: unknown, ptr: string, label: Label, ctx: Ctx, item: string | null, id: string | null): Node {
  switch (shape.t) {
    case "text":
    case "amount":
    case "int":
    case "date":
      return leaf(shape, value, ptr, label, ctx);
    case "bool":
      return checkbox(value, ptr, label, ctx);
    case "enum":
      return choice(shape.options, value, ptr, label, ctx);
    case "set":
      return tokenSet(shape.options, value, ptr, label, ctx);
    case "list":
      return listOf(shape.item, value, ptr, label, ctx);
    case "object":
      return objectOf(shape, value, ptr, label, ctx, item, id);
    case "tagged":
      return taggedOf(shape, value, ptr, label, ctx, item);
  }
}

/** One built field editor. */
export interface FieldEditor {
  /** The field's element, `[data-field="<key>"]` when built with `mark`. */
  readonly root: HTMLElement;
  /** Where a page adds notes and actions of the field, after its controls. */
  readonly notes: HTMLElement;
  /** Reads the value, or the problems of the values a person entered. */
  read(): Read;
  /** Whether a person changed a control since the editor was built. */
  touched(): boolean;
  /** The canonical text of the value the editor was built with. */
  readonly initial: string;
}

/**
 * The editor of field `def`, showing `value`. With `mark`, its root
 * carries `data-field` with the field key. `prefix` makes its control ids
 * unique on the page and must be an identifier.
 */
export function fieldEditor(def: FieldDef, value: unknown, opts: { readonly mark: boolean; readonly prefix: string }): FieldEditor {
  let touched = false;
  const ctx: Ctx = {
    prefix: opts.prefix,
    touch: () => {
      touched = true;
    },
  };
  const node = build(def.shape, value, "", fieldLabel(def.key), ctx, null, null);
  const notes = h("div", { class: "fstp-notes" });
  const attrs: Record<string, string> = { class: "fstp-field" };
  if (opts.mark) {
    attrs["data-field"] = def.key;
  }
  const root = h("div", attrs, [node.el, notes]);
  root.addEventListener("input", ctx.touch);
  root.addEventListener("change", ctx.touch);
  return {
    root,
    notes,
    read: () => node.read(),
    touched: () => touched,
    initial: canonicalJson(value) ?? "",
  };
}

/** The error elements shown for problems, by control. */
const shownErrors = new Map<HTMLElement, HTMLElement>();

/** Removes every problem shown under `scope`. */
export function clearProblems(scope: HTMLElement): void {
  for (const [control, error] of shownErrors) {
    if (scope.contains(control)) {
      clearError(control, error);
      error.remove();
      shownErrors.delete(control);
    }
  }
}

/** Shows each problem under its control, linked to it, and focuses the first. */
export function showProblems(problems: readonly Problem[]): void {
  problems.forEach((p, i) => {
    const id = `${p.control.id}.error`;
    const error = h("p", { id, class: "fstp-field-error" }, [p.message]);
    p.control.parentElement?.append(error);
    linkError(p.control, error);
    shownErrors.set(p.control, error);
    if (i === 0) {
      p.control.focus();
    }
  });
}
