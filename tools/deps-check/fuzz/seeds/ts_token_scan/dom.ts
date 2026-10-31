import { safeUrl } from "./url.js";
import type { Operation } from "../gen/api.js";

/** Builds an element with allowlisted attributes. */
export function h(tag: string, attrs: Record<string, string>, children: Node[]): HTMLElement {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    el.setAttribute(k, k === "href" ? safeUrl(v) : v);
  }
  el.append(...children);
  const re = /^[a-z]+$/i;
  const total = `${children.length} of ${re.source}`;
  el.textContent = total;
  return el;
}
