// Independent reference for catalogue message placeholders (R-NF-04),
// following the interim grammar in support/contract.ts, pending Daniel and
// `fstp_html::parse_message_format` (lane W1d).

import type { MessagePart } from "../support/contract.js";

const NAME = /^[a-z][a-z0-9_]{0,63}$/;

/** The parts of `text`, or the offset of the first refused character. */
export function refParseMessage(
  text: string,
): { readonly ok: true; readonly parts: readonly MessagePart[] } | { readonly ok: false; readonly offset: number } {
  const parts: MessagePart[] = [];
  let buf = "";
  const flush = (): void => {
    if (buf !== "") {
      parts.push({ kind: "text", text: buf });
      buf = "";
    }
  };
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === "{") {
      if (text[i + 1] === "{") {
        buf += "{";
        i += 2;
        continue;
      }
      const close = text.indexOf("}", i + 1);
      if (close < 0) {
        return { ok: false, offset: i };
      }
      const name = text.slice(i + 1, close);
      if (!NAME.test(name)) {
        return { ok: false, offset: i };
      }
      flush();
      parts.push({ kind: "placeholder", name });
      i = close + 1;
      continue;
    }
    if (c === "}") {
      if (text[i + 1] === "}") {
        buf += "}";
        i += 2;
        continue;
      }
      return { ok: false, offset: i };
    }
    buf += c;
    i += 1;
  }
  flush();
  return { ok: true, parts };
}

/** Writes parts back as message text, escaping literal braces. */
export function refWriteMessage(parts: readonly MessagePart[]): string {
  return parts
    .map((p) => (p.kind === "text" ? p.text.replace(/\{/g, "{{").replace(/\}/g, "}}") : `{${p.name}}`))
    .join("");
}

/** The formatted text: placeholders replaced by their argument, as text. */
export function refFormat(parts: readonly MessagePart[], args: Readonly<Record<string, string>>): string {
  return parts.map((p) => (p.kind === "text" ? p.text : (args[p.name] ?? ""))).join("");
}

/** The placeholder names of a message, sorted and without repeats. */
export function placeholderNames(parts: readonly MessagePart[]): string[] {
  const names = new Set<string>();
  for (const p of parts) {
    if (p.kind === "placeholder") {
      names.add(p.name);
    }
  }
  return [...names].sort();
}
