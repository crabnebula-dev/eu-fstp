// The reference increment check of the ADR-016 differential target.
//
// It restates step 4 of M5 design section 3.1 at the byte level, without
// the vendored parser: an increment holds exactly one new signature
// dictionary and the party's field object with `/V` added, then one xref
// section and a trailer whose `/Prev` and `/Root` match the revision. The
// Rust increment verifier of fstp-pdf (lane L-PDF) is the authority. This
// check stands in for it until that verifier reads the shared corpus
// web/fuzz/seeds/pdf_prepare_differential/expect.tsv.
//
// PDFs are byte strings, one code unit per byte (pdf_fixture.ts).

/** The previous revision's xref offset, size, root and ID, or a reason. */
interface Tail {
  readonly startxref: number;
  readonly size: number;
  readonly root: string;
  readonly id: string | null;
}

/** PDF white-space: NUL, tab, line feed, form feed, carriage return and space. */
const WS = /[\u0000\t\n\f\r ]+/g;

/** The /ID of a trailer body, as upper-case hex strings joined by spaces, null when absent, or a reason. */
function idOf(body: string): string | null | { readonly reason: string } {
  const at = body.indexOf("/ID");
  if (at < 0) {
    return null;
  }
  const m = /^\/ID ?\[((?: ?<[0-9A-Fa-f ]*>)*) ?\]/.exec(body.slice(at));
  if (m === null) {
    return { reason: "the revision's /ID is not an array of hex strings" };
  }
  const strings = (m[1] ?? "").match(/<[0-9A-Fa-f ]*>/g) ?? [];
  return strings
    .map((h) => {
      const hex = h.slice(1, -1).replace(/ /g, "").toUpperCase();
      return hex.length % 2 === 0 ? hex : `${hex}0`;
    })
    .join(" ");
}

/**
 * The previous revision's xref offset, size, root and ID, or the reason
 * the revision is outside the server shape this reference reads.
 */
export function refRevisionTail(revision: string): Tail | string {
  const m = /startxref[ \t\r\n]+(\d{1,10})[ \t\r\n]+%%EOF[ \t\r\n]*$/.exec(revision);
  if (m === null) {
    return "the revision does not end with startxref and %%EOF";
  }
  const startxref = Number(m[1]);
  const t = /^xref[\s\S]*?trailer[\u0000\t\n\f\r ]*<<([\s\S]*?)>>[\u0000\t\n\f\r ]*startxref/.exec(revision.slice(startxref));
  if (t === null) {
    return "the revision's startxref names no xref table and trailer";
  }
  const body = (t[1] ?? "").replace(WS, " ");
  const size = /\/Size (\d{1,10})/.exec(body);
  const root = /\/Root (\d{1,10} \d{1,5} R)/.exec(body);
  const id = idOf(body);
  if (size === null || root === null) {
    return "the revision's trailer has no /Size or /Root";
  }
  if (id !== null && typeof id === "object") {
    return id.reason;
  }
  return { startxref, size: Number(size[1]), root: root[1] ?? "", id };
}

const SIG_DICT =
  /^<<\s*\/Type\s*\/Sig\s*\/Filter\s*\/Adobe\.PPKLite\s*\/SubFilter\s*\/ETSI\.CAdES\.detached\s*\/ByteRange\s*\[\s*0\s+(\d{1,10})\s+(\d{1,10})\s+(\d{1,10})\s*\]\s*\/Contents\s*<(0+)>\s*>>$/;

/**
 * Null when `increment` is the one increment that step 4 accepts for the
 * party field named `field` of `revision`, or the reason it is not.
 */
export function refCheckIncrement(revision: string, increment: string, field: string): string | null {
  const tail = refRevisionTail(revision);
  if (typeof tail === "string") {
    return tail;
  }
  const full = revision + increment;
  const endsWithEol = revision.endsWith("\n") || revision.endsWith("\r");
  let at = revision.length;
  if (!endsWithEol) {
    if (full[at] !== "\n") {
      return "no line feed before the increment of a revision that does not end with one";
    }
    at += 1;
  }
  const objects: { num: number; body: string; offset: number }[] = [];
  for (;;) {
    const head = /^(\d{1,10}) 0 obj\n/.exec(full.slice(at));
    if (head === null) {
      break;
    }
    const start = at + head[0].length;
    const end = full.indexOf("\nendobj\n", start);
    if (end < 0) {
      return "an object of the increment does not end";
    }
    objects.push({ num: Number(head[1]), body: full.slice(start, end), offset: at });
    at = end + "\nendobj\n".length;
  }
  if (objects.length !== 2) {
    return `the increment holds ${objects.length} objects, not 2`;
  }
  const sig = objects.find((o) => o.num >= tail.size);
  const fieldObj = objects.find((o) => o.num < tail.size && o.num > 0);
  if (sig === undefined || fieldObj === undefined) {
    return "the increment does not hold one new object and one existing object";
  }
  const s = SIG_DICT.exec(sig.body);
  if (s === null) {
    return `the new object is not the signature dictionary: ${JSON.stringify(sig.body.slice(0, 200))}`;
  }
  const escaped = field.replace(/[\\()]/g, (c) => `\\${c}`);
  if (!fieldObj.body.includes(`/T (${escaped})`) || !/\/FT\s*\/Sig\b/.test(fieldObj.body)) {
    return "the changed object is not the party's signature field";
  }
  if (!new RegExp(`/V\\s+${sig.num}\\s+0\\s+R\\b`).test(fieldObj.body)) {
    return "the field's /V does not name the new signature dictionary";
  }
  // One xref section covering exactly the two objects, at their offsets.
  const xrefAt = at;
  const x = /^xref\n((?:\d{1,10} \d{1,10}\n(?:\d{10} \d{5} [nf]\r\n)+)+)trailer\n<<([\s\S]*?)>>\nstartxref\n(\d{1,10})\n%%EOF\n$/.exec(full.slice(at));
  if (x === null) {
    return "the increment does not end with one xref table, a trailer, startxref and %%EOF";
  }
  const covered = new Map<number, number>();
  const lines = (x[1] ?? "").split("\n");
  for (let i = 0; i < lines.length; ) {
    const sub = /^(\d+) (\d+)$/.exec(lines[i] ?? "");
    if (sub === null) {
      break;
    }
    const first = Number(sub[1]);
    const count = Number(sub[2]);
    for (let k = 0; k < count; k += 1) {
      const e = /^(\d{10}) 00000 n\r$/.exec(lines[i + 1 + k] ?? "");
      if (e === null) {
        return "an xref entry of the increment is not an in-use generation 0 entry";
      }
      covered.set(first + k, Number(e[1]));
    }
    i += 1 + count;
  }
  if (covered.size !== 2 || covered.get(sig.num) !== sig.offset || covered.get(fieldObj.num) !== fieldObj.offset) {
    return "the xref section does not give exactly the two objects at their offsets";
  }
  if (Number(x[3]) !== xrefAt) {
    return "startxref does not name the increment's xref section";
  }
  const trailer = (x[2] ?? "").replace(WS, " ");
  const size = /\/Size (\d{1,10})/.exec(trailer);
  const root = /\/Root (\d{1,10} \d{1,5} R)/.exec(trailer);
  const prev = /\/Prev (\d{1,10})/.exec(trailer);
  const id = idOf(trailer);
  if (size === null || Number(size[1]) !== Math.max(tail.size, sig.num + 1)) {
    return "the trailer /Size is not the new object count";
  }
  if (root === null || root[1] !== tail.root) {
    return "the trailer /Root changed";
  }
  if (prev === null || Number(prev[1]) !== tail.startxref) {
    return "the trailer /Prev does not name the revision's xref";
  }
  if (id !== tail.id) {
    return "the trailer /ID changed";
  }
  // /ByteRange covers every byte except the /Contents hex string.
  const length1 = Number(s[1]);
  const offset2 = Number(s[2]);
  const length2 = Number(s[3]);
  const lt = full.indexOf("<", full.indexOf("/Contents", sig.offset));
  const gt = full.indexOf(">", lt);
  if (length1 !== lt || offset2 !== gt + 1 || offset2 + length2 !== full.length || lt < revision.length) {
    return `/ByteRange [0 ${length1} ${offset2} ${length2}] does not cover every byte except /Contents at ${lt}..${gt}`;
  }
  return null;
}
