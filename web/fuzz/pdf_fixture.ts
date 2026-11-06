// Synthetic PDF revisions for the ADR-016 tests and fuzz targets.
//
// Each builder writes a small revision 0 in the shape that fstp-pdf
// renders (M5 design section 3.1, step 1): classic xref table, no object
// streams, no xref streams, no filters on structural objects, and one
// empty signature field per party. Synthetic data only: the parties are
// `party-1` and `party-2`, and the page holds no text.
//
// A PDF is held as a string of code units 0 to 255, one per byte, so the
// in-house harness can mutate it and the corpus can store it as a JSON
// string. `toBytes` and `fromBytes` convert.

/** One indirect object of a builder: its number and the text between `obj` and `endobj`. */
export interface FixtureObject {
  readonly num: number;
  readonly body: string;
}

/** Bytes of a byte string. Code units above 255 keep their low byte. */
export function toBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i += 1) {
    out[i] = s.charCodeAt(i) & 0xff;
  }
  return out;
}

/** The byte string of `bytes`. */
export function fromBytes(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 1) {
    s += String.fromCharCode(bytes[i] ?? 0);
  }
  return s;
}

function pad(n: number, width: number): string {
  return String(n).padStart(width, "0");
}

/** A revision from `header`, `objects` in order, and the extra trailer entries. */
export function assemble(objects: readonly FixtureObject[], trailerExtra = "", header = "%PDF-1.7\n%âãÏÓ\n"): string {
  let out = header;
  const offsets = new Map<number, number>();
  for (const o of objects) {
    offsets.set(o.num, out.length);
    out += `${o.num} 0 obj\n${o.body}\nendobj\n`;
  }
  const size = Math.max(0, ...objects.map((o) => o.num)) + 1;
  const xref = out.length;
  out += `xref\n0 ${size}\n0000000000 65535 f\r\n`;
  for (let n = 1; n < size; n += 1) {
    const at = offsets.get(n);
    out += at === undefined ? "0000000000 00000 f\r\n" : `${pad(at, 10)} 00000 n\r\n`;
  }
  out += `trailer\n<< /Size ${size} /Root 1 0 R${trailerExtra} >>\nstartxref\n${xref}\n%%EOF\n`;
  return out;
}

const APPEARANCE = "q 0.9 g 0 0 200 50 re f Q";

/** The objects of a two-party contract with empty signature fields 4 and 5. */
export function contractObjects(): FixtureObject[] {
  return [
    { num: 1, body: "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R 5 0 R] /SigFlags 3 >> >>" },
    { num: 2, body: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>" },
    { num: 3, body: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Annots [4 0 R 5 0 R] >>" },
    {
      num: 4,
      body: "<< /Type /Annot /Subtype /Widget /FT /Sig /T (party-1) /F 132 /P 3 0 R /Rect [50 50 250 100] /AP << /N 6 0 R >> >>",
    },
    {
      num: 5,
      body: "<< /Type /Annot /Subtype /Widget /FT /Sig /T (party-2) /F 132 /P 3 0 R /Rect [300 50 500 100] /AP << /N 6 0 R >> >>",
    },
    {
      num: 6,
      body: `<< /Type /XObject /Subtype /Form /BBox [0 0 200 50] /Length ${APPEARANCE.length} >>\nstream\n${APPEARANCE}\nendstream`,
    },
  ];
}

const FILE_ID = " /ID [<0123456789ABCDEF0123456789ABCDEF> <0123456789ABCDEF0123456789ABCDEF>]";

/** A valid two-party revision 0. */
export function contractRevision(): string {
  return assemble(contractObjects(), FILE_ID);
}

/** Revision 0 with a trailer `/Encrypt` dictionary (refused). */
export function encryptedRevision(): string {
  const objects = [
    ...contractObjects(),
    { num: 7, body: "<< /Filter /Standard /V 2 /R 3 /Length 128 /P -4 /O <00> /U <00> >>" },
  ];
  return assemble(objects, `${FILE_ID} /Encrypt 7 0 R`);
}

/** Revision 0 holding an object stream (refused). */
export function objectStreamRevision(): string {
  const data = "8 0 << /Kind /Hidden >>";
  const objects = [
    ...contractObjects(),
    { num: 7, body: `<< /Type /ObjStm /N 1 /First 4 /Length ${data.length} >>\nstream\n${data}\nendstream` },
  ];
  return assemble(objects, FILE_ID);
}

/** Revision 0 with a FlateDecode structural object stream (refused). */
export function flateObjectStreamRevision(): string {
  const data = "x\u009c\u0003\u0000\u0000\u0000\u0000\u0001";
  const objects = [
    ...contractObjects(),
    {
      num: 7,
      body: `<< /Type /ObjStm /N 0 /First 0 /Filter /FlateDecode /Length ${data.length} >>\nstream\n${data}\nendstream`,
    },
  ];
  return assemble(objects, FILE_ID);
}

/** Revision 0 whose cross-reference section is an xref stream (refused). */
export function xrefStreamRevision(): string {
  const base = contractRevision();
  const at = base.indexOf("xref\n");
  const head = base.slice(0, at);
  const data = "\u0000\u0000\u0000";
  return `${head}7 0 obj\n<< /Type /XRef /Size 8 /W [1 1 1] /Root 1 0 R /Length ${data.length} >>\nstream\n${data}\nendstream\nendobj\nstartxref\n${at}\n%%EOF\n`;
}

/** Revision 0 with a trailer `/Prev` pointing at its own xref (a loop, refused). */
export function prevLoopRevision(): string {
  const base = contractRevision();
  const xref = base.lastIndexOf("startxref\n");
  const offset = base.slice(xref + 10).split("\n")[0] ?? "0";
  return base.replace(" /Root 1 0 R", ` /Root 1 0 R /Prev ${offset}`);
}

/** Revision 0 whose page dictionary nests arrays `depth` deep. */
export function deepRevision(depth: number): string {
  const objects = contractObjects().map((o) =>
    o.num === 3 ? { num: 3, body: `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Annots [4 0 R 5 0 R] /Deep ${"[".repeat(depth)}${"]".repeat(depth)} >>` } : o,
  );
  return assemble(objects, FILE_ID);
}
