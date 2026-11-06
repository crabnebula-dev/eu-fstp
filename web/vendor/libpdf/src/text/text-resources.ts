/**
 * TextResources - Fonts and form XObjects reachable from a /Resources dict.
 *
 * Fonts are parsed on first use and cached by dictionary identity across a
 * page and its forms. A form without its own /Resources inherits those of the
 * invoking stream (deprecated by the spec, relied on by producers).
 */

import { parseFont } from "../fonts/font-factory.js";
import type { PdfFont } from "../fonts/pdf-font.js";
import { parseToUnicode, type ToUnicodeMap } from "../fonts/to-unicode.js";
import { Matrix } from "../helpers/matrix.js";
import type { RefResolver } from "../helpers/types.js";
import { PdfArray } from "../objects/pdf-array.js";
import { PdfDict } from "../objects/pdf-dict.js";
import { PdfNumber } from "../objects/pdf-number.js";
import { PdfStream } from "../objects/pdf-stream.js";

export interface FormXObject {
  /** Identity is used to detect recursion */
  stream: PdfStream;
  content: Uint8Array;
  matrix: Matrix;
  resources: TextResources;
}

export class TextResources {
  private readonly forms = new Map<string, FormXObject | null>();

  constructor(
    private readonly dict: PdfDict | null,
    private readonly resolve: RefResolver,
    private readonly fontCache: Map<PdfDict, PdfFont> = new Map(),
  ) {}

  getFont(name: string): PdfFont | null {
    const entry = this.lookup("Font", name);

    if (!(entry instanceof PdfDict)) {
      return null;
    }

    let font = this.fontCache.get(entry);

    if (!font) {
      font = parseFont(entry, {
        resolver: this.resolve,
        toUnicodeMap: this.parseToUnicode(entry),
      });
      this.fontCache.set(entry, font);
    }

    return font;
  }

  /** Null for image XObjects and unknown names. */
  getForm(name: string): FormXObject | null {
    let form = this.forms.get(name);

    if (form === undefined) {
      form = this.loadForm(name);
      this.forms.set(name, form);
    }

    return form;
  }

  private loadForm(name: string): FormXObject | null {
    const stream = this.lookup("XObject", name);

    if (!(stream instanceof PdfStream)) {
      return null;
    }

    if (stream.getName("Subtype", this.resolve)?.value !== "Form") {
      return null;
    }

    let content: Uint8Array;

    try {
      content = stream.getDecodedData();
    } catch {
      // Undecodable form: treat as absent rather than losing the page
      return null;
    }

    const ownResources = stream.getDict("Resources", this.resolve);

    return {
      stream,
      content,
      matrix: readMatrix(stream.getArray("Matrix", this.resolve), this.resolve),
      resources: ownResources
        ? new TextResources(ownResources, this.resolve, this.fontCache)
        : this,
    };
  }

  private lookup(category: string, name: string) {
    return this.dict?.getDict(category, this.resolve)?.get(name, this.resolve);
  }

  private parseToUnicode(fontDict: PdfDict): ToUnicodeMap | null {
    const stream = fontDict.get("ToUnicode", this.resolve);

    if (!(stream instanceof PdfStream)) {
      return null;
    }

    try {
      return parseToUnicode(stream.getDecodedData());
    } catch {
      return null;
    }
  }
}

function readMatrix(array: PdfArray | undefined, resolve: RefResolver): Matrix {
  if (!(array instanceof PdfArray) || array.length !== 6) {
    return Matrix.identity();
  }

  const values: number[] = [];

  for (let i = 0; i < 6; i++) {
    const item = array.at(i, resolve);

    if (!(item instanceof PdfNumber)) {
      return Matrix.identity();
    }

    values.push(item.value);
  }

  return Matrix.fromArray(values);
}
