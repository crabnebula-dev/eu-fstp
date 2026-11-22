// The logo controls of the tenant admin's branding page (ADR-030; I-68,
// R-WL-03): the organisation's logo and each programme's, in light and
// dark mode.
//
// For each slot the admin sees the logo in force on the light and the
// dark header, picks a file, sees it on both headers at once, reads a
// plain message when the file cannot be used, and saves it with one
// button (`tenant.branding.set_logo`, which asks for a step-up). The
// preview is drawn on a canvas from the browser's own decoding, so no
// `blob:` image and no tenant markup reach the page.

import { h, type Child } from "../../core/dom.js";
import type { I18n, Label } from "../../core/i18n.js";
import { act, anyObject, buttonEl, section } from "../../grant/kit.js";
import { readOp, type Frame, type PageEnv } from "../../reviewer/kit.js";
import {
  HEADER,
  type LogoMode,
  type LogoProblem,
  type LogosView,
  type StoredLogo,
  decodeLogos,
  fileProblem,
  logoBody,
  logoContrast,
  lowContrast,
  sizeOk,
  sniff,
  toBase64,
} from "./logos.js";

const MODES: readonly LogoMode[] = ["light", "dark"];

/** The widest preview, in CSS pixels. */
const PREVIEW_WIDTH = 240;
/** The preview height, as the top bar draws a logo. */
const PREVIEW_HEIGHT = 32;

/** One decoded, checked file. */
interface Chosen {
  readonly bytes: Uint8Array;
  readonly bitmap: ImageBitmap;
}

/** The logo in force, on the light and the dark header. */
function current(t: I18n, logo: StoredLogo | null): Child[] {
  if (logo === null) {
    return [h("p", { class: "logo-none" }, [t.label("admin.branding.logos.none")])];
  }
  const out: Child[] = [
    h(
      "div",
      { class: "logo-previews" },
      MODES.map((m) =>
        h("div", { class: `logo-swatch logo-swatch--${m}` }, [h("img", { src: logo.path, alt: "", class: "logo-preview" })]),
      ),
    ),
  ];
  if (!logo.pdf) {
    out.push(h("p", { class: "text-sm" }, [t.label("admin.branding.logos.no_pdf")]));
  }
  if (!logo.email) {
    out.push(h("p", { class: "text-sm" }, [t.label("admin.branding.logos.no_email")]));
  }
  return out;
}

/** Draws `bitmap` scaled into a canvas on the header colour of `mode`, and returns its contrast there. */
function draw(bitmap: ImageBitmap, mode: LogoMode): { readonly canvas: HTMLElement; readonly contrast: number } {
  const scale = Math.min(PREVIEW_HEIGHT / bitmap.height, PREVIEW_WIDTH / bitmap.width);
  const w = Math.max(1, Math.round(bitmap.width * scale));
  const hgt = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = h("canvas", { width: String(w), height: String(hgt), class: "logo-preview", "aria-hidden": "true" });
  let contrast = 1;
  if (canvas instanceof HTMLCanvasElement) {
    const ctx = canvas.getContext("2d");
    if (ctx !== null) {
      // The contrast reads the logo alone, then the header goes under it.
      ctx.drawImage(bitmap, 0, 0, w, hgt);
      contrast = logoContrast(ctx.getImageData(0, 0, w, hgt).data, HEADER[mode]);
      ctx.globalCompositeOperation = "destination-over";
      const [r, g, b] = HEADER[mode];
      ctx.fillStyle = `rgb(${r}, ${g}, ${b})`;
      ctx.fillRect(0, 0, w, hgt);
    }
  }
  return { canvas, contrast };
}

/** Reads and checks `file`, or names its problem. */
async function choose(file: File): Promise<Chosen | LogoProblem> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const problem = fileProblem(bytes.length, sniff(bytes));
  if (problem !== null) {
    return problem;
  }
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(new Blob([bytes]));
  } catch {
    return "unreadable";
  }
  if (!sizeOk(bitmap.width, bitmap.height)) {
    return "dimensions";
  }
  return { bytes, bitmap };
}

/** The control of one slot: the logo in force, a file picker, the preview, and save and remove. */
function slot(
  env: PageEnv,
  t: I18n,
  f: Frame,
  programme: string | null,
  mode: LogoMode,
  logo: StoredLogo | null,
  refresh: () => Promise<void>,
): HTMLElement {
  const id = `logo-${programme ?? "tenant"}-${mode}`;
  const input = h("input", { type: "file", id, accept: "image/png,image/webp" });
  const preview = h("div", { class: "logo-chosen", "aria-live": "polite" });
  const save = buttonEl(`${id}-save`, "button", t.label("admin.branding.logos.save"));
  save.className = "fstp-primary";
  save.disabled = true;
  let chosen: Chosen | null = null;
  input.addEventListener("change", () => {
    const file = input instanceof HTMLInputElement ? (input.files?.[0] ?? null) : null;
    chosen = null;
    save.disabled = true;
    preview.replaceChildren();
    if (file === null) {
      return;
    }
    void choose(file).then((c) => {
      if (typeof c === "string") {
        preview.replaceChildren(h("p", { class: "fstp-error", role: "alert" }, [t.label(`admin.branding.logos.${c}`)]));
        return;
      }
      chosen = c;
      save.disabled = false;
      const drawn = MODES.map((m) => ({ m, ...draw(c.bitmap, m) }));
      const notes: Child[] = [];
      for (const d of drawn) {
        if (lowContrast(d.contrast)) {
          notes.push(h("p", { class: "text-sm" }, [t.label(`admin.branding.logos.low_contrast_${d.m}`)]));
        }
      }
      if (sniff(c.bytes) === "webp") {
        notes.push(h("p", { class: "text-sm" }, [t.label("admin.branding.logos.no_email")]));
      }
      preview.replaceChildren(
        h("p", {}, [t.label("admin.branding.logos.preview")]),
        h(
          "div",
          { class: "logo-previews" },
          drawn.map((d) => h("div", { class: `logo-swatch logo-swatch--${d.m}` }, [d.canvas])),
        ),
        ...notes,
      );
    });
  });
  const send = async (image: string | null, done: Label): Promise<void> => {
    f.clearAlert();
    const r = await act(env, "tenant.branding.set_logo", {}, logoBody(mode, programme, image), anyObject);
    if (!r.ok) {
      if (r.problem.kind === "refused" && r.problem.rule === "I-68") {
        f.alert(t.label("admin.branding.logos.refused"));
      } else {
        f.problem(r.problem);
      }
      return;
    }
    f.status(done);
    await refresh();
  };
  save.addEventListener("click", () => {
    if (chosen === null) {
      return;
    }
    save.disabled = true;
    void send(toBase64(chosen.bytes), t.label("admin.branding.logos.saved")).finally(() => {
      save.disabled = chosen === null;
    });
  });
  const controls: Child[] = [
    h("label", { for: id }, [t.label("admin.branding.logos.choose")]),
    input,
    preview,
    save,
  ];
  if (logo !== null) {
    const remove = buttonEl(`${id}-remove`, "button", t.label("admin.branding.logos.remove"));
    remove.addEventListener("click", () => {
      remove.disabled = true;
      void send(null, t.label("admin.branding.logos.removed")).finally(() => {
        remove.disabled = false;
      });
    });
    controls.push(remove);
  }
  return h("div", { class: "logo-slot", "data-slot": id }, [
    h("h4", {}, [t.label(`admin.branding.logos.${mode}`)]),
    ...current(t, logo),
    ...controls,
  ]);
}

/** One owner's light and dark slots. */
function owner(
  env: PageEnv,
  t: I18n,
  f: Frame,
  title: Label,
  programme: string | null,
  light: StoredLogo | null,
  dark: StoredLogo | null,
  refresh: () => Promise<void>,
): HTMLElement {
  return h("div", { class: "logo-owner" }, [
    h("h3", {}, [title]),
    slot(env, t, f, programme, "light", light, refresh),
    slot(env, t, f, programme, "dark", dark, refresh),
  ]);
}

/** The body of the section for the logos in force. */
function body(env: PageEnv, t: I18n, f: Frame, v: LogosView, refresh: () => Promise<void>): Child[] {
  return [
    h("p", {}, [t.label("admin.branding.logos.intro")]),
    owner(env, t, f, t.label("admin.branding.logos.tenant"), null, v.tenant.light, v.tenant.dark, refresh),
    ...v.programmes.map((p) =>
      owner(env, t, f, t.label("admin.branding.logos.programme", { name: p.name }), p.programme, p.light, p.dark, refresh),
    ),
    h("p", { class: "text-sm" }, [t.label("admin.branding.logos.emblem_note")]),
  ];
}

/** The logos section of the branding page. It reads the logos in force and renders again after each change. */
export function logosSection(env: PageEnv, t: I18n, f: Frame): HTMLElement {
  const holder = h("div", { class: "logo-section" }, [h("p", {}, [t.label("admin.branding.logos.loading")])]);
  const unavailable = (): void => {
    holder.replaceChildren(h("p", {}, [t.label("admin.branding.logos.unavailable")]));
  };
  const refresh = async (): Promise<void> => {
    const r = await readOp(env, "tenant.branding.logos", {}, (x): x is unknown => decodeLogos(x) !== null);
    const v = r.ok ? decodeLogos(r.data) : null;
    if (v === null) {
      unavailable();
      return;
    }
    holder.replaceChildren(...body(env, t, f, v, refresh));
  };
  refresh().catch(unavailable);
  return section("branding-logos", t.label("admin.branding.logos.heading"), [holder]);
}
