// Opening a draft and choosing its starting point (R-PG-02, R-LG-03; M4
// design sections 2.2 J1 and 3.2).
//
// - `/app/creator/new`: `#creator-open` opens a draft with the default
//   funder profile, `creator.open_draft`. It creates a programme, so it
//   is high-risk: the server asks for a step-up, and a cancelled step-up
//   creates nothing (Q10).
// - `/app/programmes/{p}/creator/start`: blank, clone, a template, or a
//   document import (`creator.apply_start`, `import.upload`). A template
//   start leaves template narrative for a person to accept (TH-49).

import { h } from "../../core/dom.js";
import { busy, frame, go, hush, ready, warn } from "../frame.js";
import { t } from "../i18n.js";
import { readOpened, readProgrammes, readTemplates, type TemplateRow } from "../model.js";
import { anyObject, call, report } from "../ops.js";
import { PATHS, loadDraft, queue } from "./common.js";

/** Mounts `/app/creator/new`. */
export function mountNew(): void {
  const { main, alert } = frame({ title: t.label("creator.new.title"), alertId: "creator-error" });
  const open = h("button", { id: "creator-open", type: "button", class: "fstp-primary" }, [t.label("creator.new.open")]);
  open.addEventListener(
    "click",
    busy(open, async () => {
      hush(alert);
      const o = await call("creator.open_draft", [], {}, (v) => readOpened(v) !== null);
      if (report(alert, o) || o.kind !== "done") return;
      const programme = readOpened(o.body);
      if (programme !== null) {
        go(PATHS.start(programme));
      }
    }),
  );
  main.append(h("p", {}, [t.label("creator.new.intro")]), open);
  ready(main);
}

/**
 * The largest import document this page reads, in bytes. Interim,
 * pending Q24 and `fstp_import::ImportLimits`. The size is checked before
 * the file is read, so a larger file is never loaded.
 */
const MAX_DOCUMENT_BYTES = 1_000_000;

/**
 * The text of `bytes` as strict UTF-8 (design section 3.3), or null. A
 * byte sequence that is not UTF-8 is refused, never replaced.
 */
function strictUtf8(bytes: ArrayBuffer): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** Mounts the starting point page of programme `p`. */
export function mountStart(p: string): void {
  const { main, alert } = frame({ title: t.label("creator.start.title"), alertId: "creator-error" });
  const write = queue();

  /** Applies `start` against the current revision, then opens step 1. */
  const apply = (start: Readonly<Record<string, unknown>>): Promise<void> =>
    write(async () => {
      hush(alert);
      const d = await loadDraft(p, alert);
      if (d === null) return;
      const o = await call("creator.apply_start", [p], { base: d.revision, start }, anyObject);
      if (report(alert, o)) return;
      go(PATHS.step(p, "funder"));
    });

  const blank = h("button", { type: "button", "data-start": "blank" }, [t.label("creator.start.blank")]);
  blank.addEventListener("click", busy(blank, () => apply({ kind: "blank" })));

  const templates = h("ul", { id: "creator-templates", "aria-label": t.label("creator.start.templates") });
  const templateButton = (row: TemplateRow): HTMLElement => {
    const b = h("button", { type: "button", "data-start": "template", "data-template": row.id }, [
      t.label("creator.start.template", { name: row.name, version: String(row.version) }),
    ]);
    b.addEventListener("click", busy(b, () => apply({ kind: "template", template: row.id, version: row.version })));
    return h("li", {}, [b]);
  };

  // Clone: the source is another programme of the same tenant (I-19).
  const cloneBox = h("div", { id: "clone-choice", hidden: true });
  const clone = h("button", { type: "button", "data-start": "clone", "aria-controls": "clone-choice", "aria-expanded": "false" }, [
    t.label("creator.start.clone"),
  ]);
  clone.addEventListener(
    "click",
    busy(clone, async () => {
      hush(alert);
      const o = await call("creator.list_programmes", [], undefined, (v) => readProgrammes(v) !== null);
      if (report(alert, o) || o.kind !== "done") return;
      const rows = (readProgrammes(o.body) ?? []).filter((r) => r.id !== p);
      const select = h("select", { id: "clone-source" }, rows.map((r) => h("option", { value: r.id }, [r.name])));
      const go2 = h("button", { type: "button", id: "clone-apply" }, [t.label("creator.start.clone_apply")]);
      go2.addEventListener(
        "click",
        busy(go2, async () => {
          const source = select instanceof HTMLSelectElement ? select.value : "";
          if (source === "") {
            warn(alert, t.label("creator.start.clone_none"));
            return;
          }
          await apply({ kind: "clone", source });
        }),
      );
      cloneBox.replaceChildren(
        h("label", { for: "clone-source" }, [t.label("creator.start.clone_source")]),
        select,
        go2,
      );
      if (rows.length === 0) {
        cloneBox.replaceChildren(h("p", {}, [t.label("creator.start.clone_none")]));
      }
      cloneBox.removeAttribute("hidden");
      clone.setAttribute("aria-expanded", "true");
    }),
  );

  // Import: the document is untrusted data. Its values arrive as
  // proposals that a programme manager resolves one by one (I-65).
  const importBox = h("div", { id: "import-choice", hidden: true });
  const file = h("input", { id: "import-file", type: "file", accept: ".md,.txt,text/markdown,text/plain" });
  const upload = h("button", { id: "import-upload", type: "button" }, [t.label("creator.import.upload")]);
  importBox.append(
    h("label", { for: "import-file" }, [t.label("creator.import.file")]),
    file,
    h("p", { class: "fstp-hint" }, [t.label("creator.import.hint")]),
    upload,
  );
  const importStart = h("button", { type: "button", "data-start": "import", "aria-controls": "import-choice", "aria-expanded": "false" }, [
    t.label("creator.start.import"),
  ]);
  importStart.addEventListener("click", () => {
    importBox.removeAttribute("hidden");
    importStart.setAttribute("aria-expanded", "true");
    file.focus();
  });
  upload.addEventListener(
    "click",
    busy(upload, async () => {
      hush(alert);
      const chosen = file instanceof HTMLInputElement ? file.files?.item(0) : null;
      if (chosen === null || chosen === undefined) {
        warn(alert, t.label("creator.import.no_file"));
        return;
      }
      const name = chosen.name.toLowerCase();
      const media = name.endsWith(".md") || name.endsWith(".markdown") ? "text/markdown" : "text/plain";
      if (chosen.size > MAX_DOCUMENT_BYTES) {
        warn(alert, t.label("creator.import.too_large"));
        return;
      }
      const bytes = await chosen.arrayBuffer();
      // A file that grew after the size check is refused too.
      if (bytes.byteLength > MAX_DOCUMENT_BYTES) {
        warn(alert, t.label("creator.import.too_large"));
        return;
      }
      const text = strictUtf8(bytes);
      if (text === null) {
        warn(alert, t.label("creator.import.not_utf8"));
        return;
      }
      const o = await call("import.upload", [p], { media, text }, anyObject);
      if (report(alert, o)) return;
      go(PATHS.imports(p));
    }),
  );

  main.append(
    h("p", {}, [t.label("creator.start.intro")]),
    h("h2", {}, [t.label("creator.start.templates")]),
    templates,
    h("h2", {}, [t.label("creator.start.other")]),
    h("div", { class: "fstp-actions" }, [blank, clone, importStart]),
    cloneBox,
    importBox,
  );

  void (async () => {
    const o = await call("creator.list_templates", [], undefined, (v) => readTemplates(v) !== null);
    if (report(alert, o) || o.kind !== "done") return;
    const rows = readTemplates(o.body) ?? [];
    templates.replaceChildren(...rows.map(templateButton));
    if (rows.length === 0) {
      templates.append(h("li", {}, [t.label("creator.start.no_templates")]));
    }
    ready(main);
  })();
}
