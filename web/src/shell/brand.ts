// The footer guard of the `/app/` shell (M9 design section 2.4, lane B2,
// I-69).
//
// Every page frame builds its own footer. A page that builds none, such as
// a Judging page, still gets the platform footer of mandatory elements,
// appended outside `#app`. The guard removes its footer again as soon as a
// page builds its own, so the document holds exactly one `footer`. The
// footer holds platform wording only: no tenant brand token can name,
// hide, size or reorder an element (the brand sheet sets colour custom
// properties and nothing else).
//
// Daniel, 2026-11-15 (late): a page inside one programme shows the funder
// visibility elements of that programme's pinned funder profile, and a
// tenant-wide page shows none. Interim reading of lane m9/answers: a page
// is inside one programme when its path is `/app/programmes/{programme}/...`.
// The guard reads `programme.funder_profile.view` for it and adds one
// element per visibility element key to whichever footer the page has,
// keyed `data-mandatory="funder_visibility.<key>"` as on the public pages.
// TODO(legal): the wording of each element (L-08, L-09) stays the
// placeholder until Daniel supplies the approved text.

import { h } from "../core/dom.js";
import { defaultMandatoryElements } from "../creator/frame.js";
import { t } from "../creator/i18n.js";
import type { FunderProfileView } from "../operations/profile.js";

/** The id of the guard's footer. */
const SHELL_FOOTER_ID = "shell-footer";

/** The marker of the profile elements the guard adds. */
const PROFILE_MARK = "data-profile-element";

/** The platform footer: one element per mandatory element. */
export function shellFooter(): HTMLElement {
  const m = defaultMandatoryElements();
  const item = (key: string, text: string): HTMLElement =>
    h("li", {}, [h("span", { "data-mandatory": key }, [text])]);
  return h("footer", { class: "fstp-footer", id: SHELL_FOOTER_ID }, [
    h("ul", {}, [
      item("funder_visibility", t.approved("footer.funder_visibility")),
      item("ai_disclosure", t.approved("footer.ai_disclosure")),
      item("privacy_notice", m.privacyNotice),
      item("accessibility_statement", m.accessibilityStatement),
      item("data_act_information", m.dataActInformation),
      item("platform_attribution", m.platformAttribution),
    ]),
  ]);
}

/** The programme a page belongs to, from its path, or null for a tenant-wide page. */
export function programmeOfPath(path: string): string | null {
  const m = /^\/app\/programmes\/(0|[1-9][0-9]{0,38})(\/|$)/.exec(path);
  return m === null ? null : (m[1] ?? null);
}

/** Reads the funder profile of a programme, or null when it cannot be read. */
export type ProfileReader = (programme: string) => Promise<FunderProfileView | null>;

/** The profile elements of the page in view: its programme and what the read gave. */
let current: { readonly programme: string; readonly view: FunderProfileView | null } | null = null;
let reader: ProfileReader | null = null;
let pending: string | null = null;

/** The placeholder text of one profile element (TODO(legal), L-08). */
function elementText(key: string, profile: string, version: string): string {
  return t.approved("footer.funder_element", { element: key, profile, version });
}

/** One profile element of a footer: its `data-mandatory` key and its text. */
export interface ProfileElement {
  readonly key: string;
  readonly text: string;
}

/**
 * The profile elements a footer shows on the page at `path`, given the
 * profile read for `programme`: one per visibility element key when the
 * page is inside that programme, else none (a tenant-wide page, another
 * programme, or no profile pinned).
 */
export function profileElements(path: string, programme: string | null, view: FunderProfileView | null): ProfileElement[] {
  const p = view?.profile ?? null;
  if (p === null || programme === null || programmeOfPath(path) !== programme) {
    return [];
  }
  return p.visibility.map((k) => ({ key: `funder_visibility.${k}`, text: elementText(k, p.id, p.version) }));
}

/** Brings the profile elements of `footer` to the page in view, touching the DOM only when they differ. */
function syncProfileElements(footer: Element): void {
  const programme = programmeOfPath(location.pathname);
  if (programme !== null && current?.programme !== programme && pending !== programme && reader !== null) {
    pending = programme;
    const read = reader;
    void read(programme).then((view) => {
      pending = null;
      current = { programme, view };
      syncFooter();
    });
  }
  const want = profileElements(location.pathname, current?.programme ?? null, current?.view ?? null);
  const have = Array.from(footer.querySelectorAll(`[${PROFILE_MARK}]`));
  const same = have.length === want.length && have.every((e, i) => e.getAttribute("data-mandatory") === want[i]?.key);
  if (same) {
    return;
  }
  for (const e of have) {
    e.closest("li")?.remove();
  }
  const list = footer.querySelector("ul");
  if (list === null) {
    return;
  }
  for (const e of want) {
    list.append(h("li", {}, [h("span", { "data-mandatory": e.key, [PROFILE_MARK]: "" }, [e.text])]));
  }
}

/** Appends the platform footer if the document has none, else removes ours, then syncs the profile elements. */
export function syncFooter(): void {
  const own = document.getElementById(SHELL_FOOTER_ID);
  const others = Array.from(document.querySelectorAll("footer")).filter((f) => f !== own);
  if (others.length > 0) {
    own?.remove();
  } else if (own === null) {
    document.body.append(shellFooter());
  }
  const footer = document.querySelector("footer");
  if (footer !== null) {
    syncProfileElements(footer);
  }
}

/** Keeps exactly one footer on the page while pages render and change. */
export function installFooterGuard(read: ProfileReader | null = null): void {
  reader = read;
  current = null;
  pending = null;
  syncFooter();
  new MutationObserver(() => {
    syncFooter();
  }).observe(document.body, { childList: true, subtree: true });
}
