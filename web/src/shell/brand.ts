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

import { h } from "../core/dom.js";
import { defaultMandatoryElements } from "../creator/frame.js";
import { t } from "../creator/i18n.js";

/** The id of the guard's footer. */
const SHELL_FOOTER_ID = "shell-footer";

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

/** Appends the platform footer if the document has none, else removes ours. */
export function syncFooter(): void {
  const own = document.getElementById(SHELL_FOOTER_ID);
  const others = Array.from(document.querySelectorAll("footer")).filter((f) => f !== own);
  if (others.length > 0) {
    own?.remove();
  } else if (own === null) {
    document.body.append(shellFooter());
  }
}

/** Keeps exactly one footer on the page while pages render and change. */
export function installFooterGuard(): void {
  syncFooter();
  new MutationObserver(() => {
    syncFooter();
  }).observe(document.body, { childList: true, subtree: true });
}
