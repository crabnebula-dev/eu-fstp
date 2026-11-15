// The page gate of SA-09, as the shell asks it.
//
// The server decides whether a viewer may open an `/app/` page before it
// serves the shell (`fstp-web`, `fstp_api_core::ApiCore::page`). The shell
// asks the same gate, never a rule of its own, in three places:
//
// 1. An in-app navigation renders a page only after the gate admits it.
//    A page the viewer may not open shows "Page not found", and a viewer
//    with no session (or too weak a one) loads the page from the server,
//    whose 303 leads to sign-in.
// 2. When a page's own read is refused after it loaded, for example
//    because the session ended, the shell asks the gate again. If the
//    page is closed now, the viewer sees sign-in or "Page not found",
//    never the refusal code (rule 7).
// 3. Every in-app link stays hidden until the gate admits its page, and a
//    link to a page the viewer may not open is removed (rule 6).
//
// The question is a `HEAD` of the page path with no redirect followed:
// 200 admits, a redirect means sign in, and 404 means not found. The
// answers are kept for the page load, so each path is asked once.

/** What the gate answers for a page. */
export type Gate = "open" | "sign_in" | "not_found" | "unknown";

/** The parts of a fetch response the gate reads. */
export interface GateResponse {
  readonly type: string;
  readonly status: number;
}

/** The fetch the gate calls: the page's `fetch`, or a test fake. */
export type GateFetch = (path: string, init: RequestInit) => Promise<GateResponse>;

/** The gate's answer from a response to a `HEAD` with `redirect: "manual"`. */
export function gateOf(res: GateResponse): Gate {
  if (res.type === "opaqueredirect" || (res.status >= 300 && res.status <= 399)) {
    return "sign_in";
  }
  if (res.status === 200) {
    return "open";
  }
  if (res.status === 404) {
    return "not_found";
  }
  return "unknown";
}

/** The in-app page path of `href` on this origin, or null. */
export function pagePathOf(href: string, base: string): string | null {
  let u: URL;
  try {
    u = new URL(href, base);
  } catch {
    return null;
  }
  const b = new URL(base);
  if (u.origin !== b.origin || !(u.pathname === "/app/" || u.pathname.startsWith("/app/"))) {
    return null;
  }
  if (u.pathname.startsWith("/app/assets/")) {
    return null;
  }
  return u.pathname;
}

/** The gate of one page load. */
export interface PageGate {
  /** The gate's answer for `path`, asked once per page load. */
  check(path: string): Promise<Gate>;
  /** The gate's answer for `path`, asked again. */
  fresh(path: string): Promise<Gate>;
}

/** A gate over `fetchFn`. */
export function createGate(fetchFn: GateFetch): PageGate {
  const answers = new Map<string, Promise<Gate>>();
  const ask = async (path: string): Promise<Gate> => {
    try {
      const res = await fetchFn(path, {
        method: "HEAD",
        redirect: "manual",
        credentials: "same-origin",
        mode: "same-origin",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
      return gateOf(res);
    } catch {
      return "unknown";
    }
  };
  return Object.freeze({
    check(path: string): Promise<Gate> {
      let p = answers.get(path);
      if (p === undefined) {
        p = ask(path);
        answers.set(path, p);
      }
      return p;
    },
    fresh(path: string): Promise<Gate> {
      const p = ask(path);
      answers.set(path, p);
      return p;
    },
  });
}

/** The attribute a link carries while the gate is asked. */
export const PENDING = "data-page-gate";

/** The items that exist for their link: a mailbox message, a home page work item. */
export const ITEM_SELECTOR = "li[data-mail], li[data-work-item]";

/** The attribute that names the page path the gate admitted for a link. */
export const GATED = "data-page-gated";

/**
 * Hides each in-app link below `root` until the gate admits its page,
 * and removes a link to a page the viewer may not open, with its list
 * item when the link was all the item held (SA-09 rule 6). An answer
 * the gate could not give leaves the link shown: the server still
 * decides when it is followed.
 */
export async function gateLinks(root: ParentNode, gate: PageGate, base: string): Promise<void> {
  const found = root instanceof HTMLAnchorElement ? [root] : Array.from(root.querySelectorAll("a[href]"));
  const links = found.filter(
    (a): a is HTMLAnchorElement => a instanceof HTMLAnchorElement && !a.hasAttribute(PENDING),
  );
  await Promise.all(
    links.map(async (a) => {
      const path = pagePathOf(a.getAttribute("href") ?? "", base);
      if (path === null || a.getAttribute(GATED) === path) {
        return;
      }
      const shown = !a.hidden;
      a.setAttribute(PENDING, "");
      a.hidden = true;
      const g = await gate.check(path);
      if (g === "sign_in" || g === "not_found") {
        // A mailbox message or a home page work item exists for its link,
        // so it goes with it.
        const work = a.closest(ITEM_SELECTOR);
        if (work !== null) {
          work.remove();
          return;
        }
        const item = a.parentElement;
        a.remove();
        if (item !== null && item.tagName === "LI" && (item.textContent ?? "").trim() === "") {
          item.remove();
        }
        return;
      }
      a.hidden = !shown;
      a.removeAttribute(PENDING);
      a.setAttribute(GATED, path);
    }),
  );
}
