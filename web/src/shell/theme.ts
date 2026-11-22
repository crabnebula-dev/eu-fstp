// The theme switch of every `/app/` page and the tenant logo of its top
// bar (ADR-030 sections 1 and 2).
//
// - The server writes the person's saved choice as `data-theme` on
//   `<html>` before the first paint, so no page flashes the wrong theme.
//   System writes no attribute, and the CSS media query decides.
// - The switch applies a choice at once, then saves it with
//   `me.set_theme`, so it follows the person to every device.
// - The shell carries the tenant logo paths as `<meta>` values of the
//   logo path grammar. The top bar shows them as decorative images
//   beside the visible name, so no tenant text reaches the page here.

/** The theme choices, in the order the switch shows them. */
export const THEMES = ["system", "light", "dark"] as const;

/** One theme choice. */
export type Theme = (typeof THEMES)[number];

/** Whether `s` names a theme choice. */
export function isTheme(s: string): s is Theme {
  return (THEMES as readonly string[]).includes(s);
}

/** The `data-theme` value of a choice, or null for System. */
export function themeAttribute(t: Theme): "light" | "dark" | null {
  return t === "system" ? null : t;
}

/** The choice a `data-theme` value stands for. Anything else is System. */
export function themeOf(attribute: string | null): Theme {
  return attribute === "light" || attribute === "dark" ? attribute : "system";
}

/** The body of `me.set_theme`. */
export function themeBody(t: Theme): { readonly theme: Theme } {
  return { theme: t };
}

/** A logo path of the server's grammar: `/brand/`, 64 hex digits, `.png` or `.webp`. */
const LOGO_PATH = /^\/brand\/[0-9a-f]{64}\.(png|webp)$/;

/** Whether `p` is a logo path the shell may show. */
export function logoPathOk(p: string | null): p is string {
  return p !== null && LOGO_PATH.test(p);
}

/** The tenant logo paths of the shell document, light and dark. Dark is null when it equals light. */
export function shellLogos(doc: Pick<Document, "querySelector">): { readonly light: string | null; readonly dark: string | null } {
  const read = (name: string): string | null => {
    const v = doc.querySelector(`meta[name="${name}"]`)?.getAttribute("content") ?? null;
    return logoPathOk(v) ? v : null;
  };
  const light = read("fstp-logo-light");
  const dark = read("fstp-logo-dark");
  return { light, dark: dark === light ? null : dark };
}

/** The choice on show now. */
export function currentTheme(): Theme {
  return themeOf(document.documentElement.getAttribute("data-theme"));
}

/** Shows `t` at once. */
export function applyTheme(t: Theme): void {
  const a = themeAttribute(t);
  if (a === null) {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.setAttribute("data-theme", a);
  }
}

/** Whether the device asks for a dark page (`prefers-color-scheme: dark`). */
export function deviceIsDark(): boolean {
  const mm = (globalThis as { readonly matchMedia?: unknown }).matchMedia;
  if (typeof mm !== "function") {
    return false;
  }
  const q: unknown = (mm as (query: string) => unknown).call(globalThis, "(prefers-color-scheme: dark)");
  return typeof q === "object" && q !== null && (q as { readonly matches?: unknown }).matches === true;
}

/** The theme on screen: the saved choice, or the device's when the choice is System. */
export function effectiveTheme(choice: Theme, deviceDark: boolean): "light" | "dark" {
  return choice === "system" ? (deviceDark ? "dark" : "light") : choice;
}

/** The explicit choice a click on the sun/moon toggle makes: the opposite of what shows. */
export function toggledTheme(choice: Theme, deviceDark: boolean): "light" | "dark" {
  return effectiveTheme(choice, deviceDark) === "dark" ? "light" : "dark";
}
