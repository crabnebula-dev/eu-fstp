// The logo controls and the theme switch (ADR-030; I-68, R-WL-03). The
// admin page checks a chosen file before it is sent and says why one
// cannot be used. The theme module maps the three choices to the
// `data-theme` the server writes, and reads only logo paths of the
// server's grammar from the shell.

import { VALIDATORS } from "../src/gen/api.js";
import {
  HEADER,
  MAX_LOGO_BYTES,
  decodeLogos,
  fileProblem,
  logoBody,
  logoContrast,
  lowContrast,
  sizeOk,
  sniff,
  toBase64,
} from "../src/admin/branding/logos.js";
import { effectiveTheme, isTheme, logoPathOk, toggledTheme, themeAttribute, themeBody, themeOf } from "../src/shell/theme.js";
import { assert, eq, test } from "./support/harness.js";

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]);
const WEBP = new Uint8Array([...Array.from("RIFF").map((c) => c.charCodeAt(0)), 4, 0, 0, 0, ...Array.from("WEBP").map((c) => c.charCodeAt(0))]);
const SVG = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"/>');

test("i68_logo_file_checks_name_the_problem_in_plain_words", () => {
  eq(sniff(PNG), "png", "a PNG");
  eq(sniff(WEBP), "webp", "a WebP");
  eq(sniff(SVG), null, "SVG is no logo format");
  eq(sniff(new Uint8Array([0xff, 0xd8, 0xff])), null, "JPEG is no logo format");
  eq(fileProblem(100, "png"), null, "a small PNG");
  eq(fileProblem(MAX_LOGO_BYTES + 1, "png"), "too_big", "over 256 KB");
  eq(fileProblem(100, null), "wrong_type", "SVG and the rest");
  assert(sizeOk(16, 2048), "the bounds are inclusive");
  assert(!sizeOk(15, 100) && !sizeOk(100, 2049), "outside the bounds");
});

test("i68_logo_body_is_base64_of_the_file", () => {
  eq(toBase64(new TextEncoder().encode("foobar")), "Zm9vYmFy", "three-byte groups");
  eq(toBase64(new TextEncoder().encode("fo")), "Zm8=", "one pad");
  eq(toBase64(new TextEncoder().encode("f")), "Zg==", "two pads");
  eq(logoBody("dark", null, "Zg=="), { image: "Zg==", mode: "dark", programme: null }, "the body");
  eq(logoBody("light", "7", null), { image: null, mode: "light", programme: "7" }, "a clear");
});

test("adr030_logo_contrast_advises_on_each_header", () => {
  const white = new Uint8ClampedArray([255, 255, 255, 255, 255, 255, 255, 255]);
  const navy = new Uint8ClampedArray([0x1e, 0x29, 0x3b, 255]);
  assert(lowContrast(logoContrast(white, HEADER.light)), "white on the light header is hard to see");
  assert(!lowContrast(logoContrast(white, HEADER.dark)), "white on the dark header is clear");
  assert(lowContrast(logoContrast(navy, HEADER.dark)), "navy on the dark header is hard to see");
  eq(logoContrast(new Uint8ClampedArray([0, 0, 0, 0]), HEADER.light), 1, "no opaque pixel");
});

test("r_wl_03_logos_read_decodes_and_fits_the_schema", () => {
  const logo = { path: `/brand/${"ab".repeat(32)}.png`, format: "png", width: "320", height: "80", pdf: true, email: true, contrast: "250", advice: true };
  const reply = { tenant: { light: logo, dark: null }, programmes: [{ programme: "7", name: "Programme 7", light: null, dark: logo }] };
  const v = decodeLogos(reply);
  assert(v !== null, "decodes");
  eq(v?.tenant.light?.path, logo.path, "the tenant light path");
  eq(v?.programmes[0]?.dark?.format, "png", "the programme dark format");
  const validate = VALIDATORS["tenant.branding.logos"];
  assert(validate !== undefined && validate(reply), "the reply fits the generated schema");
  eq(decodeLogos({ ...reply, tenant: { light: { ...logo, path: "javascript:alert(1)" }, dark: null } }), null, "I-68: only a logo path");
  eq(decodeLogos({ tenant: { light: null }, programmes: [] }), null, "a missing slot");
});

test("adr030_theme_choices_map_to_data_theme", () => {
  assert(isTheme("system") && isTheme("light") && isTheme("dark") && !isTheme("sepia"), "the closed list");
  eq(themeAttribute("system"), null, "System writes no attribute");
  eq(themeAttribute("dark"), "dark", "dark");
  eq(themeOf(null), "system", "no attribute is System");
  eq(themeOf("light"), "light", "light");
  eq(themeOf("x"), "system", "anything else is System");
  eq(themeBody("dark"), { theme: "dark" }, "the me.set_theme body");
  assert(logoPathOk(`/brand/${"0f".repeat(32)}.webp`), "a logo path");
  for (const bad of [null, "/brand/x.png", `/brand/${"0F".repeat(32)}.png`, `https://x.example/brand/${"0f".repeat(32)}.png`]) {
    assert(!logoPathOk(bad), `I-68: ${String(bad)} is no logo path`);
  }
});

/** The theme toggle button of a sidebar built after `installThemeSwitch`. */
async function toggleSetup(attribute: string | null, deviceDark: boolean) {
  const { freshDom, fakeDocument, mediaAnswers } = await import("./support/fakedom.js");
  freshDom();
  mediaAnswers.set("(prefers-color-scheme: dark)", deviceDark);
  if (attribute === null) {
    fakeDocument.documentElement.removeAttribute("data-theme");
  } else {
    fakeDocument.documentElement.setAttribute("data-theme", attribute);
  }
  const nav = await import("../src/home/nav.js");
  const { h } = await import("../src/core/dom.js");
  const saved: string[] = [];
  nav.installThemeSwitch(async (t) => {
    saved.push(t);
    return true;
  });
  const parts = nav.appShell(h("main", {}));
  const find = (n: Element): Element | null => {
    if (n.getAttribute("data-slot") === "theme") {
      return n;
    }
    for (const c of Array.from(n.children)) {
      const r = find(c);
      if (r !== null) {
        return r;
      }
    }
    return null;
  };
  let button: Element | null = null;
  for (const p of parts) {
    button ??= find(p as Element);
  }
  return { button, saved, fakeDocument };
}

test("adr030_sidebar_holds_one_theme_toggle_button_without_a_heading", async () => {
  const { button } = await toggleSetup("light", false);
  assert(button !== null, "the toggle is in the shell");
  eq(button?.tagName.toLowerCase(), "button", "one button");
  eq(button?.textContent, "", "no visible heading or option text");
  eq(button?.getAttribute("type"), "button", "not a submit");
});

test("adr030_toggle_shows_a_moon_on_light_and_a_sun_on_dark_with_its_action_as_name", async () => {
  const light = (await toggleSetup("light", true)).button;
  eq(light?.getAttribute("data-icon"), "moon", "light shows the moon, whatever the device");
  eq(light?.getAttribute("aria-label"), "Switch to dark theme", "name of the action");
  eq(light?.getAttribute("title"), "Switch to dark theme", "tooltip");
  const dark = (await toggleSetup("dark", false)).button;
  eq(dark?.getAttribute("data-icon"), "sun", "dark shows the sun");
  eq(dark?.getAttribute("aria-label"), "Switch to light theme", "name of the action");
  eq(dark?.getAttribute("title"), "Switch to light theme", "tooltip");
});

test("adr030_toggle_click_applies_and_saves_the_opposite_theme", async () => {
  const s = await toggleSetup("light", false);
  s.button?.dispatchEvent(new Event("click"));
  eq(s.saved, ["dark"], "saved dark");
  eq(s.fakeDocument.documentElement.getAttribute("data-theme"), "dark", "applied at once");
  eq(s.button?.getAttribute("data-icon"), "sun", "icon follows");
  eq(s.button?.getAttribute("aria-label"), "Switch to light theme", "name follows");
  s.button?.dispatchEvent(new Event("click"));
  eq(s.saved, ["dark", "light"], "saved light");
  eq(s.button?.getAttribute("data-icon"), "moon", "icon follows back");
});

test("adr030_toggle_system_follows_the_device_until_the_first_click", async () => {
  const lightDevice = await toggleSetup(null, false);
  eq(lightDevice.button?.getAttribute("data-icon"), "moon", "a light device shows the moon");
  eq(lightDevice.saved, [], "nothing saved before a click");
  lightDevice.button?.dispatchEvent(new Event("click"));
  eq(lightDevice.saved, ["dark"], "the first click saves an explicit dark");
  const darkDevice = await toggleSetup(null, true);
  eq(darkDevice.button?.getAttribute("data-icon"), "sun", "a dark device shows the sun");
  darkDevice.button?.dispatchEvent(new Event("click"));
  eq(darkDevice.saved, ["light"], "the first click saves an explicit light");
  eq(darkDevice.fakeDocument.documentElement.getAttribute("data-theme"), "light", "applied");
});

test("adr030_toggle_theme_helpers_pick_the_effective_and_the_next_theme", () => {
  eq(effectiveTheme("system", true), "dark", "system on a dark device");
  eq(effectiveTheme("system", false), "light", "system on a light device");
  eq(effectiveTheme("light", true), "light", "a choice beats the device");
  eq(toggledTheme("dark", false), "light", "dark toggles to light");
  eq(toggledTheme("system", true), "light", "system on dark toggles to light");
});

test("i70_contrast_advice_reads_as_a_plain_ratio", async () => {
  const { ratioText, decodeLogos: decode } = await import("../src/admin/branding/logos.js");
  eq(ratioText("250"), "2.5", "hundredths to a ratio");
  eq(ratioText("1349"), "13.4", "rounded down");
  const logo = { path: `/brand/${"ab".repeat(32)}.png`, format: "png", width: "64", height: "32", pdf: true, email: true, contrast: "x", advice: false };
  eq(decode({ tenant: { light: logo, dark: null }, programmes: [] }), null, "a contrast is digits or null");
});
