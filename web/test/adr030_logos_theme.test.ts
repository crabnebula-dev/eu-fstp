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
import { isTheme, logoPathOk, themeAttribute, themeBody, themeOf } from "../src/shell/theme.js";
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

test("adr030_sidebar_holds_the_theme_switch_once_the_shell_installs_it", async () => {
  const { freshDom } = await import("./support/fakedom.js");
  freshDom();
  const nav = await import("../src/home/nav.js");
  const { h } = await import("../src/core/dom.js");
  const saved: string[] = [];
  nav.installThemeSwitch(async (t) => {
    saved.push(t);
    return true;
  });
  const parts = nav.appShell(h("main", {}));
  const text = parts.map((p) => p.textContent ?? "").join(" ");
  assert(text.includes("Theme"), "the switch is in the shell");
  assert(text.includes("System") && text.includes("Light") && text.includes("Dark"), "three choices");
});

test("i70_contrast_advice_reads_as_a_plain_ratio", async () => {
  const { ratioText, decodeLogos: decode } = await import("../src/admin/branding/logos.js");
  eq(ratioText("250"), "2.5", "hundredths to a ratio");
  eq(ratioText("1349"), "13.4", "rounded down");
  const logo = { path: `/brand/${"ab".repeat(32)}.png`, format: "png", width: "64", height: "32", pdf: true, email: true, contrast: "x", advice: false };
  eq(decode({ tenant: { light: logo, dark: null }, programmes: [] }), null, "a contrast is digits or null");
});
