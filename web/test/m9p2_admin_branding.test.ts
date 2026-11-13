// The tenant admin's branding and terminology screens (M9 lane P2;
// R-WL-03, R-WL-05, I-68, I-70, I-72). The admin sets the brand colours,
// sees each failing contrast pair, and saves only when every pair passes.
// The terminology screen sends labels of the closed list only.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { mountAdminBranding } from "../src/admin/branding/page.js";
import {
  PAIRS,
  PLATFORM,
  brandingBody,
  decodeCheck,
  editableKeys,
  fieldId,
  isBrandName,
  terminologyBody,
} from "../src/admin/branding/model.js";
import { SCHEMAS, VALIDATORS } from "../src/gen/api.js";
import type { PageEnv } from "../src/reviewer/kit.js";
import { FIXED_LABEL_KEYS, PLAIN_LABELS } from "../src/vocab/plain.js";
import { fakeDocument, freshDom, FakeElement } from "./support/fakedom.js";
import { assert, eq, test } from "./support/harness.js";
import { REPO_DIR } from "./support/paths.js";

const g = globalThis as unknown as Record<string, unknown>;

function source(...parts: string[]): string {
  return readFileSync(join(REPO_DIR, ...parts), "utf8");
}

/** The text between `start` and the next `end` after it. */
function block(text: string, start: string, end: string): string {
  const at = text.indexOf(start);
  assert(at >= 0, `${start} is in the source`);
  const stop = text.indexOf(end, at);
  return text.slice(at, stop);
}

/** R-WL-05, I-72: the web copy of the plain pack and of the fixed keys repeats the Rust sources. */
test("r_wl_05_web_plain_pack_repeats_the_shipped_pack_and_fixed_keys", () => {
  const plain = JSON.parse(source("crates", "fstp-journey", "vocab", "plain.v1.json")) as { labels: Record<string, string> };
  eq({ ...PLAIN_LABELS }, { ...plain.labels }, "web/src/vocab/plain.ts repeats vocab/plain.v1.json");
  const vocab = source("crates", "fstp-journey", "src", "vocab.rs");
  const fixed = [...block(vocab, "pub const FIXED", "];").matchAll(/key: "([^"]+)"/g)].map((m) => m[1]);
  eq([...FIXED_LABEL_KEYS], fixed, "FIXED_LABEL_KEYS repeats fstp_journey::vocab::FIXED");
  const keys = [...block(vocab, "pub const LABEL_KEYS", "];").matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  eq(Object.keys(PLAIN_LABELS), keys, "the plain labels name exactly LABEL_KEYS, in order");
  for (const k of FIXED_LABEL_KEYS) {
    assert(!editableKeys().includes(k), `${k} has no field`);
  }
});

/** I-70, D1: the platform family repeats fstp_brand, and the pair names are the cell's. */
test("i70_web_platform_palette_and_pairs_repeat_fstp_brand", () => {
  const brand = source("crates", "fstp-brand", "src", "lib.rs");
  for (const [mode, konst] of [["light", "PLATFORM_LIGHT"], ["dark", "PLATFORM_DARK"]] as const) {
    const body = block(brand, `pub const ${konst}`, "};");
    for (const [field, key] of [["brand", "brand"], ["brand_hover", "brand-hover"], ["brand_text", "brand-text"], ["on_brand", "on-brand"], ["focus", "focus"]] as const) {
      const m = new RegExp(`\\b${field}: Rgb::hex\\(0x([0-9A-F]{2})_([0-9A-F]{2})_([0-9A-F]{2})\\)`).exec(body);
      assert(m !== null, `${konst}.${field}`);
      eq(PLATFORM[mode][key], `#${m?.[1]}${m?.[2]}${m?.[3]}`.toLowerCase(), `${mode} ${key}`);
    }
  }
  const schema = SCHEMAS["tenant.branding.check"] as unknown as { fields: { failing: { schema: { items: { values: string[] } } } } };
  eq([...PAIRS], schema.fields.failing.schema.items.values, "the pair table of the generated schema");
});

/** I-68: the body holds typed tokens only, and a name or colour the cell refuses builds no body. */
test("i68_web_branding_body_is_typed_tokens", () => {
  const b = brandingBody({ name: "Synthetic Tenant", light: { ...PLATFORM.light, brand: "#ABCDEF" }, dark: PLATFORM.dark });
  assert(b !== null, "a valid body");
  const tokens = b?.tokens as Record<string, Record<string, string>>;
  eq(tokens["light"]?.["brand"], "#abcdef", "colours are lower case");
  eq(Object.keys(b?.tokens ?? {}).sort(), ["dark", "light", "name", "typography"], "exactly the four members");
  eq(b?.tokens["typography"], "system", "D2");
  assert(brandingBody({ name: "<b>x</b>", light: PLATFORM.light, dark: PLATFORM.dark }) === null, "angle brackets refused");
  assert(brandingBody({ name: "Ok", light: { ...PLATFORM.light, focus: "red" }, dark: PLATFORM.dark }) === null, "a named colour is refused");
  assert(brandingBody({ name: "Ok", light: { ...PLATFORM.light, focus: "url(x)" }, dark: PLATFORM.dark }) === null, "no CSS reaches a token");
  assert(!isBrandName(" padded") && !isBrandName("") && !isBrandName("x".repeat(81)) && isBrandName("x".repeat(80)), "name bounds");
});

/** I-70: a check reply is read only when it is accepted exactly with no failing pair, over pairs of the table. */
test("i70_web_check_reply_accepted_iff_no_pair_fails", () => {
  eq(decodeCheck({ accepted: true, failing: [] })?.accepted, true, "all pass");
  eq(decodeCheck({ accepted: false, failing: ["dark.on-brand/brand"] })?.failing, ["dark.on-brand/brand"], "one fails");
  assert(decodeCheck({ accepted: true, failing: ["dark.on-brand/brand"] }) === null, "accepted with a failing pair is refused");
  assert(decodeCheck({ accepted: false, failing: [] }) === null, "refused with no pair is refused");
  assert(decodeCheck({ accepted: false, failing: ["dark.text/page"] }) === null, "an unknown pair is refused");
  assert(VALIDATORS["tenant.branding.check"]?.({ accepted: false, failing: ["light.focus/surface-0"] }) === true, "the generated validator agrees");
});

/** I-72: fixed and unknown keys are never sent, empty fields keep the plain label, and invalid text is listed. */
test("i72_web_terminology_body_names_editable_keys_only", () => {
  const r = terminologyBody(
    { "vocab.call": " Open round ", "vocab.team": "", "journey.node.withdrawn": "Gone", "footer.privacy_notice": "x" },
    true,
  );
  assert(r.ok, "a valid body");
  if (r.ok) {
    eq({ ...r.body.labels }, { "vocab.call": "Open round" }, "only the editable, non-empty key");
    eq(r.body.voyage_on, true, "the Voyage switch");
  }
  const bad = terminologyBody({ "vocab.call": "Call {n}", "vocab.team": "<i>Team</i>" }, false);
  assert(!bad.ok && bad.invalid.length === 2, "braces and markup are listed");
  eq(fieldId("journey.map.title"), "terminology-journey-map-title", "field ids");
});

interface Sent {
  readonly line: string;
  readonly body: string | undefined;
}

function env(replies: (line: string, body: string | undefined) => unknown, sent: Sent[]): PageEnv {
  const api: ApiClient = {
    async call(op: OperationRef, _params, body, validate): Promise<ApiOutcome> {
      const line = `${op.method} ${op.path}`;
      const text = body === undefined ? undefined : JSON.stringify(body);
      sent.push({ line, body: text });
      const r = replies(line, text);
      if (r === undefined) {
        return { kind: "refused", code: "refused", rule: "test" };
      }
      return validate(r) ? { kind: "done", body: r } : { kind: "failed", reason: "invalid_response" };
    },
  };
  return { api, root: fakeDocument.body as unknown as HTMLElement, navigate: () => undefined };
}

function prepare(path: string): void {
  freshDom();
  for (const n of ["HTMLSelectElement", "HTMLFormElement", "HTMLButtonElement", "HTMLTextAreaElement", "HTMLInputElement"]) {
    g[n] = FakeElement;
  }
  g["location"] = { protocol: "http:", hostname: "cell.localhost", port: "8650", pathname: path };
}

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 20));

function text(): string {
  return fakeDocument.body.textContent ?? "";
}

function input(id: string): { value: string; checked: boolean } {
  const el = fakeDocument.getElementById(id) as unknown as { value: string; checked: boolean } | null;
  assert(el !== null, `#${id}`);
  return el as { value: string; checked: boolean };
}

/** I-70, R-WL-03: a failing pair is listed by name and the tokens are not saved; a passing set is saved. */
test("i70_branding_screen_lists_failing_pairs_and_saves_only_when_all_pass", async () => {
  prepare("/app/admin/branding");
  const sent: Sent[] = [];
  let failing: string[] = ["dark.on-brand/brand", "light.brand-text/surface-1"];
  const replies = (line: string): unknown => {
    if (line === "POST /admin/branding/check") {
      return { accepted: failing.length === 0, failing };
    }
    if (line === "PUT /admin/branding") {
      return {};
    }
    return undefined;
  };
  assert(await mountAdminBranding(env(replies, sent), "/app/admin/branding"), "the route mounts");
  await settle();
  assert(input("branding-light-brand").value === PLATFORM.light.brand, "the platform family fills the fields");
  input("branding-name").value = "Synthetic Tenant";
  fakeDocument.getElementById("branding-check")?.dispatchEvent(new Event("click"));
  await settle();
  const listed = fakeDocument.body.descendants().filter((e) => e.getAttribute("data-pair") !== null).map((e) => e.getAttribute("data-pair"));
  eq(listed, failing, "each failing pair is listed");
  assert(text().includes("Dark mode: text on the brand fill"), text().slice(0, 900));
  fakeDocument.getElementById("branding-form")?.dispatchEvent(new Event("submit", { cancelable: true }));
  await settle();
  assert(!sent.some((s) => s.line === "PUT /admin/branding"), "a failing set is never sent");
  assert(text().includes("Nothing was saved"), "the admin is told");
  failing = [];
  fakeDocument.getElementById("branding-form")?.dispatchEvent(new Event("submit", { cancelable: true }));
  await settle();
  const put = sent.find((s) => s.line === "PUT /admin/branding");
  assert(put?.body?.includes('"name":"Synthetic Tenant"') === true, put?.body ?? sent.map((s) => s.line).join(", "));
  assert(text().includes("The brand colours are saved."), "the status");
});

/** I-72, R-WL-05: the terminology screen offers no field for fixed wording and sends the edited labels. */
test("i72_terminology_screen_sends_labels_of_the_closed_list", async () => {
  prepare("/app/admin/terminology");
  const sent: Sent[] = [];
  const replies = (line: string): unknown => (line === "PUT /admin/terminology" ? {} : undefined);
  assert(await mountAdminBranding(env(replies, sent), "/app/admin/terminology"), "the route mounts");
  await settle();
  assert(fakeDocument.getElementById(fieldId("journey.node.withdrawn")) === null, "no field for fixed wording");
  input(fieldId("vocab.call")).value = "Open round";
  input("terminology-voyage").checked = true;
  fakeDocument.getElementById("terminology-form")?.dispatchEvent(new Event("submit", { cancelable: true }));
  await settle();
  const put = sent.find((s) => s.line === "PUT /admin/terminology");
  eq(put?.body, '{"labels":{"vocab.call":"Open round"},"voyage_on":true}', "the body");
  assert(text().includes("The terminology is saved."), "the status");
});
