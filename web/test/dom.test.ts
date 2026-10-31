// dom.ts: the DOM builder refuses unsafe input (M4 design section 3.9,
// ADR-014 "DOM"). Text goes in through text nodes only, tags and
// attributes come from allowlists, and URL attributes pass `safeUrl`.

import { readExpectations } from "../fuzz/harness.js";
import type { DomModule, DomRefusalCode } from "./support/contract.js";
import { FakeElement, FakeText, asFake, elementsCreated, freshDom, sinkUses } from "./support/fakedom.js";
import { markupish } from "./support/gen.js";
import { assert, eq, forAll, show, test, thrown } from "./support/harness.js";
import { core } from "./support/load.js";

async function dom(): Promise<DomModule> {
  freshDom();
  return core("dom");
}

function refusalCode(d: DomModule, fn: () => unknown, what: string): DomRefusalCode {
  const e = thrown(fn, what);
  assert(e instanceof d.DomRefusal, `${what}: threw ${show(String(e))}, not a DomRefusal`);
  return e.code;
}

/** ADR-014: `h` builds an element and puts string children in as text nodes. */
test("adr014_dom_builds_allowed_tags_with_text_children", async () => {
  const d = await dom();
  const el = asFake(d.h("p", { class: "lead", id: "intro" }, ["a <b>bold</b> & more"]));
  eq(el.localName, "p", "tag");
  eq(el.getAttribute("class"), "lead", "class");
  eq(el.getAttribute("id"), "intro", "id");
  eq(el.childNodes.length, 1, "one child");
  const t = el.childNodes[0];
  assert(t instanceof FakeText, "the child is a text node");
  eq(t.data, "a <b>bold</b> & more", "text kept as text");
  eq(elementsCreated(), 1, "no element made from the string");
  const nested = asFake(d.h("ul", {}, [d.h("li", {}, ["one"]), "two"]));
  eq(nested.children.length, 1, "element children appended");
  eq(nested.textContent, "onetwo", "mixed children in order");
  eq(sinkUses, [], "no HTML sink reached");
});

/** ADR-014: the tags a page needs build. */
test("adr014_dom_accepts_core_tags", async () => {
  const d = await dom();
  const tags = [
    "div", "span", "p", "a", "button", "input", "label", "form", "main", "nav", "header", "footer",
    "section", "h1", "h2", "ul", "ol", "li", "table", "tr", "td", "th", "select", "option", "textarea",
    "fieldset", "legend",
  ];
  for (const t of tags) {
    eq(asFake(d.h(t)).localName, t, `tag ${t}`);
  }
});

/** ADR-014: tags outside the allowlist are refused, in any spelling. */
test("adr014_dom_refuses_tags_outside_allowlist", async () => {
  const d = await dom();
  const tags = [
    "script", "SCRIPT", "Script", "iframe", "frame", "frameset", "object", "embed", "style", "link",
    "meta", "base", "template", "svg", "math", "noscript", "foreignObject", "portal", "applet",
    "", " div", "div ", "di v", "scr\u0000ipt", "a:b", "x-widget", "<div>", "div>",
  ];
  for (const t of tags) {
    eq(refusalCode(d, () => d.h(t), `tag ${show(t)}`), "tag", `refusal code for tag ${show(t)}`);
  }
  eq(sinkUses, [], "no HTML sink reached");
});

/** ADR-014: event handler attributes, in any case, and `style`, `srcdoc` and kin are refused. */
test("adr014_dom_refuses_event_handler_and_style_attributes", async () => {
  const d = await dom();
  const names = [
    "onclick", "OnClick", "ONLOAD", "onerror", "onfocusin", "onanimationstart", "onpointerdown", "on",
    "style", "STYLE", "srcdoc", "formaction", "xmlns", "xlink:href", "is", "http-equiv", "href ",
    " href", "", "data-x\u0000", "innerHTML", "outerHTML",
  ];
  for (const n of names) {
    eq(refusalCode(d, () => d.h("div", { [n]: "x" }), `attribute ${show(n)}`), "attribute", `code for ${show(n)}`);
  }
});

/** ADR-014, R-NF-03: the attributes pages and accessibility need are set as given. */
test("adr014_dom_accepts_aria_and_form_attributes", async () => {
  const d = await dom();
  const attrs: Readonly<Record<string, string>> = {
    id: "f1",
    class: "field",
    role: "group",
    "aria-label": "Amount",
    "aria-describedby": "f1-hint f1-error",
    "aria-live": "polite",
    "aria-invalid": "true",
    lang: "de",
    title: "t",
  };
  const el = asFake(d.h("div", attrs));
  for (const [k, v] of Object.entries(attrs)) {
    eq(el.getAttribute(k), v, `attribute ${k}`);
  }
  const input = asFake(d.h("input", { type: "text", name: "cap", value: "1.00", required: true, disabled: false }));
  eq(input.getAttribute("type"), "text", "type");
  eq(input.getAttribute("name"), "cap", "name");
  eq(input.value, "1.00", "value");
  eq(input.getAttribute("required"), "", "true sets an empty attribute");
  eq(input.hasAttribute("disabled"), false, "false omits the attribute");
  const label = asFake(d.h("label", { for: "f1" }, ["Amount"]));
  eq(label.getAttribute("for"), "f1", "for");
});

/** ADR-014: `href`, `src` and `action` take only what `safeUrl` accepts, unchanged. */
test("adr014_dom_refuses_unsafe_urls_in_url_attributes", async () => {
  const d = await dom();
  const corpus = readExpectations("safe_url");
  const cases: readonly [string, string][] = [
    ["a", "href"],
    ["img", "src"],
    ["form", "action"],
  ];
  for (const [tag, attr] of cases) {
    for (const e of corpus) {
      if (e.verdict === "accept") {
        eq(asFake(d.h(tag, { [attr]: e.input })).getAttribute(attr), e.input, `${tag} ${attr}=${show(e.input)}`);
      } else {
        eq(refusalCode(d, () => d.h(tag, { [attr]: e.input }), `${tag} ${attr}=${show(e.input)}`), "url", "code");
      }
    }
  }
});

/** ADR-014: a child that is neither a node nor a string is refused, never stringified. */
test("adr014_dom_refuses_non_node_non_string_children", async () => {
  const d = await dom();
  const bad: readonly unknown[] = [{}, { toString: () => "<b>x</b>" }, 1, null, undefined, true, ["x"], { nodeType: 1 }];
  for (const c of bad) {
    const code = refusalCode(d, () => d.h("p", {}, [c as string]), `child ${show(c)}`);
    eq(code, "child", `code for child ${show(c)}`);
  }
});

/** ADR-014: on markup-heavy strings, a string child is one text node and no element is parsed from it. */
test("adr014_dom_string_children_never_become_markup", async () => {
  const d = await dom();
  forAll(
    markupish,
    (s) => {
      freshDom();
      const el = asFake(d.h("span", {}, [s]));
      eq(elementsCreated(), 1, "one element created");
      const kids = el.childNodes;
      if (s === "") {
        assert(kids.length <= 1, "an empty string makes at most one node");
      } else {
        eq(kids.length, 1, "one child");
      }
      for (const k of kids) {
        assert(k instanceof FakeText, "the child is a text node");
        assert(!(k instanceof FakeElement), "no element child");
      }
      eq(el.textContent, s, "text equals the string");
      eq(sinkUses, [], "no HTML sink reached");
    },
    { runs: 500 },
  );
});

/** ADR-014: attribute values with markup stay attribute text and parse nothing. */
test("adr014_dom_attribute_values_never_become_markup", async () => {
  const d = await dom();
  forAll(
    markupish,
    (s) => {
      freshDom();
      const el = asFake(d.h("div", { title: s, "aria-label": s }));
      eq(el.getAttribute("title"), s, "title kept");
      eq(el.childNodes.length, 0, "no children");
      eq(elementsCreated(), 1, "one element created");
      eq(sinkUses, [], "no HTML sink reached");
    },
    { runs: 300 },
  );
});

/**
 * ADR-014: the page's one Trusted Types policy is `fstp-dom`, matching the
 * CSP `trusted-types fstp-dom`, and it refuses every HTML string, script
 * and script URL. Installing twice makes one policy, and a browser without
 * Trusted Types is left alone.
 */
test("adr014_trusted_types_policy_refuses_every_html_string", async () => {
  const d = await dom();
  eq(d.TRUSTED_TYPES_POLICY, "fstp-dom", "policy name");
  const made: { name: string; rules: Record<string, unknown> }[] = [];
  const g = globalThis as unknown as Record<string, unknown>;
  g["trustedTypes"] = {
    createPolicy(name: string, rules: Record<string, unknown>) {
      if (made.some((p) => p.name === name)) {
        throw new TypeError(`policy ${name} exists`);
      }
      made.push({ name, rules });
      return { name, ...rules };
    },
  };
  try {
    d.installTrustedTypesPolicy();
    d.installTrustedTypesPolicy();
    eq(made.map((p) => p.name), ["fstp-dom"], "exactly one policy, named fstp-dom");
    const rules = made[0]?.rules ?? {};
    for (const k of ["createHTML", "createScript", "createScriptURL"]) {
      const f = rules[k];
      if (f === undefined) {
        continue;
      }
      assert(typeof f === "function", `${k} is a function`);
      for (const input of ["", "<b>x</b>", "<img src=x onerror=alert(1)>", "alert(1)", "/app/x.js"]) {
        let returned = false;
        try {
          (f as (s: string) => unknown)(input);
          returned = true;
        } catch {
          // Refused, as required.
        }
        assert(!returned, `${k} accepted ${show(input)}`);
      }
    }
  } finally {
    delete g["trustedTypes"];
  }
  d.installTrustedTypesPolicy();
});

/**
 * ADR-014 (DOM clobbering, interim pending Daniel): an `id` or `name` that
 * would shadow a member of a form, a node or the window is refused, and so
 * is one that is not a whitespace-free token.
 */
test("adr014_dom_refuses_clobbering_ids_and_names", async () => {
  const d = await dom();
  const values = [
    "submit", "action", "method", "elements", "reset", "requestSubmit", "length", "name", "id",
    "appendChild", "cloneNode", "addEventListener", "__proto__", "constructor",
    "toString", "hasOwnProperty", "trustedTypes", "matchMedia", "document", "querySelector",
    "textContent", "", " x", "a b", "1a", "-a", "a/b", "a\u0000", "aé",
  ];
  for (const v of values) {
    for (const attr of ["id", "name"]) {
      eq(refusalCode(d, () => d.h("input", { [attr]: v }), `${attr} ${show(v)}`), "attribute", `code for ${attr} ${show(v)}`);
    }
  }
  eq(refusalCode(d, () => d.h("input", { id: true }), "id true"), "attribute", "a boolean id");
  eq(asFake(d.h("input", { id: "cap-error", name: "P-04.amount_2" })).getAttribute("name"), "P-04.amount_2", "a token passes");
  eq(sinkUses, [], "no HTML sink reached");
});

/** ADR-014 (DOM clobbering): `form` and `img` take no `name`, since `document` exposes it. */
test("adr014_dom_refuses_name_on_form_and_img", async () => {
  const d = await dom();
  eq(refusalCode(d, () => d.h("form", { name: "draft" }), "form name"), "attribute", "form name");
  eq(refusalCode(d, () => d.h("img", { name: "logo", src: "/x.png" }), "img name"), "attribute", "img name");
  eq(refusalCode(d, () => d.h("img", { name: "body", src: "/x.png" }), "img name body"), "attribute", "img name body");
  eq(asFake(d.h("form", { id: "draft-form" })).getAttribute("id"), "draft-form", "a form id passes");
});

/** ADR-014, R-NF-03: a skip link to `#main` builds, since a fragment-only link stays on the page. */
test("adr014_dom_builds_skip_link_to_fragment", async () => {
  const d = await dom();
  eq(asFake(d.h("a", { href: "#main" }, ["Skip to content"])).getAttribute("href"), "#main", "skip link href");
  eq(refusalCode(d, () => d.h("a", { href: "#javascript:alert(1)" }), "fragment with a colon"), "url", "fragment with a colon");
});
