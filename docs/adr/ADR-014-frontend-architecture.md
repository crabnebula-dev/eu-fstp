# ADR-014: Frontend architecture and delivery

Status: Accepted 2026-10-29 (Daniel Thompson-Yvetot).

The M4 design numbered this ADR ADR-009. M3 had already used ADR-008 to ADR-012, so it is ADR-014 (`docs/handoff/m4-design.md` section 15.0). Daniel accepted it on 2026-10-29 as design section 3.9 describes it. This text states what sections 3.9 and 10 of that design state. Where 3.9 points to section 1.1 or 9 for a detail, the text names that section. The two sections marked "Repository reading" are interim readings of the repository, not part of what Daniel accepted.

## Context

- `.claude/CLAUDE.md` sets the frontend: in-house TypeScript, no framework, compiled with the TypeScript compiler (ADR-003). TypeScript counts as JavaScript for the language rule.
- M4 builds the JSON API and a TypeScript application for every role up to NEGOTIATION (design section 0.4).
- ADR-003 allowlists tsc and Playwright. Its amendment of 2026-10-28 makes Node.js and npm build and test hosts, with npm projects only in `web/` and `e2e/`.

## Decision

The application in `web/` has no framework, no bundler and no runtime dependency. It governs `web/` and `fstp-web-assets`.

### Layout

- `web/src/core/` holds `dom.ts`, `router.ts`, `store.ts`, `api.ts`, `i18n.ts`, `a11y.ts`, `money.ts`, `forms.ts` and `stepup.ts`.
- Feature folders are `web/src/{onboarding,creator,people,calls,applicant,coordinator,reviewer,committee,irc,admin,auditor,agents}/`.
- Generated code is in `web/src/gen/api.ts`: the generated operation types (section 10). `tools/gen-ts` writes it from `OPS`: types, operation table, route segments and structural validators. CI runs its `--check` (section 1.1).
- Tests are in `web/test/` and `web/e2e/`. The repository reading below places `web/e2e/` at `e2e/`.
- The TypeScript tests run on the in-house test runner (section 10), with the Node.js host of the ADR-003 amendment.
- The in-house fuzz harness is in `web/fuzz/`.

### Compiler

- tsc with `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes` and `noImplicitOverride`. `web/tsconfig.json` carries these options.
- Target and module ES2022. The output is native ES modules in `web/dist/`.

### DOM

- `dom.ts` offers `h(tag, attrs, children)` with tag and attribute allowlists.
- Text goes in through `textContent` only.
- URLs go through `safeUrl`, which allows same-origin paths and `https:`.
- The page sets `require-trusted-types-for 'script'` with one policy that refuses every HTML string.
- The source scan blocks the banned sinks.

### Parsers in TypeScript

These modules parse input, and each has a target in the in-house harness `web/fuzz/` (Q33). The target names are those of section 9:

| Module | Input | Fuzz target |
| --- | --- | --- |
| `money.ts` | ADR-006 strings | `money_parse.fuzz.ts` |
| `dom.ts` `safeUrl` | URLs | `safe_url.fuzz.ts` |
| `router.ts` | paths against generated segments | `router_match.fuzz.ts` |
| `gen/api.ts` validators | server JSON after `JSON.parse` | `validators.fuzz.ts` |
| `i18n.ts` | message placeholders | `message_format.fuzz.ts` |

Where a Rust parser exists for the same grammar, a differential test runs both on the same corpus: `money.ts` against `fstp-money`, and `safeUrl` against the subset of the `fstp-oauth` URL parser. The harness is the interim answer to Q33. It has no coverage feedback.

### Money

`money.ts` handles ADR-006 strings only. The browser never computes money. Totals and P-04 checks come from the server.

### Step-up

On `step_up_required`, `stepup.ts` runs the M3 WebAuthn ceremony for the challenge's digest and retries once. On `strong_method_required`, it sends the user to add a passkey first. Adding a passkey is itself a high-risk action under M3's enrolment rules.

### Shell, assets and headers

- `/app/` serves a shell with one `<script type="module">` and no inline script.
- Assets are at `/app/assets/{sha256}.js` and are immutable. `fstp-web-assets` verifies them at start, against the asset manifest (section 10).
- Headers on `/app`: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types fstp-dom`.
- Also `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin` and HSTS.

### CSRF

M3's `__Host-` session cookie carries `Secure`, `HttpOnly`, `SameSite=Strict` and `Path=/`. State-changing requests need an `Origin` equal to the tenant origin and an `X-FSTP-Request: 1` header.

### Accessibility and localisation

- Accessibility (R-NF-03): landmarks, labelled controls, error summaries linked to fields, visible focus, live regions, keyboard reachability, no colour-only state and reduced motion.
- Localisation (R-NF-04): catalogues per locale. Interface strings are `Label`. Approved wording is `ApprovedText` and is never overridable (I-72 seam).

### Footer

- Every page shows the privacy notice, the accessibility statement and the platform attribution (P-68, R-WL-04, I-69 seam).
- It also shows the AI disclosure where findings appear, the Data Act information for tenant admins, and the funder visibility elements that the funder profile requires.
- The shell takes a `MandatoryElements` value with no optional fields.
- The privacy notice, accessibility statement, Data Act information and funder visibility texts carry `TODO(legal)` until Daniel supplies approved wording.

### Desktop client seam (M9)

The Tauri client of `desktop-client.md` cannot use the `__Host-` cookie, the `Origin` rule or this CSP. It will sign in as an OAuth 2.1 native public client through `fstp-oauth`, with PKCE and a loopback redirect. "Signing in the desktop client" is a high-risk step-up (`authentication.md`). It then calls `/api/v1` with a bearer token as `Via::Web`, since it shows the same interface. That token has its own audience, so an MCP token can never act as a desktop token (RFC 8707 binding). Bearer requests need no CSRF defence. This ADR records the seam. M4 builds none of it.

## Repository reading: one Playwright project

The M4 design places Playwright specs under `web/e2e/**` and names `web/playwright.config.ts`. The ADR-003 amendment allows npm projects only in `web/` and `e2e/`, and the lead landed the Playwright project at the top-level `e2e/`. So the repository has one Playwright project:

- every `web/e2e/<path>` of the M4 design means `e2e/<path>`;
- `web/playwright.config.ts` means the configuration of the `e2e/` project;
- `web/` stays the tsc project of the application and holds no Playwright dependency.

## Repository reading: the source scan's strict additions

Section 1.1 lists what the source scan refuses. `tools/deps-check/src/web_scan.rs` reads that list strictly, as an interim pending Daniel:

- It also refuses `setHTMLUnsafe`, `parseHTMLUnsafe` and `createContextualFragment`.
- It compares string literals after decoding their escapes. It refuses `eval`, `Function`, `write` and `writeln` as computed string keys of any object.
- It refuses a backslash outside a literal, a file it cannot lex to the end, and a JavaScript or TSX file below `web/src`.
- It refuses `on*` words by prefix, so a handler that HTML adds later is refused too. These words pass: `on`, `one`, `once`, `only`, `online`, `onto`, `onset`, `ongoing`, `onward`, `onwards`, `onboard`, `onboards`, `onboarded` and `onboarding`. The `onboard` words name the `onboarding` feature folder of section 3.9.

## Enforcement

- The source scan of section 1.1 is `tools/deps-check/src/web_scan.rs`. It scans every file below `web/src`. It fails on `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, string timers, `on*` attribute strings and imports from outside `web/src`. Its fuzz target is `ts_token_scan` in `tools/deps-check/fuzz` (section 9).
- The npm lockfile gate of section 10: `tools/deps-check/src/npm.rs`, `npm ci --ignore-scripts` and `deps/npm-allowlist.txt`.

## Consequences

- The application has no runtime dependency. tsc and Playwright stay build and test tools (ADR-003).
- Each TypeScript parser target exists from the module's first commit (section 9). The harness stands in for a coverage-guided fuzzer, pending Q33.
