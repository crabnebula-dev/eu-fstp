# ADR-034: The funding card in every footer

Status: Proposed. Drafted 2026-11-22 by lane L29 (`prod/funding-card`) before its code, as CLAUDE.md asks. Rows marked "Interim, pending Daniel" wait for his answer.

The number is the next free one: ADR-032 and ADR-033 are taken by other lanes' branches.

## Context

- Daniel, 2026-11-22, supplied the "Funded by the European Union" logo: the EU flag and the words, as an Inkscape SVG. The text paths are black on a transparent ground. The flag sits on its own white box. He asked: "display on footer, always include the Grant Number and the name / contact of the coordinator in the card", and "show the privacy@crabnebula.dev contact".
- He did not choose the European Commission or DG Connect logo. This ADR does not use it.
- ADR-030 (lane L22) left a fixed platform slot for the EU emblem on public pages and in PDFs (`fstp_brand::emblem::EU_EMBLEM_PNG`, empty until supplied) and a placeholder for the funding acknowledgement (L-08). Daniel approved the acknowledgement on 2026-11-22 (ADR-036).
- The programme creator already holds the action number (`funder.action_number`, the grant agreement number) and the coordinator's name (`funder.coordinator_name`) in step 1. It holds no coordinator contact. `comms.contact` is the programme's contact channel for applicants, which is a different thing.
- Binding invariants: I-68 (branding is data only), I-69 (branding cannot remove mandatory elements of the funder profile, nor the platform attribution), I-70 (AA contrast in both themes). R-WL-04 (platform attribution in every footer) and R-NF-04 (accessibility) apply.

## Decision

### 1. The asset

| Topic | Decision |
| --- | --- |
| Origin | Supplied by Daniel on 2026-11-22 as `funded-by-eu.svg`. Vendored unchanged in `third_party/eu-emblem/funded-by-eu.svg`. It is a platform asset, never tenant data. I-68 binds tenant-supplied markup only |
| Web copy | `crates/fstp-brand/assets/funded-by-eu.svg`: the vendored file with the Inkscape comment, the `sodipodi:namedview` element, every `inkscape:` and `sodipodi:` attribute and their two namespace declarations removed. Paths, colours, the transform, the view box and the size are unchanged. A test compares every path's `d`, `fill` and `style`, the group transform and the view box with the vendored original, and checks that no script, link, event attribute or Inkscape name remains |
| Serving | `GET /brand/funded-by-eu.svg` as `image/svg+xml`, with the `/brand` surface's `nosniff` and CSP. Pages show it with `<img>`, so no script in it could run in any case. Cached for a day, since it is not named by digest |
| PNG for PDFs and emails | `crates/fstp-brand/assets/funded-by-eu.png`, 1166 by 240 pixels, RGB, opaque on white. It was rasterised once with a local browser, and the PNG is committed. The browser is not a product dependency and never runs in a build or test. The file holds only `IHDR`, `IDAT` and `IEND` |
| Rasterise command | An HTML wrapper `wrap.html` beside a copy of the SVG: `<img src="funded-by-eu.svg">` styled `display:block;width:1166px;height:240px`, on a body with no margin and a white ground. Then `"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 --default-background-color=ffffffff --window-size=1166,240 --screenshot=out.png file://$PWD/wrap.html`. Any rerun must keep the size, the white ground and the absence of ancillary chunks |
| Why a PNG and not PDF paths | The SVG uses only `M m H h V v L l C c Z z`, so in-house conversion to PDF path operators would be sound. But emails need a raster image anyway, and ADR-030 already places a PNG in PDFs. One committed PNG serves both with no new code path |
| Slot | `EU_EMBLEM_PNG` now holds the PNG. `/brand/eu-emblem.png` serves it, and the PDF letterhead places it on the right as ADR-030 section 6 describes |
| Alternative text | "Funded by the European Union", the words the artwork shows. It replaces ADR-030's "Emblem of the European Union" |
| Colours | Never recoloured, never inverted in dark mode, never filtered. The card is white in both themes (section 4) |
| Usage rules | Applied by lane L35 on 2026-11-22 from the official source in section 1a. The logo is at least 1.08 cm high, so its flag is at least 1 cm. Its clear space is at least 30.3 % of its height on every side. The 32 px and 8 px placeholders are gone |

### 1a. Emblem usage rules (L-08, applied 2026-11-22)

Source, read by lane L35 on 2026-11-22 as Daniel asked:

- Title: "The use of the EU emblem in the context of EU programmes 2021-2027. Operational guidelines for recipients of EU funding". European Commission, March 2021.
- URL: https://commission.europa.eu/document/download/3192a0ef-6bda-4e1a-81ca-65ade2ffad73_en?filename=eu-emblem-rules_en.pdf

The rules this record applies, quoted from that document:

| Rule (page) | Quoted text | How the card meets it |
| --- | --- | --- |
| Minimum size (p. 9) | "The minimum height of the EU emblem must be 1 cm." | The flag is 44 of the artwork's 47.519501 units of height. Pages: the logo has `min-height: 1.08cm` (`fstp_brand::funding::EMBLEM_MIN_HEIGHT`), and is 2.5rem or 3rem high. Emails: 48 px, above 1.08 cm (41 px). PDFs: 40 pt, so the flag is 37 pt, 1.31 cm. Tests: `l08_emblem_minimum_height_keeps_the_flag_one_centimetre`, `l08_mail_logo_keeps_size_and_clear_space`, `l08_pdf_letterhead_keeps_the_flag_one_centimetre` |
| Protection area (p. 9) | "The protection area must remain free of competing texts, logos, images or any other visual element that could compromise its good legibility." | The figure marks the area as a margin x and gives no number. The card keeps at least the artwork's own gap between the flag and the words, 30.3 % of the logo's height, on every side: a margin of 0.76rem around a 2.5rem logo and 0.91rem around a 3rem one (`EMBLEM_CLEAR_SPACE`). Emails: 12 px padding plus a 4 px margin above and left, 15 px right and below. PDFs: 16 pt below the band and the page margins above and right. Interim, pending Daniel: the reading of x |
| Contrast and white border (p. 5) | "Sufficient contrast should be ensured between the EU emblem and the background. If there is no alternative to a coloured background, a white border must be placed around the flag, with the width of this being equal to one 25th of the height of the rectangle." | The card is white in both themes. The supplied artwork already has a white border of 1.76 units around the 44-unit flag, which is one 25th |
| Font colour (p. 5) | "The colour of the font should be Reflex Blue (the same blue colour as the European flag), white or black depending on the background." | The artwork's words are black on white. The artwork is never recoloured |
| Colour versions (pp. 6 and 7) | The document shows a positive version, a negative version on a dark ground and monochrome versions. | The card always uses the positive version on white, so no dark-ground version is needed. Interim, pending Daniel: if the logo is ever placed on a dark ground, the negative version is needed. The repository does not hold it |
| Other logos (p. 4) | "If other logos are displayed in addition to the EU emblem, the latter must be at least the same size as the biggest of the other logos." | Pages: tenant logos are 2rem high and at most 12rem wide; the EU logo is 2.5rem or 3rem high and about 14.6rem wide. Emails: tenant logos 40 px high, the EU logo 48 px. PDFs: every logo is 40 pt high. Interim, pending Daniel: a PDF tenant logo can be up to 200 pt wide, 6 pt wider than the EU logo |
| Placement (p. 11) | "The EU emblem, in conjunction with the funding statement, must be prominently featured on all communication material, such as printed or digital products or websites and their mobile version, intended for the public or for participants." It adds: "It is therefore recommended to place the EU emblem at a distance from the third-party organisation's logo." | The card is in the footer of every page, in contract PDFs and in programme emails (section 4). The tenant logo is in the top bar, far from the card |
| Programme name (p. 10, "Don'ts") | "Do not write the name of the programme in conjunction with the EU emblem." | The document's example names an EU programme. The card shows the FSTP programme's name as its own line, outside the logo's clear space. Interim, pending Daniel |

Open in PDFs, pending Daniel: with two wide tenant logos, the left logos of the letterhead could reach the EU logo's clear space. The writer does not shrink them yet.

### 2. What the card shows

One card per programme:

| Line | Source |
| --- | --- |
| The logo | Section 1 |
| The programme name | `identity.name` |
| "Grant agreement number" | `funder.action_number`. For the pilot: SuperSAFE 101342989, ELFA 101298715. The pilot admins enter these in step 1 |
| "Coordinator" | `funder.coordinator_name` |
| "Contact" | `funder.coordinator_contact`, a new step 1 field (section 3) |
| The acknowledgement | Approved by Daniel, 2026-11-22, with no disclaimer (L-08, ADR-036): "{{programme.name}} is funded by the European Union under the Horizon Europe grant agreement {{action.number}}, {{action.acronym}}." It is the last line of the card on pages, in PDFs and in emails. A programme that lacks a value shows no sentence. The branding page names the missing value |

The labels "Grant agreement number", "Coordinator" and "Contact" are interface labels, not legal wording.

### 3. The coordinator contact and the tenant defaults

| Topic | Decision |
| --- | --- |
| New field | `funder.coordinator_contact`: narrative text, an artefact field of step 1, not importable. Like every field, a gap is a `FieldUnset` failure, so activation is refused until it holds a value (I-66). Its text is held outside ledger bodies like the coordinator's name (ADR-007), since a contact can name a person |
| Older specs | A spec or template text written before the field existed has no `coordinator_contact` member. The decoder reads that one missing member as a gap. Every other member stays required |
| Tenant defaults | A tenant record `FundingDefaultsSet { name, contact }` through the operation `tenant.set_funding_defaults`. Each value is 1 to 200 bytes of text with no control character and no angle bracket |
| Who and how | A tenant admin, on the web, with a step-up, like `tenant.set_guide_notice`. The form sits on the branding page under "Funding card". No MCP tool |
| What the defaults do | (a) The creator's step 1 page fills an empty coordinator name and contact with the defaults, so a new programme needs no typing; the admin saves the step as usual. (b) A programme that was activated before the contact field existed shows the default contact on its card |
| The pilot | The pilot tenant sets "CrabNebula Ltd" and "privacy@crabnebula.dev" on the branding page once. Shared code holds neither value. The demo cell seeds them for the demo tenant |

Interim, pending Daniel: the defaults are kept inline in the ledger record, not in the text store. They are meant to name an organisation and a role address. The form says so: "Use an organisation name and a role address such as privacy@, not a person."

### 4. Where the card shows

| Surface | Programme in context | Card |
| --- | --- | --- |
| Public pages `/p/{slug}/...` | Always: the page's programme | That programme's card, rendered by the server in the footer |
| App pages `/app/programmes/{programme}/...` | That programme | That programme's card |
| Other app pages | None | One compact card per active programme of the tenant, as a list |
| Sign-in pages `/auth/...` | None | One compact card per active programme, as a list |
| Vault pages | None | None. They run on another origin with no programme context, and their CSP admits only the vault origin. Interim, pending Daniel |
| Contract PDFs | The contract's programme | The logo in the letterhead's emblem slot, and the card's lines as the first paragraphs under the band. They are tagged `/P`, so a screen reader reads them |
| Emails about a programme | That programme | The logo as an inline image and the card's lines at the foot of the HTML part, and the same lines at the foot of the plain-text part |

Before the organisation is activated (ADR-021), no programme is active, so the list is empty and no card shows.

The app and sign-in pages read `GET /brand/funding`, a JSON answer of the `/brand` surface with no session needed, like `/brand/logo/light`. It holds `cards` (programme id, name, grant agreement number, coordinator name and contact, for each active programme) and `defaults` (the tenant defaults or `null`). Everything in it is shown on public pages anyway. It is sent with `no-store`.

### 5. Markup, contrast and accessibility

- The card is a `section` with `aria-label` "EU funding", inside the footer. It holds the logo as `<img alt="Funded by the European Union">` and the lines as a `dl` of label and value. The sign-in pages, whose element allowlist has no `dl`, write each line as a paragraph "Label: value". Screen readers read the alternative text, then each label with its value.
- On the public pages the card is keyed `data-mandatory="funding_card"` itself. On app and sign-in pages the footer part that holds the cards carries the key, once.
- The card's ground is `#ffffff` in light and dark. Its text is `#1f2328` and its labels `#4b5563`, fixed colours that no brand token and no theme changes. A test checks each pair with `fstp_creator::meets_aa` for the card in both themes (I-70).
- Values are always text nodes, never markup (I-68).

### 6. I-69

- The card is built by platform code after branding, inside the footer of mandatory elements, keyed `data-mandatory="funding_card"`. No brand token, logo or terminology override can hide, name, size or reorder it.
- The horizon-europe funder profile lists the visibility elements `acknowledgement` and `emblem`. The card is how the platform shows both.
- A programme cannot be activated, and so cannot publish a call, while its grant agreement number, coordinator name or coordinator contact is unset. The check list says in plain words what to fill in, for example: "Fill in the grant agreement number in step 1, Funder and instrument. It appears on the funding card in every footer."

## Consequences

- One new field, one new tenant record and one new operation. No new crate, no new table and no new MCP tool.
- Contract PDFs drafted before this change re-render with the logo in the emblem slot. Contracts capture the letterhead when a version is drafted (ADR-030 section 6), so a drafted version keeps the digest it recorded.
- Tests carry I-68, I-69, I-70, R-WL-04 and R-NF-04 in their names.

## Open questions for Daniel

1. Answered: Daniel approved the funding acknowledgement on 2026-11-22, with no disclaimer (L-08). ADR-036 stores it and shows it.
2. Answered: the emblem usage rules come from the official source in section 1a, applied on 2026-11-22. The readings marked "Interim, pending Daniel" there remain.
3. Interim, pending Daniel: vault pages show no card (section 4).
4. Interim, pending Daniel: the tenant defaults sit inline in the ledger (section 3).
5. Decided by the lead on 2026-11-22 (usability): a contact that is one e-mail address is a `mailto:` link on web pages. Only the `href` of an `a` takes it, for one address with no query, in `fstp_html` (`SafeUrl::mailto`, checked again by the well-formedness check) and in both DOM builders (`mailtoHref`). Any other contact stays text. Emails and PDFs show it as text.
6. Interim, pending Daniel: `tenant.set_funding_defaults` asks for a step-up like the other tenant settings.
7. Interim, pending Daniel: only the contract PDF carries the card, as only it carries a letterhead (ADR-030 open question 7). Funder reports and the Guide PDF get it when their letterhead is pinned in their records.
8. Interim, pending Daniel: the demo cell seeds the defaults "CrabNebula Ltd" and "privacy@crabnebula.dev" for its tenant. They name an organisation and a role address, not a person.
9. Interim, pending Daniel: the protection area's x is read as the artwork's own gap between the flag and the words (section 1a).
10. Interim, pending Daniel: no dark-ground version is used, since the card is white in both themes. A placement on a dark ground needs the official negative version, which the repository does not hold (section 1a).
11. Interim, pending Daniel: the card shows the FSTP programme's name on its own line, outside the logo's clear space. The guidelines forbid writing "the name of the programme in conjunction with the EU emblem" (section 1a).
12. Open, pending Daniel: in a contract PDF with two wide tenant logos, the left logos could reach the EU logo's clear space, and a tenant logo can be up to 6 pt wider than the EU logo (section 1a).
