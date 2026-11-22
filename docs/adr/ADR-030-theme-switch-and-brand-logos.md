# ADR-030: Theme switch and brand logos

Status: Proposed. Drafted 2026-11-22 by lane L22 (`prod/branding-theme`) from Daniel's request of 2026-11-21: "I also need us to have a light mode and space for branding." Rows marked "Interim, pending Daniel" wait for his answer.

The number is the next free one: ADR-028 and ADR-029 are taken by lanes L19 and L20.

## Context

- Light and dark token sets exist in `web/src/site/tokens.css` and `web/src/auth/tokens.css`. Each follows `prefers-color-scheme` unless `:root[data-theme]` names a mode. Nothing sets `data-theme` yet.
- `fstp-brand` holds the tenant name and the brand colour family in light and dark (M9 decisions D1 and D2). D2 deferred logos to the full white-label package (B-09).
- Daniel decided on 2026-11-21: a System, Light and Dark switch per person, remembered for the account. A tenant logo in light and dark, a logo per programme, a fixed slot for the EU emblem and the funding acknowledgement, and the logo and colours in emails and PDFs.
- Binding invariants: I-68 (branding is data only), I-69 (mandatory elements stay), I-70 (AA contrast in both themes), I-72 and I-94 (approved wording stays). R-WL-01 stays deferred (B-09).
- `white-labelling.md` says images are re-encoded on upload. Re-encoding needs an image decoder and encoder. No allowlisted crate offers one, and the dependency policy forbids a new one without an ADR.

## Decision

### 1. Theme preference

| Topic | Decision |
| --- | --- |
| Values | `system`, `light`, `dark`. The default is `system` |
| Where it is kept | A tenant record `ThemeSet { account, theme }` in the tenant ledger. The tenant state keeps the latest value per account. So it follows the person across devices, and backups carry it with the ledger |
| Operation | `me.set_theme`, an action open to any signed-in account for its own preference. Class `Personal`, not high-risk, web only, no MCP tool. The switch sends it only on a change. Before the organisation is activated, the setup gate of ADR-021 refuses it as it refuses every operation outside onboarding |
| No flash | The `/app/` shell is written with `data-theme="light"` or `data-theme="dark"` on `<html>` when the session's account chose one. `system` writes no attribute, so the CSS media query decides. No inline script, no cookie and no browser storage are used |
| Where the switch is | The sidebar foot of every `/app/` page, beside Account: a group of three radio buttons named "Theme". A change applies at once and is then saved |
| Public pages `/p` | System. They read no cookie and run no script (`script-src 'none'`) |
| Sign-in pages `/auth` | System. The auth shell is a static file. Interim, pending Daniel: a signed-in auth page could read the preference later. The tenant logo shows there from the stable paths `/brand/logo/light` and `/brand/logo/dark`, which answer the current logo uncached, or 404 |
| Vault origin pages | System. They run on another origin, which never sees the app session |
| Emails and PDFs | Light only. A message or a document has no viewer preference |

Interim, pending Daniel: a ledger record for a display preference. The alternative is a new table beside the ledger. The record was chosen because the cell keeps no other durable per-account store that the production cell implements (display names still fail closed there), and because the tenant fold answers the shell without a database round trip.

### 2. Logo slots

| Slot | Where it shows |
| --- | --- |
| Tenant logo, light | App header, sign-in pages, public pages, emails, PDFs |
| Tenant logo, dark | App header and public pages in dark mode. Without it, the light logo shows in both modes |
| Programme logo, light and dark | The programme's public pages and calls, beside the tenant logo. Emails and PDFs that belong to the programme |
| EU emblem | A fixed platform slot on public pages and in PDFs. The image is a platform asset Daniel supplies. Until then the slot renders nothing |
| EU funding acknowledgement | A fixed platform slot beside the emblem. TODO(legal) (L-08): the wording is a placeholder on pages and nothing in PDFs until Daniel supplies approved text |

Interim, pending Daniel: only a tenant admin sets a programme logo, from the tenant admin branding page. The programme set-up progress page links there, and the page gate shows the link only to a viewer it admits. Programme managers may get the right later.

### 3. Image rules (I-68)

| Rule | Value |
| --- | --- |
| Formats | PNG and WebP only. SVG, GIF, JPEG and every other format are refused |
| Size | At most 256 KiB (262 144 bytes) |
| Dimensions | Width and height each from 16 to 2048 pixels |
| PNG check | Signature, `IHDR` first with a valid bit depth and colour type, a CRC on every chunk, `PLTE` where the colour type needs it, contiguous `IDAT`, `IEND` last with nothing after it. An unknown critical chunk is refused |
| WebP check | `RIFF` length equal to the file, form `WEBP`, chunk lengths in bounds. Simple lossy (`VP8 ` key frame), simple lossless (`VP8L` version 0), or extended (`VP8X`) with an optional `ALPH` and one image chunk. Animation is refused. The canvas size must equal the bitstream size |
| Rewrite on upload | The stored file keeps only the chunks that draw the image: PNG `IHDR`, `PLTE`, `tRNS`, `gAMA`, `sRGB`, `IDAT`, `IEND`; WebP `VP8X` (flags reduced to alpha), `ALPH`, and the image chunk. Text, EXIF, XMP, ICC and animation chunks are dropped. Pixel data is never decoded |
| Parser | In-house in `fstp-brand::image`, a header and chunk walk only. Fuzz target `logo_inspect` from the first commit |
| Serving | `GET /brand/{sha256}.png` or `.webp`, only for a digest a current logo names. The content type comes from the checked format, never from the request. The `/brand` surface keeps `nosniff` and its CSP. Immutable caching. Tenant bytes never enter HTML or CSS text |
| Routing | The cell front sends every `/brand/` path to the web adapter. Before this lane it sent none, so the brand stylesheet of M9 lane B2 answered 404 in a production cell |
| Preview | The admin page draws the chosen file on a `canvas` from an `ImageBitmap`. `canvas` joins the tag allowlist of `web/src/core/dom.ts`. The CSP stays as it is, with no `blob:` or `data:` image |
| Storage | The rewritten bytes go to the blob store under a new owner `Brand`, sealed like every other blob in `doc.blob` (kind 6). The ledger record holds the digest, format and size only. Base backups and WAL archives carry both. Tenant export (B-07) is deferred and will carry them when it returns |

Interim, pending Daniel: `white-labelling.md` asks for re-encoding. The chunk rewrite removes metadata and hidden payload chunks, but it keeps the encoded pixel data as uploaded. A full re-encode needs a decoder this lane may not add.

Interim, pending Daniel: the server cannot measure the contrast of a logo against the header, since that needs decoded pixels. The admin page draws the chosen file on a canvas through the browser's own decoder, shows it on the light and dark header colours, and warns in plain words when the estimated contrast is low. The warning advises. It does not refuse. I-70 binds text colour pairs, and a logo is an image with the tenant name as its text alternative.

### 4. Operations

| Operation | Kind | Who | Notes |
| --- | --- | --- | --- |
| `tenant.branding.logos` | Read | Tenant admin | The current logos of the tenant and of each programme, with their paths, formats and sizes, and whether each can appear in PDFs and emails |
| `tenant.branding.set_logo` | Action | Tenant admin | Sets or clears one slot. High-risk by the same strict reading as `tenant.branding.set`: it changes what every interface shows. So it needs a step-up and runs on the web only |
| `me.set_theme` | Action | Any account, for itself | Section 1 |

No MCP tool is added. `fstp_prepare_branding` stays for the colour tokens only. Interim, pending Daniel: a prepared logo would carry up to 350 KiB of base64 through the agent, and the admin must see the image before it applies.

### 5. Emails

- `fstp_mail::MailConfig` gains an optional brand: the tenant name, the brand colour and up to two PNG logos (tenant, then programme).
- The HTML part then opens with a header: the logos as inline images, each with the tenant or programme name as `alt`, above a rule in the brand colour. The images travel in a `multipart/related` part with fixed `Content-ID`s, so no remote image is fetched and no open is tracked.
- The plain-text part and every approved text stay unchanged (I-72, I-94). Emails carry no platform attribution (`white-labelling.md`).
- A WebP logo is left out of emails, since common mail clients do not show WebP. The name stays as text.

### 6. PDFs

- `fstp_pdf::write_with_letterhead` places the logos at the top of the first page, marked as artifacts. The text starts below them. `fstp_pdf::write` is unchanged.
- A PNG logo is embedded by passing its `IDAT` bytes through as one `/FlateDecode` stream with `/DecodeParms << /Predictor 15 /Colors c /BitsPerComponent b /Columns w >>`. This is the only filtered stream in the file. No image is decoded in-house.
- Embeddable: PNG colour types 0 (grey), 2 (RGB) and 3 (palette), bit depths up to 8, not interlaced. A `tRNS` chunk that marks exactly one fully transparent colour becomes a colour-key `/Mask`.
- Not embeddable without a decoder: PNG with an alpha channel (colour types 4 and 6), partial palette transparency, interlaced PNG, 16-bit depth, and WebP. Such a logo is left out of the PDF and the admin page says so in plain words. Interim, pending Daniel: logos with soft transparency need either a second, flat logo upload or an allowlisted inflate.
- Contracts capture the letterhead when a version is drafted, so the digest the draft records equals the digest of revision 0 even when the logo changes before sending.
- The EU emblem slot takes a platform PNG under the same rules. The constant is `None` until Daniel supplies the file.

### 7. Unchanged

- The footer of mandatory elements (I-69) is built from platform data after branding. No logo can hide, name, size or reorder it. The platform attribution stays (P-68, R-WL-04).
- Brand tokens, the I-70 pair table, CSP values and the approved wording catalogues are unchanged.

## Consequences

- A tenant admin uploads a logo with a file control and sees it at once on light and dark headers. Refusals are plain: "This file is too big", "Only PNG or WebP images can be used", "This image is too small or too large".
- No new crate, no new table and no new MCP tool.
- Tests carry I-68, I-69, I-70, R-WL-03 and R-WL-04 in their names.

## Open questions for Daniel

1. Theme preference as a ledger record, or a table beside the ledger (section 1).
2. Chunk rewrite instead of re-encoding (section 3).
3. Contrast of a logo: advise in the browser, or refuse on the server once a decoder is allowed (section 3).
4. Programme managers setting their programme's logo (section 2).
5. Logos with soft transparency in PDFs (section 6).
6. The EU emblem file, its alternative text and the usage rules. TODO(legal): the emblem usage rules and the acknowledgement wording (L-08).
7. Interim, pending Daniel: only the contract PDF carries the letterhead. Funder reports and the Guide PDF are pinned and re-rendered from their records, so their letterhead must first be pinned in those records. That is left for a later lane.
8. Interim, pending Daniel: the PostgreSQL matrix sample leaves the three ADR-030 operations out. With them, the sample reaches `me.set_display_name` in a production cell, whose text store keeps no display names yet and fails closed under SA-11. That is a gap of the cell for the lead. The matrices over fake ports cover the three operations.
9. Interim, pending Daniel: no MCP prepare tool for logos (section 4).
