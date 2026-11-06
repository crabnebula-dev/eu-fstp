# Request 05: licensing

Attach before sending:
- `LICENSE.md` (PolyForm Noncommercial License 1.0.0)
- `Cargo.toml` (the licence declaration)
- `docs/adr/ADR-016-vendored-libpdf.md` and `docs/adr/ADR-017-pdf-font.md`
- `web/vendor/libpdf/LICENSE.md`, `web/vendor/libpdf/src/fontbox/LICENSE.md` and `web/vendor/libpdf/src/fontbox/NOTICE`
- `SPEC/schemas/README.md` (the EUPL-1.2 export schema and tooling)

---

## Prompt

You are an expert in open source and software licensing. Please answer the numbered items below.

**Context.** CrabNebula Ltd ([seat of CrabNebula Ltd]) licenses its platform under the PolyForm Noncommercial License 1.0.0. The platform vendors a copy of LibPDF (MIT) into its web frontend. LibPDF's font module is Apache-2.0, derived from Apache PDFBox, and it ships no NOTICE file of its own, so the vendored copy adds PDFBox's NOTICE. The platform embeds one font, IBM Plex Sans Regular under the SIL Open Font License 1.1, unmodified, in the PDFs it gives to grantees and the public. A separate export schema and its import and export tooling are licensed under EUPL-1.2 and must stay separate from the platform code.

**Rules for your answer.**
- Cite licence sections precisely. If you are unsure, say so.
- Keep each item's ID exactly as written.

**Items.**

LC1. PolyForm Noncommercial 1.0.0 expects a `Required Notice:` line that names the licensor. Draft that line for CrabNebula Ltd, and say where it must appear.

LC2. Is the vendored LibPDF (MIT), with its Apache-2.0 font module, compatible with distributing the platform under PolyForm Noncommercial? Is the PDFBox NOTICE the right attribution for the derived font code? What notices must ship, and where: in the repository, in the web assets served to browsers, and in a third-party notices file? The vendored copy changes some files; what must the changes carry?

LC3. Does embedding the unmodified OFL 1.1 font in PDFs given to grantees and the public meet the OFL conditions? Where must the OFL text travel with the platform build: the web assets, the cell binary, the PDFs? Is the OFL compatible with the platform's PolyForm Noncommercial licence?

LC4. The export schema and tooling are EUPL-1.2, while the platform is PolyForm Noncommercial. What rules keep the two separate, for example no code moving between them? Does any EUPL obligation reach the platform when the platform produces or reads files in that schema?

LC5. The platform publishes a software bill of materials (SBOM) in CycloneDX 1.6 JSON format. Does any licence above, or the CRA, require particular SBOM content, such as licence identifiers or notices?

**Answer format.** For each item:

```
## <ID>
Answer:
Basis (licence and section):
Confidence: high | medium | low
Draft text (if asked):
To confirm:
Decision for the platform (one line):
```
