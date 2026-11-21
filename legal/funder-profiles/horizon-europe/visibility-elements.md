# Funder visibility elements of the Horizon Europe profile

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Data Protection Officer (DPO): Daniel Thompson-Yvetot.

Code sites:

- `crates/fstp-report/profiles/horizon-europe/profile.v1.json`, `visibility_elements`: two keys, `acknowledgement` and `emblem`. Each holds a wording ref (`horizon-europe/visibility/acknowledgement`, `horizon-europe/visibility/emblem`) and the status `TODO(legal)`.
- `crates/fstp-report/src/profile/mod.rs`: `WordingStatus` has one value, `PendingLegal`. The parser (`profile/parse.rs`) accepts only the status `TODO(legal)`.
- `crates/fstp-public/src/html.rs` (`public.footer.funder_element`) and `web/src/creator/messages.en.ts` (`footer.funder_element`) show a placeholder per key. `web/src/shell/brand.ts` does the same.
- Request items L-08 and L-09.

Wiring note: the profile file stores no wording, only a ref and a status. Approving the wording needs three changes. A store for the text behind each ref. A second `WordingStatus` value, such as `Approved`, with a parser rule. A new profile version, since a shipped version never changes (P-53 pins it).

---

## Element `acknowledgement`

Shown in the footer of each programme page, and wherever the profile requires it.

Draft:

> {{programme.name}} is funded by the European Union under the Horizon Europe grant agreement {{action.number}}, {{action.acronym}}.

TODO(legal): L-08, the exact acknowledgement wording the signed grant agreement requires, and whether a disclaimer must follow it. Do not use the draft until Daniel supplies or approves the wording.

Note: the element texts take no placeholder today. The programme name and grant agreement number would need slots, or one text per programme.

## Element `emblem`

Shown next to the acknowledgement.

Draft: the EU emblem image, with the text alternative "European Union emblem".

TODO(legal): L-08, the emblem rules: which version of the emblem, its size, its placement and any accompanying text. The emblem image is not in the repository. Daniel supplies it from the official source.
