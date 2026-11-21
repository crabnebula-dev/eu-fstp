# Data Act information for tenant organisations

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Responsible data officer: Daniel Thompson-Yvetot.

Used where: the footer element "Data Act information" on tenant admin pages (`footer.data_act_information` in `web/src/creator/messages.en.ts`, `public.footer.data_act` in `crates/fstp-public/src/html.rs`), and the help text `help.field.funder.p46_switch_retrieval_period` in `web/src/help/messages.en.ts`. Request item P4 (L-04).

What the specification and the code say:

- `SPEC/05-compliance/data-act.md` treats the SaaS as a data processing service, with CrabNebula Ltd as provider.
- Switching terms (O-13): no notice period; a transitional period within the statutory maximum; a data retrieval period of 30 days (P-46); full erasure of the tenant cell after it, with a confirmation.
- No switching charges (R-TD-04).
- Export and import (R-TD-01 to R-TD-04) are deferred by Daniel on 2026-11-04 (B-07). The export tool is not built.

TODO(legal): L-04, the statutory maximum transitional period and the statutory minimum retrieval period. TODO(legal): the information the provider must give tenants before the contract, and whether a pilot may run before export exists. TODO(legal): the date from which switching charges must be zero, which `data-act.md` states; Daniel verifies it.

---

## Switching provider and getting your data

You can move your programmes to another provider, or run them yourself. CrabNebula Ltd does not charge you for switching.

- **Starting.** You can ask to switch at any time. No notice period applies.
- **Transition.** We complete the switch within TODO(legal): the transitional period.
- **Your data.** You get all your exportable data and digital assets in a documented, machine-readable format. Any provider can read it, since the format and the tools are open. [NOT BUILT: the export tool is deferred (B-07). Until it exists, TODO(legal): what CrabNebula Ltd offers instead.]
- **Retrieval.** After you ask to switch, you can retrieve your data for {{P-46}}. TODO(legal): confirm that this meets the statutory minimum.
- **Erasure.** When the retrieval period ends, we erase your organisation's cell in full, and we confirm the erasure to you.

Your data stays in the European Union. We protect non-personal data against unlawful access by governments outside the European Union. TODO(legal): the wording of this safeguard, and the published information on third-country access that may be required.

Contact for switching: TODO(legal): contact address.
