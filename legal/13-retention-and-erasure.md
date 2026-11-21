# Retention and erasure notice

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Responsible data officer: Daniel Thompson-Yvetot.

Used where: section 11 of the privacy notice summarises this text. The full text suits a help page linked from the tenant admin's erasure page (`/app/admin/erasures`, `crates/fstp-api-core/src/erasure.rs`) and from the privacy notice. ADR-007 says the person concerned receives a confirmation of erasure, so section C drafts that message.

What the code does:

- Each free text has its own key. Erasure destroys the key, so the text cannot be read again, from backups either (ADR-007, R-KY-02, I-81).
- The ledger keeps its entries. After erasure, a text reference points to the erasure log entry, not to the text (I-97).
- The erasure log holds the text id, the time, the cause and the person who authorised it. It is in the tamper-evident audit chain (I-24). Tenant admins and auditors read it.
- Funder retention starts when the grant's last payment request is confirmed. It ends P-41 years later. A reminder then goes to the tenant admins, who request the erasure (`crates/fstp-domain/src/retention.rs`).
- A tenant admin can request erasure only for a grant whose retention has ended (`erasure.rs`).
- Identity erasure in the vault erases the identity's attribute tuple and makes its match key unlinkable, in the live store and in backups (ADR-004, lane L11). It is an operator command today, not a self-service route.
- A removed display name is erased at once (SA-11).

TODO(legal): which records the funder retention obligation covers, and whether deferring their erasure is lawful (ADR-007, `erasure.rs`). TODO(legal): whether the remaining ledger skeleton is anonymous data (ADR-007, D6).

---

## A. How long your data is kept

Your data is kept only as long as the programme needs it, or as long as the funder's rules require.

- **Drafts you never submit** are deleted when the call closes or when you withdraw. [NOT BUILT: no deletion job for drafts was found in the code.]
- **Identity documents** uploaded for a manual check are deleted once the check is complete, unless the programme sets a period. [NOT BUILT: document upload is not served yet.]
- **Records of a grant** are kept until the funder retention period ends. It starts when the last payment of the grant is confirmed and lasts {{P-41}}. These records may be needed for checks and audits by the granting authority and other bodies. TODO(legal): L-06.
- **AI assessment records** are kept for the same period, to support complaints and checks. [NOT BUILT: no deletion job for traces was found in the code.]
- **Records of proposals that were not funded**: TODO(legal): the period for proposals that never became grants. The code sets none.

## B. How erasure works

When your data is erased, the key that protects it is destroyed. The data can then no longer be read, from the live system or from backups.

Some records stay, with no text and no identity data: ids, amounts, scores, decisions and the times they happened. They keep the audit trail of the programme complete. They cannot be linked back to you once your identity data is erased.

If you ask for erasure, data outside the funder retention period is erased at once. Data inside it is erased when the period ends.

[NOT BUILT: a person's own erasure request has no self-service route. The tenant admin page takes erasures per grant only.]

## C. Erasure confirmation (message to the person concerned)

Subject or mailbox title:

> Your data was erased

Text:

> The data you asked us to erase was erased on {when}. Its encryption keys were destroyed, so it can no longer be read.
>
> Records under the funder retention period are kept until that period ends. They will be erased then.
>
> TODO(legal): whether the confirmation must list what was kept and why.

[NOT BUILT: no template or mailbox kind sends this confirmation yet. A new template id would be needed in `crates/fstp-mail/src/template.rs`.]
