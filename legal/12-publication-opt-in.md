# Publication opt-in (public visibility of a grant)

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Data Protection Officer (DPO): Daniel Thompson-Yvetot.

Requirements: R-PB-01 to R-PB-05, I-41 to I-43, P-50, P-51. Request items L-07 and D4.

Code site: `web/src/grant/visibility/messages.en.ts`. The marker reads "Daniel reviews the wording of both notes": `grant.visibility.note_platform` and `grant.visibility.note_reporting`.

What the code does:

- Nothing is shown until the grantee chooses. The grantee can change or withdraw the choice at any time, and the public pages change at once.
- The programme sets a maximum level (P-50 while running, P-51 after completion).
- A grant whose team includes a person under 18 is never shown. Only Hidden can be chosen.
- Public summaries come from the grantee, never from proposal text (R-PB-03).
- Public pages run no script and carry no tracking (R-PB-04).

TODO(legal): L-07, whether the grantee's opt-in is a valid basis for publication, including for natural persons, and whether every team member must agree when the grantee is a group of people.

---

## A. Note on the platform (`grant.visibility.note_platform`)

Current: "Your choice governs this platform only."

Draft:

> Your choice covers the public pages of this programme on this platform. It does not cover what the funder or the granting authority publish under their own rules.

## B. Note on reporting (`grant.visibility.note_reporting`)

Current: "Reporting to the funder covers every grant, whatever you choose here."

Draft:

> Your grant is reported to the funder and the granting authority of the EU programme, whatever you choose here. They may publish information about grants under their own rules. TODO(legal): L-08 and L-09, what the granting authority publishes and under which rule.

## C. Opt-in statement (new entry, shown above the choices)

> If you choose a level other than Hidden, you agree that the details of that level appear on this programme's public pages. They can be seen and copied by anyone. If your grant names people, make sure they agree too. You can change or withdraw your choice at any time. The public pages change at once. Copies that others made before a change are outside our control.
