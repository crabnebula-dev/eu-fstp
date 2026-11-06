# Request 03: platform contracts and EU digital regulation

Attach before sending:
- `SPEC/05-compliance/data-act.md`, `dsa.md`, `cra.md` and `other.md`
- `SPEC/03-architecture/eudi-wallet.md`, `overview.md` and `self-hosted-services.md`
- `docs/adr/ADR-005-hosting-and-database.md`
- `SPEC/11-backlog.md` (the entry on export and switching)
- `crates/fstp-signup/src/lib.rs` (the doc comment describes the three agreements a new tenant accepts)

---

## Prompt

You are an expert in EU digital regulation and SaaS contracting: GDPR processor terms, the Data Act, the Digital Services Act (DSA), the Cyber Resilience Act (CRA) and eIDAS. Please review the attached documents and answer the numbered items below.

**Context.** CrabNebula Ltd ([seat of CrabNebula Ltd]) offers a multi-tenant SaaS that runs FSTP grant programmes. It also ships a self-hosted single-tenant product, which includes an identity vault component. Tenants are funders or consortia. They sign up online and accept three agreements: the SaaS terms, a data processing agreement (DPA), and a sub-processor list. OVHcloud hosts the SaaS in the EU, and the OVHcloud contracting entity is not confirmed yet. Applicants and grantees use each tenant's programme portal on the platform. The platform may integrate EU Digital Identity Wallets as a stateless intermediary.

**Rules for your answer.**
- Cite only provisions you are sure of, by instrument and article. If you are unsure, say so.
- Where an item asks for a document, give a structured draft or outline for review by counsel.
- Keep each item's ID exactly as written.

**Items.**

P1. Outline the SaaS terms for tenants: the parties, the service description, availability, fees placeholder, liability, termination and exit, governing law, and how they link to the DPA.

P2. Draft the data processing agreement under GDPR Article 28, with CrabNebula Ltd as processor and the tenant as controller. Include the sub-processor list format, with OVHcloud and an open contracting entity. Must the DPA state the backup retention period and the backup provider?

P3 (L-15). List the due diligence to complete on OVHcloud before go-live: ownership, the contracting entity, sub-processor terms, data centre locations, certifications, and operator access to licence registration data. Say what each item must show.

P4 (L-04). Confirm the Data Act Article 25 periods marked open in `data-act.md`: the notice period, the switching period, and the data retrieval period. Draft the switching clause for the SaaS terms, and the Data Act information the platform must show tenant admins. May a SaaS pilot run before export and switching tools exist?

P5 (L-16). What does the platform's classification depend on, under Recommendation 2003/361/EC and the DSA? The facts to supply are CrabNebula Ltd's size category and its linked enterprises. Which DSA duties follow, for example under Articles 15(2) and 19?

P6 (L-17). Are tenants' programme portals information society services? If so, are tenants DSA providers towards applicants? Which tenant tooling would that require (notice and action, statements of reasons)?

P7 (L-03). Which CRA category does the self-hosted product fall into, given the identity vault component? Is Module A the right conformity route? Draft the published vulnerability handling and reporting text that the CRA requires from the first release.

P8 (L-05). As a stateless intermediary for EU Digital Identity Wallet presentations, what obligations does the platform carry under the amended eIDAS Regulation and its implementing acts?

**Answer format.** For each item:

```
## <ID>
Answer:
Basis (instrument and article):
Confidence: high | medium | low
Draft or outline (if asked):
To confirm:
Decision for the platform (one line):
```
