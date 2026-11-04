# Threat model

## Assets

Proposal content, applicant identity, reviewer identity in anonymous mode, scores and deliberation, conflict declarations, bank details, audit log, LLM traces, tenant keys, policy versions.

## Threats

| ID | Threat | Primary mitigations | Tests |
| --- | --- | --- | --- |
| TH-01 | Prompt injection in submissions to influence findings | Data channel separation, integrity findings, no assessor write access, I-10 | T-LLM-INJ |
| TH-02 | Pre-check used as an oracle for injection or rubric gaming | Findings only, rate limit, integrity findings shown to applicant, fresh assessment on submit | T-LLM-ORACLE |
| TH-03 | Second tenant account used to sit on both sides | SoD-09 verified identity check at binding and negotiation | T-SOD-SYBIL |
| TH-04 | Undeclared reviewer conflicts or collusion | Conflict declaration before content, vault conflict checks, IRC review | T-SOD-CONFLICT |
| TH-05 | Tenant admin self-escalation to read proposals | SoD-07, P-10 default, audit of every content read | T-AUTHZ-MATRIX |
| TH-06 | Cross-tenant leakage via control plane, shared infrastructure, logs or caches | Cells, per-cell keys, R-NF-02 | T-ISO |
| TH-07 | Identity leakage to reviewers through metadata or file properties | Metadata stripping, PII stripping, I-17 | T-PRIV-CANARY |
| TH-08 | De-anonymisation of reviewers via message metadata or timing | Pseudonymous handles, relayed messages, batched delivery | T-PRIV-ANON |
| TH-09 | Payment instruction tampering, such as bank detail swaps | Vault storage, re-verification on change, four-eyes (I-05) | T-PAY |
| TH-10 | Malicious tenant export used to exploit the import parser | Sandboxed parser, schema validation, fuzzing | T-FUZZ-IMPORT |
| TH-11 | Forged profile bundle | Imported fields treated as self-declared (R-PS-03) | T-PS |
| TH-12 | Retrieval poisoning through applicant-controlled sources | Source independence weighting, retrieved content as untrusted data | T-LLM-RETRIEVAL |
| TH-13 | Inference provider retention or third-country governmental access | Tenant provider choice, local inference option, PII stripping, EU-owned hosting (ADR-005) | Review item |
| TH-14 | Audit log tampering | Hash chain with external anchoring | T-AUDIT |
| TH-15 | Supply chain compromise | Dependency policy, SBOM, reproducible builds where feasible | CI gate |
| TH-16 | Malicious uploads exploiting document parsing | Sandboxed extraction, file type allowlist | T-FUZZ-UPLOAD |
| TH-17 | Policy change after publication to favour a proposal | I-12 frozen policy, policy versions append-only | T-POLICY |
| TH-18 | Platform operator insider access to tenant content | SoD-08 break-glass with tenant approval, audit | T-BREAKGLASS |

NOTE: TH-18 matters because CrabNebula operates the SaaS and also runs programmes as a tenant. The same break-glass rules apply to its own cells.

## Added threats

| ID | Threat | Primary mitigations | Tests |
| --- | --- | --- | --- |
| TH-19 | Identity exposure through group membership, such as visible phone numbers | Fan-out announcements, I-28, opt-in groups | T-MSG-GROUPS |
| TH-20 | Phishing of grantees for bank detail changes | No bank detail requests in messages, DKIM and DMARC, I-33 hold | T-PAY-BANKCHANGE |
| TH-21 | Duplicate or runaway notifications | Outbox idempotency keys, rate limits per recipient | T-NT-IDEMPOTENT |
| TH-22 | Messaging provider access to message content and metadata | I-27 content rules, minimal templates, provider assessment | Review item |
| TH-23 | Contract tampering after signature | Immutable versions, content hash in audit chain | T-CT-IMMUTABLE |
| TH-24 | Deliverable evidence changed or removed after payment | Evidence snapshots at submission and acceptance | T-PR-SNAPSHOT |
| TH-25 | Stale group membership after a role ends | I-29 reconciliation with bounded delay | T-MSG-RECONCILE |
| TH-26 | Defects in in-house parsers and protocol code | Fuzz target per parser from first commit, H-05 | T-FUZZ-* |
| TH-27 | Partner reviewers favouring proposals from their own constituencies | SoD-10, SoD-11, IRC review | T-SOD-ASSIGN |
| TH-28 | Removed group member reads later encrypted messages | Session rotation on every removal | T-MSG-ROTATE |
| TH-29 | Pre-check quota bypass by opening extra drafts | Account-level cap per call (P-23) | T-LLM-ORACLE |
| TH-30 | Deleted identity documents recoverable from backups | Per-document keys destroyed on verification | T-ID-SHRED |
| TH-31 | Contract signature validation bypass, including PDF incremental update and shadow attacks | In-house validation against ETSI procedures, fuzzing, signed byte range coverage checks | T-CT-SIGVAL |
| TH-32 | Malicious or rolled-back update delivered to self-hosted cells | Signed metadata and artefacts, rollback protection, key rotation | T-UPDATE |
| TH-33 | Licence service outage halting a live programme | Local token verification, grace period, I-39 | T-LICENCE-OUTAGE |
| TH-34 | Intermediary service retaining identity data across tenants | Stateless intermediary, direct write to tenant vault, I-19 | T-EUDI-STATELESS |
| TH-35 | Disclosure of rejected or pending applicants through public pages or feeds | I-41, publication only from GRANTED, feed built from the same filter | T-PUB-LEAK |
| TH-36 | Funder report figures diverging from actual payments | I-44 reconciliation, snapshot hashes, approval step | T-RP-RECONCILE |
| TH-37 | Public page used to track visitors | No scripts required, no cookies, no third-party assets | T-PUB-PRIVACY |
| TH-38 | Support programme used to steer grantees towards paid services of consortium partners | I-55, purpose limitation on contact data, audit of messages sent through the platform | T-SP-COMMERCIAL |
| TH-39 | Mentoring relationship biasing later reviews of the same grantee | SoD-12, I-54 conflict detection | T-SOD-MENTOR |
| TH-40 | Complaints ignored or reviewed by the people who made the contested decision | SoD-13, I-56 deadlines with escalation | T-CP-SOD |
| TH-41 | Retaliation against complainants in later evaluation | I-57, complaint records hidden from reviewers, audit | T-CP-RETALIATION |
| TH-42 | Double claiming a milestone through concurrent or repeated requests | Pending amounts reduce available; I-58 enforced in a serialisable transaction | T-PR-CONCURRENT |
| TH-43 | Amendment lowering a milestone below what was already paid | I-61 | T-PR-AMEND |
| TH-44 | Reallocation used to move money towards undelivered work or around the task structure | Reviewer approval, I-63, audit file | T-PR-REALLOC |
| TH-45 | Tenant branding used to inject script, tracking or phishing content | I-68 data-only branding, sanitisers, no third-party hosts | T-WL-INJECT |
| TH-46 | Tenant impersonating another organisation through branding or domains | Domain ownership verification (I-71), operator review of SaaS tenant identity at onboarding | T-WL-DOMAIN |
| TH-47 | Prompt injection through an imported funding document | Untrusted data channel, I-65 human confirmation | T-PG-IMPORT |
| TH-48 | Custom domain takeover after a tenant leaves | Domain mappings removed at erasure, periodic re-verification | T-WL-DANGLING |
| TH-49 | Published template leaking personal data or carrying phishing links | I-73 dual publication and scan, editable display in the creator, withdrawal | T-PG-TEMPLATE |
| TH-50 | Implementation flaw in an unaudited post-quantum crate | Hybrid rule (I-75), ACVP and differential tests, release gate (I-74) | T-CR-HYBRID |
| TH-51 | Harvest now, decrypt later against backups and exports | Hybrid key encapsulation for data at rest that leaves the system | T-CR-ATREST |
| TH-54 | Desktop client caching confidential content on lost devices (deferred with the client, B-04) | No offline proposal content, signed updates | T-DC-CACHE |
| TH-55 | Phishing of reviewers or admins | Phishing-resistant login for management roles (I-77) | T-AU-ROLES |
| TH-56 | Session hijack used for exports, role grants or new devices | Step-up for high-risk actions (I-78) | T-AU-STEPUP |
| TH-57 | Account recovery abused to take over a management account | I-79 second-admin recovery | T-AU-RECOVERY |
| TH-58 | Cross-tenant read through a shared database cluster | Per-cell databases and roles, I-82, vault on separate clusters (I-83) | T-DB-ISO |
| TH-59 | Root key exposure at the hosting or key provider | Custody backends, no plaintext export (I-80), EU-owned provider | Review item |
| TH-60 | Prompt injection through proposal content reaching a reviewer's agent through MCP | Delimited data fields, content classification, I-85 for high-risk actions, P-75 | T-MC-INJECT |
| TH-61 | Stolen MCP token used to act as the user | Short-lived scoped tokens, step-up to connect, revocation, I-85 | T-MC-TOKEN |
| TH-62 | Confidential proposals leaving the cell through users' AI providers | P-75 programme policy, disclosure in the Guide and reviewer terms | Review item |
| TH-63 | Tool poisoning through tenant-controlled text | Fixed tool descriptions, branding excluded | T-MC-POISON |
| TH-64 | Malicious or compromised external MCP server returning injected instructions or false verification results | Untrusted data handling, read-only by default (I-88), source independence weighting | T-MCC-INJECT |
| TH-65 | Tenant data exfiltrated through external MCP integrations | Declared field sets (I-89), egress limits, step-up to connect, call logging | T-MCC-EXFIL |
| TH-66 | Public MCP tools leaking non-public data | I-87 parity with public pages | T-MC-PUBLIC |
| TH-67 | Future forgery of release metadata or audit anchors once classical signatures weaken | Composite signatures (I-90), offline release key | T-CR-COMPOSITE |
| TH-68 | Flaw in moduletto ML-DSA producing forgeable signatures | Composite AND rule (I-90), ACVP and differential tests, release gate (I-74) | T-CR-MLDSA |
