# Policy parameters

Parameters are set per programme. "Frozen" parameters lock when a call publishes and apply unchanged to that call (I-12). Changes apply to the next call.

| ID | Parameter | SuperSAFE default | Frozen |
| --- | --- | --- | --- |
| P-01 | Criteria and weights | Technical excellence 30, Relevance and impact 40, Value for money 30 | Yes |
| P-02 | Stage 1 pass threshold (strictly above) | 75% | Yes |
| P-03 | Assigned reviewers per proposal (minimum) | 2 | Yes |
| P-04 | Grant range per proposal | 5k to 100k EUR | Yes |
| P-05 | Cap per recipient over programme lifetime, bounded by P-58 (I-50) | 400k EUR per the Annexe, to confirm against the Data Sheet (L-10) | No (programme-level) |
| P-06 | Call cadence | Quarterly | No |
| P-07 | Stage 2 answer window | 4 weeks | Yes |
| P-08 | Notification deadline for non-selected | 5 working days after the decision | Yes |
| P-09 | Knock-out criteria | Aligned with Open Internet Stack and SuperSAFE vision; R&D as primary objective; English | Yes |
| P-10 | Proposal read access in stages 1 and 2 | Assigned reviewers only | Yes |
| P-11 | Reviewer anonymity towards applicants | Anonymous | Yes |
| P-12 | Cooling-off before Receiving after Drafting or Judging | 1 call | No |
| P-13 | Excluded affiliation classes | Consortium partners, their affiliated entities and staff; IRC members, employers, co-workers, relatives | No |
| P-14 | IRC exemptions for amendments | Team change; plan change without budget change; additional tasks in scope at equivalent rates with total under 100k EUR | Yes |
| P-15 | IRC members per proposal (minimum) | 2 | Yes |
| P-16 | Committee voting rules | Majority, vote delegation allowed, chair casting vote | Yes |
| P-17 | Tie-break priority | EU and associated countries, with exception for exceptional quality and unique expertise | Yes |
| P-18 | Identity verification methods | EUDI Wallet; document upload with manual check | No |
| P-19 | Uploaded document retention after verification | None: deleted on verification | No |
| P-20 | Payment mode | Record-only or execution | No (tenant-level) |
| P-21 | Inference provider and pinned model | Tenant choice | Yes |
| P-22 | Trace retention | Until the funder audit period ends (P-41) | No |
| P-23 | Pre-check enabled and rate limits | Enabled; 1 per day and 5 per call per proposal; account-level cap across drafts in the same call | Yes |
| P-24 | Effective score rule after stage 2 | Higher of original and revised | Yes |
| P-25 | Programme language | English | Yes |
| P-26 | Accepted licences for deliverables | Recognised free and open source licences | Yes |
| P-27 | Hardship contribution enabled | Yes | No |
| P-28 | Show indicative LLM rubric bands to reviewers | Off | Yes |

NOTE 1: P-10 options are: assigned reviewers only, all committee members, operator staff only. The default is the narrowest.

NOTE 2: Annexe sections 5.a, 7 and 8.a disagree on who reads proposals. SuperSAFE resolves this as assigned reviewers only (O-01). Staff of any partner may be assigned (O-22), subject to SoD-10 and SoD-11.

NOTE 3: P-28 defaults to off to limit anchoring of human scores on model output.

NOTE 4: P-12 counted in calls means: the first call published after the binding ends is barred, and later calls are open. I-36 adds a further bar for calls holding a proposal the person reviewed.

NOTE 5: For SuperSAFE, a quarterly cadence with a 4-week stage 2 window leaves limited slack. An indicative cycle is knock-out 1 week, stage 1 scoring 2 weeks, stage 2 4 weeks, ranking 1 week and IRC 2 weeks. That totals about 10 of 13 weeks. Overruns push proposals into the next call through DEFERRED.

## Added parameters

| ID | Parameter | SuperSAFE default | Frozen |
| --- | --- | --- | --- |
| P-29 | Contract instrument and template version | MoU | Yes |
| P-30 | Signature level and cascade | Wallet QES, then QTSP remote QES, then approved advanced | Yes |
| P-31 | Reminder offsets | Minus 14 days, minus 3 days, due date | No |
| P-32 | Enabled channels and group types | Email, Matrix and WhatsApp (tenant-owned account); all four group types | No |
| P-33 | Overdue escalation | Plus 7 days to programme manager | No |
| P-34 | Payment request evidence requirements | Public location, release identifier, SPDX licence, report | Yes |
| P-35 | Group membership removal delay | Immediate | No |
| P-36 | Payment hold after bank detail change | 7 days | No |
| P-37 | Inbound group message handling | Not stored | No |
| P-38 | Proximity lists per partner organisation | Declared by each partner at programme start | No |
| P-39 | Minimum distinct organisations among assigned reviewers | 2 | Yes |
| P-40 | Working-day calendar | Tenant-defined public holidays and weekend days | No |
| P-41 | Funder retention period after the action's final payment | Horizon Europe Data Sheet standard time-limit; confirm in the signed GA (L-06) | No |
| P-42 | Calibration consent requests enabled | Yes | No |
| P-43 | Licence refresh grace period (self-hosted) | 30 days | No |
| P-44 | Legal nature of payments | Per funder instrument; SuperSAFE: financial support to third parties as a grant | Yes |
| P-45 | EUDI Wallet relying party mode | Tenant registration or CrabNebula as intermediary; self-hosted cells use tenant registration only | No |
| P-46 | Data retrieval period after a switch request | 30 days | No |
| P-47 | Seal level for contractual notices | Advanced electronic seal; qualified as option | No |
| P-48 | Attach sealed PDF to notice emails | Yes | No |
| P-49 | Qualified trust service provider for remote signing | Tenant choice | No |
| P-50 | Maximum public visibility of funded subgrants (grantee opts in) | Full | No |
| P-51 | Maximum public visibility of finished subgrants, including deliverables (grantee opts in) | Full | No |
| P-52 | Machine-readable public feed | On | No |
| P-53 | Funder profile and version | Horizon Europe | Yes |
| P-54 | Minimum number of grants behind any public aggregate | 3 | No |
| P-55 | Closed list of eligible activity types | From Annexe section 3, as a closed list (O-23) | Yes |
| P-56 | Action FSTP budget | From the SuperSAFE estimated budget | No |
| P-57 | Action start and end dates | From the SuperSAFE Data Sheet | No |
| P-58 | Funder per-recipient ceiling | From the SuperSAFE Data Sheet (L-10) | No |
| P-59 | Target payment time after payment approval | 15 days | Yes |
| P-60 | Support programme offered to grantees | Mentoring by consortium experts; presenting results to the consortium; promotion and visibility; CRA compliance guidance | Yes |
| P-61 | Complaint window after a procedural decision is notified | 10 working days (proposed) | Yes |
| P-62 | Coordinator response time to a complaint | 15 working days (proposed) | Yes |
| P-63 | Escalation window after the coordinator response | 10 working days (proposed) | Yes |
| P-64 | IRC response time to an escalated complaint | 20 working days (proposed) | Yes |
| P-65 | Evidence for a partial claim on a milestone | Options: public deliverables as for a full claim, or a progress report with deliverables at the final claim. SuperSAFE: public deliverables | Yes |
| P-66 | Reallocation between milestones of the same task | Enabled, with approval by an assigned reviewer | Yes |
| P-67 | Unclaimed milestone balances at grant end | Options: return to the action's FSTP budget, or lapse and report as unspent. SuperSAFE: return to the FSTP budget | No |
| P-68 | Platform attribution on tenant interfaces | Required in the footer of every interface and public page | Not tenant-configurable |
| P-69 | Default licence for published programme templates | CC BY 4.0, publisher may choose another | No (tenant-level) |
| P-70 | Enabled login methods | Passkeys always; EUDI Wallet, OPAQUE and magic links per tenant | No (tenant-level) |
| P-71 | Step-up freshness for high-risk actions | 5 minutes (proposed) | No (tenant-level, may only shorten) |
| P-72 | Session idle and absolute lifetimes | 30 minutes idle, 12 hours absolute (proposed) | No (tenant-level) |
| P-73 | Database mode | Shared; dedicated on request | No (tenant-level) |
| P-74 | MCP server enabled and roles allowed | Enabled for all roles, plus public research tools | No (tenant-level) |
| P-75 | Whether reviewers' agents may read full proposal content through MCP | Off | Yes |
| P-76 | Listing in the platform-wide directory of open calls | Off; programme opts in | No |
| P-77 | Binding actions through MCP | Options: draft only, or allowed. SuperSAFE: draft only | Yes |
| P-78 | Connected external MCP servers, purposes and declared fields | None | No (tenant-level) |
