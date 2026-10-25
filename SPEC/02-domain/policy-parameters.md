# Policy parameters

Parameters are set per programme. "Frozen" parameters lock when a call publishes and apply unchanged to that call (I-12). Changes apply to the next call.

| ID | Parameter | SuperSAFE default | Frozen |
| --- | --- | --- | --- |
| P-01 | Criteria, weights and score scale (NOTE 6) | Technical excellence 30, Relevance and impact 40, Value for money 30; scale maximum N not yet set (TODO(Daniel)) | Yes |
| P-02 | Stage 1 pass threshold (strictly above, NOTE 6) | 75.00% | Yes |
| P-03 | Assigned reviewers per proposal (minimum) | 2 | Yes |
| P-04 | Grant range per proposal | 5k to 100k EUR | Yes |
| P-05 | Cap per recipient over programme lifetime, bounded by P-58 (I-50) | 400k EUR per the Annexe, to confirm against the Data Sheet (L-10) | No (programme-level) |
| P-06 | Call cadence | Quarterly | No |
| P-07 | Stage 2 answer window | 4 weeks | Yes |
| P-08 | Notification deadline for non-selected | 5 working days after the decision | Yes |
| P-09 | Knock-out criteria | Aligned with Open Internet Stack and SuperSAFE vision; R&D as primary objective; English | Yes |
| P-10 | Proposal read access in stages 1 and 2 | Assigned reviewers only | Yes |
| P-11 | Reviewer anonymity towards applicants | Anonymous | Yes |
| P-12 | Cooling-off between the Drafting, Judging and Receiving groups (NOTE 4) | 1 call | No |
| P-13 | Excluded affiliation classes | Consortium partners, their affiliated entities and staff; IRC members, employers, co-workers, relatives | No |
| P-14 | IRC exemptions for amendments | Team change; plan change without budget change; additional tasks in scope at equivalent rates with total under 100k EUR | Yes |
| P-15 | IRC members per proposal (minimum) | 2 | Yes |
| P-16 | Committee voting rules | Majority, vote delegation allowed, chair casting vote | Yes |
| P-17 | Tie-break priority | EU and associated countries, with exception for exceptional quality and unique expertise | Yes |
| P-18 | Identity verification methods | EUDI Wallet; document upload with manual check | No |
| P-19 | Uploaded document retention after verification | None: deleted on verification | No |
| P-20 | Payment mode | Record-only or execution | No (tenant-level) |
| P-21 | Inference provider and pinned model, with an ordered fallback list (NOTE 10) | Tenant choice | Yes |
| P-22 | Trace retention | Until the funder audit period ends (P-41) | No |
| P-23 | Pre-check enabled and rate limits | Enabled; 1 per day and 5 per call per proposal; account-level cap across drafts in the same call | Yes |
| P-24 | Effective score rule after stage 2 | Higher of original and revised | Yes |
| P-25 | Programme language | English | Yes |
| P-26 | Accepted licences for deliverables | Recognised free and open source licences | Yes |
| P-27 | Hardship contribution enabled | Yes | No |
| P-28 | Show indicative LLM rubric bands to reviewers | Off | Yes |

NOTE 1: P-10 options are: assigned reviewers only, all committee members, operator staff only. The default is the narrowest. Which Judging role reads under the option "operator staff only" is open (O-43). TODO(Daniel): name that role.

NOTE 2: Annexe sections 5.a, 7 and 8.a disagree on who reads proposals. SuperSAFE resolves this as assigned reviewers only (O-01). Staff of any partner may be assigned (O-22), subject to SoD-10 and SoD-11.

NOTE 3: P-28 defaults to off to limit anchoring of human scores on model output.

NOTE 4: P-12 is counted in calls (decided 2026-10-25). A call is barred for a person when they may not hold a role from another group in it.

- P-12 applies to every switch among the Drafting, Judging and Receiving groups, since I-01 counts past bindings in all three.
- Every call published up to the end of the binding is barred, including calls published before it started.
- After the binding ends, the next P-12 calls published are barred, and later calls are open. With the default of 1, the first call published after the binding ends is barred.
- The P-12 value is pinned when each binding ends. A later edit of P-12 does not change the bar for a binding that has already ended.
- P-12 = 0 is allowed. Only calls published up to the end of the binding are then barred.

The comparison is set out under Cooling-off in `02-domain/roles-and-sod.md`. I-36 adds a further bar for calls holding a proposal the person reviewed.

NOTE 5: For SuperSAFE, a quarterly cadence with a 4-week stage 2 window leaves limited slack. An indicative cycle is knock-out 1 week, stage 1 scoring 2 weeks, stage 2 4 weeks, ranking 1 week and IRC 2 weeks. That totals about 10 of 13 weeks. Overruns push proposals into the next call through DEFERRED.

NOTE 6: Scoring under P-01 and P-02 (decided 2026-10-25).

- Each criterion is scored on an integer scale from 0 to N. N is part of P-01, so it freezes with the criteria and weights.
- Every reviewer scores every criterion. A score that leaves out a criterion is incomplete.
- Weights are positive integers. They need no particular total.
- A reviewer's weighted sum is the sum over criteria of weight times score. The maximum is N times the sum of the weights.
- The proposal score is the mean over reviewers of their weighted sums, as a fraction of the maximum.
- P-02 is a percentage of that maximum with two decimals. The comparison is exact, with no rounding, and the score must be strictly above P-02.
- For example, with N = 4, the default weights and every score at 3, the score is exactly 75.00%. It does not pass a P-02 of 75.00%.
- The spec gives no SuperSAFE value for N (O-46). TODO(Daniel): set N for the SuperSAFE default of P-01.

NOTE 7: P-05 and P-13 are not frozen (decided 2026-10-25).

- For a published call, enforcement uses the stricter of the call's publication snapshot and the live programme value. For P-05 that is the lower amount. For P-13 it is every class in either value.
- The published call policy records the publication snapshot of P-05 and P-13 next to the frozen values. The Guide for Applicants shows that snapshot.
- A change after publication produces a numbered corrigendum (I-53). How such a corrigendum squares with I-51 is open (O-52). TODO(Daniel): decide.
- Adding a P-13 class voids the Receiving bindings of every holder now in an excluded class, in the same step, as under Identity discovery in `02-domain/roles-and-sod.md` (I-04).
- An edit that lowers P-05 below a recipient's counted sum is refused (`02-domain/contracts.md`).

NOTE 8: The P-16 details are open (O-44): the majority base, the quorum and the limits on vote delegation. TODO(Daniel): set them.

NOTE 9: Applying P-17 needs the applicant's country before NEGOTIATION. The identity vault provides it as a boolean answer: whether the applicant meets the country condition of P-17 (decided 2026-10-25). How the vault learns the country before NEGOTIATION is open (O-48). TODO(Daniel): decide the source, given R-NG-01 and I-17.

NOTE 10: The frozen P-21 value is a primary model plus an ordered fallback list, all pinned at publication (decided 2026-10-25). A replacement takes the next model on the list. It regenerates every finding of the call in one atomic step, so findings never mix configurations (I-11).

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
