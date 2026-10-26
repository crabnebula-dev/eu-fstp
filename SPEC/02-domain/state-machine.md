# Proposal state machine

## States

| State | Meaning |
| --- | --- |
| DRAFT | Applicant workspace. Private to the applicant team. |
| SUBMITTED | Submitted to a call before its deadline. |
| INELIGIBLE | Failed knock-out. Terminal for this call. |
| STAGE1 | Under scoring by assigned reviewers. |
| NOT_SELECTED | Rejected at stage 1 or below the stage 2 cut-off. Terminal. |
| STAGE2 | Clarification questions and possible revised plan. |
| RANKED | Re-scored and ranked within the call. |
| IRC_REVIEW | Under independent review. |
| DEFERRED | Carried to the next call with its review history. |
| DECLINED | Terminal. No future call available, or negotiation failed with a recorded reason. |
| NEGOTIATION | Identity verification, guardian consent, amount and contract drafting. |
| WITHDRAWN | Applicant withdrew. Terminal. |
| GRANTED | Contract EFFECTIVE (`02-domain/contracts.md`). |
| IN_EXECUTION | Milestones in progress. |
| COMPLETED | Every milestone closed and every payment request in a terminal state. Terminal. |
| TERMINATED | Grant ended early. Terminal. |

## Transitions

| From | To | Actor | Guard |
| --- | --- | --- | --- |
| DRAFT | SUBMITTED | Applicant | Call open (see Call states); required fields present |
| SUBMITTED | INELIGIBLE | FSTP coordinator | Knock-out criterion failed, reason recorded |
| SUBMITTED | STAGE1 | FSTP coordinator | All knock-out criteria passed; reviewers assigned without conflict |
| STAGE1 | NOT_SELECTED | System, recorded by the FSTP coordinator | Stage 1 closed (NOTE 3); weighted score not above P-02 (I-08) |
| STAGE1 | STAGE2 | System, recorded by the FSTP coordinator | Stage 1 closed (NOTE 3); weighted score above P-02 (I-08) |
| STAGE2 | RANKED | Assigned reviewers | Revised plan scored by at least P-03 assigned reviewers, window closed with answers, or "no questions" recorded (NOTE 4); effective score follows P-24 (I-09) |
| STAGE2 | DEFERRED | System (NOTE 13) | Stage 2 window (P-07) elapsed without answers and without a "no questions" record (NOTE 4, NOTE 5) |
| RANKED | NOT_SELECTED | Committee | Ranked below the cut-off (NOTE 6); decided under P-16 (R-EV-09); remaining budget visible (R-EV-08); rationale recorded |
| RANKED | IRC_REVIEW | Committee | Ranked within the cut-off (NOTE 6); decided under P-16 (R-EV-09); remaining budget visible (R-EV-08); rationale recorded |
| IRC_REVIEW | NEGOTIATION | IRC members (P-15) | All reviewing IRC members validate; verified guardian consent if minor (I-18, R-NG-02) |
| IRC_REVIEW | DEFERRED | IRC member | Concern raised; future call exists (NOTE 7) |
| IRC_REVIEW | DECLINED | System (NOTE 13) | Concern raised; no future call (NOTE 7) |
| DEFERRED | STAGE2 or IRC_REVIEW | System (NOTE 13) | Next call opens; re-enters at the stage it left (NOTE 8) |
| NEGOTIATION | GRANTED | Applicant and programme manager | Identity verified; guardian consent if minor (I-18); amount within P-04 and P-05, with P-05 checked cumulatively (I-14); SoD-09 passes; granting keeps I-04, I-06, I-13 and I-15; contract EFFECTIVE |
| NEGOTIATION | DECLINED | System (NOTE 13) | Identity verification fails; SoD-09 refuses the applicant; the applicant's Receiving bindings were voided under I-04 or I-06 (`02-domain/roles-and-sod.md` Identity discovery); no grant amount can keep I-13 and I-14; the I-15 deliverable record is incomplete; or guardian consent (I-18) is missing; reason recorded (NOTE 9) |
| any non-terminal state before GRANTED | WITHDRAWN | Applicant | None (NOTE 10) |
| GRANTED | IN_EXECUTION | System (NOTE 13) | First milestone start date reached (NOTE 11) |
| GRANTED | TERMINATED | Programme manager | Reason recorded |
| IN_EXECUTION | COMPLETED | System (NOTE 13) | Every milestone closed and every payment request in a terminal state (NOTE 12) |
| IN_EXECUTION | TERMINATED | Programme manager | Reason recorded |

NOTE 1: Annexe 5.c lets the budget change during stage 2. The revised plan is a new plan version. I-09 selects which version carries forward. I-09 holds in every state after stage 2, terminal states included.

NOTE 2: Notifications to NOT_SELECTED applicants are sent within P-08 so they can seek funding elsewhere (Annexe 5.b, 5.c).

NOTE 3: Stage 1 closes when every active assigned reviewer has a valid score and at least P-03 valid scores exist (I-07). A valid score is the current value from an active assignment. Scores of released or conflicted reviewers never count. Scores seal when the proposal leaves the stage. Only a recorded complaint remedy reopens them (`02-domain/complaints.md`). The FSTP coordinator records the close and cannot choose its outcome, which is computed (decided 2026-10-25).

NOTE 4: In stage 2, the assigned reviewers rescore a revised plan, and at least P-03 valid stage 2 scores on it are needed. When several revisions exist, the latest scored revision counts. When the original and revised scores tie under P-24, the original plan carries forward. When the assigned reviewers record "no questions", the window closes at once with answers deemed complete, and STAGE2 to RANKED applies (decided 2026-10-25). Without that record, P-07 runs, and STAGE2 to DEFERRED applies if it elapses without answers. Every active assigned reviewer must record "no questions" before the window closes this way (decided 2026-10-25, O-50).

NOTE 5: STAGE2 to DEFERRED needs no future call (R-EV-07). A proposal deferred from STAGE2 while no next call exists waits in DEFERRED (decided 2026-10-25).

NOTE 6: The cut-off is a rank position over a total order of the call's RANKED proposals. The committee breaks ties in that order under P-17, and the tie-break is recorded. Proposals ranked within the cut-off go to IRC_REVIEW, and the rest become NOT_SELECTED. Each cut-off round covers the proposals RANKED at that time (decided 2026-10-25).

NOTE 7: A future call exists when a later call of the same programme is published (decided 2026-10-25).

NOTE 8: The original call's frozen policy keeps governing a deferred proposal. On re-entry, assignments and reviewer handles are made afresh in the new call. LLM findings stay with the call that produced them, and the new call may produce its own (decided 2026-10-25).

NOTE 9: NEGOTIATION to DECLINED ends a negotiation that cannot reach GRANTED (decided 2026-10-25). For I-13 and I-14, "cannot reach" means that no amount within P-04 fits the recipient's remaining room under P-05, so even the P-04 minimum does not fit. A plan total above the cap is no ground for declining while a smaller negotiated plan could still fit, and the lead may propose one (decided 2026-10-26). Guardian consent is checked on entry to NEGOTIATION and again before GRANTED (I-18, R-NG-02).

NOTE 10: Withdrawal is open in DRAFT, SUBMITTED, STAGE1, STAGE2, RANKED, IRC_REVIEW, DEFERRED and NEGOTIATION. This meets R-SB-03, which allows withdrawal at least until contract signature. Terminal states have no exits.

NOTE 11: Each milestone carries a start date as well as a due date. GRANTED to IN_EXECUTION uses the earliest milestone start date in the effective contract version (decided 2026-10-25).

NOTE 12: A milestone can close without being fully paid, since P-67 releases unclaimed balances at COMPLETED (decided 2026-10-25). The programme manager closes each milestone with a recorded reason. A payment request is terminal when PAID, REJECTED, WITHDRAWN or CLOSED (`02-domain/payment-requests.md`, decided 2026-10-25, O-51).

NOTE 13: R-LA-03 requires a named human to record every decision. Where a System row records a decision, its outcome stays computed and a named human records it. The FSTP coordinator records the stage 1 rows. The programme manager records IRC_REVIEW to DECLINED and NEGOTIATION to DECLINED, which are decisions with a recorded reason. The rows driven by a timer or a date are not decisions, and the system records them: STAGE2 to DEFERRED, DEFERRED re-entry, GRANTED to IN_EXECUTION and IN_EXECUTION to COMPLETED (decided 2026-10-25, O-49).

## Call states

| State | Meaning |
| --- | --- |
| DRAFT | Call text and criteria being drafted. |
| APPROVED | Publication approved by a person other than its drafter (R-PC-03). An edit to the call text, P-01 or P-09 after approval revokes the approval, and the call returns to DRAFT (confirmed 2026-10-25). |
| PUBLISHED | Published with a frozen policy version (R-PC-02, I-12). |

Open and closed are not states. A published call is open from its opening time until its deadline, and closed afterwards (decided 2026-10-25).

## Milestones and payment requests

Each milestone is closed through one or more payment requests (`02-domain/payment-requests.md`). Payment may be full or partial per milestone (Annexe 5).

## Hardship contribution

Hardship contributions are payment requests of type "hardship", proportional to delivered work, with evidence held in the identity vault.

## Amendments

An amendment is a new plan version and a new contract version on a GRANTED or IN_EXECUTION proposal. It runs as a separate workflow, and the proposal state does not change. It bypasses IRC_REVIEW only when an exemption in P-14 applies. The programme manager decides whether an exemption applies. A "total" in P-14 means the amended contract total (decided 2026-10-25). Repeat grants and amendments are subject to I-15.
