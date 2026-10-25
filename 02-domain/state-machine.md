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
| DECLINED | Terminal. No future call available. |
| NEGOTIATION | Identity verification, guardian consent, amount and contract drafting. |
| WITHDRAWN | Applicant withdrew. Terminal. |
| GRANTED | Contract EFFECTIVE (`contracts.md`). |
| IN_EXECUTION | Milestones in progress. |
| COMPLETED | All milestones accepted and paid. Terminal. |
| TERMINATED | Grant ended early. Terminal. |

## Transitions

| From | To | Actor | Guard |
| --- | --- | --- | --- |
| DRAFT | SUBMITTED | Applicant | Call open; required fields present |
| SUBMITTED | INELIGIBLE | FSTP coordinator | Knock-out criterion failed, reason recorded |
| SUBMITTED | STAGE1 | FSTP coordinator | All knock-out criteria passed; reviewers assigned without conflict |
| STAGE1 | NOT_SELECTED | System | Weighted score not above P-02 (I-08) |
| STAGE1 | STAGE2 | System | Weighted score above P-02 |
| STAGE2 | RANKED | Assigned reviewers | Revised plan scored or window closed with answers |
| STAGE2 | DEFERRED | System | Stage 2 window (P-07) elapsed without answers |
| RANKED | NOT_SELECTED | Committee | Below cut-off; rationale recorded |
| RANKED | IRC_REVIEW | Committee | Above cut-off |
| IRC_REVIEW | NEGOTIATION | IRC members (P-15) | All reviewing IRC members validate |
| IRC_REVIEW | DEFERRED | IRC member | Concern raised; future call exists |
| IRC_REVIEW | DECLINED | System | Concern raised; no future call |
| DEFERRED | STAGE2 or IRC_REVIEW | System | Next call opens; re-enters at the stage it left |
| NEGOTIATION | GRANTED | Applicant and programme manager | Identity verified; guardian consent if minor (I-18); amount within P-04 and P-05; contract EFFECTIVE |
| any pre-GRANTED | WITHDRAWN | Applicant | None |
| GRANTED | IN_EXECUTION | System | First milestone start date reached |
| IN_EXECUTION | COMPLETED | System | All milestone payment requests PAID |
| IN_EXECUTION | TERMINATED | Programme manager | Reason recorded |

NOTE 1: Annexe 5.c lets the budget change during stage 2. The revised plan is a new plan version. I-09 selects which version carries forward.

NOTE 2: Notifications to NOT_SELECTED applicants are sent within P-08 so they can seek funding elsewhere (Annexe 5.b, 5.c).

## Milestones and payment requests

Each milestone is closed through one or more payment requests (`payment-requests.md`). Payment may be full or partial per milestone (Annexe 5).

## Hardship contribution

Hardship contributions are payment requests of type "hardship", proportional to delivered work, with evidence held in the identity vault.

## Amendments

An amendment is a new plan version and a new contract version on a GRANTED or IN_EXECUTION proposal. It bypasses IRC_REVIEW only when an exemption in P-14 applies. Repeat grants and amendments are subject to I-15.
