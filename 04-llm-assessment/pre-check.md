# Applicant pre-submission check

## Purpose

Applicants can check a draft against the same rubric before submitting. This helps first-time and less experienced applicants meet the bar on substance.

## Rules

- Uses the same pinned configuration as the open call (I-11).
- Returns findings only. Never scores or rubric bands.
- Integrity findings are shown to the applicant as well, so attempts to address the assessor become visible to the person making them.
- Rate-limited per proposal and per account across drafts in the same call (P-23). The interface shows remaining checks and when the next one becomes available.
- Drafts and pre-check runs stay in the applicant workspace. Operator and Judging roles cannot read them (I-21).
- Unsubmitted drafts and their pre-check runs are deleted when the call closes or the applicant withdraws.
- The operator sees aggregate usage counts only.
- The submitted version receives a fresh assessment. Pre-check results are not carried over.
- The interface discloses that the applicant is interacting with an AI system (R-LA-08).

NOTE: The pre-check is an oracle for anyone probing the assessor. Hiding scores, rate limiting and the injection resistance tests in `07-test-plan/llm-evaluation.md` are the mitigations. TH-02 tracks this.
