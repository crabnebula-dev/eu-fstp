# LLM assessment of submissions

## Purpose

Every submission receives findings on completeness, quality and accuracy of representation. Findings support human reviewers. They never decide (I-10).

## Pipeline

1. Extract text from the submission and attachments in a sandboxed parser.
2. Strip PII and replace it with stable placeholders.
3. Check completeness against the call's required elements.
4. Assess quality per criterion in P-01, using the pinned rubric.
5. Extract factual claims (maintainership, user numbers, upstream support, prior work).
6. Verify claims through the retrieval proxy against public sources.
7. Run integrity checks for instructions aimed at the assessor.
8. Validate output against the finding schema and publish to reviewers.

## Finding schema (outline)

| Field | Content |
| --- | --- |
| id | Stable identifier |
| type | completeness, quality, accuracy, integrity |
| criterion | P-01 criterion, where applicable |
| severity | info, minor, major |
| statement | Plain-language observation |
| evidence | Pointers into submission spans or retrieved sources |
| confidence | Model-reported confidence |
| config_id | Pinned model, prompt and rubric configuration (I-11) |
| trace_id | Reference to the retained trace |

## Rules

- Submission and retrieved content travel only in the data channel. Instructions come only from the pinned prompt.
- Integrity findings flag suspected instructions to the assessor. Reviewers see them.
- Indicative rubric bands are hidden from reviewers unless P-28 is on.
- Reviewers can mark each finding as agreed or disputed. These marks feed calibration. Marking stays open after the proposal reaches a terminal state, and a mark never changes the proposal (I-10) (decided 2026-10-26).
- If the pinned model becomes unavailable during a call, all findings in that call are regenerated with the replacement configuration before ranking.
- English fluency is not a quality signal. Quality refers to substance against the criteria.

## Claim verification

Retrieved sources may be under the applicant's control, such as their own repository README. Verification weighs independent sources above applicant-controlled ones and states which kind it used.

## Traces

Full traces (input hashes, prompt version, model response, retrieval log) of submission assessments are retained in the tenant cell for P-22, which ends with the funder audit period (P-41). A scheduled job deletes them afterwards. They support appeals and calibration. Trace use beyond the tenant requires tenant consent.
