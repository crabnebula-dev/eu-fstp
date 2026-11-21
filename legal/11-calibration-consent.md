# Calibration consent request and withdrawal

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Responsible data officer: Daniel Thompson-Yvetot.

Requirements: R-LA-09, R-LA-10, R-LA-11, I-37, P-42. Request items W11 (wording) and D5 (basis).

Code sites: `crates/fstp-domain/src/calibration.rs` (module marker), `crates/fstp-domain/src/command.rs` (`GiveCalibrationConsent.wording`), `crates/fstp-domain/src/record.rs` (consent record wording), `crates/fstp-domain-testkit/tests/i37_support/mod.rs` (test wording). The command stores the wording shown as a `TextRef`, so the approved text is stored as a text and referenced.

What the code does:

- The request opens only after the outcome notice record is committed. A proposal found ineligible gets no request (I-37, decided 2026-11-13).
- The lead gives consent to the wording shown. The lead can revoke it. A revoked proposal leaves every later calibration run (R-LA-10).
- Use beyond the tenant, research included, is not built (R-LA-11). It would need tenant agreement and a separate consent.

TODO(legal): D5, whether consent is the right basis, what the request must say, and whether calibration results already made can be kept after a withdrawal.

---

## A. Consent request

Heading:

> Help improve the AI assessor

Text:

> Your proposal has received its outcome. The organisation that runs this programme would like to use your proposal to check and improve the AI assessor it uses.
>
> If you agree:
>
> - Your proposal is used only by this organisation, on this platform, for this purpose.
> - Names, contact details, bank details and addresses are replaced with placeholders first.
> - Your proposal is compared with the findings of the AI assessor and with reviewers' marks on those findings.
> - Your proposal is not shared with anyone outside this organisation and is not used for research.
>
> Your choice has no effect on your proposal, its outcome, any complaint or any later application.
>
> You can withdraw your consent at any time on the platform. Your proposal then leaves every later calibration run.
>
> TODO(legal): what happens to calibration results made before a withdrawal (D5).

Choice labels:

- "I agree to the use of my proposal for calibration"
- "No, thank you"

## B. Confirmation of consent

> Thank you. Your proposal can now be used to calibrate the AI assessor of this programme. You can withdraw this consent at any time.

## C. Withdrawal

Button:

> Withdraw my consent

Confirmation:

> Your consent is withdrawn. Your proposal will not be used in any later calibration run.
