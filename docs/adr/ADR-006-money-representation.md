# ADR-006: Money representation

Status: Accepted by Daniel on 2026-10-25.

## Context

Amounts appear in records that are hashed and signed. Decisions and policy versions are append-only (I-23), and a signed contract version is immutable (I-30). Amounts are also checked against the grant range and the per-recipient cap (I-13, I-14).

Content hashes and signatures use canonical JSON as defined by RFC 8785. RFC 8785 formats every JSON number as an IEEE 754 double.

- A double cannot represent every decimal amount exactly. Two different amounts can map to the same double, and so to the same canonical form and hash.
- The canonical number form also drops trailing zeros, so the minor-unit digits of an amount are lost.
- fstp-json's canonical serializer already refuses a number whose canonical form would change its value. That prevents a silent collision, but it is not a rule for amounts.

## Decision

Amounts are decimal strings in JSON, never JSON numbers. Each amount has exactly one canonical form.

- The form is the integer digits, a full stop, and exactly the currency's minor-unit digits. EUR always has two, for example `"1234.50"`.
- The integer part has no leading zeros. A single `0` stands for a zero integer part, as in `"0.50"`.
- An amount is never negative, and carries no sign. A deduction, reversal or refund is its own record type with a positive amount, decided by Daniel on 2026-10-25.
- Any other spelling is rejected on input, never normalised. For EUR this rejects `"1234.5"`, `"01234.50"`, `"+1234.50"`, `"-1234.50"`, `"1234.500"`, `"1.23450e3"` and the JSON number `1234.50`.
- Rust code holds amounts in an exact in-house decimal type. A floating-point type never holds an amount.
- PostgreSQL stores amounts as `numeric` with the currency's scale, which is 2 for EUR. Amounts are read and written through the exact decimal path of fstp-pgwire, its `Numeric` type, never through a float.

## Consequences

- Hashes and signatures over amounts are exact. Two different amounts never share a canonical form.
- Equal amounts in the same currency always have the same spelling, so they hash equally.
- The tenant export schema (`schemas/README.md`) records amounts as strings in this canonical form.
- Conversions between currencies are out of scope.
- TODO(legal): Daniel to confirm whether the grant agreement or the funder's rules fix how a calculated amount is rounded to the minor unit, for example a share of eligible costs.
