# M2 design: domain core (final)

Milestone M2 in `SPEC/09-milestones.md`: "Domain core: state machine, policy engine, SoD, scoring". Exit criteria: "I-01 to I-15 and I-23 green".

Status: final design for Daniel's review. No repository file was changed while writing it. Every repository change named here is staged by the implementing agent with a proposed commit message. Daniel creates, signs and pushes each commit.

Labels such as `Q4`, `W3`, `L-SOD` and `M-LIFE` exist only in this document. They are not spec identifiers. Every `I-`, `R-`, `P-`, `SoD-`, `TH-`, `T-`, `O-`, `L-` and `ADR-` identifier is quoted from the repository. Crate, type, model and test names are design proposals.

Sources re-read for this final version:

- `.claude/CLAUDE.md`, `SPEC/README.md`, `SPEC/00-scope.md`, `SPEC/09-milestones.md`, `SPEC/10-open-questions.md`.
- `SPEC/02-domain/`: `invariants.md`, `state-machine.md`, `roles-and-sod.md`, `policy-parameters.md`, `contracts.md`, `payment-requests.md`, `complaints.md`, `guide-for-applicants.md`.
- `SPEC/01-requirements/functional.md`, `SPEC/03-architecture/overview.md`, `SPEC/03-architecture/authentication.md`, `SPEC/04-llm-assessment/assessment.md`.
- `SPEC/06-threat-model/threat-model.md`, `SPEC/07-test-plan/test-plan.md`, `SPEC/07-test-plan/synthetic-corpus.md`, `docs/adr/ADR-006-money-representation.md`.
- The workspace `Cargo.toml`, `clippy.toml` and `deps/*.txt`.
- The public APIs of `fstp-prop`, `fstp-mc`, `fstp-json`, `fstp-pgwire` (`Numeric`) and `fstp-crypto`.

---

## 0. Approach

### 0.1 Base and grafts

The base is the ledger-first proposal. It had the highest combined judge scores (40 and 38). It gives one pure `queries`, `decide`, `apply` core over an append-only ledger. The model checker drives that production code directly, and the M3 seams are the clearest of the three.

Grafted from model-first:

- A crate boundary for I-10: `fstp-domain` has no dependency path to `fstp-findings`.
- Outcomes are computed, never chosen. `CloseStage1`, `RecordCutOff` and `RecordIrcReview` carry no target state.
- A minimal, history-normalised projection for model checking. Ids come from the shell, so interleavings merge.
- A reduced clock: `Tick` jumps only to scenario instants and one microsecond before each.
- `decide` recomputes its own vault questions and refuses with `FactsIncomplete` when an answer is missing.
- An `ACTOR_RULES` table as the single source for the M4 authorisation matrix and MCP parity (I-84).
- A deliberate-bug ("teeth") test per model, with predicates that never reuse guard code.

Grafted from types-first:

- Private-constructor witnesses for the highest-value guards only: `Quorum`, `Stage1Verdict`, `EffectiveScore`, `GrantClearance`, `CapReservation`, `RepeatClearance`, `PaymentChain<Released>`, and `FrozenPolicy` built only by the fold of a publication record.
- `CapReservation`: the I-14 check counts open reservations, so two concurrent negotiations cannot both pass.
- Cooling-off as one comparison: `barred_through = latest published call seq at binding end + pinned P-12`.
- The R1 analysis: I-06 and I-04 can hold only if discovery acts in the same step and the affected bindings stop counting as held.
- The M-RACE model, the `max_states` tripwire, two-way postconditions and `reachable` witnesses in every model.

Kept from ledger-first, as the judges highlighted:

- The fold checks structure only and never re-runs guards on load. Each decision records the rule-set version that produced it.
- An insert-only `RecordStore` with expected head and idempotency key, and canonical record text.
- `TextRef` keeps free text out of ledger bodies.
- A vault change in a model is followed by `VaultChanged` in the same step.
- Symmetry reduction is enabled only together with a self-test that compares verdicts with and without it.

### 0.2 Fixes applied to the proposals

These are the spec errors and flaws the judges found. Each is fixed here. Section 9.4 lists them with sources.

1. Money follows the accepted ADR-006: an optional minus sign, no `+`, no `"-0.00"`, and PostgreSQL `numeric` through `fstp-pgwire`'s `Numeric`. No design stores amounts as `bigint`.
2. `Amount` has no `PartialOrd` or `Ord`. Comparisons go through `cmp_same`, which refuses mixed currencies.
3. STAGE2 to DEFERRED has no future-call guard, as written.
4. The STAGE2 to RANKED guard and the GRANTED to IN_EXECUTION guard stay as written. Gaps go to Daniel.
5. I-06 and I-04 are stated over verified identities and the vault's knowledge. Every vault change is processed in the same model step.
6. Model start states are built by running the production engine from genesis.
7. The P-12 increase refusal is dropped. P-12 is pinned when a binding ends.
8. The I-11 call binding is the full `config_id` (model, prompt and rubric), not P-21 alone.
9. `FrozenPolicy` carries every frozen parameter, interpreted or not.
10. I-09 is asserted in every state after stage 2, including terminal ones.
11. The NEGOTIATION to GRANTED actors stay as written. The contract signatory conflict goes to Daniel.
12. The design no longer claims that the platform never learns an account link. A boolean answer over a one-member set is a link. Section 4.4 states what the platform learns and who can see it.

### 0.3 Where each exit invariant is held

| Invariant | Structure | Single checked constructor or guard | Tests |
| --- | --- | --- | --- |
| I-01 | Bindings and cooling windows live only in the roster; no binding record bypasses `grant_role` | Cooling comparison and group check | Machine, M-SOD (3 instances), teeth |
| I-02 | IRC assignment needs an active IRC member binding; IRC grant refused while another Judging role is active | Same | Machine, M-SOD, teeth |
| I-03 | Every read and reviewer act needs a `ReviewerAct` witness | Active assignment, no-conflict declaration, fresh vault answer | Machine, M-CONFLICT (truthful and havoc), teeth |
| I-04 | Receiving bindings are created only by draft and team commands | Vault answer at creation, at negotiation and on every vault or P-13 change | Machine, M-EXCL, teeth |
| I-05 | `PaymentChain<Released>` built only by `release` | Releaser differs from every acceptor and the approver | Machine, M-PAY, compile-fail twins, teeth |
| I-06 | Drafting and Judging grants need verification | Vault answers at grant, at verification and at GRANTED | Machine, M-SOD with identities, M-RACE, teeth |
| I-07 | Stage 1 exit records need a `Stage1Verdict`, which needs a `Quorum` | Count of distinct valid scores | Pure, machine, M-LIFE-S1, teeth |
| I-08 | `CloseStage1` carries no outcome | Strict `>` by cross-multiplication | Pure against exact reference, M-LIFE-S1, teeth |
| I-09 | `EffectiveScore` has exactly one plan field and is never cleared | P-24 in `effective_score` | Pure, M-LIFE-S2, teeth |
| I-10 | `fstp-domain` cannot name a finding; findings commands cannot emit core records | None | Twin machine, M-LIFE-S1 with findings, layering gate |
| I-11 | `FindingStore` keyed by producing call | Insert compares with the call's pinned `config_id` | Machine, M-FIND, teeth |
| I-12 | Guards read frozen values only through the published call's `FrozenPolicy` | Fold of `CallPublished` | Twin machine, M-POLICY, catalogue test, teeth |
| I-13 | GRANTED needs a `GrantClearance` holding a `GrantAmount` | Range and deduction check | Machine, M-MONEY, teeth |
| I-14 | GRANTED needs a `CapReservation` | Vault answer over granted plus reserved; P-05 edit check | Machine, M-MONEY, M-RACE, teeth |
| I-15 | GRANTED and amendment activation need a `RepeatClearance` | Local record check, then a vault answer | Property, M-MONEY, teeth |
| I-23 | Store API has no update or delete; views are folds | Correction targets checked in the fold | Ledger machine, verifier property, M-LEDGER, compile-fail twins |

---

## 1. Crate layout

Six new in-house crates. No third-party crate is added, so no dependency ADR is needed.

| Crate | Responsibility | In-house dependencies | Fuzz project |
| --- | --- | --- | --- |
| `fstp-money` | ADR-006 `Amount`, `Currency`, `NonNegAmount`, `PosAmount`, `AmountRange`. Exact `Percent` and `Ratio`. String codecs, checked arithmetic | `fstp-json` | `amount_parse`, `amount_json`, `percent_parse` |
| `fstp-ledger` | Generic append-only ledger: `Seq`, `Entry<R>`, `RecordStore`, `MemStore`, `verify_append_only`, `Canonical` | `fstp-json` | `entry_decode` |
| `fstp-domain` | Pure domain core without findings: ids, time, policy engine, programmes and calls, roles and SoD, assignments and conflicts, proposals and plans, scoring, decisions, grants, payments seam, visibility, vault query types, `queries`, `decide`, `apply`, `due`, codecs | `fstp-money`, `fstp-ledger`, `fstp-json` | `record_decode`, `command_decode`, `policy_decode` |
| `fstp-findings` | `Finding` as data, `UntrustedText`, `FindingStore`, the I-11 check, finding records and codec | `fstp-domain`, `fstp-money`, `fstp-ledger`, `fstp-json` | `finding_decode` |
| `fstp-engine` | Composition: `EngineState`, `Command` and `Record` envelopes over core and findings, the synchronous reference driver, the sync `IdentityOracle` trait | all of the above | `envelope_decode`, `decide_sequence` |
| `fstp-domain-testkit` | Test only, `publish = false`. Synthetic vault, independent references, generators, scenario builder, reduced clock, fstp-prop and fstp-mc adapters. The invariant suites live in its `tests/` | all of the above, `fstp-prop`, `fstp-mc` | none: it holds no parser |

```text
fstp-json <- fstp-money  <- fstp-domain <- fstp-findings <- fstp-engine
fstp-json <- fstp-ledger <-'      ^                              ^
                                  '------------------------------'
fstp-prop, fstp-mc <- fstp-domain-testkit -> every crate above
```

Rules:

- **No I/O.** No M2 crate depends on `fstp-rt`, `fstp-http`, `fstp-tls`, `fstp-pgwire`, `fstp-pgtest`, `fstp-migrate` or `fstp-crypto`. M2 needs no async runtime, so ADR-002 is untouched.
- **I-10 boundary.** `fstp-domain` has no dependency path to `fstp-findings` or `fstp-engine`. Findings depend on the domain, never the reverse.
- **Testkit never ships.** No crate takes `fstp-domain-testkit`, `fstp-prop` or `fstp-mc` as a normal dependency, except the testkit itself.
- **Layering gate.** A new module in `tools/deps-check` enforces the three rules above from `cargo metadata`, with its own tests. Until it lands, a testkit test runs the same check.
- **No floats.** Each new crate adds `#![deny(clippy::float_arithmetic, clippy::float_cmp, clippy::cast_precision_loss, clippy::arithmetic_side_effects)]`. A testkit source scan also fails on `f32`, `f64`, `as_f64_lossy` or `fstp_json::Decimal` in the five production crates. The workspace lint table does not change.
- **Determinism.** No `HashMap` or `HashSet` in domain state. `BTreeMap` and `BTreeSet` keep order stable for `fstp-mc`.
- **Derives.** State and witness types derive `Clone, PartialEq, Eq, Hash, Debug`, which `fstp-mc` needs. They never derive `Default`. Witnesses never implement `FromJson`.
- **Money in JSON.** `fstp_json::Decimal` never carries money. It maps to JSON numbers and normalises `1234.50` to `1234.5`, which ADR-006 forbids. The `fstp-json` crate docs still describe `Decimal` as "for money". A follow-up doc change is listed in section 10.

Repository changes to stage in W0:

- `Cargo.toml`: six `members` entries and six `[workspace.dependencies]` path entries.
- `deps/fuzz-required.txt`: `fstp-money`, `fstp-ledger`, `fstp-domain`, `fstp-findings`, `fstp-engine`.
- `crates/<each>/fuzz/`: one cargo-fuzz project per parser-bearing crate with at least one target from the first commit.
- `tools/deps-check/src/layering.rs` and its registration and tests.

---

## 2. Domain model

### 2.1 Identifiers

```rust
macro_rules! id { ($($n:ident),*) => { $(
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct $n(u128);
    impl $n { pub const fn from_raw(r: u128) -> Self { Self(r) } pub const fn raw(self) -> u128 { self.0 } }
)* } }
id!(ProgrammeId, CallId, PolicyVersionId, AccountId, BindingId, ProposalId, PlanVersionId,
    MilestoneId, DeliverableId, AssignmentId, DecisionId, AmendmentId, RequestId, OrganisationId,
    LlmConfigId, TextId);

pub struct CommandId([u8; 16]);   // idempotency key from the shell
pub struct Handle([u8; 16]);      // P-11 handle; never derived from AccountId
pub struct VaultEpoch(u64);
pub struct CallSeq(NonZeroU32);   // publication order within a programme, from 1
pub struct ContentDigest([u8; 32]); // computed outside the core (M3 uses fstp-crypto)
pub struct TextRef { id: TextId, digest: ContentDigest } // free text held outside ledger bodies (section 5.2)
```

- **The shell supplies ids** inside commands. M3 draws them with `fstp_crypto::random_array`. Tests use small fixed pools. `decide` refuses a reused id. In the model checker the pool size bounds how many entities exist, and two orders of the same creations give the same state.
- **No identity data.** The domain holds no names, dates of birth, contact data or person keys. The vault alone links accounts to people.
- **JSON.** Every `u128` id and every `Seq` is a decimal string, because RFC 8785 numbers are exact only up to 2^53.

### 2.2 Time

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);   // UTC microseconds since the Unix epoch
pub struct Days(u16);
impl Timestamp { pub fn checked_add_days(self, d: Days) -> Option<Timestamp>; }
```

- `decide` never reads a clock. The shell reads `Clock::now()` once per command and passes it in `Ctx`.
- `decide` refuses a `ctx.now` earlier than the latest recorded time, so the ledger is time-monotone.
- Guards only compare times. That makes the reduced clock in section 6.1 sound.
- A call deadline is a UTC instant plus its IANA zone name as text. M2 does not interpret zones. Working days (P-08, P-40) belong to M6.
- Interim: P-07 is a whole number of days, and the stage 2 window closes at `opened_at + days × 86 400 s` in UTC. M6 may refine this with the timeline engine.

### 2.3 Money and exact numbers (`fstp-money`, ADR-006)

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Currency { Eur }
impl Currency {
    pub const fn code(self) -> &'static str;       // "EUR"
    pub const fn minor_digits(self) -> u8;         // 2
    pub fn from_code(code: &str) -> Result<Currency, CurrencyError>;
}

/// Exact signed amount in minor units of one currency.
/// No PartialOrd or Ord: use cmp_same. No float conversion exists. No operator traits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Amount { minor: i64, currency: Currency }
impl Amount {
    /// 18 digits. i64::MIN is never representable, so negation is total.
    pub const MAX_ABS_MINOR: i64 = 999_999_999_999_999_999;
    pub fn from_minor(minor: i64, c: Currency) -> Result<Amount, MoneyError>;
    pub fn zero(c: Currency) -> Amount;
    pub fn minor(self) -> i64;
    pub fn currency(self) -> Currency;
    pub fn checked_add(self, o: Amount) -> Result<Amount, MoneyError>;
    pub fn checked_sub(self, o: Amount) -> Result<Amount, MoneyError>;
    pub fn neg(self) -> Amount;
    pub fn cmp_same(self, o: Amount) -> Result<core::cmp::Ordering, MoneyError>;
    pub fn parse(text: &str, c: Currency) -> Result<Amount, AmountParseError>;
}
impl core::fmt::Display for Amount { /* canonical ADR-006 spelling */ }
pub fn checked_sum(c: Currency, it: impl IntoIterator<Item = Amount>) -> Result<Amount, MoneyError>;

/// Zero or more. Grant amounts, P-04, P-05, budgets, deductions, sums.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NonNegAmount(Amount);
/// Above zero. Milestone amounts and payment lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PosAmount(Amount);
/// Same currency, min <= max, checked at construction.
pub struct AmountRange { min: NonNegAmount, max: NonNegAmount }
impl AmountRange {
    pub fn new(min: NonNegAmount, max: NonNegAmount) -> Result<AmountRange, MoneyError>;
    pub fn contains(&self, a: NonNegAmount) -> Result<bool, MoneyError>; // inclusive (interim, Q7)
}

pub enum MoneyError { CurrencyMismatch, Overflow, Negative, Zero, OutOfRange }
/// Byte offset and kind only, never input content (R-NF-02).
pub struct AmountParseError { pub offset: usize, pub kind: AmountParseErrorKind }

impl fstp_json::ToJson for Amount { /* always Value::String */ }
pub fn amount_from_json(v: &fstp_json::Value, c: Currency) -> Result<Amount, fstp_json::FromJsonError>;
```

- **Grammar (EUR).** `-?(0|[1-9][0-9]*)\.[0-9]{2}`, excluding `-0.00`, with `|minor| <= MAX_ABS_MINOR`.
- **Rejected spellings.** The JSON number `1234.50`, `"1234.5"`, `"01234.50"`, `"+1234.50"`, `"1234.500"`, `"1.23450e3"`, `"-0.00"`, `"1234"`, `".50"`, `"1234."`, whitespace, separators, a comma and non-ASCII digits. Rejection is never normalisation.
- **Round trip.** Every accepted `s` satisfies `format(parse(s)) == s`.
- **Currency in records.** `FromJson` has no currency context. Each record carries its programme currency code, and its amounts decode through `amount_from_json` with that currency.
- **Storage seam (M3).** The ADR-006 canonical text equals the canonical text of `fstp_pgwire::types::Numeric` at scale 2 for the same value. M3 converts with `Numeric::parse(&a.to_string())` and back with `Amount::parse(n.as_str(), c)`. It checks `n.scale() == minor_digits`. `fstp-money` does not depend on `fstp-pgwire`.
- **Bound.** ADR-006 sets no range. The 18-digit bound is a design choice that keeps every sum checked in `i64`. M3 picks a `numeric` precision that holds it.
- **No division.** M2 has no division, so no rounding rule is needed. ADR-006 keeps rounding as `TODO(legal)`.

```rust
/// 0.00 to 100.00 percent in basis points. Canonical JSON form "75.00" (interim, Q1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Percent { bp: u16 }
impl Percent { pub fn parse(t: &str) -> Result<Percent, PercentParseError>; pub fn bp(self) -> u16; }

/// Exact non-negative rational in lowest terms, so derived Eq and Hash match value equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ratio { num: u64, den: NonZeroU64 }
impl Ratio {
    pub fn new(num: u64, den: NonZeroU64) -> Ratio;
    /// num * 10_000 > bp * den, computed in u128. I-08 strict comparison.
    pub fn exceeds(self, p: Percent) -> bool;
}
impl Ord for Ratio { /* a/b vs c/d as a*d vs c*b in u128 */ }
```

### 2.4 Policy engine and freezing

```rust
pub enum ParamId { P01, P02, /* ... */ P78 }
pub enum Freeze { Frozen, Live }
pub enum Level { Programme, Tenant, Fixed }
pub struct ParamSpec { pub id: ParamId, pub freeze: Freeze, pub level: Level }
/// Hand-transcribed from SPEC/02-domain/policy-parameters.md. Reviewed row by row in W1c.
pub const CATALOGUE: [ParamSpec; 78];

/// Every frozen programme parameter. Typed where M2 interprets it, opaque otherwise.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrozenValues {
    pub p01: Criteria,               // criteria, weights, score scale (Q1)
    pub p02: Percent,
    pub p03: NonZeroU8,
    pub p04: AmountRange,
    pub p07: Days,
    pub p09: KnockOutCriteria,
    pub p10: ReadAccess,             // AssignedReviewersOnly | AllCommitteeMembers | OperatorStaffOnly
    pub p11: ReviewerAnonymity,      // Anonymous | Named
    pub p14: IrcExemptions,
    pub p15: NonZeroU8,
    pub p16: VotingRules,
    pub p17: TieBreakRule,           // recorded rule, applied by people (Q17)
    pub p21: InferenceBinding,       // provider and pinned model
    pub p24: EffectiveScoreRule,     // one variant: HigherOfOriginalAndRevised
    pub p26: LicenceSet,             // exact SPDX identifiers
    pub p39: NonZeroU8,
    pub p53: FunderProfileRef,
    pub p77: McpBindingActions,      // DraftOnly | Allowed
    /// P-08, P-23, P-25, P-28, P-29, P-30, P-34, P-44, P-55, P-59 to P-66, P-75 and any other
    /// frozen parameter, as canonical JSON text, so it freezes with the rest.
    pub opaque: BTreeMap<ParamId, OpaqueValue>,
}

/// Non-frozen programme parameters, read live at decision time.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LiveValues {
    pub p05: NonNegAmount,
    pub p12: CoolingOff,             // Calls(u8)
    pub p13: ExclusionClasses,       // opaque class ids the vault matches (Q9)
    pub p38: ProximityLists,
    pub p56: Option<NonNegAmount>,
    pub p58: Option<NonNegAmount>,
    pub opaque: BTreeMap<ParamId, OpaqueValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyVersion {
    pub id: PolicyVersionId,
    pub programme: ProgrammeId,
    pub parent: Option<PolicyVersionId>,
    pub currency: Currency,
    pub frozen: FrozenValues,
    pub live: LiveValues,
}
pub struct OpaqueValue(String); // RFC 8785 text, so Eq and Hash are exact

/// Built only by the fold of a CallPublished record. No public constructor.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrozenPolicy { call: CallId, version: PolicyVersionId, values: Arc<FrozenValues> }
```

- **Tenant-level parameters** (P-20, P-69 to P-74, P-78) and the fixed P-68 are not in the programme policy. They belong to tenant configuration in M3 and M4.
- **Edits.** `EditPolicy { programme, base, new_version, changes }` appends a new version (I-23). `base` must equal the current head. The projection records the last author of each parameter, which R-PC-03 needs.
- **Validation refuses only values that are inconsistent or unsafe.**
  - Inconsistent: P-04 min above max, a currency mismatch, P-02 above 100.00, an empty P-01, P-05 above P-58 (I-50).
  - Unsafe for exact arithmetic: more than 16 criteria, a weight above 1000, a scale maximum above 100, P-03 above 64.
- **Other cross-checks are warnings** in the validation report for the M4 creator. Examples are P-04 max above P-05 and P-39 above P-03. The spec states no such rule, so the engine does not invent a refusal.
- **Live edits that would break an invariant are refused.** Lowering P-05 below any recipient's granted plus reserved sum is refused, after an `AllRecipientsWithinCap` vault answer (I-14, Q7). Adding a P-13 class runs enforcement point 3 in the same batch (Q5, Q9).
- **I-12 by construction.**
  1. `CallPublished { call, policy }` points to an immutable version. The fold refuses a second publication of the same call.
  2. No record kind changes a call's policy after publication. A corrigendum (M9) has no record kind that can reach frozen values.
  3. Every guard reads frozen values through `governing_policy(state, proposal) -> &FrozenPolicy`. It never receives a `PolicyVersion`. Q15 can change which call governs a deferred proposal by editing this one function.
  4. Live values come from the programme head. The decision record that used them copies the values it read.

### 2.5 Programmes and calls

```rust
pub struct CallView {
    pub id: CallId,
    pub programme: ProgrammeId,
    pub status: CallStatus,            // Draft | Approved | Published; open and closed derive from time (Q14)
    pub seq: Option<CallSeq>,          // set at publication
    pub opens: Timestamp,
    pub deadline: Timestamp,
    pub deadline_zone: ZoneName,
    pub budget: NonNegAmount,          // call record field, not a parameter; immutable once published (Q14)
    pub authors: BTreeSet<AccountId>,  // every account that drafted or edited the call text
    pub approval: Option<DecisionId>,
    pub frozen: Option<FrozenPolicy>,  // Some once published (I-12, R-PC-02)
    pub llm_config: Option<LlmConfigId>, // config_id pinned at publication (I-11, R-LA-05)
}
```

- **R-PC-03.** `ApproveCallPublication` needs a programme manager who is not a drafter of the call. Interim drafter set (Q14): the call's authors plus the last authors of P-01 and P-09 in the version being frozen. `SPEC/00-scope.md` defines a drafter as the author of call text and criteria.
- **Publication.** `PublishCall { call, config: LlmConfigId, config_model: ModelRef }` needs the approval. It binds the head version and assigns the next `CallSeq`. It refuses unless `config_model` equals the frozen P-21 model. M7 verifies the config's contents.
- **High risk.** `Command::high_risk()` marks `PublishCall` and every Drafting, Judging, Operations or tenant admin grant. The M3 shell enforces the step-up (I-78). The domain does not check freshness.

### 2.6 Roles and bindings over time

```rust
pub enum Group { Drafting, Judging, Receiving, Operations }
pub enum Role {
    ProgrammeManager, CallDrafter,                                   // Drafting
    FstpCoordinator, CommitteeMember, CommitteeChair, IrcMember,     // Judging
    Applicant, ApplicantTeamMember, Guardian,                        // Receiving
    TenantAdmin, FinanceApprover, PaymentReleaser, Auditor,          // Operations
}
impl Role { pub const fn group(self) -> Group; }
pub enum BindingScope { Programme, Proposal { proposal: ProposalId, call: CallId } }

pub struct BindingGranted {
    pub binding: BindingId, pub account: AccountId, pub programme: ProgrammeId,
    pub role: Role, pub scope: BindingScope, pub start: Timestamp,
    pub granted_by: AccountId,
    pub second_admin: Option<AccountId>,      // SoD-07
    pub confidentiality: Option<TextRef>,     // Drafting and Judging; terms wording TODO(legal)
    pub organisation: Option<OrganisationId>, // committee members, for I-34 (Q12)
    pub verified_epoch: Option<VaultEpoch>,   // SoD-09 answer used
}
/// barred_through counts calls: 0 when no call of the programme was published before the end.
pub struct BindingEnded { pub binding: BindingId, pub at: Timestamp, pub barred_through: u32, pub p12: CoolingOff }
pub struct BindingSuspended { pub binding: BindingId, pub rule: RuleRef, pub epoch: VaultEpoch }
pub struct BindingVoided { pub binding: BindingId, pub rule: RuleRef, pub epoch: VaultEpoch } // Q5
pub struct BindingReinstated { pub binding: BindingId, pub by: AccountId, pub reason: TextRef }
```

- **Assigned reviewer** is an assignment, not a binding. It needs an active committee member binding. It counts as a Judging role for I-01 and I-02.
- **Receiving bindings** are written by the domain itself (interim, Q11). `CreateDraft` grants Applicant scoped to the proposal and call. `AddTeamMember` and `AddGuardian` grant the other two Receiving roles. They end when the proposal reaches a terminal state.
- **Cooling-off in one place.** `BindingEnded` pins `barred_through = latest published CallSeq at end + P-12 at end`. The projection keeps, per programme, account and group, the largest `barred_through`.
  - A Receiving binding in call `c` is refused while `c.seq <= barred_through` of any Drafting or Judging window of that account. This bars the calls published while the binding was active, and the next P-12 calls (strict reading, Q4).
  - Interim strict reading of I-01 (Q4): every switch among Drafting, Judging and Receiving uses the same windows. A programme-level target is refused while the latest published seq is at most `barred_through`.
  - P-12 is not frozen. Pinning it at the end makes each window fixed. A later edit changes only bindings that end afterwards.
- **Other account-level rules at binding:**
  - SoD-01: no overlap across Drafting, Judging and Receiving.
  - SoD-02 and I-02: an IRC member holds no other active Judging role or assignment, and the reverse.
  - SoD-03: Operations and Receiving never overlap.
  - SoD-07: a tenant admin's self-grant needs a second admin.
- **SoD-09 at binding.** A Drafting or Judging grant needs `IsVerified(candidate)` true and `SameIdentityAsAny(candidate, S)` false. `S` holds the accounts whose bindings or open windows would break I-01 if they were the candidate's.
- **No backdating.** Starts and ends earlier than `ctx.now` are refused.
- **Suspended and voided bindings** are inactive for every action. Whether they count as held is Q5. The interim reading in section 9.3 keeps I-04 and I-06 satisfiable.
- **Grant authority** (who may grant which role) is unspecified. Interim: a tenant admin grants programme roles, with SoD-07 on self-grants.

### 2.7 Assignments, conflicts, handles and reads

```rust
pub enum AssignmentKind { Reviewer, Irc, Amendment(AmendmentId) }
pub enum AssignmentStatus { AwaitingDeclaration, Active, Released(ReleaseCause) }
pub enum ReleaseCause { DeclaredConflict, DetectedConflict, Unassigned, BindingEnded, BindingSuspended, BindingVoided }

pub struct Assigned { pub assignment: AssignmentId, pub proposal: ProposalId, pub call: CallId,
                      pub reviewer: AccountId, pub kind: AssignmentKind, pub handle: Option<Handle>,
                      pub by: AccountId, pub epoch: VaultEpoch }
pub struct ConflictDeclared { pub assignment: AssignmentId, pub conflicted: bool, pub notifiable: bool } // R-CF-02, R-CF-04
pub struct ConflictDetected { pub account: AccountId, pub proposal: ProposalId, pub epoch: VaultEpoch } // no reason (R-CF-03)
pub struct AssignmentReleased { pub assignment: AssignmentId, pub cause: ReleaseCause }
pub struct ContentRead { pub account: AccountId, pub proposal: ProposalId } // R-AU-01

/// The only proof a read or reviewer act may proceed (I-03). Built by review::reviewer_act.
pub struct ReviewerAct { account: AccountId, proposal: ProposalId, assignment: AssignmentId, epoch: VaultEpoch }
```

- **Assign** (interim actor: FSTP coordinator) needs all of these:
  - an active committee member binding for a reviewer, or an active IRC member binding for IRC;
  - `HasConflict(reviewer, team)` false and no earlier conflict fact on this proposal in any call;
  - under P-11 anonymous, a handle that was never issued before in this cell;
  - when organisation and proximity data exist, I-34 and I-35 (Q12).
- **Reviewer act.** `reviewer_act` needs an active assignment, a `ConflictDeclared { conflicted: false }` on it, no conflict fact, and a fresh `HasConflict` false at the current epoch. Interim scope (Q10): content reads, scores, corrections, stage 2 questions, amount determination, line acceptance, reallocation approval and IRC reviews.
- **Coordinator reads.** I-03 bars reads by any conflicted person. The FSTP coordinator therefore declares per proposal before the knock-out read, and the same fresh vault check applies.
- **Declaring a conflict** releases the assignment in the same batch. The proposal then shows a reassignment need. The conflict fact is permanent for that proposal, across calls.
- **Handles.** The projection keeps every handle ever issued. Uniqueness across proposals and calls is checked exactly within the cell.

### 2.8 Proposals and plan versions

```rust
pub enum ProposalState {
    Draft, Submitted, Ineligible, Stage1, NotSelected, Stage2, Ranked, IrcReview,
    Deferred { left: ReentryStage }, Declined, Negotiation, Withdrawn,
    Granted, InExecution, Completed, Terminated,
}
pub enum ReentryStage { Stage2, IrcReview }
impl ProposalState {
    /// INELIGIBLE, NOT_SELECTED, DECLINED, WITHDRAWN, COMPLETED, TERMINATED.
    pub fn is_terminal(self) -> bool;
    /// DRAFT, SUBMITTED, STAGE1, STAGE2, RANKED, IRC_REVIEW, DEFERRED, NEGOTIATION.
    pub fn is_withdrawable(self) -> bool;
}

pub struct PlanVersionRecorded { pub plan: PlanVersionId, pub proposal: ProposalId, pub origin: PlanOrigin,
                                 pub supersedes: Option<PlanVersionId>, pub tasks: Vec<Task>,
                                 pub content: ContentDigest }
pub enum PlanOrigin { Submitted, Stage2Revision, Negotiated, Amendment }
pub struct Task { pub milestones: Vec<Milestone> }  // task and plan totals are derived, never stored
pub struct Milestone { pub id: MilestoneId, pub amount: PosAmount, pub due: Timestamp,
                       pub activity: Option<ActivityTypeRef>, pub deliverables: Vec<DeliverableId> }
```

- **R-SB-01 by type.** No submission command or plan type has an identity document, date of birth or payment field.
- **R-SB-02.** `Submit` needs no guardian record.
- **R-SB-05.** `Submit` needs an `EthicsDeclaration { issues_declared: bool, text: TextRef }`.
- **R-NG-06 seam.** `Submit` carries the data protection notice version that M4 showed.
- **The minor flag** is a fact supplied at draft creation. Its derivation relative to the call deadline is M3 (R-ID-04).
- **Plan text** lives outside the domain. The domain holds amounts, structure and a content digest.

### 2.9 Scores and scoring

```rust
pub struct Criteria { scale_max: NonZeroU8, items: Vec<Criterion> } // 1..=16 unique criteria (Q1)
pub struct Criterion { pub id: CriterionId, pub weight: NonZeroU16 }  // weight <= 1000
pub enum Stage { One, Two }
pub struct ScoreKey { pub assignment: AssignmentId, pub stage: Stage, pub plan: PlanVersionId }
pub struct ScoreVector(Vec<u8>); // one value per P-01 criterion, each 0..=scale_max
pub struct ScoreRecorded { pub key: ScoreKey, pub values: ScoreVector, pub supersedes: Option<Seq>, pub reason: Option<TextRef> }
pub struct ScoreVoided { pub key: ScoreKey, pub cause: VoidCause }

/// I-07 witness. Distinct, active, non-conflicted assignments with a current score, at least P-03.
pub struct Quorum { proposal: ProposalId, stage: Stage, plan: PlanVersionId, keys: BTreeSet<ScoreKey>, required: NonZeroU8 }
pub fn establish_quorum(state: &State, proposal: ProposalId, stage: Stage, plan: PlanVersionId,
                        policy: &FrozenPolicy, answers: &Answers) -> Result<Quorum, Refusal>;

/// Mean over reviewers of the weighted sum, as a fraction of the maximum (interim, Q1):
/// num = sum_r sum_i w_i * s_ri, den = R * scale_max * sum_i w_i.
pub fn weighted_score(q: &Quorum, state: &State, policy: &FrozenPolicy) -> Ratio;

/// I-08 witness. Built only here. Passed is exactly score.exceeds(P-02).
pub struct Stage1Verdict { quorum: Quorum, score: Ratio, threshold: Percent, passed: bool }
pub fn judge_stage1(q: Quorum, state: &State, policy: &FrozenPolicy) -> Stage1Verdict;

/// I-09 witness. Exactly one plan version, by field type.
pub struct EffectiveScore { plan: PlanVersionId, value: Ratio, basis: Basis } // Original | Revised
pub fn effective_score(rule: EffectiveScoreRule, original: (PlanVersionId, Ratio),
                       revised: Option<(PlanVersionId, Ratio)>) -> EffectiveScore; // tie keeps the original (Q3)
```

- **Valid score (interim, Q2).** The current value of its key, from an assignment that is active now, with no conflict fact for its account on the proposal. Scores of released or conflicted reviewers never count. A correction replaces the current value and never counts twice.
- **Bounds.** At most 16 criteria, weights at most 1000, scale maximum at most 100 and at most 64 valid scores. The largest denominator is 1.024e8, so every product fits easily in `u128`.
- **Edge case kept in tests.** Weights 30/40/30, scale 0 to 4, every score 3: the score is exactly 75.00%, so the proposal is NOT_SELECTED.
- **Scale independence.** The score is a fraction of the maximum. Scaling all weights leaves it unchanged. With complete vectors, "average then weight" equals "weight then average".

### 2.10 Decisions and records

Every decision is a ledger record. A correction is a new record with `supersedes`. Each decision carries `rules: RulesVersion(u16)`, the version of the interim readings that produced it.

| Record | Holds |
| --- | --- |
| `KnockOutRecorded` | coordinator, outcome per P-09 criterion, reason `TextRef` |
| `Stage1Closed` | built from `Stage1Verdict`: score, threshold, counted keys, outcome, recorder (Q2) |
| `EffectiveScoreSet` | built from `EffectiveScore`: plan, value, basis, counted keys |
| `CutOffRecorded` | call, ordered proposals, nominated count, rationale `TextRef`, ballots and delegations, remaining budget |
| `IrcReviewRecorded` | assignment, `Validate` or `Concern(TextRef)` |
| `DeferralRecorded`, `ReEntered` | source call, target call, stage left |
| `AmountDetermined` | effective plan total, deductions with reasons, granted amount, agreed plan |
| `CapReserved`, `CapReleased` | proposal, amount, epoch |
| `GrantDecided` | applicant acceptance, programme manager approval, contract reference, clearances' epochs |
| `AmendmentActivated` | amendment, plan, route (exemption or IRC), contract reference |
| `Transitioned` | proposal, from, to, row, actor, decision (R-AU-01) |
| `VaultOutcome` | query digest, boolean, epoch; never a reason (section 4.4) |
| `OutboxEnqueued` | notification or group event for M6 and M8 (I-29 seam) |

`Row` names a state machine row by its endpoints, for example `Row::Stage1ToStage2`. It introduces no spec identifier.

### 2.11 Grants, reservations and deliverables (I-13, I-14, I-15)

```rust
/// I-13. granted == effective plan total - deductions (interim, Q7), within P-04, and
/// the agreed plan total equals granted.
pub struct GrantAmount { proposal: ProposalId, granted: NonNegAmount, agreed_plan: PlanVersionId, decision: DecisionId }
pub fn determine_amount(state: &State, act: &ReviewerAct, deductions: &[IneligibleCost],
                        agreed: PlanVersionId, policy: &FrozenPolicy) -> Result<GrantAmount, Refusal>;

/// I-14. Built from a vault answer over every grant and open reservation in the programme.
pub struct CapReservation { proposal: ProposalId, amount: NonNegAmount, epoch: VaultEpoch }
pub fn reserve_cap(state: &State, g: &GrantAmount, answers: &Answers) -> Result<CapReservation, Refusal>;

/// I-15. Local completeness check of prior records, then one vault answer.
pub struct RepeatClearance { subject: AccountId, epoch: VaultEpoch }
pub fn clear_repeat(state: &State, subject: AccountId, policy: &FrozenPolicy, answers: &Answers)
    -> Result<RepeatClearance, Refusal>;

/// Everything row 14 needs. Built only by clear_grant.
pub struct GrantClearance {
    amount: GrantAmount, cap: CapReservation, repeat: RepeatClearance,
    identity: IdentityCleared,   // IsVerified(lead); SoD-09 and I-06; I-04 for every Receiving account
    minor: MinorCleared,         // I-18 seam: consent if minor-flagged (M3 vault)
    contract: ContractEffective, // M5 port fact
    acceptance: DecisionId, approval: DecisionId,
}

pub struct DeliverableRecorded {
    pub deliverable: DeliverableId, pub grant: ProposalId, pub milestone: MilestoneId,
    pub public_location: TextRef, pub release: TextRef, pub licence: SpdxId,
    pub snapshot: ContentDigest, pub accepted: bool,
}
```

- **Reservation timing.** `DetermineAmount` (assigned reviewer, R-NG-03) reserves headroom with `WithinRecipientCap`. Withdrawal, a negotiation failure or a later amount change releases it in the same batch.
- **Contract seam.** M5 calls `grant_preconditions(state, proposal)` before a contract goes to SENT and again at countersignature. A countersigned contract can then never fail I-14 or I-15 at GRANTED.
- **Granted sums** are kept per programme and per account. The vault groups them by verified identity.
- **I-64 seam.** At COMPLETED or TERMINATED, committed amounts drop to the paid total (interim, Q7).
- **Amendments** leave the proposal state unchanged (Q18). `ProposeAmendment`, then `RouteAmendment` (P-14 exemption or IRC), then `ActivateAmendment` on the M5 contract-version fact. Activation needs `RepeatClearance` (I-15), the I-13 range on the amended total and a delta `CapReservation` (I-14) (interim, Q7).

### 2.12 Payments seam (I-05)

```rust
pub struct PaymentChain<S> { request: RequestId, grant: ProposalId, state: S }
pub struct LinesAccepted { acceptors: BTreeSet<AccountId> }
pub struct Approved { acceptors: BTreeSet<AccountId>, approver: AccountId }
pub struct Released { acceptors: BTreeSet<AccountId>, approver: AccountId, releaser: AccountId }
impl PaymentChain<LinesAccepted> { pub fn approve(self, by: AccountId) -> Result<PaymentChain<Approved>, Refusal>; }
impl PaymentChain<Approved> {
    /// The only constructor of Released. The releaser is not an acceptor and not the approver.
    pub fn release(self, by: AccountId) -> Result<PaymentChain<Released>, Refusal>;
}
```

- `decide` rebuilds the chain from the projection and calls the typestate method. The record builder for `PaymentReleased` takes `&PaymentChain<Released>`.
- `AcceptLine` needs a `ReviewerAct` on the grant (I-03). A mentor of the grant is refused (SoD-12). `ApprovePayment` needs a finance approver binding. `ReleasePayment` needs a payment releaser binding.
- M5 adds lines, balances, checks and adapters around this chain without changing it.

### 2.13 Findings (`fstp-findings`)

```rust
/// No Display, no Deref<Target = str>, no AsRef<str>. Cannot be pasted into an instruction by accident.
pub struct UntrustedText(String);
pub struct Finding {
    pub id: FindingId, pub call: CallId, pub proposal: ProposalId,
    pub config: LlmConfigId,       // config_id: model, prompt and rubric (assessment.md, I-11)
    pub kind: FindingKind,         // Completeness | Quality | Accuracy | Integrity
    pub criterion: Option<CriterionId>, pub severity: Severity, pub confidence: Confidence,
    pub statement: UntrustedText, pub evidence: Vec<EvidenceRef>, pub trace: TraceRef,
}
pub struct FindingStore { by_call: BTreeMap<CallId, BTreeMap<FindingId, Finding>> }
pub enum FindingCommand { Record(Finding), Mark { finding: FindingId, mark: Mark } } // Agreed | Disputed
pub enum FindingRecord { Recorded(Finding), Marked { finding: FindingId, by: AccountId, mark: Mark } }

/// Reads the domain state; returns only FindingRecord values. I-11: config must equal the call's pinned config_id.
pub fn decide_finding(core: &fstp_domain::State, store: &FindingStore, cmd: &FindingCommand, ctx: &Ctx)
    -> Result<Vec<FindingRecord>, FindingRefusal>;
```

- Findings stay keyed to the call that produced them, including after a deferral (Q15). Each call's set therefore holds one config at most.
- M2 has no regeneration operation (Q16).
- The ranking view in `fstp-domain` cannot hold a finding, because that crate cannot name the type.

### 2.14 The projection (`State`)

The projection holds current, decision-relevant facts only. Two histories that reach the same situation give equal projections. This keeps `fstp-mc` state spaces small. The ledger keeps every record.

```rust
pub struct State {
    now_floor: Timestamp,
    epoch: VaultEpoch,              // last vault epoch processed
    used_ids: UsedIds,              // shell-supplied ids already taken
    policy: PolicyState,            // per programme: head, versions referenced, last author per parameter
    calls: CallState,
    roster: RosterState,            // active, suspended, voided bindings; cooling windows (max barred_through)
    review: ReviewState,            // assignments, conflict facts, handles, reviewed-by facts (I-36)
    proposals: ProposalStore,       // state, call history, plans, current scores, stage results, negotiation
    money: MoneyState,              // granted and reserved per programme and account, deliverable completeness
    payments: PaymentState,
    texts: TextIndex,               // TextRef ids and digests only
}
```

- Superseded scores and ended bindings leave the projection. Cooling windows and conflict facts stay.
- Each sub-state struct is defined in the module that owns it (section 10), so lanes never share a file.
- `State` is `Clone + Eq + Hash + Debug`. Policy values sit behind `Arc`.
- Command-id deduplication lives in the store, not in the state.

---

## 3. State machine and enforcement

### 3.1 Engine API

```rust
// fstp-domain
pub struct Ctx { pub now: Timestamp, pub actor: Actor, pub command: CommandId, pub via: Via } // Via: Web | Mcp
pub enum Actor { Account(AccountId), System(SystemCause) } // no assessor variant (I-10)

pub fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal>;
/// Recomputes queries itself. Refuses FactsIncomplete if any answer is missing,
/// StaleFacts if any answer's epoch differs from state.epoch.
pub fn decide(state: &State, cmd: &Command, ctx: &Ctx, answers: &Answers) -> Result<Vec<Record>, Refusal>;
/// Structural fold. Fails only on a log the engine could not have produced.
pub fn apply(state: &mut State, entry: &Entry<Envelope>) -> Result<(), FoldError>;
pub fn replay<'a>(entries: impl IntoIterator<Item = &'a Entry<Envelope>>) -> Result<State, FoldError>;
/// System commands enabled at `now`, for the M6 timeline and for tests.
pub fn due(state: &State, now: Timestamp) -> Vec<Command>;

/// Closed enums; no account ids, no free text (R-CF-03).
pub struct Refusal { pub rule: RuleRef, pub reason: RefusalReason }
```

- `RuleRef` is a closed enum of existing spec identifiers (`I01`, `Sod09`, `Rpc03` and so on) plus non-spec reasons (`Row`, `Actor`, `FactsIncomplete`, `StaleFacts`, `OracleDown`, `NotImplemented`).
- `Command::high_risk()` and `Command::binding_action()` classify commands for M3 step-up (I-78) and P-77 (R-MC-05). With `Via::Mcp` and P-77 "draft only", `decide` refuses binding actions.

```rust
// fstp-engine
pub struct EngineState { pub core: fstp_domain::State, pub findings: fstp_findings::FindingStore }
pub enum Command { Core(fstp_domain::Command), Finding(fstp_findings::FindingCommand) }
pub enum Record { Core(fstp_domain::Record), Finding(fstp_findings::FindingRecord) }
pub trait IdentityOracle { fn ask(&self, q: &Query) -> Result<Answer, OracleDown>; fn epoch(&self) -> Result<VaultEpoch, OracleDown>; }

/// Synchronous reference driver for tests. M3 writes an async driver over the same pure functions.
pub struct Engine<S: RecordStore<Envelope>, O: IdentityOracle> { store: S, oracle: O, state: EngineState }
impl<S: RecordStore<Envelope>, O: IdentityOracle> Engine<S, O> {
    pub fn open(store: S, oracle: O) -> Result<Self, OpenError>; // replays the store
    pub fn execute(&mut self, cmd: Command, ctx: Ctx) -> Result<Seq, ExecError>;
}
```

`execute` runs:

1. If the oracle epoch is ahead of `state.epoch`, process `VaultChanged` first.
2. `queries`, then ask the oracle, failing closed on `OracleDown`.
3. `decide`, then `store.append(expected_head, ...)`, then `apply`.
4. On `StaleHead`, retry from fresh state.

Finding commands go to `decide_finding`, which returns only finding records. Core commands go to `fstp_domain::decide`, which never sees the finding store.

### 3.2 Transitions as data

```rust
pub struct TransitionRule { pub row: Row, pub from: &'static [StateTag], pub to: StateTag,
                            pub actor: ActorRule, pub guards: &'static [Guard] }
pub const TRANSITIONS: &[TransitionRule];   // the 18 rows of SPEC/02-domain/state-machine.md
pub const ACTOR_RULES: &[(CommandKind, ActorRule)]; // seed of the M4 authorisation matrix (I-84)
```

The conformance properties and the M4 matrix seed are derived from these tables. "Added" lists guards that higher-ranked sources require.

| Row | Command | Actor | Guard as written | Added |
| --- | --- | --- | --- | --- |
| DRAFT to SUBMITTED | `Submit` | Lead with active Applicant binding | Call open; required fields present | No guardian record (R-SB-02); ethics declaration (R-SB-05); notice version (R-NG-06) |
| SUBMITTED to INELIGIBLE | `RecordKnockOut` | FSTP coordinator | Knock-out failed, reason recorded | Coordinator passes I-03 for the read |
| SUBMITTED to STAGE1 | `AdmitToStage1` | FSTP coordinator | All knock-outs passed; reviewers assigned without conflict | At least P-03 active, declared, conflict-free assignments (R-EV-02, I-03); I-34 and I-35 when data exists |
| STAGE1 to NOT_SELECTED or STAGE2 | `CloseStage1` (no outcome field) | System outcome, recorded by a named human (R-LA-03, Q2) | Weighted score versus P-02 | `Stage1Verdict` needs a `Quorum` (I-07); strict `>` (I-08) |
| STAGE2 to RANKED | `RankAfterStage2` | Assigned reviewer | Revised plan scored, or window closed with answers | Effective score per P-24 on one plan (I-09) |
| STAGE2 to DEFERRED | `ExpireStage2` | System | P-07 elapsed without answers | None. No future-call guard |
| RANKED to NOT_SELECTED or IRC_REVIEW | `RecordCutOff` (outcome computed per proposal) | Committee | Below or above the cut-off; rationale recorded | P-16 ballots (R-EV-09), remaining budget (R-EV-08), conflicted members recused (Q10) |
| IRC_REVIEW to NEGOTIATION | Last `RecordIrcReview` | IRC members | All reviewing IRC members validate | At least P-15 active IRC assignments, all validated, none outstanding (R-IR-01); guardian consent if minor (I-18, R-NG-02) |
| IRC_REVIEW to DEFERRED | `RecordIrcReview(Concern)` | IRC member | Concern raised; future call exists | Concern sent to the applicant through the outbox (R-IR-02) |
| IRC_REVIEW to DECLINED | `DeclineAfterConcern` | System | Concern raised; no future call | Same outbox event |
| DEFERRED to STAGE2 or IRC_REVIEW | `ReEnter` | System | Next call opens; re-enters at the stage it left | History kept; I-36 checked |
| NEGOTIATION to GRANTED | Computed after `AcceptGrant`, `ApproveGrant` or the contract fact | Applicant and programme manager | Identity verified; consent if minor; amount within P-04 and P-05; contract EFFECTIVE | `GrantClearance`: I-13, cumulative I-14, I-15, SoD-09 and I-06, I-04 for every Receiving account |
| any pre-GRANTED to WITHDRAWN | `Withdraw` | Lead | None | Only the eight non-terminal pre-GRANTED states; releases any reservation |
| GRANTED to IN_EXECUTION | `StartExecution` | System | First milestone start date reached | Date comes from the M5 contract fact (Q18) |
| IN_EXECUTION to COMPLETED | `Complete` | System | All milestone payment requests PAID | Milestone status comes from the M5 port (Q18) |
| IN_EXECUTION to TERMINATED | `Terminate` | Programme manager | Reason recorded | I-64 seam |

### 3.3 Command catalogue

| Command | Actor (interim where marked) | Main guards | Vault queries |
| --- | --- | --- | --- |
| `CreateProgramme` | Tenant admin | Valid initial policy | none |
| `EditPolicy` | Programme manager | Base is head; validation; live-edit checks | `AllRecipientsWithinCap` when P-05 is lowered |
| `DraftCall`, `EditCall` | Call drafter or programme manager | Call not published | none |
| `ApproveCallPublication` | Programme manager not in the drafter set | R-PC-03 | none |
| `PublishCall` | Programme manager | Approval present; P-21 model matches the pinned config | none |
| `GrantRole` | Tenant admin (interim) | SoD-01 to SoD-07, cooling windows, I-02, SoD-09 | `IsVerified`, `SameIdentityAsAny` for Drafting and Judging |
| `EndRole` | Tenant admin | Binding active | none |
| `VaultChanged` | System | Epoch newer than `state.epoch` | `SameIdentityAsAny`, `InExcludedClass`, `HasConflict`, `AllRecipientsWithinCap` for changed accounts |
| `CreateDraft`, `AddTeamMember`, `AddGuardian` | Lead | Call published and open; I-01 windows; I-36 | `InExcludedClass` |
| `RecordPlanVersion` | Lead | Proposal state allows the origin | none |
| `Submit` | Lead | Row 1 | none |
| `DeclareConflict` | Assignee or coordinator | Assignment awaiting declaration | none |
| `Assign` | FSTP coordinator (interim) | Section 2.7 | `HasConflict`; `DeclaresAffiliationOnList` (I-35) |
| `ReadContent` | Any reader allowed by P-10 | `ReviewerAct` or the coordinator equivalent | `HasConflict` |
| `RecordKnockOut`, `AdmitToStage1` | FSTP coordinator | Rows 2 and 3 | `HasConflict` |
| `RecordScore`, `CorrectScore` | Assigned reviewer | `ReviewerAct`; stage open; sheet not sealed | `HasConflict` |
| `CloseStage1` | Named human recorder (Q2) | Trigger (Q2); `Stage1Verdict` | `HasConflict` per counted reviewer |
| `AskQuestion`, `Answer`, `SubmitRevision` | Reviewer; lead | Stage 2 window open | `HasConflict` for the reviewer |
| `RankAfterStage2`, `ExpireStage2` | Reviewer; System | Rows 6 and 7 | `HasConflict` per counted reviewer |
| `RecordCutOff` | Committee member recording, with ballots | Row 8 and 9 guards | `HasConflict` per voter (Q10) |
| `RecordIrcReview`, `DeclineAfterConcern` | IRC member; System | Rows 10 to 12 | `HasConflict`; `HasGuardianConsent` if minor |
| `ReEnter` | System | Row 13 | none |
| `DetermineAmount` | Assigned reviewer | I-13; reservation | `HasConflict`, `WithinRecipientCap` |
| `AcceptGrant`, `ApproveGrant` | Lead; programme manager | NEGOTIATION | Grant clearance queries when the set completes |
| `ContractFact` | System, from the M5 port | Proposal in NEGOTIATION or later | Grant clearance queries when the set completes |
| `Withdraw` | Lead | Row 15 | none |
| `StartExecution`, `Complete`, `Terminate` | System; System; programme manager | Rows 16 to 18 | none |
| `RequestPayment`, `AcceptLine`, `ApprovePayment`, `ReleasePayment`, `ConfirmPaid` | Lead; reviewer; finance approver; releaser; System | Section 2.12 | `HasConflict` for line acceptance |
| `RecordDeliverable` | System, from M5 checks | Accepted line evidence | none |
| `ProposeAmendment`, `RouteAmendment`, `ActivateAmendment` | Lead or reviewer; programme manager (interim); System | Section 2.11 | `WithinRecipientCap`, `SameIdentityAsAny` |

Grant clearance queries: `IsVerified(lead)`, `SameIdentityAsAny(lead, Drafting and Judging accounts with active bindings or open windows)`, `InExcludedClass` for every Receiving account of the proposal, `HasGuardianConsent` when minor-flagged, `WithinRecipientCap`, and `SameIdentityAsAny(lead, leads of prior grants with incomplete records)`.

### 3.4 Enforcement points (`roles-and-sod.md`)

1. **At binding.** `GrantRole`, `CreateDraft`, `AddTeamMember` and `AddGuardian` run the account-level rules and the vault checks.
2. **At every content read or state change.** Every `decide` re-checks the actor's binding: active at `now`, not suspended, not voided. Reads and reviewer acts also need a `ReviewerAct`.
3. **On a vault or policy change.** `VaultChanged { epoch }`, a P-13 edit and a P-38 edit re-evaluate the affected accounts in one batch. The batch emits `BindingVoided` or `BindingSuspended` (Q5), `ConflictDetected` and `AssignmentReleased`.

### 3.5 Computed outcomes and witnesses

- No command names a target state. `decide` computes the outcome and emits `Transitioned`.
- Record payload structs for stage 1 exits, effective scores, grants and releases have private fields. Their only builders take the witness (`Stage1Verdict`, `EffectiveScore`, `GrantClearance`, `PaymentChain<Released>`). The decode path is crate-private.
- Outside the crate, forging a witness or a record literal does not compile. Inside the crate, review and the teeth tests cover deliberate misuse.
- Each forbidden construction gets a `compile_fail` doctest paired with a `no_run` twin that differs only in the forbidden line. A typo in shared text then breaks the twin, so the pair cannot pass vacuously. W0 checks whether the pinned rustdoc 1.97 enforces error codes on `compile_fail`. If it does, the codes are added too.

### 3.6 Time and `due`

- Cooling-off counts `CallPublished` records (P-12 NOTE 4). It never uses a wall-clock duration.
- A binding is active at `t` when `start <= t`, it has not ended, and it is neither suspended nor voided.
- `due(state, now)` returns `ExpireStage2`, `DeclineAfterConcern`, `ReEnter` and `StartExecution` when their guards hold, plus `CloseStage1` when its trigger holds.

### 3.7 Visibility and the ranking view

```rust
pub fn can_read_content(state: &State, account: AccountId, proposal: ProposalId, now: Timestamp) -> bool; // R-AC-01, P-10
pub struct RankingRow {
    pub proposal: ProposalId, pub title: TextRef, pub neutral_summary: TextRef,
    pub criterion_scores: Vec<(CriterionId, Ratio)>, pub requested: NonNegAmount,
    pub remaining_budget: Amount,   // signed: a call can be over-nominated
    pub rationale: TextRef,
}
pub fn ranking_view(state: &State, call: CallId) -> Vec<RankingRow>; // no findings field exists or can exist
```

Interim remaining budget (Q14): the call budget minus the requested totals of the call's proposals in IRC_REVIEW, NEGOTIATION and later states. Withdrawn, declined and deferred proposals do not count. Visibility outside stages 1 and 2 is M4.

---

## 4. Identity seam (I-03, I-04, I-06, I-14, I-15)

### 4.1 Query types

```rust
// fstp-domain
pub enum Query {
    IsVerified { account: AccountId },                                               // SoD-09
    SameIdentityAsAny { subject: AccountId, others: BTreeSet<AccountId> },           // I-06, SoD-09, I-15
    HasConflict { reviewer: AccountId, team: BTreeSet<AccountId> },                  // I-03, I-54
    InExcludedClass { account: AccountId, programme: ProgrammeId, classes: ExclusionClasses }, // I-04
    WithinRecipientCap { subject: AccountId, amount: NonNegAmount,
                         committed: BTreeMap<AccountId, NonNegAmount>, cap: NonNegAmount }, // I-14
    AllRecipientsWithinCap { committed: BTreeMap<AccountId, NonNegAmount>, cap: NonNegAmount }, // I-14 on edits
    HasGuardianConsent { proposal: ProposalId },                                     // I-18 seam
    DeclaresAffiliationOnList { team: BTreeSet<AccountId>, list: ProximityListRef }, // I-35 (Q12)
    ChangedSince { epoch: VaultEpoch },                                              // enforcement point 3
}
pub struct Answer { pub holds: bool, pub accounts: Option<BTreeSet<AccountId>>, pub epoch: VaultEpoch }
pub struct Answers(BTreeMap<Query, Answer>);
```

`accounts` is set only for `ChangedSince`, and lists accounts whose vault facts changed. Every other answer is one bit.

### 4.2 How candidate sets work

The platform works out which accounts matter from its own bindings. The vault answers one yes-or-no question about them.

- **Drafting or Judging grant (I-06, SoD-09).** `IsVerified(candidate)` must be true. `SameIdentityAsAny(candidate, S)` must be false. `S` holds accounts in another group, active or inside an open window.
- **Applicant at negotiation (SoD-09, I-06).** `SameIdentityAsAny(lead, S')` must be false. `S'` holds Drafting and Judging accounts that are active or inside an open window.
- **Detected conflict (I-03).** `HasConflict(reviewer, lead plus team accounts)` must be false.
- **Cap (I-14).** `WithinRecipientCap` receives per-account totals of granted plus reserved amounts in the programme. The vault groups them by verified identity.
- **Repeat grant (I-15).** The platform first checks the applicant's own account. Then `SameIdentityAsAny(lead, leads of prior grants with incomplete records)` must be false.

The four queries in `SPEC/03-architecture/overview.md` do not cover `IsVerified`, I-06 at grant time, I-15 or P-05 edits. The invariants outrank that file, so the port adds them. Q13 asks Daniel to confirm the set for the M3 vault interface.

### 4.3 Vault changes, epochs and fail-closed

- **Same-step reaction.** A vault change reaches the domain as `VaultChanged { epoch }`. Its batch voids or suspends bindings, records detections and releases assignments. Models run the ground-truth change and `VaultChanged` in one step.
- **Epoch match.** `decide` accepts answers only at `state.epoch`. A newer vault epoch makes the driver process `VaultChanged` first and ask again.
- **Fail closed.** `OracleDown` refuses the command and appends nothing (interim, Q13).
- **M3 verification commit protocol (Q5).** The vault marks a new verification or affiliation as provisional. The platform processes it with `VaultChanged` and commits its reaction with that epoch. The vault then makes it effective, and queries count only effective facts. Under this protocol I-04 and I-06 hold at every instant, not only in the model. M-RACE shows a violating state without the protocol and none with it.

### 4.4 What the platform learns

- Each answer is one bit. With a one-member `others` set, a positive `SameIdentityAsAny` reveals that two accounts share an identity. The I-15 query and the SoD-09 negotiation query can both have one member.
- Enforcement makes the link evident anyway, because the platform must void or refuse in response.
- **Controls.** Refusals carry only a rule reference and never an account. `VaultOutcome` records store a query digest and the bit. M4 exposes them to the Auditor role only, never to Judging roles (R-CF-03).
- Q13 asks Daniel to accept that positive matches are recorded and visible to auditors.

### 4.5 Test doubles (`fstp-domain-testkit`)

```rust
pub struct GroundTruth {
    identity_of: BTreeMap<AccountId, IdentityTag>,   // synthetic numbers only
    verified: BTreeSet<AccountId>,
    relations: BTreeSet<(IdentityTag, IdentityTag, Relation)>, // co-worker, relative, mentoring
    excluded: BTreeSet<(IdentityTag, ClassId)>,
    pending: BTreeSet<PendingFact>,                  // facts revealed on verification
    consents: BTreeSet<ProposalId>,
    epoch: VaultEpoch,
}
pub struct SyntheticVault { truth: GroundTruth }      // truthful; predicates read `truth` directly
pub struct HavocOracle { script: BTreeMap<Query, bool> } // arbitrary answers; the domain must obey them
pub struct DownOracle;                                // always OracleDown
pub fn sybil_pair(g: &mut Gen) -> (AccountId, AccountId, IdentityTag);   // corpus variant "Sybil"
pub fn excluded_applicant(g: &mut Gen) -> (AccountId, ClassId);          // "Excluded affiliation"
pub fn repeat_applicant(g: &mut Gen) -> RepeatFixture;                   // "Repeat applicant"
pub fn minor_applicant(g: &mut Gen) -> MinorFixture;                     // "Minor applicant"
```

Domain code sees only `Query` and `Answer`. Property predicates read the ground truth. Fixtures are synthetic numbers shaped like the corpus variants in `SPEC/07-test-plan/synthetic-corpus.md`. No real data is used.

---

## 5. I-23 append-only and the M3 seams

### 5.1 Ledger

```rust
// fstp-ledger
pub struct Seq(u64);
pub struct Entry<R> { pub seq: Seq, pub at: i64, pub command: [u8; 16], pub schema: u16, pub record: R }
pub trait RecordStore<R> {
    fn head(&self) -> Seq;
    /// Appends atomically if the head is still `expected`. There is no update or delete.
    fn append(&mut self, expected: Seq, at: i64, command: [u8; 16], batch: Vec<R>) -> Result<Seq, AppendError>;
    fn read(&self, from: Seq, limit: usize, out: &mut Vec<Entry<R>>) -> Result<(), StoreError>;
}
pub enum AppendError { StaleHead { head: Seq }, DuplicateCommand { at: Seq }, Store(StoreError) }
pub struct MemStore<R> { entries: Vec<Entry<R>>, commands: BTreeMap<[u8; 16], Seq> } // private fields
pub trait Canonical { fn canonical(&self) -> Vec<u8>; }                             // RFC 8785 bytes
pub fn verify_append_only<R: Canonical>(old: &[Entry<R>], new: &[Entry<R>]) -> Result<(), Divergence>;
pub enum Divergence { Truncated { old_len: u64, new_len: u64 }, Changed { seq: Seq }, Gap { seq: Seq }, Reordered { seq: Seq } }
```

- **Corrections.** A score correction is a new `ScoreRecorded` with `supersedes`. A decision correction is a new record with `supersedes`. Ending a binding is `BindingEnded`. A policy change is a new `PolicyVersionRecorded`.
- **Fold checks.** The fold refuses a correction whose target is missing or of another kind. It refuses a correction to a sealed stage (Q2).
- **Schema versions.** Every entry carries `schema`. Decoders accept every published version and upcast in memory. Stored bytes are never rewritten.
- **Structural replay.** The fold never re-runs guards. A later answer from Daniel changes behaviour going forward. Old decisions stay valid under their recorded `RulesVersion`.

### 5.2 Seams for M3

- **Store.** `PgRecordStore` over an insert-only table over a mutually authenticated connection. The database role has INSERT and SELECT only. Appends are conditional on the expected head. Bodies are canonical text, not `jsonb`, so bytes are kept exactly.
- **Amounts and ADR-006.** Canonical record text holds amounts as ADR-006 strings. Queryable projections store amounts in `numeric` columns through `Numeric`. Q19 asks whether that split satisfies ADR-006's storage rule.
- **Audit chain (I-24).** `link_n = H(link_{n-1} || canonical(entry_n))`, with `H` from `fstp-crypto`, written in the same transaction. Anchoring and composite signatures follow ADR-001 and I-90.
- **Async driver.** M3 runs `queries`, awaits the vault over a mutually authenticated connection on `fstp-rt`, then runs `decide`, the conditional append and `apply`. It reuses the fstp-prop suites against the real store.
- **Outbox.** Notification and group events are records in the same batch. M6 dispatches them, and M8 meets the I-29 "same transaction" rule.
- **Free text.** Reasons, rationale, concerns and plan text sit behind `TextRef { id, digest }`. Later erasure (P-41, I-81) never rewrites a ledger body (Q19).
- **Reads.** `ContentRead` records cover the read logging in R-AU-01 for M2.
- **Snapshots.** Projection checkpoints speed up startup. A test compares each checkpoint with a full replay.
- **Export (M9).** Records map to `policies/`, `roles.ndjson`, `reviews.ndjson` and `decisions.ndjson` through the file interface only. No EUPL code is linked.

---

## 6. Test plan

### 6.1 Conventions

- **Names.** Every test names its identifiers, for example `i07_stage1_exit_requires_p03_valid_scores`. Each test function holds one `check`, `check_machine` or `fstp_mc::check`, because of the fstp-prop replay rule.
- **Exhaustive model runs.** Every `fstp_mc` test uses `Config::default().with_stop_when_decided(false)`. It asserts `outcome.exhaustive` and calls `require_all_passed()`. `max_states` is a tripwire at twice the measured count, so growth fails visibly.
- **No vacuous models.** Every model has `reachable` witnesses. An engine that refuses everything fails them.
- **Two-way postconditions.** Every `StateMachine` postcondition compares accept and refuse with an independent reference in both directions. This catches over-denial as well as over-permission.
- **Independent references.** References and predicates are written from the spec text in the testkit. They share only id and record types with production. A different agent writes each reference than writes the production code it checks (section 10).
- **Replay and append-only every step.** Each machine's invariant also checks `replay(ledger) == state` and `verify_append_only(previous, current)`.
- **Start states from genesis.** `Scenario` builds every mid-lifecycle start state by running production commands from an empty state. No model starts from a hand-built state.
- **Reduced clock.** `Tick` moves `now` to the next scenario instant: each opening, deadline, window end and next-call opening, and one microsecond before each. Guards only compare times, so this covers every distinct guard outcome.
- **Vault changes in one step.** An environment action changes the ground truth and runs `VaultChanged` in the same model step. M-RACE alone splits them, to study the protocol.
- **Ghost state.** Facts the domain does not store live in a ghost: frozen values at publication, binding intervals in call-seq terms, scored inputs. Predicates read the ghost and the ground truth, never production structures.
- **Symmetry.** Off at first. It is enabled per model only with a test that compares all verdicts with and without it on a smaller universe.
- **Teeth.** Each model and machine has a teeth test. The adapter injects records that a broken engine would emit, by calling the public structural `apply` on the state. Each teeth test asserts that the property fails. No production hook exists. Injected faults include:
  - STAGE2 at exact equality, and a superseded score counted;
  - a Receiving binding inside a window;
  - a finding with a foreign config, and an outcome computed from the programme head;
  - a releaser equal to the approver, a grant above the cap, and a repeat grant without records;
  - a changed past entry.
- **Over-denial mutants.** The adapter drops a legal command, and the test asserts that a `reachable` property becomes unreachable.
- **Fixtures.** Synthetic numeric ids and generated strings only, shaped like the corpus variants.

### 6.2 Per invariant

**I-01 (SoD-01, SoD-05)**

- `i01_sod01_sod05_bindings_match_reference` (machine). Commands: `GrantRole` for every role, `EndRole`, `PublishCall`, `EditPolicy(P-12)`, `CreateDraft`, environment affiliation changes. The reference checks every pair of bindings with the interval and call-list rule. Edge bias: P-12 = 0, an end at the same instant as a publication, a call published while the binding is active.
- `i01_m_sod_p12_0`, `i01_m_sod_p12_1`, `i01_m_sod_p12_2` on M-SOD. Properties: `always("I-01")`, `transition("SoD-01")`, `transition("SoD-05")`. Witnesses: a former programme manager holds Applicant in a later call; the first call after the end is barred and the next is open.
- `i01_m_sod_two_programmes`: one account, two programmes; a binding in one programme never counts in the other.
- `i01_teeth_binding_inside_window_is_caught`.

**I-02 (SoD-02)**

- `i02_sod02_irc_member_holds_no_other_judging_role` (machine): grants and ends of every Judging role, reviewer and IRC assignments.
- `i02_m_sod_irc_exclusive`: `always("I-02")`, `transition("SoD-02")`. Witness: a committee member becomes an IRC member after the committee binding ends.
- `i02_teeth_irc_with_assignment_is_caught`.

**I-03 (R-CF-02, T-SOD-CONFLICT)**

- `i03_rcf02_conflicted_person_cannot_read_or_act` (machine). Commands: `Assign`, `DeclareConflict`, `ReadContent`, `RecordScore`, `CorrectScore`, `AskQuestion`, `DetermineAmount`, `RecordIrcReview`, `AcceptLine`, coordinator reads. Environment: relationships and mentoring added mid-run. Invariant: no read or act record for `(a, p)` follows the first conflict fact for `(a, p)`.
- `i03_m_conflict_truthful` and `i03_m_conflict_havoc` on M-CONFLICT: `transition("I-03")`, `transition("R-CF-02")`, `always("I-03")`. Witnesses: content read after a no-conflict declaration; reassignment restores P-03 after a declared conflict.
- `i03_teeth_read_after_conflict_is_caught`.

**I-04 (SoD-06)**

- `i04_sod06_excluded_account_holds_no_receiving_role` (machine). Commands: Receiving bindings, affiliation declarations, verifications that reveal pending facts, P-13 edits, entry into NEGOTIATION. Invariant: no account whose vault knowledge marks it excluded holds an active, non-voided Receiving binding (Q5).
- `i04_m_excl`: `always("I-04")`, `transition("SoD-06")`. Witnesses: blocked at binding; revealed at negotiation and voided in the same step.
- `i04_teeth_excluded_receiving_is_caught`.
- The test plan has no I-04 row. Proposed row for Daniel (Q12): "Random Receiving bindings, affiliation changes, verifications and P-13 edits never leave an active Receiving binding for an account the vault knows to be excluded."

**I-05 (SoD-04, R-EX-04, T-PAY)**

- `i05_sod04_releaser_is_never_acceptor_or_approver` (machine). Accounts hold random combinations of committee member, finance approver and payment releaser. Commands: accept line, approve, release.
- `i05_m_pay`: `always("I-05")`, `transition("SoD-04")`, `transition("SoD-12")` for mentors. Witness: a release by a third account.
- Compile-fail twins: `PaymentChain<Released>` cannot be built except by `release`.
- `i05_teeth_releaser_equals_approver_is_caught`.

**I-06 (SoD-09, TH-03, T-SOD-SYBIL)**

- `i06_sod09_verified_identity_never_spans_groups` (machine). Sybil pairs from `sybil_pair`. Verification arrives as an environment event. Invariant over ground truth: for each identity, the union of non-voided bindings and open windows of its verified accounts satisfies the I-01 predicate.
- `i06_m_sod_sybil`: accounts A and B share an identity, C has another. `always("I-06")`, `transition("SoD-09")` (no Drafting or Judging grant without a true `IsVerified`). Witnesses: the Sybil is voided at verification; a distinct identity reaches GRANTED.
- `i06_m_race_with_protocol` (all pass) and `i06_m_race_without_protocol_reaches_violation` (asserts the violation is reachable, which documents the M3 need).
- `i06_teeth_sybil_left_bound_is_caught`.

**I-07**

- `i07_quorum_counts_valid_scores_once` (pure). P-03 from 1 to 4; assignment sets below, at and above P-03; corrections, voids, conflicts and releases. The reference is a set computation over raw records.
- `i07_stage1_exit_requires_p03_valid_scores` (machine), including withdrawals from STAGE1.
- `i07_i08_m_life_s1`: `transition("I-07")` (an exit from STAGE1 by score needs at least P-03 valid scores in `before`); `always("I-07")`; both exits reachable.
- `i07_teeth_superseded_score_counted_is_caught`.

**I-08**

- `i08_weighted_score_matches_exact_reference` (pure). The reference uses common-denominator integers, written separately from production. Generators favour equality. Metamorphic checks: monotone in each score, invariant under reviewer permutation and under scaling all weights.
- `i08_equality_is_not_a_pass` (pure): 30/40/30, scale 0 to 4, every score 3, P-02 75.00: NOT_SELECTED.
- `r_pc_01_weights_change_scores_for_discriminating_inputs` (pure). The AC is false for inputs whose criterion scores are all equal, so the generator draws unequal criterion scores.
- In `i07_i08_m_life_s1`: `transition("I-08")` in both directions; `always("I-08")` for every proposal in STAGE2 or later, including after re-entry; a transition property that only `CloseStage1` leaves STAGE1 by score. Witness: equality ends in NOT_SELECTED. Instances: weights (1, 1) at 50.00 and (3, 1) at 75.00, both reaching equality.
- `i08_teeth_ge_instead_of_gt_is_caught`.

**I-09**

- `i09_effective_score_follows_p24_and_names_one_plan` (pure). Original plan plus zero to three revisions. The value is the reference maximum. It names the winning plan. The original wins without a revision and on a tie (Q3). A later amendment never changes the effective score record.
- `i09_m_life_s2`: `always("I-09")`: every proposal with a recorded STAGE2 to RANKED transition, in any later state including NOT_SELECTED, DECLINED, WITHDRAWN, DEFERRED, COMPLETED and TERMINATED, has exactly one current effective score naming one of its plans. `transition("I-09")`: entering RANKED sets it per P-24. Witnesses: both bases reachable.
- `i09_teeth_effective_cleared_is_caught`.

**I-10 (domain level; M7 covers the pipeline, Q12)**

- `i10_domain_crates_cannot_reach_findings` (layering check).
- `i10_findings_never_alter_core_state` (twin machine). Twin B also receives `RecordFinding` and `MarkFinding` of every kind, severity, criterion and confidence, with generated strings and injection phrases, and P-28 on. Assertions: identical core projections, identical core ledgers after removing finding records, identical refusals.
- In `i07_i08_m_life_s1` with `AddFinding` actions (at most two): `transition("I-10")`: `AddFinding` leaves `core` unchanged; for every other action, `step(s, a).core == step(strip(s), a).core`. The predicate captures the model.
- `i10_teeth_finding_driven_transition_is_caught`: the adapter injects a core transition whenever twin B receives a finding, and the twin comparison must fail.

**I-11**

- `i11_call_findings_share_pinned_config` (machine). Findings with random config ids, including pre-check origin. Only the call's pinned `config_id` is stored. At every step each call holds at most one config, equal to its pin.
- `i11_m_find`: two calls, two configs, a proposal deferred between them. `always("I-11")`, witnesses of a stored finding in each call.
- `i11_teeth_foreign_config_is_caught`.

**I-12 (TH-17, T-POLICY)**

- `i12_every_frozen_parameter_is_in_the_snapshot` (pure). Every `CATALOGUE` entry with `Freeze::Frozen` and `Level::Programme` is either a typed `FrozenValues` field or a key of `opaque`.
- `i12_frozen_edits_leave_call_outcomes_unchanged` (twin machine). Random frozen edits after publication interleaved with evaluation commands. Identical transitions, scores, effective scores, decisions and `call.frozen`. Each edit appends one version. A later call uses the new values. For live parameters, the decision's copied value equals the head at decision time.
- `i12_m_policy`: P-02 in {50.00, 75.00}, P-03 in {1, 2}. `transition("I-12")`: an edit never changes any published `FrozenPolicy`. `always("I-12")`: each published call's values equal the ghost copy. Witness: an edit between publications, with the second call using new values.
- `i12_teeth_head_instead_of_snapshot_is_caught`.

**I-13 and I-14**

- `i13_i14_grant_sequences_respect_range_and_cap` (machine). Commands: plan revisions, deductions, `DetermineAmount`, contract facts, acceptance, approval, withdrawal, amendments, P-05 edits, P-58 edits under the Horizon Europe profile. Several accounts share one identity. The reference does plain integer arithmetic per ground-truth identity.
- `i14_p05_edit_below_committed_is_refused` (machine).
- `i13_i14_m_money`: identities {a, b} and {c}, three proposals reaching NEGOTIATION from genesis, P-04 = [2.00, 4.00], P-05 = 6.00. `always("I-13")`, `always("I-14")` over granted plus reserved per identity, `transition("I-14")` for P-05 edits. Witnesses: granted at P-04 min; at P-04 max; a recipient's sum exactly P-05; a Sybil pair blocked by the cap.
- `i14_m_race_reservation`: two concurrent negotiations cannot both pass.
- `i13_teeth_out_of_range_grant_is_caught`, `i14_teeth_grant_above_cap_is_caught`.

**I-15**

- `i15_repeat_grant_requires_public_deliverables` and `i15_amendment_requires_public_deliverables` (property). Prior deliverables in five states: none, public under P-26, public under another licence, not accepted, snapshot missing. Acceptance exactly under the reference rule (Q8).
- `i15_m_money_repeat`: `transition("I-15")`: entering GRANTED with prior grants, and activating an amendment, need the condition in `before`. Witnesses: a repeat grant exists; an amendment exists; GRANTED disabled by a missing record.
- `i15_teeth_repeat_without_records_is_caught`.

**I-23**

- `i23_ledger_is_prefix_monotone_and_replays` (machine over the full engine): the old ledger is a prefix of the new; replay equals state; every correction targets an existing record of the same kind.
- `i23_verifier_flags_every_mutation` (property): byte changes, deletions, swaps, truncations and mid-ledger insertions are always reported.
- `i23_store_api_has_no_mutation`: compile-fail twins for `remove`, `get_mut`, `IndexMut`, `truncate`, field access on `MemStore`.
- `i23_m_ledger`: a small alphabet with corrections, ledger carried in the state with at most six records. `transition("I-23")`: `before.ledger` is a prefix of `after.ledger`, and `replay(after.ledger) == after.state`.
- `i23_teeth_changed_past_entry_is_caught`.

### 6.3 Models

| Model | Universe | Budgets | Instances |
| --- | --- | --- | --- |
| M-SOD | Accounts a, b, c (a and b share an identity); 1 programme; programme manager, committee member, IRC member, Applicant via draft | At most 3 publications, 2 grants per account, 1 verification per account | P-12 = 0, 1, 2; plus a 2-programme, 1-account variant |
| M-CONFLICT | 3 reviewers, 1 proposal (variant: 2), P-03 = 2 | Each truth bit flips once; 1 correction per score | Truthful and havoc vault |
| M-EXCL | 2 accounts, 2 classes | 1 P-13 edit; 1 verification each | none |
| M-PAY | 3 accounts, 1 request with 2 lines, 1 mentor | Each action once | none |
| M-LIFE-S1 | 1 proposal, 3 reviewers, 2 criteria, scale 0 to 2, P-03 = 2 | 1 correction, 1 conflict, 2 findings | Weights (1, 1) at 50.00; (3, 1) at 75.00 |
| M-LIFE-S2 | Starts at STAGE2 from genesis; 2 calls | 1 revision, 1 deferral, 1 re-entry | none |
| M-FIND | 2 calls, 2 configs, 1 proposal | 3 findings offered, 1 deferral | none |
| M-POLICY | P-02 in {50.00, 75.00}, P-03 in {1, 2}; 2 calls with 1 proposal each | 2 edits | Product of edited and unedited copies |
| M-MONEY | Identities {a, b} and {c}; 3 proposals in NEGOTIATION from genesis | Requested 1.00 to 5.00; deductions 0.00 or 1.00; 1 P-05 edit; prior records in 3 states; 1 amendment | none |
| M-LEDGER | 1 proposal, 2 reviewers | 6 records | none |
| M-RACE | 1 grant request and 1 vault change; 2 negotiations for the cap | 3 steps each | With and without the protocol |
| M-LIFECYCLE | 1 proposal, 2 calls, havoc vault, coarse scores | One of each action kind | Conformance only |

The first run records each model's state count in its test. A change that grows a model past its tripwire fails visibly. If a model grows too large, it is split further before any bound is relaxed.

### 6.4 Conformance and diagnostics (not exit criteria)

- `lifecycle_all_sixteen_states_reachable` and `lifecycle_terminal_set_matches_spec` on M-LIFECYCLE.
- `r_ev_01_ineligible_has_no_successor`, `r_sb_03_withdrawn_only_from_eight_states_by_lead`, `r_ev_07_stage2_deferral_needs_no_future_call`, `r_ir_02_concern_defers_or_declines`.
- `deadlock_free` holds trivially before GRANTED because withdrawal stays enabled. A diagnostic variant without withdrawal shows where nothing else moves: NEGOTIATION after a failed check (Q6), DEFERRED with no next call (Q15), and STAGE2 with no questions waiting out P-07 (Q3). It stays out of CI until Daniel decides.

---

## 7. Fuzz targets

| Crate | Target | Checks |
| --- | --- | --- |
| `fstp-money` | `amount_parse` | Never panics. Accepted input round-trips byte for byte. Acceptance matches a separate byte-level grammar check in the target. Arithmetic on parsed values never panics. |
| `fstp-money` | `amount_json` | `fstp_json::parse` then `amount_from_json`. JSON numbers are always rejected. `to_canonical` keeps the string unchanged. |
| `fstp-money` | `percent_parse` | Never panics, canonical round trip, range 0.00 to 100.00. |
| `fstp-ledger` | `entry_decode` | Never panics. Decode, encode, decode gives the same value. Canonical bytes are stable. |
| `fstp-domain` | `record_decode` | Every schema version. Never panics, unknown members rejected, round trip. |
| `fstp-domain` | `command_decode` | Never panics, round trip. |
| `fstp-domain` | `policy_decode` | Never panics, validation total, round trip. |
| `fstp-findings` | `finding_decode` | Never panics, round trip, `UntrustedText` preserved byte for byte. |
| `fstp-engine` | `envelope_decode` | Never panics, round trip. |
| `fstp-engine` | `decide_sequence` | Bytes become commands and oracle answers. `decide`, `apply` and `replay` never panic. Replay equals the incremental state. Every appended record decodes. |

`decide_sequence` is not a parser target. It guards the workspace no-panic lints (`unwrap_used`, `panic` and others) over the core.

---

## 8. Risks

1. **State-space growth.** Mitigations: per-invariant models on tiny universes, a history-normalised projection, shell-supplied ids, the reduced clock, budgets, tripwires, and symmetry only with a self-test.
2. **Shared misreadings.** References and production share the interim readings. A different agent writes each side, and Daniel's answers remove the interim readings.
3. **Vault race in M3.** The vault sits on a separate cluster (I-83). The epoch match and the provisional-verification protocol close the window. M3 must build the protocol (Q5).
4. **Liveness gaps.** NEGOTIATION after a failed check, DEFERRED with no next call, and STAGE2 with no questions can stall. They are not invariant violations. The diagnostic variant shows them (Q3, Q6, Q15).
5. **Grant timing.** A contract countersigned before the guards run could fail I-14 or I-15. Reservations and `grant_preconditions` before SENT remove this, if M5 calls them.
6. **Erasure against append-only.** Free text sits behind `TextRef`. Retention and crypto-shredding still need a design (Q19).
7. **Hand-transcribed tables.** `CATALOGUE`, `TRANSITIONS`, `ACTOR_RULES` and `RuleRef` are copied by hand. Each gets a row-by-row review in W1c.
8. **compile_fail on stable.** If rustdoc 1.97 ignores error codes, the paired `no_run` twins carry the guarantee.
9. **Witness clones.** Witnesses derive `Clone` for `fstp-mc`. A stale clone is refused by the proposal id and epoch checks, not by its type.
10. **CI time.** Model runs are exhaustive. W6 measures them and splits models before relaxing any bound.

---

## 9. Readings

### 9.1 Resolved by the source-of-truth order

Order from `.claude/CLAUDE.md`: `SPEC/02-domain/invariants.md`, then `SPEC/01-requirements/`, then `SPEC/02-domain/`, then `SPEC/03-architecture/`.

1. **Guardian consent before NEGOTIATION.** I-18 and R-NG-02 require consent before entry. Row 14 also lists it. Both outrank and add to the row, so row 10 checks consent for a minor-flagged proposal and row 14 checks again. How consent is gathered before negotiation, given R-NG-01 and L-02, is M3 work.
2. **R-PC-02 covers frozen parameters only.** Its AC cites I-12. Reading "a parameter edit" as every parameter would contradict I-04, because adding a P-13 class must affect existing Receiving roles. The invariant wins.
3. **A named human records outcome decisions.** R-LA-03 outranks the state machine's "System" actor. A recording human weakens nothing, because the outcome stays computed. Which role records is part of Q2.
4. **I-09 holds after stage 2 in every later state.** The invariant text has no state limit, so terminal states are included.
5. **I-12 covers every frozen parameter.** Parameters M2 does not interpret are frozen as opaque values.
6. **Model replacement versus frozen P-21.** `SPEC/04-llm-assessment/assessment.md` regenerates findings with a replacement configuration. That folder is not in the order, and I-12 freezes P-21. M2 offers no replacement operation. Q16 asks how Daniel wants replacement to work.
7. **The I-11 pin is the full `config_id`.** R-LA-05 pins model, prompt and rubric per call. P-21 names only the provider and model.
8. **Vault queries beyond the four in `overview.md`.** I-04, I-06, I-14 and I-15 outrank that file, so the port adds queries. Q13 confirms them for the M3 interface.
9. **I-14 is cumulative.** Row 14 says "within P-04 and P-05". The invariant sums every grant to one recipient, so the guard uses the sum.
10. **Row 14 gains SoD-09, I-06, I-04 and I-15.** They are invariants or SoD rules that name negotiation.
11. **STAGE2 to DEFERRED has no future-call guard.** Row 7 and R-EV-07 state none. Only rows 11 and 12 depend on a future call.
12. **Withdrawal.** R-SB-03 sets a minimum ("before contract signature"). Row 15 permits withdrawal until GRANTED. Allowing it until GRANTED satisfies both. Terminal states have no exits by definition, and INELIGIBLE is terminal.
13. **R-EV-08 budget visibility and R-EV-09 voting** are guards on rows 8 and 9, because requirements outrank the rows.

### 9.2 Readings that satisfy every source at once

1. **I-05.** The releaser differs from every line acceptor and from the finance approver. This satisfies R-EX-04, SoD-04, the roles table ("Finance approver: accepts milestones for payment") and `payment-requests.md` (assigned reviewers set ACCEPTED). Daniel can relax it later.
2. **"Person" means tenant account.** `SPEC/00-scope.md` says so, and no higher document contradicts it. Only I-06 lifts I-01 to verified identity. I-02, I-03, I-05, SoD-03 and SoD-07 apply per account.
3. **I-02 means current roles.** It says "holds". Past Judging roles never matter to it, because I-01 windows apply only across groups.
4. **Money storage wording.** `payment-requests.md` says "integer euro cents". ADR-006 says `numeric` at scale 2. The domain holds integer minor units, which matches both. Storage follows ADR-006, Daniel's later decision. The domain file needs a wording update.
5. **NEGOTIATION to GRANTED actors.** The row names the applicant and the programme manager. `contracts.md` names an Operations signatory as a contract party. The domain requires both human records plus the M5 contract-effective fact. The missing signatory role is Q18.

### 9.3 Interim strict readings (until Daniel answers)

Daniel answered Q1 to Q3 on 2026-10-25 (section 12.1). Those rows are now decisions. One differs from the interim reading: under Q3, a "no questions" record from the reviewers closes the stage 2 window at once.

Where the spec is silent, the design takes the strictest reading. Each sits in one function and changes locally.

| Topic | Interim reading | Question |
| --- | --- | --- |
| Scoring | Integer scale 0 to N in P-01, complete vectors, mean of weighted sums as a fraction of the maximum, P-02 in basis points | Q1 |
| Stage 1 close | Every active assignee has a valid score and at least P-03 exist; FSTP coordinator records; stages seal at exit | Q2 |
| Valid score | Current value, active assignment, no conflict fact | Q2 |
| Stage 2 | P-03 valid stage 2 scores on the revised plan; latest scored revision counts; tie keeps the original; no questions means waiting out P-07 | Q3 |
| Cooling-off | Every switch among Drafting, Judging and Receiving; calls published while active barred; P-12 pinned at end; P-12 = 0 allowed | Q4 |
| Discovery | Same-step voiding of the discovered account's Receiving bindings; voided bindings never count as held | Q5 |
| NEGOTIATION failure | Proposal stays in NEGOTIATION; GRANTED disabled | Q6 |
| I-13 | Granted equals effective plan total minus deductions, within P-04 inclusive | Q7 |
| I-14 | Granted plus reserved per verified identity of the lead, per programme; amended totals count; closure drops to paid | Q7 |
| I-15 | Every deliverable of every prior grant, tenant-wide, under both calls' P-26 | Q8 |
| Non-frozen limits | Enforce the stricter of the call snapshot and the live value for P-05 and P-13 | Q9 |
| I-03 scope | Reads and every Judging act on the proposal or its grant; coordinator declares; conflicted committee members recuse from the cut-off vote | Q10 |
| Receiving bindings | From draft creation to the proposal's terminal state, scoped to proposal and call | Q11 |
| Future call | A later call of the same programme is published | Q14 |
| Deferral | Original call's frozen policy governs; findings stay with the producing call | Q15 |
| COMPLETED | Every milestone fully paid and every payment request in a terminal state, from the M5 port | Q18 |
| Grant authority | Tenant admin grants programme roles | none |

### 9.4 Corrections to the proposals

| Proposal text | Correct reading | Source |
| --- | --- | --- |
| All three: amount codec rejects any minus sign; storage as `bigint` minor units | Optional minus, no `+`, no `-0.00`; storage as `numeric` through `Numeric` | `docs/adr/ADR-006-money-representation.md` |
| All three: P-21 is the whole pinned LLM config | P-21 is provider and model; `config_id` adds prompt and rubric | `policy-parameters.md`, `assessment.md`, R-LA-05 |
| All three: the platform never learns account links | A one-member query reveals a link; controls in section 4.4 | R-CF-03, `overview.md` |
| types-first: STAGE2 deferral needs a next call | No such guard | `state-machine.md` row 7, R-EV-07 |
| types-first: I-09 structural from RANKED on | Some later states lacked the field; I-09 covers every state after stage 2 | I-09 |
| types-first: only typed frozen fields | Every frozen parameter freezes | I-12 |
| types-first: public `FrozenPolicy::snapshot` | Built only by the publication fold | I-12, R-PC-02 |
| ledger-first: no questions means RANKED at once | Row 6 guard kept; question raised | `state-machine.md` row 6 |
| ledger-first: IN_EXECUTION starts at contract effective date | "First milestone start date reached" kept; question raised | `state-machine.md` row 16 |
| ledger-first: COMPLETED when every request is paid | "All milestone payment requests PAID" kept; conflict with P-67 raised | `state-machine.md`, `payment-requests.md` |
| ledger-first: TH-26 for `decide_sequence` | TH-26 covers parsers; the target guards the no-panic lints | `threat-model.md` |
| model-first: I-06 over all accounts of an identity | Verified identities only | I-06, SoD-09 NOTE 1 |
| model-first: NEGOTIATION to GRANTED is a System command | Applicant and programme manager | `state-machine.md` row 14 |
| model-first: IRC_REVIEW to DECLINED by an IRC member; advance with an IRC member outstanding | System actor; every reviewing IRC member validates | `state-machine.md` rows 10, 12 |
| model-first: SoD-09 only at contract EFFECTIVE | Also when the applicant is verified, in the same step | SoD-09 |
| model-first: suspended bindings always count; P-12 increase refused | Q5; P-12 pinned at end, no refusal | I-01, I-04, I-06 |
| model-first: `Amount` derives `Ord` | No `PartialOrd` or `Ord` | ADR-006 intent, judge finding |
| model-first: Daniel stages commits | The agent stages and proposes; Daniel commits | `.claude/CLAUDE.md` |

---

## 10. Work plan

Each step lists its owner, the files it owns, and its tests. Tests come first in every step. They compile against stubs that return `Refusal::NotImplemented`. Stubs fail the two-way postconditions and the `reachable` properties, so each step starts red without `todo!` or panics. Each lane has two agents: one writes references, predicates and tests, and the other writes production code. No two agents own the same file.

| Step | Agents | Owns | Tests first | Depends on |
| --- | --- | --- | --- | --- |
| W0 | lead | `Cargo.toml`, `deps/fuzz-required.txt`, `crates/*/Cargo.toml`, `crates/*/fuzz/**` (initial targets), `tools/deps-check/src/layering.rs` plus registration | Layering gate tests; sentinel doctests for compile_fail error codes; every fuzz target builds | none |
| W1a | money (2) | `crates/fstp-money/**` | Grammar and round-trip properties, rejected-spelling table, JSON-number rejection, checked arithmetic, `cmp_same` mismatch; fuzz targets in the first commit. Public API stub lands first for W1c | W0 |
| W1b | ledger (2) | `crates/fstp-ledger/**` | `i23_verifier_flags_every_mutation`, prefix and idempotency properties, compile-fail twins | W0 |
| W1c | interface (1) | `crates/fstp-domain/src/{lib,id,time,rules,refusal,command,record,oracle,engine,state}.rs` and an empty stub file per lane module | Interface compiles; `CATALOGUE`, `TRANSITIONS`, `ACTOR_RULES`, `RuleRef` reviewed row by row against the spec | W1a API stub |
| W2 | harness (1) | `crates/fstp-engine/src/{lib,driver}.rs`, `crates/fstp-domain-testkit/src/{lib,vault,scenario,clock}.rs`, `.../src/harness/{prop,mc,teeth}.rs` | Harness self-tests: vault answers match truth; scenario from genesis; injection reaches `apply`; tripwire helper; symmetry self-test helper | W1b, W1c |
| W3 | L-POL (2), L-SOD (2), L-SCORE (2), L-CODEC (2), L-FIND-A (2) in parallel | L-POL: `fstp-domain/src/policy/**`, `src/programme.rs`, testkit `reference/policy.rs`, `gen/policy.rs`, `mc/policy_model.rs`, `tests/i12_*.rs`, `tests/r_pc_*.rs`. L-SOD: `src/roles/**`, testkit `reference/sod.rs`, `gen/roster.rs`, `mc/{sod,excl,race}_model.rs`, `tests/i01_*.rs`, `i02_*`, `i04_*`, `i06_*`. L-SCORE: `src/scoring.rs`, testkit `reference/scoring.rs`, `gen/scores.rs`, pure `tests/i07_quorum*`, `i08_*`, `i09_effective*`, `r_pc_01*`. L-CODEC: `src/codec/**`, `fuzz/**` targets of `fstp-domain`. L-FIND-A: `crates/fstp-findings/**` | Per section 6.2 for each invariant listed | W2 |
| W4 | L-REV (2) then L-LIFE (2) | L-REV: `src/assignment.rs`, `src/visibility.rs`, testkit `reference/review.rs`, `gen/review.rs`, `mc/conflict_model.rs`, `tests/i03_*.rs`, `tests/i34_i35_*.rs`, `tests/i36_*.rs`. L-LIFE: `src/proposal/**`, `src/decision.rs`, testkit `reference/lifecycle.rs`, `mc/life_model.rs`, `mc/lifecycle_model.rs`, `tests/i07_stage1*`, `tests/i07_i08_m_life*`, `tests/i09_m_life*`, `tests/lifecycle_*.rs`, `tests/r_*` conformance | I-03, I-07 to I-09 machine and model tests, conformance | W3 (L-POL, L-SOD, L-SCORE) |
| W5 | L-MONEY (2), L-FIND-B (2), L-LEDGER (2) in parallel | L-MONEY: `src/grant.rs`, `src/payment.rs`, `src/amendment.rs`, testkit `reference/{money,payment}.rs`, `gen/money.rs`, `mc/{money,pay}_model.rs`, `tests/i05_*`, `i13_i14_*`, `i14_*`, `i15_*`. L-FIND-B: `crates/fstp-engine/src/findings.rs`, testkit `reference/findings.rs`, `gen/findings.rs`, `mc/findings_model.rs`, `tests/i10_*`, `tests/i11_*`. L-LEDGER: testkit `mc/ledger_model.rs`, `tests/i23_*` over the full engine | I-05, I-13 to I-15, I-10, I-11, I-23 | W4 |
| W6 | lead plus L-POL | testkit `tests/i12_frozen_edits*` over the full engine, `tests/teeth_*` cross-cutting, CI timing notes | I-12 twin over everything; all teeth; symmetry self-tests; measured state counts written into tripwires | W5 |
| W7 | lead | milestone report text, staged commits with proposed messages | All exit tests green in CI | W6 |

Follow-ups staged alongside, for Daniel's review:

- `fstp-json` docs: stop describing `Decimal` as the type for money, citing ADR-006.
- Spec wording proposals, not edits: the I-04 test-plan row, the `payment-requests.md` storage wording, and the `SPEC/schemas/README.md` amount note that ADR-006 lists as missing.

---

## 11. M2 exit checklist

Every test below is green in CI, each model run is exhaustive, and each teeth test fails its property as expected.

| Invariant | Property and pure tests | Model checks | Teeth | Blocked on |
| --- | --- | --- | --- | --- |
| I-01 | `i01_sod01_sod05_bindings_match_reference` | `i01_m_sod_p12_0`, `i01_m_sod_p12_1`, `i01_m_sod_p12_2`, `i01_m_sod_two_programmes` | `i01_teeth_binding_inside_window_is_caught` | Q4, Q11 |
| I-02 | `i02_sod02_irc_member_holds_no_other_judging_role` | `i02_m_sod_irc_exclusive` | `i02_teeth_irc_with_assignment_is_caught` | none |
| I-03 | `i03_rcf02_conflicted_person_cannot_read_or_act` | `i03_m_conflict_truthful`, `i03_m_conflict_havoc` | `i03_teeth_read_after_conflict_is_caught` | Q10 |
| I-04 | `i04_sod06_excluded_account_holds_no_receiving_role` | `i04_m_excl` | `i04_teeth_excluded_receiving_is_caught` | Q5, Q9 |
| I-05 | `i05_sod04_releaser_is_never_acceptor_or_approver`, compile-fail twins | `i05_m_pay` | `i05_teeth_releaser_equals_approver_is_caught` | none |
| I-06 | `i06_sod09_verified_identity_never_spans_groups` | `i06_m_sod_sybil`, `i06_m_race_with_protocol`, `i06_m_race_without_protocol_reaches_violation` | `i06_teeth_sybil_left_bound_is_caught` | Q4, Q5 |
| I-07 | `i07_quorum_counts_valid_scores_once`, `i07_stage1_exit_requires_p03_valid_scores` | `i07_i08_m_life_s1` | `i07_teeth_superseded_score_counted_is_caught` | Q2 |
| I-08 | `i08_weighted_score_matches_exact_reference`, `i08_equality_is_not_a_pass`, `r_pc_01_weights_change_scores_for_discriminating_inputs` | `i07_i08_m_life_s1` | `i08_teeth_ge_instead_of_gt_is_caught` | Q1 |
| I-09 | `i09_effective_score_follows_p24_and_names_one_plan` | `i09_m_life_s2` | `i09_teeth_effective_cleared_is_caught` | Q3 |
| I-10 | `i10_domain_crates_cannot_reach_findings`, `i10_findings_never_alter_core_state` | `i07_i08_m_life_s1` (I-10 properties) | `i10_teeth_finding_driven_transition_is_caught` | Q12 |
| I-11 | `i11_call_findings_share_pinned_config` | `i11_m_find` | `i11_teeth_foreign_config_is_caught` | Q12, Q15 |
| I-12 | `i12_every_frozen_parameter_is_in_the_snapshot`, `i12_frozen_edits_leave_call_outcomes_unchanged` | `i12_m_policy` | `i12_teeth_head_instead_of_snapshot_is_caught` | none |
| I-13 | `i13_i14_grant_sequences_respect_range_and_cap` | `i13_i14_m_money` | `i13_teeth_out_of_range_grant_is_caught` | Q7 |
| I-14 | `i13_i14_grant_sequences_respect_range_and_cap`, `i14_p05_edit_below_committed_is_refused` | `i13_i14_m_money`, `i14_m_race_reservation` | `i14_teeth_grant_above_cap_is_caught` | Q7, Q9 |
| I-15 | `i15_repeat_grant_requires_public_deliverables`, `i15_amendment_requires_public_deliverables` | `i15_m_money_repeat` | `i15_teeth_repeat_without_records_is_caught` | Q8 |
| I-23 | `i23_ledger_is_prefix_monotone_and_replays`, `i23_verifier_flags_every_mutation`, `i23_store_api_has_no_mutation` | `i23_m_ledger` | `i23_teeth_changed_past_entry_is_caught` | Q12 |

Additional tests if Q12 adds them to the exit: `i34_i35_assignment_respects_orgs_and_proximity`, `i36_former_reviewer_never_receives_in_call_under_evaluation`, `p11_handles_never_repeat_across_proposals_and_calls`.

Requirements covered at domain level in M2:

- Programmes and submission: R-PC-01, R-PC-02, R-PC-03, R-SB-01 (by type), R-SB-02, R-SB-03, R-SB-05 (record).
- Evaluation: R-EV-01, R-EV-02, R-EV-03, R-EV-05, R-EV-06, R-EV-07, R-EV-08 (record and budget figure), R-EV-09 (interim).
- Independent review and negotiation: R-IR-01, R-IR-02 (record and outbox), R-IR-04 (route), R-NG-02 (guard seam), R-NG-03, R-NG-05.
- Conflicts and access: R-CF-01, R-CF-02, R-CF-03, R-CF-04 (flag), R-AC-01, R-AN-01.
- Assessment, audit, execution and MCP: R-LA-03, R-LA-05, R-AU-01 (partial), R-EX-04 (abstract), R-MC-05 (classification seam).

---

## 12. Questions for Daniel

Each question lists options and a recommendation. The interim reading in section 9.3 is what M2 builds until you answer.

### 12.1 These block M2

Q1 to Q3 are answered. Q4 to Q19 are open.

**Q1. Scoring arithmetic (I-08, R-EV-03).** The spec gives no criterion scale, no rule for combining reviewers and no base for "75%".

- A: Integer scale 0 to N per criterion, with N in P-01. Every reviewer scores every criterion. Mean over reviewers of weighted sums, as a fraction of the maximum. P-02 is a percentage of that maximum with two decimals, compared exactly.
- B: As A, with a 1 to N scale normalised as (s - 1) / (N - 1).
- C: Median of reviewers' weighted sums instead of the mean.
- Recommendation: A. Also confirm that weights are positive integers with no required total.
- **Answered by Daniel on 2026-10-25: A.** Weights are positive integers with no required total.

**Q2. Stage 1 close (I-07, R-LA-03).** No trigger and no stage 1 deadline parameter exist. R-LA-03 outranks the "System" actor.

- Trigger. A: every active assignee has a valid score, and at least P-03 exist. B: P-03 valid scores exist. C: a deadline set by a new parameter.
- Valid scores. A: scores of released or conflicted reviewers never count. B: they count if recorded before the release.
- Late corrections. A: scores seal at stage exit, and only a recorded complaint remedy reopens them. B: a correction after exit can change the outcome.
- Recorder. A: the FSTP coordinator records the close and cannot choose its outcome. B: the committee chair. C: you rule that computed outcomes are not decisions under R-LA-03.
- Recommendation: A for all four.
- **Answered by Daniel on 2026-10-25: A for all four.**

**Q3. Stage 2 and I-09 (R-EV-05, R-EV-06).**

- Rescoring. A: assigned reviewers rescore a revised plan, and P-03 valid stage 2 scores are needed. B: any one assigned reviewer.
- Several revisions. A: the latest scored revision counts. B: the highest-scoring revision.
- P-24 tie. A: the original plan carries forward. B: the revised plan.
- No questions asked. Row 7 defers after P-07 "without answers". A: literal, so the proposal waits P-07 and is DEFERRED. B: reviewers record "no questions", the window closes at once with answers deemed complete, and row 6 applies. C: as B, but still waiting P-07.
- Recommendation: A, A, A, and B for the last part. B changes a row guard, so it needs your decision.
- **Answered by Daniel on 2026-10-25: A, A, A, and B for the last part.** The row 7 guard in `SPEC/02-domain/state-machine.md` changes accordingly, and the spec is updated before M2 code depends on it.

**Q4. Cooling-off (I-01, SoD-05, P-12).**

- Scope. A: every switch among Drafting, Judging and Receiving, since I-01 counts past bindings in all three groups. B: only Drafting or Judging followed by Receiving, as SoD-05 and P-12 say.
- Calls published while the binding was active. A: barred. B: open, reading NOTE 4 literally.
- P-12 edits. A: the value is pinned when each binding ends. B: the current value always applies.
- P-12 = 0. A: allowed. B: minimum 1.
- Recommendation: A for all four.

**Q5. Sybil and exclusion discovery (I-06, I-04).** When the vault verifies an applicant at negotiation, the combined state can break I-06 or I-04 before the platform acts. The platform can restore them only if the affected bindings stop counting as held.

- A: In the same step, void the discovered account's Receiving bindings. Voided bindings never count as held, including as past bindings. The Judging binding stays, since it was verified at grant time.
- B: Suspend both sides. Suspended bindings do not count as held.
- C: Suspend, and keep counting suspended bindings as held. I-04 and I-06 then cannot be green as written, and you would restate them.
- Also confirm two points. The I-04 predicate is stated over the vault's knowledge, since the system holds no other. The M3 provisional-verification protocol in section 4.3 is acceptable.
- Recommendation: A, plus the protocol. For scores the Judging account already gave, record a notifiable conflict (R-CF-04) and leave re-evaluation to complaint remedies.

**Q6. NEGOTIATION failures.** Identity, SoD-09, I-04, I-13, I-14, I-15 or consent can fail. No transition leaves NEGOTIATION except GRANTED and WITHDRAWN.

- A: A new System transition from NEGOTIATION to DECLINED with a recorded reason.
- B: A new terminal state for failed negotiation, named by you.
- C: The proposal stays in NEGOTIATION until the applicant withdraws. After Q5 voiding, the lead cannot act, so it stalls.
- Recommendation: B, because DECLINED means "no future call available". You choose the name and update the state machine.

**Q7. Grant amount and cap (I-13, I-14, R-NG-03).**

- I-13. A: granted equals the effective plan total minus recorded deductions. B: granted is at most that.
- P-04 bounds. A: inclusive at both ends. B: exclusive at one or both ends, as you specify.
- Recipient. A: the verified identity of the applicant lead. B: each team member separately. C: an applicant organisation, a concept the spec does not yet have.
- Counting. A: granted plus open reservations from amount determination, amended totals included, dropping to the paid total at closure (I-64). B: granted amounts only.
- P-05 lowered below a recipient's committed sum. A: the edit is refused. B: the edit applies and blocks further grants.
- Recommendation: A for all five. A in the first part means every reduction carries a recorded reason.

**Q8. Repeat grants (I-15, R-NG-05).**

- Same applicant. A: verified identity of the lead, tenant-wide, since I-15 has no programme qualifier. B: within the programme.
- Prior deliverables. A: every deliverable of every prior grant's effective plan. B: every deliverable accepted so far. C: final deliverables of completed grants only.
- Licence list. A: the P-26 of both the prior and the new call. B: the prior call's P-26 only.
- Amendments. A: this grant's accepted deliverables must also be recorded. B: only other prior grants count.
- P-65 "progress report". Does a partial claim without public deliverables leave the record incomplete until the final claim?
- Recommendation: A, B, B, A, and yes. Interim builds the strictest combination (A, A, A, A).

**Q9. Non-frozen limits in published calls (P-05, P-13, I-51).** The Guide shows P-05 and P-13, and I-51 ties Guide values to the frozen call policy. I-04 and I-14 must hold against the programme's current values.

- A: Enforce the live programme value. The Guide shows the publication snapshot, and a change produces a corrigendum (M9).
- B: Freeze P-05 and P-13 per call. I-04 and I-14 would then need restating per call.
- C: Enforce the stricter of the call snapshot and the live value. Adding a P-13 class re-evaluates existing Receiving holders under Q5.
- Recommendation: C. It keeps I-04 and I-14, and never applies a looser limit than the published Guide.

**Q10. I-03 scope and committee conflicts.**

- Acts covered. A: content reads by anyone, and every assigned-reviewer act, IRC review and knock-out on the proposal or its grant. B: A plus committee votes on the cut-off. C: reads and scores only.
- Declarations. Must the FSTP coordinator declare before the knock-out read? Must every committee member declare under the P-10 option "all committee members"?
- Conflicted committee members. A: recuse from the cut-off vote of any call where they hold a conflict on a ranked proposal, with no delegation to or from them. B: vote, with no special rule.
- Recommendation: B for acts, yes to both declarations, and A for conflicted members.

**Q11. Receiving bindings (I-01, I-04, I-36).** Roles bind to programmes, but NOTE 4 and I-36 need a call.

- Start. A: at draft creation. B: at submission.
- End. A: at the proposal's terminal state, so grantees stay bound until COMPLETED or TERMINATED. B: never, as a programme-level binding.
- Scope. A: the proposal and its call. B: the programme only.
- Recommendation: A for all three, applied equally to team members and guardians.

**Q12. M2 exit scope.**

- A: M2 claims I-10 and I-11 at domain level with a fake assessor, and M7 covers the pipeline. It claims I-13 to I-15 with the synthetic vault, and I-23 by prevention, verifier and replay, with I-24 in M3. B: some of these wait for later milestones.
- I-34, I-35 and I-36 sit in no milestone's exit. A: add them to M2. B: leave them unassigned. If A: reviewer organisations are a field on the committee binding, and proposal-declared affiliations stay in the vault behind `DeclaresAffiliationOnList`. A DEFERRED proposal counts as under evaluation in the next call for I-36.
- The test plan has no I-04 row. Do you accept the row proposed in section 6.2?
- Recommendation: A, A with that data placement, and yes.

### 12.2 These shape M2 but can follow

**Q13. Vault interface for M3.** Accept the query set in section 4.1, fail-closed on vault unavailability, and recording positive matches visible to auditors only? Options: A, accept as listed; B, keep to the four queries in `overview.md` and restate the affected invariants. Recommendation: A.

**Q14. Calls.** Call states: A, draft, approved and published, with open and closed derived from time; B, a richer lifecycle you define. "Future call exists": A, a later call of the programme is published; B, one is scheduled under P-06. Call budget: A, immutable once published and display-only; B, a hard nomination limit. R-PC-03 drafters: A, call authors plus the last authors of P-01 and P-09; B, call authors only. P-10 "operator staff only": which role reads? Recommendation: A, A, A, A, and a named Judging role for the P-10 option.

**Q15. Deferral.** Which call's frozen policy governs a deferred proposal: A, the original call, matching what the applicant was told; B, the new call. Do assignments and handles carry over: A, new assignments and handles in the new call; B, they carry over. A STAGE2 deferral with no next call: A, it waits; B, it becomes DECLINED after a limit. Findings: A, they stay with the producing call and M7 may regenerate in the new call; B, they move. Recommendation: A for all four.

**Q16. Model replacement versus frozen P-21.** A: the frozen P-21 value is a primary model plus an ordered fallback list, pinned at publication, with atomic regeneration of the call's findings. B: no replacement, and the call stops using findings. C: unfreeze P-21. Recommendation: A, which keeps I-11 and I-12 intact.

**Q17. Cut-off and voting (R-EV-08, R-EV-09).** Cut-off: A, a rank position over a total order, with ties broken by the committee under P-17 and recorded; B, a score. P-16: majority base, quorum, delegation limits. P-17 needs applicant country before NEGOTIATION: A, a vault boolean; B, a self-declared field. Rounds: A, each cut-off covers the proposals currently RANKED; B, one per call. Recommendation: A, then your P-16 details, A, A.

**Q18. Execution, amendments and signatory.** Milestones have due dates, not start dates: what is the "first milestone start date" (A, contract effective date plus an offset you set; B, a start date added to milestones)? COMPLETED with partial payments: "all milestone payment requests PAID" seems to conflict with P-67 releasing unclaimed balances at COMPLETED (A, every milestone closed by M5's rule and every request terminal; B, every milestone fully paid). Is GRANTED to TERMINATED allowed? Amendments: A, a separate workflow with the proposal state unchanged, the programme manager deciding P-14 exemptions, and "total" meaning the amended contract total. The contract signatory: add an "Operations role with signing authority" to the roles table? Recommendation: B, A, yes, A, and yes.

**Q19. Persistence.** A: one ledger per cell, recorded in a new ADR before M3, with canonical record text holding ADR-006 strings and `numeric` columns in projections. B: one ledger per programme. Also confirm `TextRef` for free text, and say how P-41 retention and I-81 shredding should coexist with I-23. Recommendation: A, plus the `TextRef` approach.
