# ADR-027: Facts of the production creator shell

Status: Proposed. Drafted 2026-11-20 by lane L6 `prod/shell-facts` for gap G13 of `docs/handoff/production-mcp-design.md`. Every row is interim, pending Daniel. The rows were written before the code, as CLAUDE.md asks. It proposes one amendment of ADR-009 "Outbound destinations".

## Context

- G13: `ProductionShell` supplies no probe, no Q35 vault answer and no Guide inputs. So no programme activates and no call publishes on a production cell.
- I-66: a programme cannot be activated while its validation report shows any failure. Warnings need a recorded acknowledgement.
- I-51 and I-52: a Guide is generated only when every required section is present, and every parameter value equals the frozen call policy.
- Q5 (interim): an absent prober reports a failure for the channel and sending domain checks. Inference gives its warning.
- Q35 was answered "A" on 2026-11-06 (`docs/handoff/m4-design.md`, decision table). `SPEC/03-architecture/overview.md` NOTE 8 names the two queries `classes_defined` and `proximity_lists_declared`.
- M4 design section 3.2, "Fresh probes": an approval makes the shell run every probe in the same request.
- ADR-009 closes `Destination` of `fstp-cell`. Its assessor amendment of 2026-11-07 says that `Destination` gains no inference member.
- The creator shell interface (`fstp_cell::shell::CreatorShell`) is synchronous. The route reads it before the gate admits the command.

## Decision

| Topic | Interim choice | Basis |
| --- | --- | --- |
| Q35 query set | Two domain queries join `fstp_domain::oracle::Query` and the vault protocol, codes 13 and 14: `ClassesDefined { programme, classes }` and `ProximityListsDeclared { programme, lists }`. Each answers one bit and names no account | Q35 A; NOTE 8 |
| `ClassesDefined` | Yes when every class of the set appears on at least one effective affiliation of the vault's view. The vault holds no class register, so a class with no declared member counts as unknown. The empty set answers yes | NOTE 8; interim reading |
| `ProximityListsDeclared` | Yes when the vault holds an effective `ProximityListDeclared` fact for every list of the set. The cell sends the list ids of the draft's P-38. The empty set answers yes | NOTE 8; P-38 |
| Who asks | The cell's decision asks both queries for the commands that read the report (acknowledging a warning, requesting, approving and overriding activation). It asks only when the shell supplies no answer of its own. A test shell may stand in for the vault with its own answers | NOTE 8; `fstp_cell_core::creator` |
| Unanswered | A vault that cannot answer refuses the command and records nothing (NOTE 2). This is stricter than leaving the rows standing as not checked, and no activation follows from either | NOTE 2 |
| Recording | The vault logs every asked query in its own query log. The ledger records no `VaultOutcome` for the two answers yet, as for the SoD preview answers | NOTE 5; open point |
| Probes run | The command route asks the shell for fresh facts once the gate admitted the command. For a request for activation, an approval and an override, the shell runs every probe in that request. Every other command reads the last results | Design 3.2 "Fresh probes" |
| Stale probes | A caller that reads the synchronous facts of an approval gets results no older than 60 seconds. An older or missing result counts as absent, so the check fails closed | Q5; I-66 |
| Channel probe | P-32 enables email only. The probe opens the configured submission relay through `Destination::MailSubmission`, completes the TLS handshake and reads a `220` greeting, then sends `QUIT` | ADR-018; P-32 |
| Sending domain probe | SPF, DKIM and DMARC records of the configured sending domain, read as TXT records. SPF: exactly one record starting `v=spf1` (RFC 7208 section 4.5). DMARC: exactly one record at `_dmarc.<domain>` starting `v=DMARC1` with a valid `p` tag (RFC 7489 section 6.6.3). DKIM: a record at `<selector>._domainkey.<domain>` with a non-empty `p` tag (RFC 6376 section 3.6.1). All three must pass | Spec "sending domain with SPF, DKIM and DMARC checks" |
| DNS | An in-house DNS client asks the configured resolver over TCP (RFC 7766), one TXT question per lookup, recursion desired. The answer parser is in-house and fuzzed (`dns_txt_decode`). No DNSSEC validation | CLAUDE.md dependency and fuzz rules |
| Inference probe | Absent in the cell. The assessor amendment of ADR-009 gives the cell no inference destination. `InferenceUnreachable` is a warning, so a tenant admin acknowledges it until the assessor offers a probe | ADR-009 assessor amendment; Q5 |
| Settings | `ShellSettings` names the resolver address, the sending domain, the DKIM selector, the relay host and its pinned CA, and the platform address of the Guide. A setting that is missing makes its probe absent. Lane L4 wires them from the configuration file | ADR-026 configuration |
| Funder profile | The shipped profiles only (rule A9b). Their wording is `TODO(legal)`, so `LegalWordingPending` stays a failure until Daniel approves it | Q6 |
| Ports | No pre-check provider and no score tools until M7 | Q38 C |
| Guide inputs | The template of the programme's P-53 profile and the complete creator draft, the configured platform address, the stored narratives read from the cell's text store while live, and the pre-check flag | I-51; I-52; R-GA-01 |
| Data protection texts | The tenant's own notice when its settings name one. The platform default is `TODO(legal)` in `fstp-tenant`, so the shell supplies no Guide while it is used, and the publication is refused with I-52 | I-52; `TODO(legal)` |
| Inference record | A publication through the API core reads the latest `InferenceConfigRecorded` of the ledger's tenant part. The shell adds nothing | R-LA-05 |

## Amendment of ADR-009, proposed

`Destination` of `fstp-cell` gains one member:

```rust
DnsResolver { addr: SocketAddr },   // the configured resolver, TCP port 53 only (ADR-027)
```

- It carries DNS questions for the sending domain probe only. It reaches no payment service and names no platform account (I-16).
- A CrabNebula host is never asked through it, since it takes an address, not a host name. The question names the tenant's sending domain only.
- R-NF-09 is not claimed. DNS over TCP to a resolver is neither encrypted nor authenticated. A spoofed answer can only make a probe pass or fail. The SMTP relay is still verified by TLS.
- `i16_cell_egress_has_no_payment_destination` enumerates the new member.

## Consequences

- A production cell can produce a clean report once its settings name a reachable relay and a sending domain with all three records, and the vault knows the classes and lists of the draft.
- Activation still waits on Daniel's approved wording of the shipped profiles (`LegalWordingPending`).
- Publication through the shell still waits on the platform data protection texts, unless the tenant set its own notice.
- `InferenceUnreachable` stays a warning to acknowledge.
- A test world may pass its own shell with its own answers. Claims built on such a shell say so.

## Tests

- `q35_classes_defined_answers_known_and_unknown`, `q35_classes_defined_counts_effective_facts_only`, `q35_proximity_lists_declared_answers_known_and_unknown` and `q35_answers_are_set_inclusion_over_random_facts` in `fstp-vault-core`.
- `q35_queries_take_codes_13_and_14`, `q35_queries_round_trip_on_the_wire`, `q35_query_args_are_checked_against_their_kind` and `q35_answers_name_no_account` in `fstp-vault-proto`.
- `q35_questions_name_the_draft_classes_and_lists`, `q35_only_report_commands_on_a_policy_ask` and `q35_report_commands_ask_the_vault_without_shell_answers` in `fstp-cell-core`.
- `q5_fake_prober_reachable_passes`, `q5_fake_prober_unreachable_fails`, `q5_absent_prober_reports_failure`, `i66_stale_probe_results_are_absent_at_approval` and `adr027_sending_domain_probe_over_a_fake_resolver` in `fstp-cell`, with the unit tests of the DNS codec and the record checks.
- The fuzz target `dns_txt_decode` of `fstp-cell`.
- `q6_shipped_wording_is_the_only_profile_difference`, `i66_i51_i52_production_shell_facts_activate_and_publish_on_pg` and `i66_q35_unknown_class_keeps_the_programme_a_draft_on_pg` in `fstp-celltest`.
- `i16_cell_egress_has_no_payment_destination`, `i38_only_egress_reaches_crabnebula_hosts` and `adr009_cell_egress_connect_builds_the_closed_set_only` enumerate `DnsResolver`.

## Open points

- Whether a class counts as defined only through a declared member, or through a class register in the vault.
- Whether the ledger records the two Q35 answers as `VaultOutcome` records in an approval entry.
- How the inference probe reaches P-21: through the assessor, or through an ADR-009 member.
- The API core path. `CellAsyncEngine` in `crates/fstp-cell/src/api/` still reads the synchronous shell facts and `AsyncEngine::creator_inputs` keeps its default, so a report read and a request for activation through the API core see no probe and no Q35 answer. Lane L5 or the lead calls `creator_facts_fresh` and `guide_inputs_fresh` there.
- The approved wording of the shipped profiles and of the platform data protection texts (`TODO(legal)`).
