# ADR-019: Inference client and wire protocol

Status: Proposed 2026-11-06 (lanes L-SEAM and L-WIRE of `docs/handoff/m7-design.md`). Pending Daniel (M7 Q1).

The number is the next free one after ADR-018, which `docs/handoff/m6-design.md` claims. The lead renumbers it if a merge batch takes 019 first.

## Context

- **R-LA-04** Each tenant selects its inference provider. Self-hosted cells can use a local endpoint.
- **R-LA-05** Model, prompt and rubric are pinned per call (I-11).
- **TH-01** Prompt injection in submissions. `assessment.md`: submission and retrieved content travel only in the data channel, and instructions come only from the pinned prompt.
- **TH-13** Provider retention or third-country access. The tenant chooses the provider. A local endpoint is possible.
- No spec text or ADR names a provider, a model or an API shape. M7 design Q1 asks Daniel for them, and section 9 marks the wire protocol ADR-required.
- ADR-009 and `fstp-cell/src/egress.rs` record that no allowlisted crate provides a public TLS root store (M7 design Q2).

## Decision (proposed)

| Topic | Proposal | Basis |
| --- | --- | --- |
| Wire protocol | One adapter for the chat-completions JSON shape, non-streaming, over HTTP/1.1 `POST` | M7 design Q1 recommendation, pending Daniel |
| Model | Open. Daniel picks one EU-hosted or local open-weight model for the exit run | Q1, TH-13 |
| Structured output | The v1 output schema goes as the `response_format` request parameter, never as prompt text | M7 design section 3.3 |
| Trust anchors | The tenant's inference record pins PEM anchors for its endpoint | Q2 recommendation, pending Daniel |
| New crates | None. `fstp-http`, `fstp-tls`, `fstp-json` and aws-lc-rs digests through `fstp-crypto` | M7 design section 9 |

### The data channel, by type

`crates/fstp-infer` makes it impossible to put submission text into an instruction:

- `Instruction` is built only from a `Prompt`, a closed enum. Each prompt is `prompts/v1/common.txt` followed by its task file, compiled in through `include_str!`. The only parameters are a P-01 `CriterionId`, rendered as 32 hex digits, and closed rubric `ElementTag`s. No constructor takes a `String` or an `UntrustedText`, and two `compile_fail` doctests check that.
- `DataPart` is the only request type that takes `UntrustedText`. Its label is a closed enum.
- `encode` is the only builder of a request body. A source scan fails if another module names both the `messages` and `system` members.

### Request

`encode` writes canonical JSON (RFC 8785). Credentials never enter the body, so its SHA-256 keys recordings.

| Member | Value |
| --- | --- |
| `model` | The P-21 model name: 1 to 128 bytes of ASCII letters, digits and `. _ - : / @ +` |
| `messages[0]` | `{"role": "system", "content": <rendered instruction>}` |
| `messages[1]` | `{"role": "user", "content": <canonical JSON {"parts": [{"label", "text"}]} as one string>}` |
| `max_tokens` | Integer |
| `temperature` | Decimal from thousandths, 0 to 2. No floats in the code |
| `seed` | 32-bit integer |
| `stream` | `false` |
| `response_format` | `{"type": "json_schema", "json_schema": {"name": "findings_v1", "strict": true, "schema": ...}}` when a schema is set |

The body is at most 4 MiB. The credential, when present, goes in `Authorization: Bearer` only.

### Response

`decode_response` refuses any member outside these closed sets. One unknown member fails the whole reply, so a model or server cannot add `score`, `decision` or `state` (I-10).

| Object | Members | Rules |
| --- | --- | --- |
| Response | `id`, `object`, `created`, `model`, `choices`, `usage`, `system_fingerprint`, `service_tier` | `object` is `chat.completion`. The string members may be null |
| Choice | `index`, `message`, `finish_reason`, `logprobs` | Exactly one choice, index 0. `logprobs` absent or null. `stop` is accepted, `length` is refused as truncated |
| Message | `role`, `content`, `refusal`, `tool_calls` | Role `assistant`. Content a string of at most 64 KiB. `refusal` absent or null. `tool_calls` absent, null or empty |
| Usage | `prompt_tokens`, `completion_tokens`, `total_tokens` | Non-negative integers, all optional |

The body is at most 1 MiB, and the parser limits depth, nodes and container length. The content stays `UntrustedText`. Its schema check is the separate `assess_output_decode` of lane L-PIPE.

### Transports

| Transport | Use |
| --- | --- |
| `HttpTransport` | A real endpoint through `fstp-http`. Any status but 200 fails |
| `Record` | Wraps a transport and writes `<dir>/<sha256 of body>.json` with the exact response bytes |
| `Replay` | Reads that file only. A miss fails the run |
| `SyntheticModel` | Deterministic code that speaks the wire format in memory, for the demo cell and the `synthetic` mode. Never reported as an LLM result |

A failed call leaves findings pending and never blocks evaluation (R-NF-10).

## Consequences

- A prompt change is a code change. It changes `prompt_set_digest`, and so every `config_id` and every recording key.
- The prompts live in `fstp-infer`, not in `fstp-assess` as the M7 design section 3.3 says. A prompt in another crate would need a constructor from `&'static str`, and `String::leak` makes such a value from runtime text.
- A server that adds a member outside the closed sets is refused until this ADR and the decoder change. Common extras such as `prompt_tokens_details` are refused today.
- Hosted endpoints stay unreachable until the tenant record pins trust anchors (Q2).

## Tests

- TH-01: `th01_data_channel_never_reaches_instruction` (property), `th01_instruction_renders_only_pinned_text`, `th01_only_the_encoder_builds_request_bodies`, `th01_decoder_rejects_unknown_members`, `th01_synthetic_flags_injection`, and the two `compile_fail` doctests.
- R-LA-04: `r_la_04_decode_accepts_minimal_reply`, `r_la_04_decoder_refuses_other_shapes`, `r_la_04_replay_reproduces_recorded_exchange_byte_exact`, `r_la_04_replay_miss_fails`, `r_la_04_synthetic_reports_missing_element`, `r_la_04_http_transport_posts_to_local_endpoint`.
- Fuzz targets in `crates/fstp-infer/fuzz`: `infer_response_decode`, with an independent closed-member oracle, and `synthetic_answer`.

## Open points

- Q1: the protocol and the model. This draft builds the chat-completions shape as the recommendation.
- Q2: trust anchors for hosted endpoints.
- Whether the decoder should accept `prompt_tokens_details` and `completion_tokens_details` as objects of integers.
- `TODO(legal)`: the DPIA and the provider as a sub-processor in each tenant's DPA (`gdpr.md`), before a production tenant enables P-21.

## Record

| Item | Value | Recorded |
| --- | --- | --- |
| Third-party crates added by this ADR | None | 2026-11-06 |
| Prompt set version | `v1` | 2026-11-06 |
