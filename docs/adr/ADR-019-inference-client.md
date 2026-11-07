# ADR-019: Inference client and wire protocol

Status: Accepted by Daniel Thompson-Yvetot on 2026-11-07: the Anthropic Messages API by default, the chat-completions shape to an open-weight EU or local model as secondary, and the model chosen per tenant (P-21). Drafted 2026-11-06 by lanes L-SEAM and L-WIRE, updated 2026-11-07 by lane m7anth. Q2 (trust anchors) is answered by the ADR-001 amendment of 2026-11-06 (webpki-roots).

The number is the next free one after ADR-018, which `docs/handoff/m6-design.md` claims. The lead renumbers it if a merge batch takes 019 first.

## Context

- **R-LA-04** Each tenant selects its inference provider. Self-hosted cells can use a local endpoint.
- **R-LA-05** Model, prompt and rubric are pinned per call (I-11).
- **TH-01** Prompt injection in submissions. `assessment.md`: submission and retrieved content travel only in the data channel, and instructions come only from the pinned prompt.
- **TH-13** Provider retention or third-country access. The tenant chooses the provider. A local endpoint is possible.
- **P-21** The inference provider and the pinned model are a tenant choice.
- ADR-009 and `fstp-cell/src/egress.rs` record that no allowlisted crate provides a public TLS root store (M7 design Q2).

## Decision record

| Date | Who | Decision |
| --- | --- | --- |
| 2026-11-06 | Daniel (`docs/handoff/m4-design.md` section 15.0, "M7 inference provider") | The client speaks the Anthropic Messages API by default, verified against the official API documentation. The chat-completions shape to an open-weight EU-hosted or local model is the secondary path. The demo stays synthetic or replayed |

## Decision

| Topic | Decision | Basis |
| --- | --- | --- |
| Default protocol | Anthropic Messages, `POST /v1/messages`, non-streaming, `anthropic-version: 2026-10-21` | Decision record |
| Secondary protocol | The chat-completions JSON shape, non-streaming, over HTTP/1.1 `POST` | Decision record |
| Model | Tenant configuration (P-21), never hard-coded. The encoder sends the configured name unchanged | P-21, TH-13 |
| Suggested model | `claude-opus-5-5` for a tenant on the Anthropic protocol. `claude-sonnet-5-5` is the cheaper option. The tenant decides | Model list of the reference below |
| Structured output | The v1 output schema goes as a request parameter, never as prompt text | M7 design section 3.3 |
| Trust anchors | The tenant's inference record pins PEM anchors for its endpoint | Q2, pending Daniel |
| New crates | None. `fstp-http`, `fstp-tls`, `fstp-json` and aws-lc-rs digests through `fstp-crypto` | M7 design section 9 |

`Protocol` in `crates/fstp-infer` holds the two protocols, and `Protocol::default()` is `Anthropic`. `InferenceProvider` in `crates/fstp-api-core/src/port.rs` gains `Anthropic` beside `Synthetic` and `ChatCompletions`.

### Sources

The Anthropic wire format was read on 2026-11-07 from these pages. Nothing in it was written from memory.

- Request, response, content blocks, stop reasons and usage: <https://platform.claude.com/docs/en/api/messages/create>.
- The `anthropic-version` header and the 2026-10-21 changes: <https://platform.claude.com/docs/en/api/versioning> and <https://platform.claude.com/docs/en/api/migration-2026-10-21>.
- Error shape and status codes: <https://platform.claude.com/docs/en/api/errors>.
- Stop reason meanings: <https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons>.
- `output_config.format` and its schema limits: <https://platform.claude.com/docs/en/build-with-claude/structured-outputs>.

### The data channel, by type

`crates/fstp-infer` makes it impossible to put submission text into an instruction, in both protocols:

- `Instruction` is built only from a `Prompt`, a closed enum. Each prompt is `prompts/v1/common.txt` followed by its task file, compiled in through `include_str!`. The only parameters are a P-01 `CriterionId`, rendered as 32 hex digits, and closed rubric `ElementTag`s. No constructor takes a `String` or an `UntrustedText`, and two `compile_fail` doctests check that.
- `DataPart` is the only request type that takes `UntrustedText`. Its label is a closed enum.
- `encode` is the only builder of a request body. A source scan fails if another module names both the `messages` and `system` members.
- The data is one canonical JSON object `{"parts": [{"label", "text"}]}`. Every part is a JSON string value. Both protocols carry that object as the text of the one user message.

### Request, Anthropic (default)

`encode` writes canonical JSON (RFC 8785). Credentials never enter the body, so its SHA-256 keys recordings.

| Member | Value |
| --- | --- |
| `model` | The P-21 model name: 1 to 128 bytes of ASCII letters, digits and `. _ - : / @ +` |
| `max_tokens` | Integer |
| `system` | The rendered instruction, as a string. Nothing else ever goes here |
| `messages` | `[{"role": "user", "content": [{"type": "text", "text": <canonical data JSON>}]}]` |
| `stream` | `false` |
| `output_config` | `{"format": {"type": "json_schema", "schema": ...}}` when a schema is set |

- No `temperature`, `top_p` or `top_k`. Version 2026-10-21 answers 400 to any of them. The Messages API has no seed. `Decoding.temperature_milli` and `seed` stay inputs of the `config_id`, but only the chat-completions body carries them.
- No `thinking`. Current models then think adaptively, and a reply may hold thinking blocks, which the decoder drops.
- The schema sent leaves out `maxLength`, `minLength`, `maxItems`, `minimum`, `maximum` and `multipleOf`. The structured outputs page lists them as unsupported, with a 400 for each. The output decoder of lane L-PIPE still enforces the full schema.
- Headers: `content-type: application/json`, `accept: application/json`, `x-api-key: <key>` and `anthropic-version: 2026-10-21`. The errors page and the curl examples show `x-api-key`. The migration guide says the API also accepts `Authorization: Bearer`.

### Request, chat-completions (secondary)

| Member | Value |
| --- | --- |
| `model` | As above |
| `messages[0]` | `{"role": "system", "content": <rendered instruction>}` |
| `messages[1]` | `{"role": "user", "content": <canonical data JSON as one string>}` |
| `max_tokens` | Integer |
| `temperature` | Decimal from thousandths, 0 to 2. No floats in the code |
| `seed` | 32-bit integer |
| `stream` | `false` |
| `response_format` | `{"type": "json_schema", "json_schema": {"name": "findings_v1", "strict": true, "schema": ...}}` when a schema is set |

The credential, when present, goes in `Authorization: Bearer` only. Both bodies are at most 4 MiB.

### Response, Anthropic

`decode_anthropic_response` refuses any member outside these closed sets. One unknown member fails the whole reply, so a model or server cannot add `score`, `decision` or `state` (I-10).

| Object | Members | Rules |
| --- | --- | --- |
| Message | `id`, `type`, `role`, `content`, `model`, `stop_reason`, `stop_sequence`, `stop_details`, `usage`, `container`, `diagnostics` | `type` is `message`, `role` is `assistant`. `id` and `model` are strings or null. `container`, `diagnostics` and `stop_sequence` are absent or null, since no request asks for them |
| `text` block | `type`, `text`, `citations` | Exactly one per reply. `text` is a string of at most 64 KiB. `citations` absent, null or empty |
| `thinking` block | `type`, `thinking`, `signature` | Strings. Checked and dropped |
| `redacted_thinking` block | `type`, `data` | A string. Checked and dropped |
| `stop_details` | `type`, `category`, `explanation` | Null, or `type` `refusal` with `stop_reason` `refusal` |
| `usage` | `input_tokens`, `output_tokens` | Non-negative integers. Input tokens add the two cache counts, as the reference defines the total |

Every other block type is refused: `tool_use`, `server_tool_use`, tool results and `container_upload`.

The allowlist of harmless extra usage members is closed too. Each holds counts or a short label and no model text:

| Member | Shape |
| --- | --- |
| `cache_creation_input_tokens`, `cache_read_input_tokens` | Integer or null |
| `cache_creation` | Null, or `{ephemeral_1h_input_tokens, ephemeral_5m_input_tokens}` |
| `output_tokens_details` | Null, or `{thinking_tokens}` |
| `server_tool_use` | Null, or `{web_fetch_requests, web_search_requests}` |
| `inference_geo`, `service_tier`, `speed` | String or null |

Stop reasons map to typed results. Every one but `end_turn` leaves the findings pending (R-NF-10).

| `stop_reason` | Result |
| --- | --- |
| `end_turn` | The reply, `FinishReason::Stop` |
| `max_tokens`, `model_context_window_exceeded` | `DecodeError::Truncated` |
| `refusal` | `DecodeError::Refused` |
| `stop_sequence`, `tool_use`, `pause_turn` | `DecodeError::Unexpected(StopReason)` |
| Any other or null | `DecodeError::Shape("stop_reason")` |

Errors come as a non-200 status with an `{"type": "error", "error": {...}, "request_id"}` body. The transport keeps only the status, as `TransportError::Status`, and never reads or logs the body.

### Response, chat-completions

| Object | Members | Rules |
| --- | --- | --- |
| Response | `id`, `object`, `created`, `model`, `choices`, `usage`, `system_fingerprint`, `service_tier` | `object` is `chat.completion`. The string members may be null |
| Choice | `index`, `message`, `finish_reason`, `logprobs` | Exactly one choice, index 0. `logprobs` absent or null. `stop` is accepted, `length` is refused as truncated |
| Message | `role`, `content`, `refusal`, `tool_calls` | Role `assistant`. Content a string of at most 64 KiB. `refusal` absent or null. `tool_calls` absent, null or empty |
| Usage | `prompt_tokens`, `completion_tokens`, `total_tokens` | Non-negative integers, all optional |

For both protocols, the body is at most 1 MiB, and the parser limits depth, nodes and container length. The content stays `UntrustedText`. Its schema check is the separate `assess_output_decode` of lane L-PIPE.

### Credentials

`ApiKey` holds a key. It has no `Display`, and its `Debug` shows only the length. `HttpTransport`'s `Debug` shows the URL and the kind of credential, never the key (R-NF-02).

### Transports

| Transport | Use |
| --- | --- |
| `HttpTransport::anthropic` | The Anthropic endpoint, normally `https://api.anthropic.com/v1/messages`, through `fstp-http`. Any status but 200 fails |
| `HttpTransport::new` | A chat-completions endpoint, with an optional bearer |
| `Record` | Wraps a transport and writes `<dir>/<sha256 of body>.json` with the exact response bytes |
| `Replay` | Reads that file only. A miss fails the run |
| `SyntheticModel` | Deterministic code that answers each request in its own protocol, in memory, for the demo cell and the `synthetic` mode. Never reported as an LLM result |

Record and replay are protocol-blind: the protocol is part of the body, so it is part of the key. A failed call leaves findings pending and never blocks evaluation (R-NF-10).

## Consequences

- A prompt change is a code change. It changes `prompt_set_digest`, and so every `config_id` and every recording key.
- The prompts live in `fstp-infer`, not in `fstp-assess` as the M7 design section 3.3 says. A prompt in another crate would need a constructor from `&'static str`, and `String::leak` makes such a value from runtime text.
- A server that adds a member outside the closed sets is refused until this ADR and the decoder change. The versioning page says Anthropic may add output values within a version. Such an addition fails closed, and findings stay pending until a reviewed decoder change.
- With the Anthropic protocol, sampling uses the API defaults. Two runs of one recorded request still replay byte-exact, but a live rerun can differ.
- Hosted endpoints stay unreachable until the tenant record pins trust anchors (Q2), or the webpki-roots amendment of 2026-11-06 lands in `fstp-tls`.

## Tests

- TH-01: `th01_data_channel_never_reaches_instruction` and `th01_anthropic_data_channel_never_reaches_instruction` (properties), `th01_instruction_renders_only_pinned_text`, `th01_only_the_encoder_builds_request_bodies`, `th01_decoder_rejects_unknown_members`, `th01_anthropic_decoder_rejects_unknown_members`, `th01_anthropic_decoder_refuses_malformed_blocks`, `th01_synthetic_flags_injection`, and the two `compile_fail` doctests.
- R-LA-04: `r_la_04_anthropic_request_shape`, `r_la_04_anthropic_decode_accepts_minimal_reply`, `r_la_04_anthropic_decode_accepts_documented_fixture`, `r_la_04_anthropic_stop_reasons_map_to_typed_results`, `r_la_04_anthropic_replay_reproduces_recorded_exchange_byte_exact`, `r_la_04_anthropic_synthetic_reports_missing_element`, `r_la_04_anthropic_http_transport_sends_documented_headers`, `r_la_04_api_key_never_in_debug_output`, and the chat-completions tests `r_la_04_decode_accepts_minimal_reply`, `r_la_04_decoder_refuses_other_shapes`, `r_la_04_replay_reproduces_recorded_exchange_byte_exact`, `r_la_04_replay_miss_fails`, `r_la_04_synthetic_reports_missing_element`, `r_la_04_http_transport_posts_to_local_endpoint`.
- Fuzz targets in `crates/fstp-infer/fuzz`: `anthropic_response_decode` and `infer_response_decode`, each with an independent closed-member oracle, and `synthetic_answer` for both protocols.
- No test makes a live network call. The HTTP tests use a local server on 127.0.0.1.

## Open points

- Q2: trust anchors for hosted endpoints.
- A live check of the Anthropic body against the API, once a key and Q2 allow it. In particular, whether the v1 schema's `enum` members without `type`, and `"type": ["string", "null"]`, pass the structured outputs compiler.
- Whether a `refusal` should switch to the next P-21 fallback (NOTE 10). Today it leaves findings pending. The API's server-side `fallbacks` parameter is not used, so every model stays pinned by the tenant.
- Whether the decoder should accept `prompt_tokens_details` and `completion_tokens_details` on the chat-completions path.
- `TODO(legal)`: the DPIA and the provider as a sub-processor in each tenant's DPA (`gdpr.md`), before a production tenant enables P-21. This covers Anthropic as a non-EU provider (TH-13).

## Record

| Item | Value | Recorded |
| --- | --- | --- |
| Third-party crates added by this ADR | None | 2026-11-06 |
| Prompt set version | `v1` | 2026-11-06 |
| Default protocol | Anthropic Messages, `anthropic-version: 2026-10-21` | 2026-11-07 |
| Secondary protocol | chat-completions | 2026-11-07 |
