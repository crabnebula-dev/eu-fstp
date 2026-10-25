# Tenant export schema

This folder holds the export and import schema. The schema and the import and export tooling are licensed under EUPL-1.2, separately from the platform (O-10), so that any provider can ingest a tenant export.

## Layout of an export

```
export/
  manifest.json            schema version, export time, entity counts, content hashes, composite signature
  policies/                all policy versions, append-only
  programmes.ndjson
  calls.ndjson
  proposals.ndjson         including all plan versions
  reviews.ndjson           scores, conflict declarations, stage 2 messages
  decisions.ndjson         committee and IRC decisions with rationale
  contracts.ndjson         all versions, diffs against template, signature records
  notices/                 sealed contractual notice PDFs with hashes
  contract-templates/      versioned templates
  payment-requests.ndjson  requests with lines per milestone, checks, evidence snapshots, line approvals and reasons, releases
  reallocations.ndjson     reallocation requests between milestones, approvals and reasons
  closures.ndjson          grant closures with unclaimed balances and their disposition
  branding/                white-label package: tokens, logos, fonts, legal pages, terminology
  programme-drafts/        programme creator drafts, import proposals and confirmations
  integrations.ndjson      connected external MCP servers, purposes, declared fields (credentials excluded)
  agent-clients.ndjson     connected MCP clients per user, scopes and revocations
  roles.ndjson             role bindings with start and end dates
  timeline-events.ndjson   derived events with source references, including cancelled ones
  message-log.ndjson       sent message metadata, template versions, delivery status
  message-templates/       versioned, per locale
  groups.ndjson            group definitions and membership history
  findings.ndjson          LLM findings with config_id
  publications.ndjson      public visibility per grant, consents, public summaries
  funder-documents/        generated documents with snapshot hashes and approvals
  guides/                  Guide for Applicants versions and corrigenda per call
  complaints.ndjson        complaints, responses, escalations and remedies
  llm-configs.ndjson       pinned model, prompt and rubric versions
  traces/                  retained traces
  attachments/             content-addressed files
  audit/                   hash-chained audit log
  vault/                   encrypted identity vault export, separate key
```

## Rules

- Every record carries a stable identifier and schema version.
- The vault export is encrypted under a key the tenant controls.
- The message log holds metadata only, never message bodies sent to external channels.
- Import validates all hashes and the audit chain before writing any data.

## Licensing and contributions

External contributions are accepted with a Developer Certificate of Origin sign-off (O-25). A sign-off certifies the right to contribute under EUPL-1.2. It does not grant CrabNebula rights to relicense under PolyForm Noncommercial.

The export and import tooling is therefore a separate executable. The platform invokes it and exchanges data through the export format on disk or through a pipe. The platform links no EUPL code. Self-hosted distributions ship the executable under EUPL-1.2 with its source, alongside the platform under PolyForm Noncommercial.

NOTE: Keep the boundary a documented process and file interface. Moving tooling code into the platform binary would reopen the licensing question.
