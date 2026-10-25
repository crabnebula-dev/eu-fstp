# MCP server

Each cell exposes a Model Context Protocol (MCP) server. Users connect their own AI agents to act on the platform on their behalf, within their roles. The MCP server is one more client of the same API the web frontend uses. It adds no powers of its own.

Status: scope decided by Daniel on 2026-10-10 (O-40).

## Transport and authorisation

- Remote MCP over Streamable HTTP, served at the tenant's domain. White-labelling covers the server's name.
- Authorisation follows the MCP authorisation specification: OAuth 2.1 with PKCE. The cell is the authorisation server.
- Tokens are per user, per client, short-lived and scoped. The consent screen lists every scope in plain language.
- Connecting a new MCP client counts as linking a new device, so it needs a step-up (I-78).
- Users see their connected agents, the scopes each holds and its recent activity, and can revoke any of them at once.
- Tenants can disable the MCP server, or limit it to some roles (P-74).
- The JSON-RPC and OAuth code is in-house, with fuzz targets from the first commit.

## Capabilities by role

| Role | Tools and resources |
| --- | --- |
| Applicant | Read open calls and the Guide; draft and edit proposals; run the pre-check within its quota (P-23); read own notifications and stage 2 questions; draft answers |
| Grantee | Read own grant, milestones and balances; draft payment requests and reallocation requests; read reviewer decisions |
| Reviewer and committee | Read assignments, ranking view and findings within P-10 and P-75; draft scores and comments |
| Programme staff | Programme creator drafts, call drafting, timeline and reminder status, reporting drafts |
| Finance roles | Payment queue status and reconciliation views |
| Auditor | Read-only audit views and aggregates |
| Anyone, without an account | Public research tools: open calls, Guides for Applicants, eligibility and deadlines, and published subgrants within each grantee's publication choice |

## Rules

- **I-84** Every MCP call passes the same policy engine, separation of duties checks and audit logging as the web interface. No tool exists that the user's roles could not perform in the interface.
- **I-85** High-risk actions (I-78) cannot complete through MCP. An agent can prepare them. The user confirms in the platform with a step-up.
- **I-86** Identity attributes, bank details and vault contents are never returned through MCP.
- Every audit entry made through MCP records the client identity alongside the user.
- MCP never exposes another user's drafts, pre-check runs or private notes (I-21).
- Anonymous reviewer handles apply through MCP exactly as in the interface (P-11).

## Untrusted content

- Proposal text, deliverables, messages and any user-supplied content returned by a tool sit in clearly delimited data fields. They are never placed in tool descriptions or instructions.
- Tool names, descriptions and schemas are fixed by the platform. Tenants cannot edit them, and branding never alters them, which prevents tool poisoning.
- Responses carry a content classification (public, confidential, personal) so agents and their hosts can apply their own policies.

## Public research tools

Agents can research funding opportunities without an account. The public tools return only what the public pages show.

- **I-87** Public MCP tools return exactly the data of the public pages and feed, under the same filters (I-41, I-42, I-43, P-54).
- Public tools are rate-limited per client and need no login.
- A programme can opt in to a platform-wide directory of open calls (P-76). The directory holds public call data only, published from each cell like templates (I-73), and lets agents search across programmes and tenants.

## Binding actions (P-77)

Each programme decides whether agents may complete binding actions, such as submitting a proposal, answering stage 2, submitting a payment request or recording a score:

- **Draft only:** agents prepare, and the user confirms in the platform.
- **Allowed:** agents complete the action through MCP.

In both modes, high-risk actions still need confirmation in the platform with a step-up (I-85). Every action is attributed to the human user, with the agent client recorded. The Guide for Applicants and reviewer terms state the programme's choice.

## Confidentiality

When a reviewer's agent reads a proposal, its content goes to that user's AI provider, outside the tenant cell. Whether that is allowed is a programme decision (P-75), off by default, and stated in the Guide for Applicants and in reviewer confidentiality terms. With P-75 off, reviewers' agents see assignments, the ranking view, scores and findings that quote no submission text.

## Rate limits

Per-token and per-user rate limits apply. Pre-check quotas count MCP and interface runs together.
