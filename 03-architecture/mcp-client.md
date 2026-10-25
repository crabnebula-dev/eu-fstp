# MCP client

The platform can also call external MCP servers. Tenants connect the tools their programmes rely on, and platform components use them for checks and hand-offs.

## Uses

| Component | Example external servers | Purpose |
| --- | --- | --- |
| Payment request checks | Code forges, package registries, open access repositories | Verify that deliverables are public, licensed and match their identifiers |
| Claim verification in the assessor | Code forges, publication databases | Check applicant claims such as maintainership or prior work |
| Record-only payment mode | The tenant's finance or accounting system | Hand over approved payments |
| Funder reporting | The tenant's document management system | File approved funder documents |
| Notifications and tasks | The tenant's ticketing or project tools | Mirror deadlines and tasks |

## Connection

- Tenant admins add an MCP server to the cell with a declared purpose, the components allowed to use it, and the fields each call may send (P-78).
- Credentials are cell secrets and never reach the control plane.
- Adding or changing an integration is a high-risk action with a step-up (I-78).
- Egress is limited to the hosts of connected servers.
- Self-hosted cells work the same way.

## Rules

- **I-88** Calls initiated by platform components, including the assessor, use read-only tools only. A tool that changes external state runs only for a specific action approved by a named human.
- **I-89** Each call sends only the fields declared for that integration. Identity attributes and bank details go only to an integration of type "finance hand-over", approved with a step-up.
- Responses from external servers are untrusted data, handled like submission content. They never become instructions, and they never change platform state without the normal human decision.
- Every external call is logged with integration, tool, fields sent and response hash.
- Each connected server is a recipient of tenant data. Tenants list it in their records, and their DPA covers it where personal data is sent.

NOTE: The assessor's retrieval proxy (`04-llm-assessment/assessment.md`) may route claim checks through connected read-only MCP servers instead of raw web retrieval. Source independence weighting still applies.
