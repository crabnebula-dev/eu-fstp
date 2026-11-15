# ADR-021: Setup gate until the organisation is activated

Status: Accepted 2026-11-14 (Daniel Thompson-Yvetot), option "Server gate at activation". Drafted 2026-11-14 by lane `m4/setup-gate`. The readings marked "Reading" below are the lane's, pending Daniel.

## Context

- Daniel, 2026-11-14: "Until the tenant admin has set everything up (and created the other roles) nothing else is possible."
- He chose "Server gate at activation". The cell refuses every command, read and grant outside tenant onboarding until the organisation is activated.
- Activation means onboarding complete and then activated. Onboarding is complete when every step is validated and two tenant admins with verified identity exist (`tenant.complete`, SoD-07). Activation is requested by one tenant admin and approved by another (SoD-18).
- Before activation only tenant admins act. They may invite or grant only the roles onboarding needs: the second tenant admin and the Financial and Legal signatories (SoD-14, SoD-15).
- Everyone else, including signed-in accounts with no role and anonymous visitors, sees a plain notice that the organisation is still being set up. The open-calls pages have nothing to show before activation.
- The demo scenes are rebuilt through real onboarding and activation. They then only hold people who could exist in that state.

What the code did before this ADR:

- `fstp-tenant` already records the activation (`TenantState::is_active`, SoD-14 to SoD-18). No rule of the API core read it.
- A tenant admin could open a programme draft before onboarding finished. The authorisation reference said so in its reading of the sole tenant admin: "nothing in the spec makes a draft wait for onboarding to finish".
- Most demo scenes had no tenant part in their ledger at all. Their programme came straight from engine commands.

SPEC lines this ADR extends:

- `SPEC/02-domain/programme-creator.md`, "Tenant onboarding", the paragraph after the table: "Each step validates before the next opens. ... Activation is requested by one tenant admin and approved by another (SoD-18)." This ADR adds that nothing outside onboarding runs until that approval.
- The "Administrators" row of the same table names the roles onboarding grants: two tenant admins (SoD-07), a Financial signatory and a Legal signatory (SoD-14, SoD-15).
- `SPEC/02-domain/roles-and-sod.md`, "Granting roles" (O-47): a tenant admin grants Drafting, Judging and Operations roles in a programme. This ADR adds that no such grant runs before activation, since no programme exists then.
- R-TN-01: new tenants are set up through a guided onboarding flow.

## Decision

### The gate

The API core checks one rule for every call, after session strength (I-77) and the channel policy (I-84), before rate limits and before any dry run.

| Organisation | Caller | Admitted | Everything else |
| --- | --- | --- | --- |
| Active | Anyone | Every operation, judged by its own rules | None |
| Not active | Tenant admin | The onboarding set and the admin's own set below | Refused, rule `ADR-021` |
| Not active | Any other account | The account security set below | Refused, rule `ADR-021` |
| Not active | No account | Nothing | Refused, rule `ADR-021` |

An admitted operation is then judged by its own rules, as before.

- The organisation is active once a second tenant admin approved the activation request (`Activation::Active` in the ledger's tenant part). No command ends an activation, so the gate never closes again.
- The refusal has code `refused` and rule `ADR-021`, and it names no account. It is audited as every refusal is (I-24).
- The authorisation matrix classes the rule `ADR-021` as its own class, `Setup`.

### The onboarding set

Every `tenant.*` operation, and `admin.approvals`, `admin.approve_self_grant` and `admin.approve_recovery`.

- The grants among them are `tenant.invite_admin`, `tenant.grant_signatory` and `tenant.end_signatory`. These are the roles onboarding needs.
- `roles.grant`, `creator.invite` and every other grant are refused before activation.
- `admin.approve_break_glass` is outside the set. No content exists before activation, so there is nothing to break the glass to.

### The admin's own set

`me.roles`, `me.get_verification` and `me.begin_verification`, for a tenant admin only.

- Reading: an admin needs `me.roles` for the home page, which shows the onboarding links.
- Reading: completion needs two verified admins, so an admin must be able to begin and read their own verification.

### The account security set

`me.sessions`, `me.end_session` and `me.add_passkey`, for any account.

- Reading: R-LG-04 says "Users can see and end their sessions and linked devices." That requirement ranks above this decision, so these three stay open to every account. They show and change only the caller's own sessions and passkeys.

### Where the answer comes from

- The ledger's tenant part answers whether the organisation is active.
- Interim reading: a cell whose ledger holds no tenant part asks the `TenantConfig` port, as the admin set and P-74 already do. The port's default answer is "not active", so a port that does not know fails closed.
- The fake port of the test kit answers "active" by default. It stands for the attested tenant of the worlds from before the tenant part, as its attested admin set does. A test can set it to "not active".
- The e2e cell sets its port to "not active". So every demo scene must be built through real onboarding and activation, or it shows the notice.

### The authorisation reference

- The reference judges the gate first among the authorisation rules, after session strength and the channel rules, as the system does.
- A new state, `AwaitingActivation`, sits between the onboarding steps and the programme states: onboarding is complete, and the activation is not yet approved.
- The sole tenant admin exists only while onboarding runs. Completion needs a second admin, so no programme draft can have a sole admin as its builder any more.
- Every programme state now implies an active organisation. The harness worlds activate the organisation before the programme exists.

### The pages

- The home page (`/app/`) shows a plain notice to anyone the gate refuses: "This organisation is still being set up. Its pages open once a second tenant administrator has approved its activation."
- The open-calls page (`/app/calls`) shows the same notice, and no list.
- A refusal under `ADR-021` on any other page says the same in words, not as a rule id.
- The tenant admin's home page keeps its onboarding links.
- A `/p` page answers a plain HTML page instead of the JSON refusal: "This organisation's pages are not published yet." It keeps the refusal's status, 403, and links the platform stylesheets (decision 3 below; `fstp_web::shell::not_published`). The feed `/p/{slug}/feed.json` is data, so it keeps the JSON refusal.

### The demo

Every scene of the e2e cell starts from the tenant's provisioning and runs onboarding through the API core: the signatory grants, each step, `tenant.complete`, the activation request by the first admin and its approval by the second. The programme and its people come after that. The reset scene stays a cell at first start, before activation, with its first admin only.

## Consequences

- Nothing outside onboarding can happen in a cell whose organisation is not active. This holds on every channel, since the gate sits in the one dispatch.
- The authorisation matrices gain the `Setup` class and the `AwaitingActivation` state. Their onboarding cells now expect `Setup` wherever the gate refuses.
- The interim fake port answer keeps the test worlds from before the tenant part working. Those worlds never run in production, where provisioning writes the tenant part first.

## Decided by Daniel, 2026-11-15 (evening)

1. **Account security set.** Accepted. Before activation every signed-in account manages its own sessions and passkeys (R-LG-04). Everything else stays gated.
2. **Activation request.** Accepted. `tenant.request_activation` checks the completion conditions itself and does not ask for the `OnboardingCompleted` record.
3. **Public pages.** A `/p` page of an organisation that is not yet activated answers with a plain HTML page saying its pages are not published yet. It keeps the refusal's status code. It replaces the JSON refusal.

4. **Admin's own set and fail-closed port default.** Accepted on 2026-11-15 (late).

## Open points for Daniel

1. `SPEC/02-domain/roles-and-sod.md` lets a tenant admin record the manual identity check of another account. No API core operation does that yet. When one exists, it joins the onboarding set, since completion needs two verified admins.
2. Public MCP tools (I-87, R-MC-04) are refused before activation. No programme exists then, so there is nothing for them to show.
