# EU FSTP programmes for Claude

This plugin lets Claude help you set up and run FSTP funding programmes on an EU FSTP cell. Claude works through the cell's MCP server, with your own account and roles.

Claude can draft a programme, fill its fields, check its validation report, draft calls and follow the timeline. It cannot complete anything binding or high-risk on its own. Activation, publication, invitations, role grants and tenant settings are prepared by Claude and confirmed by you in the platform, often with a passkey.

## What you need

- An account on an EU FSTP cell with a programme staff or tenant admin role.
- The cell's MCP URL, which is `https://<your cell domain>/mcp`.
- Claude Code, or a claude.ai plan that allows custom connectors.

## Claude Code

```sh
claude plugin marketplace add crabnebula-dev/eu-fstp
claude plugin install fstp-programmes@eu-fstp
```

Claude Code asks for the cell MCP URL when you enable the plugin. Then run `/mcp`, choose `fstp` and sign in. The cell shows a consent page that lists every permission. Approving it needs a passkey step-up.

Ask Claude, for example: "Set up a new programme from the Horizon Europe funder profile" or "Draft the second call of programme 12 and prepare it for approval".

## claude.ai

1. Go to Customize, then Connectors, and add a custom connector with the cell MCP URL. Choose automatic registration.
2. Build the skill archive from a checkout of this repository:

   ```sh
   cd integrations/claude/fstp-programmes/skills
   zip -r programme-setup.zip programme-setup/
   ```

3. Upload `programme-setup.zip` under Customize, then Skills, and turn it on.

## Trying it on the demo cell

The demo cell runs on your own machine with synthetic data. Follow `docs/guide/claude-connector-demo.md`. When the plugin asks for the URL, enter `http://localhost:8640/mcp`.

## Confirming prepared actions

Every `fstp_prepare_*` tool leaves a pending action. Open the platform, go to your pending actions and confirm or discard each one. Pending actions expire after 24 hours. Some steps need a second person: a programme is activated by a tenant admin who did not build it, and a call is approved by someone who did not draft it.

## Revoking access

Access tokens live 10 minutes and refresh within your session's lifetime. To end Claude's access at once, sign it out in Claude Code with `claude mcp logout fstp`, or remove the claude.ai connector. The platform's API also revokes a connected agent at once through `POST /api/v1/me/agents/{client}/revocation`. A page for this in the web interface is not built yet.
