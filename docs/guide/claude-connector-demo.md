# Connect Claude to the demo cell

This guide connects Claude Code, or a claude.ai custom connector, to the MCP server of the demo cell. Claude then acts as one synthetic person of the demo, within that person's roles.

The demo cell is `fstp-e2e-cell`, a test-only binary. It holds synthetic data only. Its demo sign-in and its demo step-up exist only when it starts with `--demo-signin`.

The design is in `SPEC/03-architecture/mcp-server.md` and ADR-013. The record of lane mcp-demo in ADR-013 lists what Claude Code sends and what the cell does with it.

## 1. Start the demo cell

Run this from the repository root:

```sh
FSTP_DEMO_PUBLIC_ORIGIN=http://localhost:8640 tools/demo/run.sh start
```

The script builds the pages and the cell, and starts it with `--demo-signin`. The public origin makes the cell name `http://localhost:8640` as its own origin.

Claude Code sends a token request over plain `http` only to `localhost`, `127.0.0.1` or `::1`. The default origin `http://a.fstp.localhost:8640` is refused by Claude Code for that reason.

To start the binary by hand instead, build the pages once first. `tools/demo/run.sh start` does that, and `tools/demo/run.sh stop` stops its cell.

```sh
cargo build -p fstp-api-testkit --bin fstp-e2e-cell
target/debug/fstp-e2e-cell --port 8640 --web web --demo-signin \
  --public-origin http://localhost:8640
```

The demo page is at <http://127.0.0.1:8641/demo>. It lists the scene, its people and their sign-in buttons.

Seed the scene you want to show:

- `tools/demo/run.sh seed applicant OPEN_CALL` gives an active programme. Its call 1 is open. Its call 2, "SuperSAFE open call 2027", is approved and not yet published.
- `tools/demo/run.sh seed setup` gives a draft programme that programme manager M1 builds. The script prints its programme number.

A new scene ends every agent connection. Claude Code then asks you to authenticate again.

## 2. Sign in as the demo person

Pick **Programme manager M1**. M1 may use the creator tools and the call tools, which are the tools this demo shows.

On the demo page, choose "Sign in as Programme manager M1". Do this in the browser that will open for the connection. The consent step needs that sign-in.

## 3. Add the server to Claude Code

```sh
claude mcp add --transport http fstp-demo http://localhost:8640/mcp
```

Then authenticate. In a Claude Code session, run `/mcp`, choose `fstp-demo` and choose to authenticate. From a terminal, `claude mcp login fstp-demo` does the same.

The browser opens the cell's consent page. It shows:

- the agent's name, marked as unverified;
- the host the browser returns to, which is `localhost` for Claude Code;
- each scope Claude Code asks for, in plain words.

Choose **Approve**. Connecting an agent links a new device, so the cell asks for a step-up. In the demo, it is one **Confirm** button. Without `--demo-signin` that button does not exist, and a passkey is needed.

The browser then returns to Claude Code. `claude mcp list` shows `fstp-demo` as connected.

## 4. Try it

Ask Claude to use the tools. For example:

- "List the open calls of the tenant."
- "Read the draft of programme 1." In the set-up scene, use the programme number the seed printed.
- "Save the field value ... in the draft of programme N."
- "Draft a call of programme 1." Then "Edit call N."
- "Prepare the publication of call 2."

Claude Code lists only the tools that M1's roles and the approved scopes allow. Each call runs through the same API core as the web pages, with the same checks.

## 5. Confirm the prepared action in the platform

Publishing a call is high risk. Claude can prepare it, but cannot complete it. The tool answers `awaiting_confirmation` with a `confirm_path` such as `/app/pending/<id>`.

Open that path in the browser where M1 is signed in. The mailbox at `/app/mailbox` lists it too. M1 confirms there, with the step-up.

## What Claude can and cannot do

- Claude acts as M1 and can do no more than M1's roles allow.
- Claude holds only the scopes approved on the consent page.
- Reads and drafts complete through MCP.
- High-risk actions are prepare-only. Each waits for M1's confirmation in the platform.
- Claude never receives identity attributes, bank details or vault contents.
- The tool names, descriptions and schemas are fixed by the platform.
- Revoking the agent, or a new scene, ends the connection at once.

## Optional: claude.ai through an HTTPS tunnel

A claude.ai connector reaches the cell from the internet, so it needs an `https` origin. Any HTTPS tunnel to the loopback port works. One example is `cloudflared tunnel --url http://localhost:8640`, a tool outside this repository.

1. Start the tunnel first, and note its `https` origin.
2. Start the cell with that origin:

   ```sh
   FSTP_DEMO_PUBLIC_ORIGIN=https://<tunnel host> tools/demo/run.sh start
   ```

3. Open the demo page on <http://127.0.0.1:8641/demo>. Its sign-in buttons now point at the tunnel origin. Sign in as M1.
4. In claude.ai, add a custom connector with the URL `https://<tunnel host>/mcp`.
5. Approve on the consent page and confirm the step-up, as above.

This path is not tested yet. The ADR-013 record lists three open points. If the connection fails, start the cell with `--log-requests <file>` to see each request and its status.

The tunnel puts the cell on the internet while it runs. The data is synthetic. The demo page stays on loopback, so no one else can get a sign-in link. Stop the tunnel when the demo ends.

## Troubleshooting

- **"Refusing to send credentials to non-https token endpoint".** The cell runs on `a.fstp.localhost`. Restart it with the `localhost` public origin.
- **"OAuth error: invalid_client" after a restart.** The cell forgot the client that Claude Code registered. Run `claude mcp logout fstp-demo`, then authenticate again.
- **"Sign in first".** No demo session exists in this browser. Sign in on the demo page, return to the tab and approve again.
- **"Request expired".** A consent lives ten minutes and is used once. Start the authentication again from Claude Code.
- **Every call answers 401 after a new scene.** The scene ended the connection. Authenticate again.
- **What the client sent.** `--log-requests <file>` logs each request's method, path, MCP headers and status. It never logs a query, body, cookie or token.
