# Run a production cell and connect Claude

Two people run a host. The **technical admin** uses a terminal over SSH, and parts 1 to 4 are for them. The **programme manager** uses only the web app and Claude, and part 5 is for them.

**A pilot is not a release.** Label every pilot cell as a pilot to its users. A release still waits for the Mythos confirmation of the Tier B formats crates (I-74) and the legal wording marked `TODO(legal)`. The per-service detail is in `docs/guide/production-reference.md`. The design is ADR-028.

## 1. What you need

- A Linux host in the EU with PostgreSQL 16 installed (the distribution package is enough) and systemd.
- A domain, for example `grants.example.eu`, and `id.grants.example.eu`, both pointing at the host, with TCP port 443 open.
- A public certificate covering both names, for example from certbot. Without one, setup makes a self-signed one, which browsers refuse.
- An account on a mail relay for sign-in mail. Put its password in `/etc/fstp/mail.password`.
- A second machine that stays on: the **second custodian**. It guards the copies of the keys (part 2a). A small Linux machine with systemd is enough. The pilot host must reach it on TCP port 7460.
- Optional: a versioned object storage bucket for backups and the daily key snapshots, with its two key files in `/etc/fstp/s3-access-key-id` and `/etc/fstp/s3-secret-access-key`.

Install the release: the binaries into `/usr/local/bin`, and its `migrations/` and `web/` directories into `/usr/share/fstp`.

## 2. Set up

```sh
sudo fstp-admin setup
```

The first time, it asks four questions: the domain, the first admin's email, the mail relay and its user name. It writes them to `/etc/fstp/fstp.json`, the host's only configuration file. Add more there when you need it:

```json
{
  "domain": "grants.example.eu",
  "operator_email": "admin@example.eu",
  "mail": {"relay": "smtp.example.eu", "username": "cell"},
  "tls": {"cert": "/etc/letsencrypt/live/grants.example.eu/fullchain.pem",
          "key": "/etc/letsencrypt/live/grants.example.eu/privkey.pem"},
  "backup": {"endpoint": "s3.gra.io.cloud.ovh.net", "region": "gra", "bucket": "fstp-backups"}
}
```

Setup creates the databases, keys, certificates and services, starts everything, and adds the cell's route. If a step fails, it says what to fix. Fix it and run `setup` again: it skips what is done.

At the end it tells you two things:

- **The invitation.** `/root/fstp-first-admin.token` holds two lines. Give each line to the first admin through a different channel, for example one by phone and one by chat. They open `https://<domain>/auth/invite#<line 1><line 2>`. Then delete the file.
- **The passphrases.** Copy the four files in `/etc/fstp/keyd` into a password manager, off the host, once.

## 2a. Pair the second custodian

Decided by Daniel on 2026-11-23: the second custodian is required. Each key copy is sealed to a key that lives only on that machine. Every erasure replaces that key there, so an old copy no longer opens anything erased since. Pair it once:

1. On the pilot host: `sudo fstp-admin pair-custodian custodian.example.eu`, with the custodian's host name or address. It writes `/root/fstp-custodian.pair` and adds `"custodian"` to `/etc/fstp/fstp.json` itself.
2. Copy that one file to the custodian machine, for example with `scp`. It holds a private key, so copy it nowhere else.
3. On the custodian machine, with `fstp-keyd` and `fstp-admin` installed in `/usr/local/bin`: `sudo fstp-admin custodian /root/fstp-custodian.pair`. It sets up and starts `fstp-keyd-custodian`, then deletes the file.
4. Back on the pilot host: `sudo fstp-admin setup`. It links every key custody entry to the custodian and says `checked  second custodian linked`.

While the custodian does not answer, erasures wait: the data is unreadable on the host at once, but the erasure is reported complete only once the custodian answered. `status` and the page **System** then show the custodian in red. Keep the custodian on.

If the pilot host is lost, set up the new host, run steps 1 to 4 again with the same custodian, then restore. If the custodian machine is lost, pair a new one the same way, then run `fstp-admin backup-keys` at once: the old copies no longer open. The custodian's certificate lasts two years, and `status` asks for a new pairing a month before it ends.

## 3. Open the organisation

`fstp-admin status` walks both of you through this and names who acts next. The steps (ADR-026 record of lane L18):

1. **Web, first admin.** Open the invitation link, enrol a passkey, and invite the second admin by email on "Onboarding summary".
2. **Web, second admin.** Open the mailed link within 72 hours and enrol a passkey.
3. **Host admin.** Check both admins' ID documents in person, then run `sudo fstp-admin verify`. It lists both accounts and asks for each one's document type, names, date of birth and issuing state. It never asks for the document number.
4. **Web, both admins.** Grant each other Financial and Legal signatory, save each onboarding step, then one asks to open the organisation and the other approves. The checklist on "Onboarding summary" shows what is left.

`setup` recorded the agreement versions `1,1,1` (SaaS terms, data processing agreement, sub-processor list). If the tenant accepted others, set `"agreements"` in `fstp.json` before the first `setup`.

## 4. Every day: `fstp-admin status`

`status` shows every service, the route, the certificates, the backups, the daily key snapshots and the admins on one screen, and ends with one line `Next:`, the single most urgent thing to do and who does it. Do that, then run `status` again. Exit status 0 means healthy, 3 means a problem.

The web admin sees the same on the page **System** (`https://<domain>/app/admin/system`, linked from the home page): one green, amber or red line per part, and for each problem who acts and what to tell the host admin. The host writes the facts behind it to `/var/lib/fstp/status/host.json` every 15 minutes (timer `fstp-admin-report`), and after `status`, `backup`, `renew` and `backup-keys`. The file holds no secret and no personal data. If the page says the host report is old, run `fstp-admin report` and check the timer (ADR-028 record of lane L20).

## 5. Other commands

| Command | When |
| --- | --- |
| `fstp-admin verify` | Step 3 of part 3. `fstp-admin admins` only lists the accounts |
| `fstp-admin backup-keys /media/usb/fstp-keys` | Once after setup and pairing, and after each erasure. Keep the stick apart from the passphrases. It needs the second custodian, which seals each copy |
| `fstp-admin pair-custodian <host>` | Once, part 2a. Again after the loss of either machine, and when `status` asks |
| `fstp-admin backup` | A backup now. A timer runs it daily |
| `fstp-admin restore` | After data loss. It restores both databases from their newest backups, then the cell's and the vault's keys |
| `fstp-admin renew` | Only when `status` asks. A daily timer renews certificates and updates the route |
| `fstp-admin report` | Rarely. It writes the status file of the page System. A timer runs it every 15 minutes |
| `fstp-admin erase-identity <account>` | When a person's identity must be erased from the vault |
| `fstp-admin stop` and `start` | Around host maintenance |
| `fstp-admin route add <file>`, `remove <cell>`, `list` | Rarely. Setup and renew keep the cell's own route current |

Exit status: 0 done, 1 failed (the message says what to fix), 2 a wrong configuration or argument, 4 waits on a part not built yet. The second custodian is required (part 2a). Its escrow of the backup group key is described in `docs/guide/production-reference.md`.

## 6. Connect Claude (programme manager)

You need an account with a programme staff or tenant admin role, and a passkey. The MCP URL is `https://<domain>/mcp`.

1. In Claude Code: `claude plugin marketplace add crabnebula-dev/eu-fstp`, then `claude plugin install fstp-programmes@eu-fstp`, and give it the MCP URL. On claude.ai, add a custom connector with the same URL.
2. Run `/mcp`, choose `fstp` and sign in. The consent page lists each permission in plain words. Choose **Approve** and confirm with your passkey.
3. Ask Claude, for example: "Set up a new programme draft called Green Valleys 2027". Nothing changes until you open the pending action under `/app/pending/` in the platform and confirm it.

To end Claude's access, run `claude mcp logout fstp` or remove the connector. Recovering your account also ends it (I-79).

## Checked by

`crates/fstp-celltest/tests/l19_admin_setup_e2e.rs` runs `fstp-admin setup` on a fresh host over local PostgreSQL and the real binaries, then `status`, `verify` of the first admin, a second `setup` and `route add`. The tests listed in `docs/guide/production-reference.md` cover each service.
