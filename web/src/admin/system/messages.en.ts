// The English labels of the tenant admins' System page (ADR-028 record of
// lane L20). Every id starts with `system.`. Plain words for a reader who
// does not use a terminal: each problem says who acts and what to tell
// them. The commands quoted are for the host admin to type.

export const SYSTEM_LABELS: Readonly<Record<string, string>> = {
  "system.title": "System",
  "system.intro":
    "This page shows whether the platform runs well: its parts, its backups, its certificates, its admins and its mail. Green needs nothing. Amber needs attention soon. Red needs attention now.",
  "system.overall.green": "Everything is running.",
  "system.overall.amber": "Something needs attention soon. The rows below say what.",
  "system.overall.red": "Something needs attention now. The rows below say what.",
  "system.overall.unknown": "Some facts are not known yet. The rows below say why.",
  "system.light.green": "Fine",
  "system.light.amber": "Attention",
  "system.light.red": "Problem",
  "system.light.unknown": "Not known",
  "system.actor.host": "Who acts: the host admin. Tell them:",
  "system.actor.you": "Who acts: you.",
  "system.parts.heading": "Is everything running?",
  "system.backups.heading": "Backups and certificates",
  "system.admins.heading": "Admins",
  "system.next.heading": "Next on the host",
  "system.refresh": "Check again",
  "system.checked": "Checked just now.",
  "system.back": "Back to home",

  // ADR-012 record of lane m10/declared-restore: the audit log findings.
  "system.findings.heading": "Audit log findings",
  "system.findings.intro":
    "The audit log records every change and cannot be changed without notice. Each finding below says that recorded entries are missing. Acknowledge each one once you have read it. An acknowledged finding stays on this page and in the audit log.",
  "system.findings.open": "Needs acknowledgement",
  "system.findings.acknowledged": "Acknowledged",
  "system.findings.acknowledge": "Acknowledge",
  "system.findings.done": "Acknowledged. The finding stays in the audit log.",
  "system.findings.lost_in_restore.app":
    "The platform was restored to an earlier time. Entries {from} to {to} of its audit log were lost, with the changes they recorded. Ask the people who worked in that window to check their work.",
  "system.findings.lost_in_restore.vault":
    "The identity vault was restored to an earlier time. Entries {from} to {to} of its audit log were lost, with the identity changes they recorded.",
  "system.findings.possible_deletion.app":
    "Entry {from} of the platform's audit log is missing. The platform may have stopped while saving it, or it was deleted. Ask the host admin which.",
  "system.findings.possible_deletion.vault":
    "Entry {from} of the identity vault's audit log is missing. The vault may have stopped while saving it, or it was deleted. Ask the host admin which.",

  "system.age.minutes": "{n} minutes",
  "system.age.hours": "{n} hours",
  "system.age.days": "{n} days",

  "system.name.report": "Host report",
  "system.name.cell": "Platform",
  "system.name.vault": "Identity vault",
  "system.name.services": "Databases, key store and witness",
  "system.name.edge": "Public address",
  "system.name.mail": "Outgoing mail",
  "system.name.backups": "Backups",
  "system.name.archive": "Backup of recent changes",
  "system.name.witness": "Copy of the audit witness",
  "system.name.drill": "Restore test",
  "system.name.keys": "Key copy",
  "system.name.snapshots": "Key store snapshots",
  "system.name.certificates": "Certificates",

  "system.row.report.fresh": "The host reported {age} ago.",
  "system.row.report.old":
    "The host last reported {age} ago, so the rows below may be out of date. The host normally reports every 15 minutes.",
  "system.row.report.not_configured": "This platform gets no report from its host yet.",
  "system.row.report.missing": "The host has not written its report yet.",
  "system.row.report.unreadable": "The host's report could not be read.",
  "system.row.cell.running": "The platform is running. You are using it now.",
  "system.row.vault.answers": "The identity vault answers.",
  "system.row.vault.silent":
    "The identity vault does not answer. Identity checks and new sign-ups wait until it does.",
  "system.row.services.running": "The databases, the key store and the witness run.",
  "system.row.services.down": "A database, the key store or the witness has stopped.",
  "system.row.services.unknown": "Not known until the host reports.",
  "system.row.edge.running": "The public address works and leads to this platform.",
  "system.row.edge.down": "The public address has stopped. People outside cannot reach the platform.",
  "system.row.edge.mismatch":
    "The public address still uses an older certificate. The night renewal fixes this by itself.",
  "system.row.edge.route_unknown": "The host could not check the public address.",
  "system.row.edge.unknown": "Not known until the host reports.",
  "system.row.mail.works": "Outgoing mail works. Invitations and sign-in links reach people.",
  "system.row.mail.fails": "Outgoing mail does not work. Invitations and sign-in links cannot be sent.",
  "system.row.mail.not_configured": "No mail relay is set up, so the platform cannot send mail.",
  "system.row.backups.fresh": "The last backup ran {age} ago. Backups run every night.",
  "system.row.backups.late": "The last backup ran {age} ago. Backups should run every night.",
  "system.row.backups.none": "No backup has run yet.",
  "system.row.backups.not_configured": "Backups are not set up. A lost server would lose all data.",
  "system.row.backups.unknown": "Not known until the host reports.",
  "system.row.archive.fresh": "Recent changes are saved off the host as they happen. The last one was saved {age} ago.",
  "system.row.archive.none_yet": "Recent changes are saved off the host as they happen. None needed saving yet.",
  "system.row.archive.late":
    "Recent changes wait longer than usual to be saved off the host. A lost server now would lose them.",
  "system.row.archive.failing":
    "Recent changes are not reaching the backup store. A lost server now would lose every change since the last one saved.",
  "system.row.archive.off": "Recent changes are saved off the host once backups are set up.",
  "system.row.archive.unknown": "Not known: the host could not read it. Running fstp-admin status shows why.",
  "system.row.witness.fresh": "The audit witness's records are copied off the host every minute. The last full copy was {age} ago.",
  "system.row.witness.late":
    "The audit witness's records have not been copied off the host for over 10 minutes. A lost server now would lose their newest history.",
  "system.row.witness.failing":
    "The audit witness's records are not reaching the backup store. A lost server now would lose the proof of what happened since the last copy.",
  "system.row.witness.off": "The audit witness's records are copied off the host once backups are set up.",
  "system.row.witness.unknown": "Not known: no copy has run yet, or the host could not read it. Running fstp-admin status shows why.",
  "system.row.drill.passed":
    "The backups were last restored and checked in a test copy on {date}. Restoring took about {minutes} minutes. This test runs every month.",
  "system.row.drill.late": "The backups were last restored in a test on {date}. The test should run every month.",
  "system.row.drill.never": "The backups have never been restored in a test yet.",
  "system.row.drill.off": "The backups are tested every month once backups are set up.",
  "system.row.drill.unknown": "Not known until the host reports.",
  "system.row.drill.failed_space": "The last restore test could not run: the host lacks free disk space for the test copy.",
  "system.row.drill.failed_restore": "The last restore test failed: the backup could not be fetched or opened.",
  "system.row.drill.failed_recovery": "The last restore test failed: the restored database did not start.",
  "system.row.drill.failed_database": "The last restore test failed: the restored platform database is missing or does not answer.",
  "system.row.drill.failed_keystore": "The last restore test failed: the restored keys do not open.",
  "system.row.drill.failed_cleanup": "The last restore test passed its checks, but its test copy could not be removed.",
  "system.row.drill.failed_witness":
    "The last restore test failed: the copies of the audit witness could not be fetched, did not load, or differ from the live witness.",
  "system.row.keys.copied": "The keys were last copied off the host on {date}.",
  "system.row.keys.never":
    "The keys have never been copied off the host. Without a copy, the backups cannot be opened after a lost server.",
  "system.row.keys.before_erasure":
    "The keys were last copied off the host on {date}, before the erasure of {erased}. That copy still holds the erased data's key.",
  "system.row.keys.unknown": "Not known until the host reports.",
  "system.row.keys.custodian_down":
    "The second custodian does not answer, or a key guard is still to be replaced. Erasures wait until it answers.",
  "system.row.keys.custodian_unpaired": "No second custodian guards the key copies yet.",
  "system.row.keys.custodian_copy_owed":
    "The second custodian answers, but its fresh copy of the keys did not arrive after the last erasure. The host retries every ten minutes.",
  "system.row.snapshots.fresh": "The key stores of the platform and the vault were last saved off the host {age} ago. This runs every day.",
  "system.row.snapshots.late": "A key store was last saved off the host {age} ago. This should run every day.",
  "system.row.snapshots.none": "A key store has not been saved off the host yet.",
  "system.row.snapshots.failed": "The last daily save of a key store off the host failed.",
  "system.row.snapshots.failed_busy":
    "The last daily save of a key store off the host did not run: an erasure was running at the time, or no backup store is set up.",
  "system.row.snapshots.failed_image": "The last daily save of a key store off the host failed: the key store could not be read.",
  "system.row.snapshots.failed_database":
    "The last daily save of a key store off the host failed: the database did not accept a write.",
  "system.row.snapshots.failed_custody":
    "The last daily save of a key store off the host failed: the key custody refused, or the snapshot key did not open.",
  "system.row.snapshots.failed_upload": "The last daily save of a key store off the host failed: the upload to the object store failed.",
  "system.row.snapshots.failed_fetch":
    "The last daily save of a key store off the host failed: the saved copy could not be read back from the object store.",
  "system.row.snapshots.failed_open":
    "The last daily save of a key store off the host failed: the saved copy did not check out or open when read back.",
  "system.row.snapshots.failed_check":
    "The last daily save of a key store off the host failed: the saved keys did not open under the current key.",
  "system.row.snapshots.failed_pointer":
    "The last daily save of a key store off the host failed: the object store did not take the note that names the newest copy.",
  "system.row.snapshots.off": "The key stores are saved off the host once backups are set up.",
  "system.row.snapshots.unknown": "Not known until the host reports.",
  "system.row.certificates.fine":
    "Certificates renew by themselves at night. The next renewal is due in {due} days.",
  "system.row.certificates.ending":
    "A certificate ends in {days} days and the night renewal has not renewed it.",
  "system.row.certificates.self_signed":
    "The public certificate is made by the host itself, so browsers warn people who open the platform.",
  "system.row.certificates.unknown": "Not known until the host reports.",

  "system.tell.report_setup":
    "Please run fstp-admin setup once more. It tells the platform where the host report is.",
  "system.tell.report_now": "Please run fstp-admin report, and check that its timer fstp-admin-report runs.",
  "system.tell.report_timer":
    "Please run fstp-admin status. The timer fstp-admin-report seems to have stopped.",
  "system.tell.start": "Please run fstp-admin status. It names what stopped, then fstp-admin start starts it.",
  "system.tell.renew": "Please run fstp-admin renew.",
  "system.tell.status": "Please run fstp-admin status and read its route line.",
  "system.tell.mail":
    "Please check the mail relay in /etc/fstp/fstp.json and its password in /etc/fstp/mail.password, then run fstp-admin status.",
  "system.tell.mail_setup": "Please add the mail relay to /etc/fstp/fstp.json, then run fstp-admin setup.",
  "system.tell.configure_backups":
    "Please add an object store under backup in /etc/fstp/fstp.json, then run fstp-admin setup.",
  "system.tell.backup": "Please run fstp-admin backup, and check that its nightly timer runs.",
  "system.tell.wal_archive":
    "Please run fstp-admin status. It names the database whose changes are not saved; read that database's log, fix the object store or its keys, then run fstp-admin status again.",
  "system.tell.witness_copy":
    "Please run fstp-admin witness-copy. It says why the witness records do not reach the backup store, often the object store or its keys. Then run fstp-admin status.",
  "system.tell.drill":
    "Please run fstp-admin drill. If it fails, it names the step, and its log is in admin/logs/fstp-admin.log.",
  "system.tell.custodian":
    "Please check that the second custodian machine is on and reachable, then run fstp-admin status. Erasures wait until it answers.",
  "system.tell.custodian_copy":
    "Please run fstp-admin status, check the free space on the second custodian machine, and read the log of fstp-keyd there.",
  "system.tell.pair_custodian":
    "Please pair the second custodian with fstp-admin pair-custodian, then run fstp-admin setup.",
  "system.tell.copy_keys":
    "Please run fstp-admin backup-keys to a USB stick. It holds the passphrases too, so keep it somewhere safe, away from the host and the custodian machine.",
  "system.tell.copy_keys_again":
    "Please run fstp-admin backup-keys to a USB stick again, then destroy the older copy. An erasure took place since the last copy.",
  "system.tell.keystore_snapshot":
    "Please run fstp-admin status. It names the key store snapshot that failed or is late; read that service's log, then run fstp-admin start.",
  "system.tell.public_certificate":
    "Please get a certificate for the domain, name it under tls in /etc/fstp/fstp.json, then run fstp-admin renew.",

  "system.next.run_setup": "The host admin finishes the set-up with fstp-admin setup.",
  "system.next.start_service": "The host admin starts what stopped with fstp-admin start.",
  "system.next.backup_key":
    "The host admin checks the backup keys: they changed outside the set-up, so backups stopped. If nobody changed them, the host may be broken into.",
  "system.next.custodian": "The host admin checks the second custodian: erasures wait until it answers.",
  "system.next.pair_custodian": "The host admin pairs the second custodian with fstp-admin pair-custodian.",
  "system.next.renew_route": "The host admin runs fstp-admin renew to update the public address.",
  "system.next.renew": "The host admin runs fstp-admin renew: a certificate ends soon.",
  "system.next.public_certificate": "The host admin gets a public certificate for the domain.",
  "system.next.configure_backups": "The host admin sets up backups.",
  "system.next.wal_archive": "The host admin checks why recent changes are not reaching the backup store.",
  "system.next.witness_copy": "The host admin checks why the audit witness's records are not reaching the backup store.",
  "system.next.backup": "The host admin runs a backup with fstp-admin backup.",
  "system.next.restore_drill": "The host admin tests the backups with fstp-admin drill.",
  "system.next.custodian_copy": "The host admin checks why the fresh key copy did not reach the second custodian.",
  "system.next.keystore_snapshot":
    "The host admin checks why a key store snapshot failed or is late, then runs fstp-admin start.",
  "system.next.web_admins":
    "You: sign in with your passkey and invite the second admin on the onboarding checklist.",
  "system.next.verify_admins":
    "The host admin checks each admin's ID document in person and records it with fstp-admin verify.",
  "system.next.copy_keys": "The host admin copies the keys off the host with fstp-admin backup-keys.",

  "system.admins.intro": "Each admin must have their identity checked in person by the host admin.",
  "system.admins.row.verified": "{handle}: identity checked.",
  "system.admins.row.unverified": "{handle}: identity not checked yet.",
  "system.admins.none": "No admin is listed yet.",
  "system.admins.checklist": "Open the onboarding checklist for the next steps",
  "system.admins.unavailable": "The list of admins could not be read just now.",
};
