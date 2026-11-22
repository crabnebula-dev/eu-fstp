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
  "system.name.keys": "Key copy",
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
  "system.row.keys.copied": "The keys were last copied off the host on {date}.",
  "system.row.keys.never":
    "The keys have never been copied off the host. Without a copy, the backups cannot be opened after a lost server.",
  "system.row.keys.before_erasure":
    "The keys were last copied off the host on {date}, before the erasure of {erased}. That copy still holds the erased data's key.",
  "system.row.keys.unknown": "Not known until the host reports.",
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
  "system.tell.copy_keys":
    "Please run fstp-admin backup-keys to a USB stick, and keep the passphrases apart from it.",
  "system.tell.copy_keys_again":
    "Please run fstp-admin backup-keys to a USB stick again, then destroy the older copy. An erasure took place since the last copy.",
  "system.tell.public_certificate":
    "Please get a certificate for the domain, name it under tls in /etc/fstp/fstp.json, then run fstp-admin renew.",

  "system.next.run_setup": "The host admin finishes the set-up with fstp-admin setup.",
  "system.next.start_service": "The host admin starts what stopped with fstp-admin start.",
  "system.next.renew_route": "The host admin runs fstp-admin renew to update the public address.",
  "system.next.renew": "The host admin runs fstp-admin renew: a certificate ends soon.",
  "system.next.public_certificate": "The host admin gets a public certificate for the domain.",
  "system.next.configure_backups": "The host admin sets up backups.",
  "system.next.backup": "The host admin runs a backup with fstp-admin backup.",
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
