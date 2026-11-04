// The English catalogue of the cell origin's auth pages (R-NF-04, M3
// design section 11.2). Every user-visible string of `web/src/auth` comes
// from here, keyed by id. English is the M3 catalogue.

/** The message ids of the auth pages. */
export type AuthMessageId = keyof typeof MESSAGES;

const MESSAGES = {
  'error.cancelled': 'The passkey request was cancelled, or this device has no passkey for this site. Try again.',
  'error.unsupported': 'This browser cannot use passkeys on this site. Try another browser or device.',
  'error.refused': 'This was not accepted. Check the link, or start again.',
  'error.session': 'Your session has ended. Sign in again.',
  'error.unavailable': 'The service could not complete this now. Try again later.',
  'error.malformed': 'The reply could not be used. Try again.',
  'error.link': 'This link is incomplete. Open the whole link from your email.',

  'field.email': 'Email address',
  'field.email.missing': 'Enter your email address.',
  'field.email.invalid': 'Enter an email address in the form name@example.org.',

  'login.title': 'Sign in',
  'login.passkey.heading': 'Sign in with a passkey',
  'login.passkey': 'Sign in with a passkey',
  'login.magic.heading': 'Sign in with an email link',
  'login.magic.intro':
    'Applicant accounts can ask for a sign-in link when the programme allows it. Staff accounts sign in with a passkey.',
  'login.magic.submit': 'Send me a link',
  'login.magic.sent':
    'If this address may sign in with a link, a link is on its way. It works once and expires soon.',
  'login.more': 'Other options',
  'login.signup': 'Create an applicant account',
  'login.recovery': 'Recover your account',

  'signup.title': 'Create an applicant account',
  'signup.intro': 'Enter your email address. We send you a link to confirm it. Then you create a passkey.',
  'signup.submit': 'Continue',
  'signup.sent': 'Check your email. If this address can be used, a link to continue is on its way.',
  'signup.register.title': 'Create your passkey',
  'signup.register.intro': 'Your email address is confirmed. Create a passkey on this device to finish.',
  'signup.register': 'Create a passkey',

  'invite.title': 'Accept your invitation',
  'invite.intro': 'Create a passkey on this device to accept the invitation and sign in.',
  'invite.register': 'Create a passkey',

  'magic.title': 'Confirm sign-in',
  'magic.intro': 'Select the button to sign in with this link. The link works once.',
  'magic.confirm': 'Sign in',

  'recovery.title': 'Recover your account',
  'recovery.intro': 'Enter the email address of your account. We send you a link to continue.',
  'recovery.submit': 'Send a recovery link',
  'recovery.sent': 'If this address has an account, a recovery link is on its way.',
  'recovery.proof.intro': 'Select the button to continue the recovery of your account. The link works once.',
  'recovery.proof.confirm': 'Continue the recovery',
  'recovery.checking': 'Checking your link.',
  'recovery.path.second_admin':
    'Another tenant admin must approve this recovery. You then get an email with a link to finish.',
  'recovery.path.operator':
    'The platform operator must verify this recovery. You then get an email with a link to finish.',
  'recovery.path.host':
    'The administrator of your host must approve this recovery on the host console. You then get an email with a link to finish.',
  'recovery.complete.title': 'Create a new passkey',
  'recovery.complete.intro':
    'Creating a new passkey removes your old passkeys and ends every session of your account.',
  'recovery.complete': 'Create a new passkey',
  'recovery.approve.title': 'Approve an account recovery',
  'recovery.approve.intro':
    'Approve only when you have checked that the person who asks is the holder of the account.',
  'recovery.approve': 'Approve the recovery',
  'recovery.approved': 'The recovery is approved. The account holder can now finish it.',

  'account.title': 'Your account',
  // Interim, design section 15.0 (2026-10-31): the way back to the home page.
  'account.nav': 'Main navigation',
  'account.nav.home': 'Home: your work',
  'account.nav.assignments': 'My assignments',
  'account.nav.irc-cases': 'My cases',
  'account.nav.onboarding': 'Onboarding',
  'account.nav.creator': 'Programme set-up',
  'account.nav.approvals': 'Approvals',
  'account.nav.proposals': 'My applications',
  'account.nav.calls': 'Open calls',
  'account.nav.account': 'Account',
  'account.sessions': 'Sessions',
  'account.session.passkey': 'Signed in with a passkey',
  'account.session.magic_link': 'Signed in with an email link',
  'account.session.other': 'Signed in',
  'account.session.detail': 'Started {started}. Last used {last_used}.',
  'account.session.current': 'This session',
  'account.session.end': 'End this session',
  'account.session.signout': 'Sign out',
  'account.session.ended': 'The session is ended.',
  'account.devices': 'Passkeys',
  'account.device.label': 'Passkey ending {suffix}',
  'account.device.current': 'Used for this session',
  'account.device.remove': 'Remove passkey ending {suffix}',
  'account.device.removed': 'The passkey is removed.',
  'account.passkey.add': 'Add a passkey',
  'account.passkey.added': 'The passkey is added.',

  'stepup.title': 'Confirm with your passkey',
  'stepup.intro': 'This action needs a fresh confirmation with your passkey.',
  'stepup.confirm': 'Confirm',
  'stepup.cancel': 'Cancel',
} as const;

/** The English catalogue. */
export const AUTH_EN = { locale: 'en', messages: MESSAGES } as const;
