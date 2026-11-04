// The English catalogue of the demo modules (R-NF-04). Test only: the
// test cell `fstp-e2e-cell` serves these modules on a cell started with
// `--demo-signin`, and no shipped cell serves them (layering rule A9).

/** The message ids of the demo modules. */
export type DemoMessageId = keyof typeof MESSAGES;

const MESSAGES = {
  'signin.title': 'Demo sign-in',
  'signin.busy': 'Signing you in.',
  'signin.refused': 'This sign-in link is used, expired or not valid. Open a new one from the demo page.',
  'signin.missing': 'This sign-in link has no token. Open the whole link from the demo page.',
  'notice.text': 'Demo sign-in',
  'stepup.confirm': 'Confirm',
  'stepup.intro': 'Demo sign-in: confirm this action with the button. A real session confirms it with a passkey.',
  'stepup.failed': 'The confirmation was not recorded. Try again, or cancel.',
} as const;

/** The demo catalogue. */
export const DEMO_EN = { locale: 'en', messages: MESSAGES } as const;
