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
  'notice.switch': 'Demo sign-in. Switch person',
  'notice.switch_as': 'Demo sign-in: {name}. Switch person',
  'switch.title': 'Switch person',
  'switch.scene': 'Scene: {scene}. Choose a person to sign in as them in this tab. Their home page opens.',
  'switch.loading': 'Loading the people of this scene.',
  'switch.roles_after': ': ',
  'switch.current': 'Signed in now',
  'switch.signin': 'Sign in as {name}',
  'switch.busy': 'Signing in as {name}.',
  'switch.close': 'Close',
  'switch.list_failed': 'The people of this scene could not be read. Close this and try again, or use the demo page.',
  'switch.failed': 'The switch did not work. Close this and try again, or use the demo page.',
  'stepup.confirm': 'Confirm',
  'stepup.intro': 'Demo sign-in: confirm this action with the button. A real session confirms it with a passkey.',
  'stepup.failed': 'The confirmation was not recorded. Try again, or cancel.',
} as const;

/** The demo catalogue. */
export const DEMO_EN = { locale: 'en', messages: MESSAGES } as const;
