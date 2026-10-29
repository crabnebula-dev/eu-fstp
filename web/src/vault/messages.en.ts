// The English catalogue of the vault origin's pages (R-NF-04, M3 design
// section 11.2). Every user-visible string of `web/src/vault` comes from
// here, keyed by id.
//
// TODO(legal): the consent and attestation statements below are interim
// wording, not approved text (L-02, ADR-009 "Write kinds"). Daniel
// supplies the approved wording.

/** The message ids of the vault pages. */
export type VaultMessageId = keyof typeof MESSAGES;

const MESSAGES = {
  'release.title': 'Identity release',
  'release.opening': 'Opening the identity release.',

  'write.title': 'Identity details',
  'write.intro':
    'What you enter here goes only to the identity vault of this tenant. The application does not see it.',
  'write.submit': 'Save',
  'write.saved': 'Saved. You can close this page.',

  'error.link': 'This link is incomplete or has expired. Ask the application for a new link.',
  'error.kind': 'This page cannot take this kind of entry yet. Ask the application team for help.',
  'error.refused':
    'The vault did not accept this entry. The link may have expired or been used. Ask the application for a new link.',
  'error.unavailable': 'The vault could not save this now. Try again later.',
  'error.unsupported': 'This browser cannot open this page. Try another browser.',

  'guardian.legend': 'Consent of a parent or guardian',
  'guardian.consent': 'I am a parent or legal guardian of the lead applicant, and I consent to this proposal.',
  'guardian.missing': 'Select the box to give your consent.',

  'adult.legend': 'Age confirmation',
  'adult.birth': 'Date of birth',
  'adult.birth.missing': 'Enter your date of birth.',
  'adult.confirm': 'I confirm that this date of birth is correct.',
  'adult.confirm.missing': 'Select the box to confirm.',
} as const;

/** The English catalogue. */
export const VAULT_EN = { locale: 'en', messages: MESSAGES } as const;
