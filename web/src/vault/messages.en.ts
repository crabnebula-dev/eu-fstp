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

  'bank.legend': 'Bank details for payments of this grant',
  'bank.holder': 'Account holder name',
  'bank.holder.missing': 'Enter the account holder name, up to 140 characters.',
  'bank.iban': 'IBAN',
  'bank.iban.invalid': 'Enter a valid IBAN, such as DE89 3704 0044 0532 0130 00.',
  'bank.hold':
    'Payments wait until the finance team verifies these details and the hold period has passed. This applies to every change, the first entry included.',
  'bank.verify.legend': 'Verify the latest bank details',
  'bank.verify.method': 'Document checked',
  'bank.method.bank_letter': 'Letter from the bank',
  'bank.method.bank_statement': 'Bank statement',
  'bank.check.holder_matches': 'The holder on the document matches the grantee.',
  'bank.check.iban_matches': 'The IBAN on the document matches the entered IBAN.',
  'bank.verify.missing': 'Select at least one check you made.',
  'bank.verify.resolve': 'Resolve the open dispute instead of verifying',
  'bank.dispute.legend': 'Dispute the bank details',
  'bank.dispute.confirm': 'The bank details on file are wrong or were changed without my consent. Freeze payments.',
  'bank.dispute.missing': 'Select the box to open the dispute.',

  'hardship.legend': 'Hardship evidence',
  'hardship.statement': 'Describe the hardship',
  'hardship.statement.missing': 'Describe the hardship, up to 4000 characters.',
  'hardship.saved': 'Saved. Your evidence reference is {ref}. Enter it in your hardship request.',
  'hardship.verify.legend': 'Verify hardship evidence',
  'hardship.verify.evidence': 'Evidence reference',
  'hardship.verify.evidence.missing': 'Enter the evidence reference from the request.',
  'hardship.verify.confirm': 'I checked this evidence and it supports the hardship request.',
  'hardship.verify.confirm.missing': 'Select the box to confirm.',
} as const;

/** The English catalogue. */
export const VAULT_EN = { locale: 'en', messages: MESSAGES } as const;
