// The email address check of the copy request and the team invitations.

/**
 * An email address as these forms take it: one `@`, no white space, a
 * dot in the domain, at most 254 characters. The cell checks it again
 * before anything is sent (M6).
 */
const EMAIL = /^[^\s@]{1,64}@[^\s@.]+(?:\.[^\s@.]+)+$/;

/** Whether `v` passes the form check of an email address. */
export function isEmail(v: string): boolean {
  return v.length <= 254 && EMAIL.test(v);
}
