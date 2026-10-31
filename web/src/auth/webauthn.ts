// The browser half of the WebAuthn ceremonies (M3 design sections 8.1,
// 8.3, 8.4 and 11.2, ADR-008).
//
// Options from the cell go through the browser's
// `parseRequestOptionsFromJSON` and `parseCreationOptionsFromJSON`, and
// the result comes back through `toJSON()`, so these pages hold no
// WebAuthn parser. The base64url members of `toJSON()` become the
// lowercase hex members the cell takes (lane w3ar body forms).
//
// The cell fixes the RP id, the challenge and user verification in its
// options and checks each in the reply. Nothing here relaxes them.

import { base64urlToHex, isHex } from './encoding.js';
import { record } from './api.js';

/** Why a ceremony did not complete. Each code has a catalogue message. */
export type FailureCode =
  | 'cancelled'
  | 'unsupported'
  | 'refused'
  | 'session'
  | 'unavailable'
  | 'malformed'
  | 'link';

/** A ceremony or call that did not complete. */
export class Failure extends Error {
  readonly code: FailureCode;

  constructor(code: FailureCode) {
    super(code);
    this.name = 'AuthFailure';
    this.code = code;
  }
}

/** The failure of a reply status that is not 2xx. */
export function failureOf(status: number): Failure {
  if (status === 401) return new Failure('session');
  if (status === 400 || status === 403 || status === 404 || status === 409 || status === 410) {
    return new Failure('refused');
  }
  return new Failure('unavailable');
}

/** A challenge id and the WebAuthn options it carries, from the cell. */
export interface Options {
  readonly challengeId: string;
  readonly publicKey: Readonly<Record<string, unknown>>;
}

/** Reads `{challenge_id, public_key}` from an options reply. */
export function optionsOf(body: unknown): Options {
  const o = record(body);
  const publicKey = record(o?.['public_key']);
  const challengeId = o?.['challenge_id'];
  if (publicKey === null || !isHex(challengeId, 16, 16)) {
    throw new Failure('malformed');
  }
  return { challengeId, publicKey };
}

/** The hex members of an assertion, as the cell's assertion body names them. */
export interface AssertionBody {
  readonly authenticator_data: string;
  readonly client_data_json: string;
  readonly credential_id: string;
  readonly signature: string;
}

/** The hex members of a new credential, as the ceremony bodies name them. */
export interface RegistrationBody {
  readonly attestation_object: string;
  readonly client_data_json: string;
  readonly credential_id: string;
}

function available(): void {
  if (
    typeof PublicKeyCredential !== 'function' ||
    typeof PublicKeyCredential.parseRequestOptionsFromJSON !== 'function' ||
    typeof PublicKeyCredential.parseCreationOptionsFromJSON !== 'function' ||
    typeof navigator.credentials?.get !== 'function'
  ) {
    throw new Failure('unsupported');
  }
}

/** The failure of a browser ceremony error. */
function ceremonyFailure(e: unknown): Failure {
  if (e instanceof Failure) return e;
  const name = e instanceof Error ? e.name : '';
  if (name === 'NotAllowedError' || name === 'AbortError') return new Failure('cancelled');
  if (name === 'NotSupportedError' || name === 'SecurityError') return new Failure('unsupported');
  if (name === 'InvalidStateError') return new Failure('refused');
  return new Failure('malformed');
}

function member(o: Readonly<Record<string, unknown>> | null, name: string): string {
  try {
    return base64urlToHex(o?.[name]);
  } catch {
    throw new Failure('malformed');
  }
}

/** Runs `navigator.credentials.get` for the cell's request options. */
export async function assertion(publicKey: Readonly<Record<string, unknown>>): Promise<AssertionBody> {
  try {
    available();
    const options = PublicKeyCredential.parseRequestOptionsFromJSON(
      publicKey as unknown as PublicKeyCredentialRequestOptionsJSON,
    );
    const c = await navigator.credentials.get({ publicKey: options });
    if (!(c instanceof PublicKeyCredential)) {
      throw new Failure('malformed');
    }
    const j = record(c.toJSON() as unknown);
    const response = record(j?.['response']);
    return {
      authenticator_data: member(response, 'authenticatorData'),
      client_data_json: member(response, 'clientDataJSON'),
      credential_id: member(j, 'rawId'),
      signature: member(response, 'signature'),
    };
  } catch (e) {
    throw ceremonyFailure(e);
  }
}

/** Runs `navigator.credentials.create` for the cell's creation options. */
export async function registration(
  publicKey: Readonly<Record<string, unknown>>,
): Promise<RegistrationBody> {
  try {
    available();
    const options = PublicKeyCredential.parseCreationOptionsFromJSON(
      publicKey as unknown as PublicKeyCredentialCreationOptionsJSON,
    );
    const c = await navigator.credentials.create({ publicKey: options });
    if (!(c instanceof PublicKeyCredential)) {
      throw new Failure('malformed');
    }
    const j = record(c.toJSON() as unknown);
    const response = record(j?.['response']);
    return {
      attestation_object: member(response, 'attestationObject'),
      client_data_json: member(response, 'clientDataJSON'),
      credential_id: member(j, 'rawId'),
    };
  } catch (e) {
    throw ceremonyFailure(e);
  }
}
