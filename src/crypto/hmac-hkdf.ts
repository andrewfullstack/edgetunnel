// HMAC, HKDF, and TLS 1.2 PRF, built on Web Crypto API.
// Used by the TLS 1.2/1.3 handshake key schedule and Shadowsocks.

import { concatBytes, tlsBytes, uint16be, textEncoder } from '../utils/bytes.js';

export type HashName = 'SHA-256' | 'SHA-384' | 'SHA-512';

/**
 * Length in bytes of a hash function's output.
 */
export const hashByteLength = (hash: string): number =>
  hash === 'SHA-512' ? 64 : hash === 'SHA-384' ? 48 : 32;

/**
 * HMAC-SHA-X. Imports the key and signs in a single call.
 */
export async function hmac(
  hash: HashName,
  key: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array<ArrayBuffer>> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash },
    false,
    ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, data));
}

/**
 * Plain hash digest, returned as a Uint8Array.
 */
export async function digestBytes(
  hash: HashName,
  data: Uint8Array
): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(hash, data));
}

/**
 * TLS 1.2 PRF (P_hash). RFC 5246 §5.
 */
export async function tls12Prf(
  secret: Uint8Array,
  label: string,
  seed: Uint8Array,
  length: number,
  hash: HashName = 'SHA-256'
): Promise<Uint8Array> {
  const labelSeed = concatBytes(textEncoder.encode(label), seed);
  let output = new Uint8Array(0);
  let currentA = labelSeed;
  while (output.length < length) {
    currentA = await hmac(hash, secret, currentA);
    const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
    output = concatBytes(output, block);
  }
  return output.slice(0, length);
}

/**
 * HKDF-Extract (RFC 5869).
 * Produces a pseudo-random key (PRK) from input key material (IKM).
 */
export async function hkdfExtract(
  hash: HashName,
  salt: Uint8Array | null,
  inputKeyMaterial: Uint8Array
): Promise<Uint8Array> {
  if (!salt || !salt.length) {
    salt = new Uint8Array(hashByteLength(hash));
  }
  return hmac(hash, salt, inputKeyMaterial);
}

/**
 * Internal HKDF-Expand (RFC 5869).
 */
async function hkdfExpand(
  hash: HashName,
  secret: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  const hashLen = hashByteLength(hash);
  const roundCount = Math.ceil(length / hashLen);
  let output = new Uint8Array(0);
  let previousBlock = new Uint8Array(0);
  for (let round = 1; round <= roundCount; round++) {
    previousBlock = await hmac(
      hash,
      secret,
      concatBytes(previousBlock, info, new Uint8Array([round]))
    );
    output = concatBytes(output, previousBlock);
  }
  return output.slice(0, length);
}

/**
 * HKDF-Expand-Label as defined in RFC 8446 §7.1 (TLS 1.3 key schedule).
 *
 * HkdfLabel = struct {
 *   uint16 length;
 *   opaque label<7..255> = "tls13 " + Label;
 *   opaque context<0..255> = Context;
 * }
 */
export async function hkdfExpandLabel(
  hash: HashName,
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number
): Promise<Uint8Array> {
  const fullLabel = textEncoder.encode('tls13 ' + label);
  const info: Uint8Array = tlsBytes(
    uint16be(length),
    fullLabel.length,
    fullLabel,
    context.length,
    context
  );
  return hkdfExpand(hash, secret, info, length);
}
