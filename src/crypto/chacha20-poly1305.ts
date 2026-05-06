// ChaCha20-Poly1305 AEAD (RFC 8439).
// Composes the ChaCha20 stream cipher and Poly1305 MAC into an authenticated
// encryption scheme.

import { concatBytes } from '../utils/bytes.js';
import { chacha20Block, chacha20Xor } from './chacha20.js';
import { poly1305Mac } from './poly1305.js';

/**
 * Encrypt plaintext using ChaCha20-Poly1305 with the given key, 12-byte
 * nonce, and additional authenticated data (AAD).
 *
 * Returns ciphertext concatenated with the 16-byte Poly1305 tag.
 */
export function chacha20Poly1305Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  additionalData: Uint8Array
): Uint8Array {
  const polyKey = chacha20Block(key, 0, nonce).slice(0, 32);
  const ciphertext = chacha20Xor(key, nonce, plaintext);

  // Construct MAC-input as defined in RFC 8439 §2.8.
  const aadPad = (16 - (additionalData.length % 16)) % 16;
  const ctPad = (16 - (ciphertext.length % 16)) % 16;
  const macData = new Uint8Array(
    additionalData.length + aadPad + ciphertext.length + ctPad + 16
  );
  macData.set(additionalData, 0);
  macData.set(ciphertext, additionalData.length + aadPad);

  const lenView = new DataView(
    macData.buffer,
    additionalData.length + aadPad + ciphertext.length + ctPad
  );
  lenView.setBigUint64(0, BigInt(additionalData.length), true);
  lenView.setBigUint64(8, BigInt(ciphertext.length), true);

  const tag = poly1305Mac(polyKey, macData);
  return concatBytes(ciphertext, tag);
}

/**
 * Decrypt and authenticate. Throws "ChaCha20-Poly1305 authentication failed"
 * if the tag does not match.
 */
export function chacha20Poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array,
  additionalData: Uint8Array
): Uint8Array {
  if (ciphertextWithTag.length < 16) throw new Error('Ciphertext too short');
  const tag = ciphertextWithTag.slice(-16);
  const ciphertext = ciphertextWithTag.slice(0, -16);

  const polyKey = chacha20Block(key, 0, nonce).slice(0, 32);

  const aadPad = (16 - (additionalData.length % 16)) % 16;
  const ctPad = (16 - (ciphertext.length % 16)) % 16;
  const macData = new Uint8Array(
    additionalData.length + aadPad + ciphertext.length + ctPad + 16
  );
  macData.set(additionalData, 0);
  macData.set(ciphertext, additionalData.length + aadPad);

  const lenView = new DataView(
    macData.buffer,
    additionalData.length + aadPad + ciphertext.length + ctPad
  );
  lenView.setBigUint64(0, BigInt(additionalData.length), true);
  lenView.setBigUint64(8, BigInt(ciphertext.length), true);

  const expectedTag = poly1305Mac(polyKey, macData);

  // Constant-time tag comparison.
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= tag[i] ^ expectedTag[i];
  if (diff !== 0) throw new Error('ChaCha20-Poly1305 authentication failed');

  return chacha20Xor(key, nonce, ciphertext);
}
