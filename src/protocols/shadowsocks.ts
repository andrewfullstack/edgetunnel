// Shadowsocks AEAD (legacy) helpers.
//
// Implements key derivation (EVP_BytesToKey-style MD5 chain) and the AEAD
// packet framing using AES-GCM. Only the AES-128/256-GCM ciphers are
// supported here because Workers' Web Crypto doesn't expose ChaCha20-Poly1305.

import { concatByteArrays } from '../utils/bytes.js';
import { SS_SUBKEY_INFO, type ShadowsocksCipher } from '../constants.js';

const ssTextEncoder = new TextEncoder();

/** Module-level cache of master keys by (keyLen:password). */
const masterKeyCache = new Map<string, Promise<Uint8Array>>();

/**
 * Increment a little-endian nonce counter in-place.
 * Used after each AEAD encrypt/decrypt to ensure unique nonces per chunk.
 */
export function ssIncrementNonce(counter: Uint8Array): void {
  for (let i = 0; i < counter.length; i++) {
    counter[i] = (counter[i] + 1) & 0xff;
    if (counter[i] !== 0) return;
  }
}

/**
 * Derive the SS master key from the password using EVP_BytesToKey
 * (chained MD5 digests of password || prev).
 *
 * Cached because the same password+keyLen combination is used for every
 * connection of the same user.
 */
export async function ssDeriveMasterKey(
  passwordText: string,
  keyLen: number
): Promise<Uint8Array> {
  const cacheKey = `${keyLen}:${passwordText}`;
  const cached = masterKeyCache.get(cacheKey);
  if (cached) return cached;

  const task = (async () => {
    const pwBytes = ssTextEncoder.encode(passwordText || '');
    let prev = new Uint8Array(0);
    let result = new Uint8Array(0);
    while (result.byteLength < keyLen) {
      const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
      input.set(prev, 0);
      input.set(pwBytes, prev.byteLength);
      prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
      result = concatByteArrays(result, prev);
    }
    return result.slice(0, keyLen);
  })();

  masterKeyCache.set(cacheKey, task);
  try {
    return await task;
  } catch (err) {
    masterKeyCache.delete(cacheKey);
    throw err;
  }
}

/**
 * Derive the per-session AEAD key using HKDF-SHA1 with the salt sent by
 * the client and the fixed info string "ss-subkey".
 */
export async function ssDeriveSessionKey(
  config: ShadowsocksCipher,
  masterKey: Uint8Array,
  salt: Uint8Array,
  usages: ReadonlyArray<'encrypt' | 'decrypt'>
): Promise<CryptoKey> {
  const hmacOpts = { name: 'HMAC', hash: 'SHA-1' } as const;
  const saltKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
  const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltKey, masterKey));
  const prkKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);

  const subKey = new Uint8Array(config.keyLen);
  let prev = new Uint8Array(0);
  let written = 0;
  let counter = 1;
  while (written < config.keyLen) {
    const input = concatByteArrays(prev, SS_SUBKEY_INFO, new Uint8Array([counter]));
    prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkKey, input));
    const copyLen = Math.min(prev.byteLength, config.keyLen - written);
    subKey.set(prev.subarray(0, copyLen) as Uint8Array, written);
    written += copyLen;
    counter += 1;
  }
  return crypto.subtle.importKey(
    'raw',
    subKey,
    { name: 'AES-GCM', length: config.aesLength },
    false,
    usages as any
  );
}

/**
 * Encrypt one SS frame. Increments nonceCounter in-place after.
 * The IV is a copy of the nonce taken before incrementing.
 */
export async function ssAeadEncrypt(
  cryptoKey: CryptoKey,
  nonceCounter: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const iv = nonceCounter.slice();
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    cryptoKey,
    plaintext
  );
  ssIncrementNonce(nonceCounter);
  return new Uint8Array(ct);
}

/**
 * Decrypt one SS frame. Increments nonceCounter in-place after.
 * Throws on AEAD authentication failure.
 */
export async function ssAeadDecrypt(
  cryptoKey: CryptoKey,
  nonceCounter: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  const iv = nonceCounter.slice();
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    cryptoKey,
    ciphertext
  );
  ssIncrementNonce(nonceCounter);
  return new Uint8Array(pt);
}
