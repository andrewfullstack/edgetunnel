// AES-GCM AEAD wrappers around Web Crypto API.

/**
 * Import a raw AES-GCM key into a CryptoKey object.
 */
export async function importAesGcmKey(
  key: Uint8Array,
  usages: ReadonlyArray<'encrypt' | 'decrypt' | 'sign' | 'verify'>
): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, usages as any);
}

/**
 * AES-GCM encrypt with explicit IV and additional authenticated data (AAD).
 * Returns ciphertext concatenated with the 16-byte authentication tag.
 */
export async function aesGcmEncrypt(
  cryptoKey: CryptoKey,
  iv: Uint8Array,
  plaintext: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData, tagLength: 128 },
      cryptoKey,
      plaintext
    )
  );
}

/**
 * AES-GCM decrypt. Throws if the authentication tag is invalid.
 */
export async function aesGcmDecrypt(
  cryptoKey: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData, tagLength: 128 },
      cryptoKey,
      ciphertext
    )
  );
}
