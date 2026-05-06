// ECDH key agreement helpers using Web Crypto API.
// Supports X25519 and NIST P-curves (P-256, P-384, P-521).

export type CurveName = 'X25519' | 'P-256' | 'P-384' | 'P-521';

export interface KeyShare {
  keyPair: CryptoKeyPair;
  publicKeyRaw: Uint8Array;
}

/**
 * Generate an ephemeral ECDH key pair and return the raw public key
 * for inclusion in TLS ClientHello / ServerHello key_share extension.
 */
export async function generateKeyShare(group: CurveName = 'P-256'): Promise<KeyShare> {
  const algorithm: any =
    group === 'X25519' ? { name: 'X25519' } : { name: 'ECDH', namedCurve: group };
  const keyPair = (await crypto.subtle.generateKey(algorithm, true, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const publicKeyRaw = (await crypto.subtle.exportKey(
    'raw',
    keyPair.publicKey
  )) as ArrayBuffer;
  return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) };
}

/**
 * Derive the shared secret from your private key + peer's raw public key.
 * Returns the raw bits (suitable for input into HKDF).
 */
export async function deriveSharedSecret(
  privateKey: CryptoKey,
  peerPublicKey: Uint8Array,
  group: CurveName = 'P-256'
): Promise<Uint8Array> {
  const algorithm: any =
    group === 'X25519' ? { name: 'X25519' } : { name: 'ECDH', namedCurve: group };
  const peerKey = await crypto.subtle.importKey('raw', peerPublicKey, algorithm, false, []);
  const bits = group === 'P-384' ? 384 : group === 'P-521' ? 528 : 256;
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: algorithm.name, public: peerKey } as any,
      privateKey,
      bits
    )
  );
}
