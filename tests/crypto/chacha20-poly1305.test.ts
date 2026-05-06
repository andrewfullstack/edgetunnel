import { describe, it, expect } from 'vitest';
import {
  chacha20Poly1305Encrypt,
  chacha20Poly1305Decrypt,
} from '../../src/crypto/chacha20-poly1305.js';

const hexToBytes = (hex: string): Uint8Array => {
  const cleaned = hex.replace(/\s+/g, '');
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(cleaned.substr(i * 2, 2), 16);
  }
  return out;
};

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');

describe('chacha20Poly1305Encrypt', () => {
  // RFC 8439 §2.8.2 test vector
  it('produces correct ciphertext+tag for the RFC 8439 test vector', () => {
    const key = hexToBytes(
      '80818283 84858687 88898a8b 8c8d8e8f 90919293 94959697 98999a9b 9c9d9e9f'
    );
    const nonce = hexToBytes('07 00 00 00 40 41 42 43 44 45 46 47');
    const aad = hexToBytes('50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7');
    const plaintext = new TextEncoder().encode(
      "Ladies and Gentlemen of the class of '99: " +
      'If I could offer you only one tip for the future, sunscreen would be it.'
    );

    const result = chacha20Poly1305Encrypt(key, nonce, plaintext, aad);

    // Expected ciphertext + tag from RFC 8439
    const expectedCt = hexToBytes(
      'd31a8d34 648e60db 7b86afbc 53ef7ec2' +
      'a4aded51 296e08fe a9e2b5a7 36ee62d6' +
      '3dbea45e 8ca96712 82fafb69 da92728b' +
      '1a71de0a 9e060b29 05d6a5b6 7ecd3b36' +
      '92ddbd7f 2d778b8c 9803aee3 28091b58' +
      'fab324e4 fad67594 5585808b 4831d7bc' +
      '3ff4def0 8e4b7a9d e576d265 86cec64b' +
      '6116'
    );
    const expectedTag = hexToBytes('1ae10b59 4f09e26a 7e902ecb d0600691');

    const expected = new Uint8Array(expectedCt.length + expectedTag.length);
    expected.set(expectedCt);
    expected.set(expectedTag, expectedCt.length);

    expect(bytesToHex(result)).toBe(bytesToHex(expected));
  });
});

describe('chacha20Poly1305Decrypt', () => {
  it('round-trip: encrypt then decrypt recovers plaintext', () => {
    const key = new Uint8Array(32);
    key.fill(0x42);
    const nonce = new Uint8Array(12);
    nonce.fill(0x01);
    const aad = new Uint8Array([1, 2, 3, 4]);
    const plaintext = new TextEncoder().encode('Hello, ChaCha20-Poly1305!');

    const ciphertext = chacha20Poly1305Encrypt(key, nonce, plaintext, aad);
    const decrypted = chacha20Poly1305Decrypt(key, nonce, ciphertext, aad);
    expect(new TextDecoder().decode(decrypted)).toBe('Hello, ChaCha20-Poly1305!');
  });

  it('rejects ciphertext with tampered tag', () => {
    const key = new Uint8Array(32);
    const nonce = new Uint8Array(12);
    const aad = new Uint8Array(0);
    const plaintext = new TextEncoder().encode('hello');

    const ciphertext = chacha20Poly1305Encrypt(key, nonce, plaintext, aad);
    // Flip a bit in the tag (last 16 bytes)
    ciphertext[ciphertext.length - 1] ^= 1;

    expect(() => chacha20Poly1305Decrypt(key, nonce, ciphertext, aad)).toThrow(
      'ChaCha20-Poly1305 authentication failed'
    );
  });

  it('rejects ciphertext with tampered AAD', () => {
    const key = new Uint8Array(32);
    const nonce = new Uint8Array(12);
    const plaintext = new TextEncoder().encode('hello');

    const ciphertext = chacha20Poly1305Encrypt(key, nonce, plaintext, new Uint8Array([1, 2, 3]));
    expect(() =>
      chacha20Poly1305Decrypt(key, nonce, ciphertext, new Uint8Array([1, 2, 4]))
    ).toThrow('ChaCha20-Poly1305 authentication failed');
  });

  it('rejects too-short ciphertext', () => {
    const key = new Uint8Array(32);
    const nonce = new Uint8Array(12);
    expect(() =>
      chacha20Poly1305Decrypt(key, nonce, new Uint8Array(8), new Uint8Array(0))
    ).toThrow('Ciphertext too short');
  });
});
