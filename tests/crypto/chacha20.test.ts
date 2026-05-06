import { describe, it, expect } from 'vitest';
import { chacha20Block, chacha20Xor } from '../../src/crypto/chacha20.js';

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

describe('chacha20Block', () => {
  // RFC 8439 §2.3.2 test vector
  it('produces correct keystream block (RFC 8439 §2.3.2)', () => {
    const key = hexToBytes(
      '00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f'
    );
    const nonce = hexToBytes('00 00 00 09 00 00 00 4a 00 00 00 00');
    const counter = 1;

    const block = chacha20Block(key, counter, nonce);
    const expected = hexToBytes(
      '10f1e7e4 d13b5915 500fdd1f a32071c4 c7d1f4c7 33c06803 0422aa9a c3d46c4e' +
      'd2826446 079faa09 14c2d705 d98b02a2 b5129cd1 de164eb9 cbd083e8 a2503c4e'
    );

    expect(bytesToHex(block)).toBe(bytesToHex(expected));
  });
});

describe('chacha20Xor', () => {
  // RFC 8439 §2.4.2 test vector
  it('encrypts the RFC 8439 sunscreen plaintext correctly', () => {
    const key = hexToBytes(
      '00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f'
    );
    const nonce = hexToBytes('00 00 00 00 00 00 00 4a 00 00 00 00');
    const plaintext = new TextEncoder().encode(
      "Ladies and Gentlemen of the class of '99: " +
      'If I could offer you only one tip for the future, sunscreen would be it.'
    );

    const ciphertext = chacha20Xor(key, nonce, plaintext);

    const expected = hexToBytes(
      '6e2e359a 2568f980 41ba0728 dd0d6981' +
      'e97e7aec 1d4360c2 0a27afcc fd9fae0b' +
      'f91b65c5 524733ab 8f593dab cd62b357' +
      '1639d624 e65152ab 8f530c35 9f0861d8' +
      '07ca0dbf 500d6a61 56a38e08 8a22b65e' +
      '52bc514d 16ccf806 818ce91a b7793736' +
      '5af90bbf 74a35be6 b40b8eed f2785e42' +
      '874d'
    );

    expect(bytesToHex(ciphertext)).toBe(bytesToHex(expected));
  });

  it('encryption then decryption yields original plaintext', () => {
    const key = hexToBytes(
      '0000000000000000000000000000000000000000000000000000000000000000'
    );
    const nonce = hexToBytes('000000000000000000000000');
    const plaintext = new TextEncoder().encode('Hello, world!');

    const ciphertext = chacha20Xor(key, nonce, plaintext);
    const decrypted = chacha20Xor(key, nonce, ciphertext);
    expect(new TextDecoder().decode(decrypted)).toBe('Hello, world!');
  });
});
