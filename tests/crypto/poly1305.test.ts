import { describe, it, expect } from 'vitest';
import { poly1305Mac } from '../../src/crypto/poly1305.js';

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

describe('poly1305Mac', () => {
  // RFC 8439 §2.5.2 test vector
  it('produces correct tag for the "Cryptographic Forum Research Group" message', () => {
    const key = hexToBytes(
      '85d6be78 57556d33 7f4452fe 42d506a8 0103808a fb0db2fd 4abff6af 4149f51b'
    );
    const message = new TextEncoder().encode(
      'Cryptographic Forum Research Group'
    );

    const tag = poly1305Mac(key, message);
    expect(bytesToHex(tag)).toBe('a8061dc1305136c6c22b8baf0c0127a9');
  });

  it('produces correct tag for empty message (RFC 8439 Appendix A.3 test #1)', () => {
    // All-zero key → all-zero tag for empty message
    const key = new Uint8Array(32);
    const message = new Uint8Array(0);
    const tag = poly1305Mac(key, message);
    expect(bytesToHex(tag)).toBe('00000000000000000000000000000000');
  });

  it('produces a 16-byte tag', () => {
    const key = new Uint8Array(32);
    key.fill(0x42);
    const message = new TextEncoder().encode('Some message');
    const tag = poly1305Mac(key, message);
    expect(tag.length).toBe(16);
  });

  it('different messages produce different tags', () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const tag1 = poly1305Mac(key, new TextEncoder().encode('msg1'));
    const tag2 = poly1305Mac(key, new TextEncoder().encode('msg2'));
    expect(bytesToHex(tag1)).not.toBe(bytesToHex(tag2));
  });
});
