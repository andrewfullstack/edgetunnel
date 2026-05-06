import { describe, it, expect } from 'vitest';
import { sha224 } from '../../src/crypto/sha224.js';

describe('sha224', () => {
  // Test vectors from RFC 3874 / FIPS 180-4 Appendix A
  it('hashes empty string', () => {
    expect(sha224('')).toBe(
      'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'
    );
  });

  it('hashes "abc"', () => {
    expect(sha224('abc')).toBe(
      '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'
    );
  });

  it('hashes 56-byte FIPS test vector', () => {
    expect(
      sha224('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')
    ).toBe('75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525');
  });

  it('produces 56-character lowercase hex output', () => {
    const hash = sha224('test password');
    expect(hash.length).toBe(56);
    expect(/^[0-9a-f]{56}$/.test(hash)).toBe(true);
  });

  it('handles UTF-8 input', () => {
    // Just check that non-ASCII doesn't crash and produces consistent output
    const hash1 = sha224('你好');
    const hash2 = sha224('你好');
    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(56);
  });

  it('produces different hashes for different inputs', () => {
    expect(sha224('password1')).not.toBe(sha224('password2'));
  });

  it('matches the Trojan protocol expectation (56 ASCII hex chars)', () => {
    // In the Trojan protocol, the first 56 bytes sent over TLS are
    // the ASCII hex of SHA-224(password). Verify length matches what
    // the parser expects.
    const hash = sha224('SuperSecret123');
    expect(hash.length).toBe(56);
    const asciiBytes = new TextEncoder().encode(hash);
    expect(asciiBytes.length).toBe(56);
  });
});
