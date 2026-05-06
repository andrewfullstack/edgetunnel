import { describe, it, expect } from 'vitest';
import { parseSocks5Auth } from '../../src/admin/proxy-resolver.js';

describe('parseSocks5Auth', () => {
  it('parses host:port without auth', () => {
    expect(parseSocks5Auth('1.2.3.4:1080')).toEqual({
      username: undefined,
      password: undefined,
      hostname: '1.2.3.4',
      port: 1080,
    });
  });

  it('uses default port when only host is given', () => {
    expect(parseSocks5Auth('proxy.example.com', 1080)).toEqual({
      username: undefined,
      password: undefined,
      hostname: 'proxy.example.com',
      port: 1080,
    });
  });

  it('parses user:pass@host:port', () => {
    expect(parseSocks5Auth('alice:secret@1.2.3.4:1080')).toEqual({
      username: 'alice',
      password: 'secret',
      hostname: '1.2.3.4',
      port: 1080,
    });
  });

  it('parses IPv6 with port', () => {
    expect(parseSocks5Auth('[2001:db8::1]:1080')).toEqual({
      username: undefined,
      password: undefined,
      hostname: '[2001:db8::1]',
      port: 1080,
    });
  });

  it('parses user:pass@[ipv6]:port', () => {
    expect(parseSocks5Auth('alice:secret@[::1]:1080')).toEqual({
      username: 'alice',
      password: 'secret',
      hostname: '[::1]',
      port: 1080,
    });
  });

  it('decodes base64-encoded auth', () => {
    // base64('alice:secret') = 'YWxpY2U6c2VjcmV0'
    const result = parseSocks5Auth('YWxpY2U6c2VjcmV0@1.2.3.4:1080');
    expect(result.username).toBe('alice');
    expect(result.password).toBe('secret');
    expect(result.hostname).toBe('1.2.3.4');
  });

  it('throws on auth without password', () => {
    expect(() => parseSocks5Auth('justuser@1.2.3.4:1080')).toThrow(
      /Invalid SOCKS auth format/
    );
  });

  it('throws on bare IPv6 without brackets', () => {
    expect(() => parseSocks5Auth('2001:db8::1:1080')).toThrow(
      /IPv6 must be wrapped in brackets/
    );
  });

  it('strips non-digits from port input (port becomes 0 if no digits)', () => {
    // Original behaviour: non-digit characters are stripped from port,
    // empty string converts to 0. This is a pre-existing quirk.
    const result = parseSocks5Auth('host:abc');
    expect(result.port).toBe(0);
  });

  it('handles %3D-encoded equals signs in base64 auth', () => {
    // 'YQ==' is base64 for 'a' (just 1 char user) - might not pass other validation
    // Use a base64 with padding: 'YWI6Yw==' = 'ab:c'
    const encoded = 'YWI6Yw%3D%3D';
    const result = parseSocks5Auth(`${encoded}@1.2.3.4:1080`);
    expect(result.username).toBe('ab');
    expect(result.password).toBe('c');
  });
});
