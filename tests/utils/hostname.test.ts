import { describe, it, expect } from 'vitest';
import {
  stripIPv6Brackets,
  isIPHostname,
  isSpeedTestSite,
} from '../../src/utils/hostname.js';

describe('stripIPv6Brackets', () => {
  it('removes brackets from IPv6 literal', () => {
    expect(stripIPv6Brackets('[::1]')).toBe('::1');
    expect(stripIPv6Brackets('[2001:db8::1]')).toBe('2001:db8::1');
  });

  it('leaves non-bracketed input unchanged', () => {
    expect(stripIPv6Brackets('example.com')).toBe('example.com');
    expect(stripIPv6Brackets('1.2.3.4')).toBe('1.2.3.4');
    expect(stripIPv6Brackets('2001:db8::1')).toBe('2001:db8::1');
  });

  it('handles empty / whitespace', () => {
    expect(stripIPv6Brackets('')).toBe('');
    expect(stripIPv6Brackets('   ')).toBe('');
  });
});

describe('isIPHostname', () => {
  it('detects IPv4', () => {
    expect(isIPHostname('1.2.3.4')).toBe(true);
    expect(isIPHostname('192.168.1.1')).toBe(true);
    expect(isIPHostname('255.255.255.255')).toBe(true);
    expect(isIPHostname('0.0.0.0')).toBe(true);
  });

  it('detects IPv6', () => {
    expect(isIPHostname('::1')).toBe(true);
    expect(isIPHostname('2001:db8::1')).toBe(true);
    expect(isIPHostname('[::1]')).toBe(true); // bracketed
  });

  it('rejects domain names', () => {
    expect(isIPHostname('example.com')).toBe(false);
    expect(isIPHostname('www.google.com')).toBe(false);
  });

  it('rejects malformed IPs', () => {
    expect(isIPHostname('256.256.256.256')).toBe(false);
    expect(isIPHostname('1.2.3')).toBe(false);
    expect(isIPHostname('not-an-ip')).toBe(false);
  });
});

describe('isSpeedTestSite', () => {
  it('blocks Cloudflare speed test', () => {
    expect(isSpeedTestSite('speed.cloudflare.com')).toBe(true);
  });

  it('blocks subdomains of speed test', () => {
    expect(isSpeedTestSite('foo.speed.cloudflare.com')).toBe(true);
  });

  it('does not block similar but unrelated domains', () => {
    expect(isSpeedTestSite('cloudflare.com')).toBe(false);
    expect(isSpeedTestSite('speed.example.com')).toBe(false);
    expect(isSpeedTestSite('myspeed.cloudflare.com')).toBe(false);
  });
});
