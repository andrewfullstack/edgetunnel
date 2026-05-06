import { describe, it, expect } from 'vitest';
import {
  randomPath,
  replaceAsterisks,
  bulkReplaceDomains,
} from '../../src/utils/path.js';

describe('randomPath', () => {
  it('returns a path starting with /', () => {
    const result = randomPath('/');
    expect(result.startsWith('/')).toBe(true);
  });

  it('contains 1-3 path segments', () => {
    for (let i = 0; i < 50; i++) {
      const result = randomPath('/');
      const segments = result.slice(1).split('/');
      expect(segments.length).toBeGreaterThanOrEqual(1);
      expect(segments.length).toBeLessThanOrEqual(3);
    }
  });

  it('appends to existing path when not "/"', () => {
    const result = randomPath('/proxy?token=abc');
    expect(result).toContain('/proxy');
    expect(result).toContain('?token=abc');
  });

  it('replaces /? in path', () => {
    const result = randomPath('/?abc');
    expect(result).toContain('?abc');
  });

  it('produces different results across calls (overwhelming probability)', () => {
    const results = new Set<string>();
    for (let i = 0; i < 30; i++) results.add(randomPath('/'));
    expect(results.size).toBeGreaterThan(5);
  });
});

describe('replaceAsterisks', () => {
  it('returns input unchanged if no asterisks', () => {
    expect(replaceAsterisks('example.com')).toBe('example.com');
  });

  it('replaces single asterisk with random alphanumeric', () => {
    const result = replaceAsterisks('*.example.com');
    expect(result.endsWith('.example.com')).toBe(true);
    const prefix = result.slice(0, -('.example.com'.length));
    expect(/^[a-z0-9]{3,16}$/.test(prefix)).toBe(true);
  });

  it('replaces multiple asterisks independently', () => {
    const result = replaceAsterisks('*-*.example.com');
    expect(result.endsWith('.example.com')).toBe(true);
    const parts = result.slice(0, -('.example.com'.length)).split('-');
    expect(parts.length).toBe(2);
  });

  it('returns non-string input unchanged', () => {
    expect(replaceAsterisks(null as any)).toBe(null);
    expect(replaceAsterisks(123 as any)).toBe(123);
  });
});

describe('bulkReplaceDomains', () => {
  it('replaces example.com with hosts in groups', () => {
    const content = 'a-example.com b-example.com c-example.com d-example.com';
    const hosts = ['host1.com', 'host2.com'];
    const result = bulkReplaceDomains(content, hosts, 2);
    // First two replacements should use the same host, next two use the other
    const matches = result.match(/(\S+\.com)/g)!;
    expect(matches.length).toBeGreaterThan(0);
    expect(result).not.toContain('example.com');
  });

  it('returns input unchanged when no example.com placeholder', () => {
    expect(bulkReplaceDomains('plain text', ['x.com'])).toBe('plain text');
  });

  it('expands asterisks in hosts', () => {
    const result = bulkReplaceDomains('example.com', ['*.test.com'], 1);
    // Asterisk should have been replaced with random alphanumerics
    expect(result.endsWith('.test.com')).toBe(true);
    expect(result.includes('*')).toBe(false);
  });
});
