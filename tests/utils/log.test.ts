import { describe, it, expect } from 'vitest';
import { maskSensitive } from '../../src/utils/log.js';

describe('maskSensitive', () => {
  it('masks middle of long strings', () => {
    expect(maskSensitive('1234567890', 3, 2)).toBe('123*****90');
  });

  it('returns input unchanged if too short', () => {
    expect(maskSensitive('abc', 3, 2)).toBe('abc'); // length 3, prefix+suffix=5
    expect(maskSensitive('abcde', 3, 2)).toBe('abcde');
  });

  it('handles password-like strings', () => {
    const password = 'SuperSecret123Password';
    const masked = maskSensitive(password);
    expect(masked.startsWith('Sup')).toBe(true);
    expect(masked.endsWith('rd')).toBe(true);
    expect(masked).toContain('*');
  });

  it('uses custom prefix/suffix lengths', () => {
    expect(maskSensitive('1234567890', 1, 1)).toBe('1********0');
    expect(maskSensitive('1234567890', 4, 4)).toBe('1234**7890');
  });

  it('returns falsy / non-string input unchanged', () => {
    expect(maskSensitive('')).toBe('');
    expect(maskSensitive(null as any)).toBe(null);
    expect(maskSensitive(undefined as any)).toBe(undefined);
    expect(maskSensitive(123 as any)).toBe(123);
  });

  it('preserves total length', () => {
    const input = 'abcdefghijklmnop';
    const masked = maskSensitive(input);
    expect(masked.length).toBe(input.length);
  });
});
