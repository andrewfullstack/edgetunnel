import { describe, it, expect } from 'vitest';
import { normalizeRequestUrl, toArray } from '../../src/utils/url.js';

describe('normalizeRequestUrl', () => {
  it('removes backslash escapes', () => {
    expect(normalizeRequestUrl('https://example.com/foo\\bar')).toBe('https://example.com/foobar');
    expect(normalizeRequestUrl('https://example.com/foo%5Cbar')).toBe('https://example.com/foobar');
    expect(normalizeRequestUrl('https://example.com/foo%5cbar')).toBe('https://example.com/foobar');
  });

  it('replaces first %3F with ? when no real ? exists', () => {
    expect(normalizeRequestUrl('https://example.com/path%3Fquery=1')).toBe(
      'https://example.com/path?query=1'
    );
  });

  it('does not replace %3F when ? already present', () => {
    expect(normalizeRequestUrl('https://example.com/path?already=1&also=%3F')).toBe(
      'https://example.com/path?already=1&also=%3F'
    );
  });

  it('preserves the URL fragment', () => {
    expect(normalizeRequestUrl('https://example.com/path%3Fa=1#fragment')).toBe(
      'https://example.com/path?a=1#fragment'
    );
  });

  it('only replaces in the path/query part, not the fragment', () => {
    expect(normalizeRequestUrl('https://example.com/path#hash%3Fval')).toBe(
      'https://example.com/path#hash%3Fval'
    );
  });

  it('returns input unchanged when no normalisation needed', () => {
    expect(normalizeRequestUrl('https://example.com/clean?path=1')).toBe(
      'https://example.com/clean?path=1'
    );
  });
});

describe('toArray', () => {
  it('splits a comma-separated string', () => {
    expect(toArray('a,b,c')).toEqual(['a', 'b', 'c']);
  });

  it('treats tabs, quotes, newlines as delimiters', () => {
    expect(toArray('a\tb\rc\n"d"\'e\'')).toEqual(['a', 'b', 'c', 'd', 'e']);
  });

  it('collapses consecutive delimiters', () => {
    expect(toArray('a,,,b,,c')).toEqual(['a', 'b', 'c']);
  });

  it('strips leading and trailing delimiters', () => {
    expect(toArray(',a,b,')).toEqual(['a', 'b']);
  });

  it('handles a mix of delimiters', () => {
    expect(toArray('1.2.3.4,5.6.7.8\n9.10.11.12')).toEqual(['1.2.3.4', '5.6.7.8', '9.10.11.12']);
  });
});
