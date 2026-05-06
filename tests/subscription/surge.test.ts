import { describe, it, expect } from 'vitest';
import { patchSurgeSubscription } from '../../src/subscription/surge.js';

describe('patchSurgeSubscription', () => {
  it('prepends the #!MANAGED-CONFIG header', () => {
    const input = '[Proxy]\nfoo = direct\n';
    const output = patchSurgeSubscription(input, 'https://example.com/sub', {
      'preferredSub': { SUBUpdateTime: 6 },
    });
    expect(output).toMatch(/^#!MANAGED-CONFIG https:\/\/example\.com\/sub interval=21600/);
  });

  it('uses default 6 hours when SUBUpdateTime not specified', () => {
    const input = '[Proxy]\nx = direct\n';
    const output = patchSurgeSubscription(input, 'https://x.com/sub', {});
    expect(output).toContain('interval=21600');
  });

  it('replaces the first line and preserves the rest of the body', () => {
    // Matches original behaviour: header overwrites first line, remainder kept.
    const input = '[General]\n[Rule]\nDOMAIN-SUFFIX,google.com,Proxy\n';
    const output = patchSurgeSubscription(input, 'https://x.com/sub', {});
    expect(output).toMatch(/^#!MANAGED-CONFIG/);
    expect(output).toContain('[Rule]');
    expect(output).toContain('DOMAIN-SUFFIX,google.com,Proxy');
  });

  it('handles CRLF line endings', () => {
    const input = '[General]\r\nfoo = direct\r\n';
    const output = patchSurgeSubscription(input, 'https://x.com/sub', {});
    expect(output).toMatch(/^#!MANAGED-CONFIG/);
    expect(output).toContain('foo = direct');
  });
});
