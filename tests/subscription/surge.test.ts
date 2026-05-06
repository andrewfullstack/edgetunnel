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

  it('injects ws=true and ws-path for trojan lines without ws config', () => {
    const input =
      '[General]\n' +
      'NodeA = trojan, host.example.com, 443, password=abc, sni=host.example.com, skip-cert-verify=false\n';
    const output = patchSurgeSubscription(input, 'https://x.com/sub', {
      skipCertVerify: false,
      fullNodePath: '/proxy',
      randomPath: false,
    });
    expect(output).toContain('ws=true');
    expect(output).toContain('ws-path=/proxy');
    expect(output).toContain('ws-headers=Host:"host.example.com"');
  });

  it('does not double-patch lines that already have ws=true', () => {
    const input =
      '[General]\n' +
      'NodeA = trojan, host.example.com, 443, password=abc, sni=host.example.com, ' +
      'ws=true, ws-path=/p, ws-headers=Host:"host.example.com"\n';
    const output = patchSurgeSubscription(input, 'https://x.com/sub', {
      skipCertVerify: false,
      fullNodePath: '/p',
    });
    expect(output).toContain('NodeA = trojan, host.example.com, 443');
    expect((output.match(/ws=true/g) || []).length).toBe(1);
  });

  it('preserves non-trojan lines as-is', () => {
    const input = '[General]\n[Rule]\nDOMAIN-SUFFIX,google.com,Proxy\n';
    const output = patchSurgeSubscription(input, 'https://x.com/sub', {});
    expect(output).toContain('DOMAIN-SUFFIX,google.com,Proxy');
  });

  it('handles CRLF line endings', () => {
    const input =
      '[General]\r\n' +
      'NodeA = trojan, host.example.com, 443, password=abc, sni=host.example.com, skip-cert-verify=false\r\n';
    const output = patchSurgeSubscription(input, 'https://x.com/sub', {
      skipCertVerify: false,
      fullNodePath: '/proxy',
    });
    expect(output).toContain('ws=true');
  });
});
