import { describe, it, expect } from 'vitest';
import { validateConfig, formatIssues } from '../../src/admin/config-schema.js';

describe('validateConfig', () => {
  describe('root', () => {
    it('returns empty config + issue when input is null', () => {
      const { config, issues } = validateConfig(null);
      expect(config).toEqual({});
      expect(issues).toHaveLength(1);
      expect(issues[0].path).toBe('');
      expect(issues[0].message).toMatch(/expected object/);
    });

    it('returns empty config + issue when input is an array', () => {
      const { config, issues } = validateConfig([1, 2, 3]);
      expect(config).toEqual({});
      expect(issues).toHaveLength(1);
    });

    it('returns empty config + issue when input is a primitive', () => {
      const { config, issues } = validateConfig('hello');
      expect(config).toEqual({});
      expect(issues).toHaveLength(1);
    });

    it('passes a valid empty object through unchanged', () => {
      const input = {};
      const { config, issues } = validateConfig(input);
      expect(config).toBe(input);
      expect(issues).toEqual([]);
    });

    it('passes a fully valid config through unchanged', () => {
      const input = {
        protocol: 'vless',
        transport: 'ws',
        grpcMode: 'gun',
        enable0RTT: false,
        randomPath: true,
        skipCertVerify: false,
        ECH: false,
        PATH: '/',
        Fingerprint: 'chrome',
        HOSTS: ['example.com'],
        tlsFragment: null,
        SS: { cipher: 'aes-128-gcm', TLS: true },
        preferredSub: {
          local: true,
          SUBUpdateTime: 6,
          SUBNAME: 'edgetunnel',
          localIP: { randomIP: true, count: 16, port: -1 },
        },
      };
      const { issues } = validateConfig(input);
      expect(issues).toEqual([]);
    });
  });

  describe('enum fields', () => {
    it('rejects invalid protocol and replaces with vless', () => {
      const input = { protocol: 'vmess' };
      const { config, issues } = validateConfig(input);
      expect(config.protocol).toBe('vless');
      expect(issues).toHaveLength(1);
      expect(issues[0].path).toBe('protocol');
      expect(issues[0].message).toMatch(/vmess/);
    });

    it('rejects non-string protocol', () => {
      const { config, issues } = validateConfig({ protocol: 42 });
      expect(config.protocol).toBe('vless');
      expect(issues[0].message).toMatch(/number 42/);
    });

    it('rejects invalid transport and replaces with ws', () => {
      const { config, issues } = validateConfig({ transport: 'tcp' });
      expect(config.transport).toBe('ws');
      expect(issues[0].path).toBe('transport');
    });

    it('rejects invalid grpcMode and replaces with gun', () => {
      const { config, issues } = validateConfig({ grpcMode: 'unknown' });
      expect(config.grpcMode).toBe('gun');
      expect(issues[0].path).toBe('grpcMode');
    });

    it('leaves missing fields untouched', () => {
      const input: any = {};
      const { config, issues } = validateConfig(input);
      expect('protocol' in config).toBe(false);
      expect(issues).toEqual([]);
    });
  });

  describe('boolean fields', () => {
    it('rejects string "true" for enable0RTT', () => {
      const { config, issues } = validateConfig({ enable0RTT: 'true' });
      expect(config.enable0RTT).toBe(false);
      expect(issues).toHaveLength(1);
      expect(issues[0].path).toBe('enable0RTT');
    });

    it('rejects 1 for randomPath', () => {
      const { config, issues } = validateConfig({ randomPath: 1 });
      expect(config.randomPath).toBe(false);
      expect(issues[0].path).toBe('randomPath');
    });

    it('accepts true and false', () => {
      const { issues: issuesTrue } = validateConfig({ ECH: true });
      const { issues: issuesFalse } = validateConfig({ ECH: false });
      expect(issuesTrue).toEqual([]);
      expect(issuesFalse).toEqual([]);
    });
  });

  describe('HOSTS array', () => {
    it('rejects non-array', () => {
      const { config, issues } = validateConfig({ HOSTS: 'example.com' });
      expect(config.HOSTS).toEqual([]);
      expect(issues[0].path).toBe('HOSTS');
    });

    it('rejects array containing non-string entry', () => {
      const { config, issues } = validateConfig({ HOSTS: ['ok.com', 42] });
      expect(config.HOSTS).toEqual([]);
      expect(issues[0].path).toBe('HOSTS');
    });

    it('accepts a valid string array', () => {
      const input = { HOSTS: ['a.com', 'b.com'] };
      const { config, issues } = validateConfig(input);
      expect(config.HOSTS).toEqual(['a.com', 'b.com']);
      expect(issues).toEqual([]);
    });
  });

  describe('tlsFragment', () => {
    it('accepts null', () => {
      const { issues } = validateConfig({ tlsFragment: null });
      expect(issues).toEqual([]);
    });

    it('accepts Shadowrocket', () => {
      const { issues } = validateConfig({ tlsFragment: 'Shadowrocket' });
      expect(issues).toEqual([]);
    });

    it('accepts Happ', () => {
      const { issues } = validateConfig({ tlsFragment: 'Happ' });
      expect(issues).toEqual([]);
    });

    it('rejects unknown string and replaces with null', () => {
      const { config, issues } = validateConfig({ tlsFragment: 'NekoBox' });
      expect(config.tlsFragment).toBeNull();
      expect(issues[0].path).toBe('tlsFragment');
    });

    it('rejects boolean and replaces with null', () => {
      const { config, issues } = validateConfig({ tlsFragment: true });
      expect(config.tlsFragment).toBeNull();
      expect(issues[0].path).toBe('tlsFragment');
    });
  });

  describe('SS sub-object', () => {
    it('replaces non-object SS with default', () => {
      const { config, issues } = validateConfig({ SS: 'invalid' });
      expect(config.SS).toEqual({ cipher: 'aes-128-gcm', TLS: true });
      expect(issues[0].path).toBe('SS');
    });

    it('coerces SS.TLS non-boolean', () => {
      const { config, issues } = validateConfig({ SS: { TLS: 'yes' } });
      expect(config.SS.TLS).toBe(true);
      expect(issues[0].path).toBe('SS.TLS');
    });

    it('coerces SS.cipher non-string', () => {
      const { config, issues } = validateConfig({ SS: { cipher: 42 } });
      expect(config.SS.cipher).toBe('aes-128-gcm');
      expect(issues[0].path).toBe('SS.cipher');
    });
  });

  describe('preferredSub sub-object', () => {
    it('reports issue when preferredSub is not an object', () => {
      const { issues } = validateConfig({ preferredSub: 'oops' });
      expect(issues[0].path).toBe('preferredSub');
    });

    it('rejects SUBUpdateTime as string', () => {
      const { config, issues } = validateConfig({
        preferredSub: { SUBUpdateTime: '24' },
      });
      expect(config.preferredSub.SUBUpdateTime).toBe(3);
      expect(issues[0].path).toBe('preferredSub.SUBUpdateTime');
    });

    it('rejects negative SUBUpdateTime', () => {
      const { config, issues } = validateConfig({
        preferredSub: { SUBUpdateTime: -1 },
      });
      expect(config.preferredSub.SUBUpdateTime).toBe(3);
      expect(issues[0].path).toBe('preferredSub.SUBUpdateTime');
    });

    it('rejects non-integer count', () => {
      const { config, issues } = validateConfig({
        preferredSub: { localIP: { count: 1.5 } },
      });
      expect(config.preferredSub.localIP.count).toBe(16);
      expect(issues[0].path).toBe('preferredSub.localIP.count');
    });

    it('accepts port = -1 (auto)', () => {
      const { issues } = validateConfig({
        preferredSub: { localIP: { port: -1 } },
      });
      expect(issues).toEqual([]);
    });

    it('rejects port out of range', () => {
      const { config, issues } = validateConfig({
        preferredSub: { localIP: { port: 99999 } },
      });
      expect(config.preferredSub.localIP.port).toBe(-1);
      expect(issues[0].path).toBe('preferredSub.localIP.port');
    });

    it('rejects port as string', () => {
      const { config, issues } = validateConfig({
        preferredSub: { localIP: { port: '443' } },
      });
      expect(config.preferredSub.localIP.port).toBe(-1);
      expect(issues[0].path).toBe('preferredSub.localIP.port');
    });
  });

  describe('multi-issue behaviour', () => {
    it('collects all issues without short-circuit', () => {
      const { config, issues } = validateConfig({
        protocol: 'vmess',
        transport: 'tcp',
        enable0RTT: 'yes',
        HOSTS: 42,
        SS: { TLS: 'maybe' },
      });
      expect(issues.length).toBeGreaterThanOrEqual(5);
      const paths = issues.map((i) => i.path);
      expect(paths).toContain('protocol');
      expect(paths).toContain('transport');
      expect(paths).toContain('enable0RTT');
      expect(paths).toContain('HOSTS');
      expect(paths).toContain('SS.TLS');
      // and config should have all the corrected defaults
      expect(config.protocol).toBe('vless');
      expect(config.transport).toBe('ws');
      expect(config.enable0RTT).toBe(false);
      expect(config.HOSTS).toEqual([]);
      expect(config.SS.TLS).toBe(true);
    });

    it('mutates the input in place (same reference returned)', () => {
      const input: any = { protocol: 'vmess' };
      const { config } = validateConfig(input);
      expect(config).toBe(input);
      expect(input.protocol).toBe('vless');
    });
  });
});

describe('formatIssues', () => {
  it('returns empty string for no issues', () => {
    expect(formatIssues([])).toBe('');
  });

  it('formats issues with path and message', () => {
    const formatted = formatIssues([
      { path: 'protocol', message: 'replaced with vless' },
      { path: '', message: 'root broken' },
    ]);
    expect(formatted).toContain('config.json validation: 2 issue(s)');
    expect(formatted).toContain('- protocol: replaced with vless');
    expect(formatted).toContain('- <root>: root broken');
  });
});
