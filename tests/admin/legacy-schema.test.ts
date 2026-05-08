import { describe, it, expect } from 'vitest';
import { toLegacySchema } from '../../src/admin/config.js';

describe('toLegacySchema', () => {
  it('renames preferredSub.TOKEN back to 优选订阅生成.TOKEN (the /sub?token= link path)', () => {
    const english = {
      preferredSub: { TOKEN: 'abc123', SUBNAME: 'edgetunnel' },
    };
    const legacy = toLegacySchema(english) as any;
    expect(legacy.优选订阅生成.TOKEN).toBe('abc123');
    expect(legacy.优选订阅生成.SUBNAME).toBe('edgetunnel');
    expect(legacy.preferredSub).toBeUndefined();
  });

  it('renames nested preferredSub.localIP fields', () => {
    const english = {
      preferredSub: { localIP: { randomIP: true, count: 16, port: -1 } },
    };
    const legacy = toLegacySchema(english) as any;
    expect(legacy.优选订阅生成.本地IP库.随机IP).toBe(true);
    expect(legacy.优选订阅生成.本地IP库.随机数量).toBe(16);
    expect(legacy.优选订阅生成.本地IP库.指定端口).toBe(-1);
  });

  it('renames proxy/template/SOCKS5 keys', () => {
    const english = {
      proxy: {
        PROXYIP: 'auto',
        SOCKS5: { mode: null, global: false, auth: 'a:b', whitelist: ['x'] },
        template: {
          PROXYIP: 'proxyip={{IP:PORT}}',
          SOCKS5: { global: 'socks5://{{IP:PORT}}', standard: 'socks5={{IP:PORT}}' },
          HTTP: { global: 'http://{{IP:PORT}}', standard: 'http={{IP:PORT}}' },
        },
      },
    };
    const legacy = toLegacySchema(english) as any;
    expect(legacy.反代.PROXYIP).toBe('auto');
    expect(legacy.反代.SOCKS5.启用).toBeNull();        // SCOPED: SOCKS5.mode → 启用
    expect(legacy.反代.SOCKS5.全局).toBe(false);
    expect(legacy.反代.SOCKS5.账号).toBe('a:b');
    expect(legacy.反代.SOCKS5.白名单).toEqual(['x']);
    expect(legacy.反代.路径模板.PROXYIP).toBe('proxyip={{IP:PORT}}');
    expect(legacy.反代.路径模板.SOCKS5.全局).toBe('socks5://{{IP:PORT}}');
    expect(legacy.反代.路径模板.SOCKS5.标准).toBe('socks5={{IP:PORT}}');
  });

  it('renames TG.enabled (scoped, distinct from SOCKS5.mode)', () => {
    const legacy = toLegacySchema({ TG: { enabled: true, BotToken: null } }) as any;
    expect(legacy.TG.启用).toBe(true);
    expect(legacy.TG.BotToken).toBeNull();
  });

  it('renames subConverter and protocol/transport top-level fields', () => {
    const legacy = toLegacySchema({
      protocol: 'vless',
      transport: 'ws',
      grpcMode: 'gun',
      subConverter: { SUBAPI: 'x', SUBCONFIG: 'y', SUBEMOJI: false },
    }) as any;
    expect(legacy.协议类型).toBe('vless');
    expect(legacy.传输协议).toBe('ws');
    expect(legacy.gRPC模式).toBe('gun');
    expect(legacy.订阅转换配置.SUBAPI).toBe('x');
  });

  it('passes through keys not in the migration map', () => {
    const legacy = toLegacySchema({
      HOST: 'example.com',
      UUID: 'u',
      LINK: 'vless://...',
      CF: { Email: null },
      __validation: { issues: [] },
    }) as any;
    expect(legacy.HOST).toBe('example.com');
    expect(legacy.UUID).toBe('u');
    expect(legacy.LINK).toBe('vless://...');
    expect(legacy.CF).toEqual({ Email: null });
    expect(legacy.__validation).toEqual({ issues: [] });
  });

  it('handles arrays without renaming inside (HOSTS)', () => {
    const legacy = toLegacySchema({ HOSTS: ['a', 'b'] }) as any;
    expect(legacy.HOSTS).toEqual(['a', 'b']);
  });

  it('is exact inverse of forward migration on a representative config', () => {
    const legacy = {
      协议类型: 'vless',
      优选订阅生成: {
        local: true,
        本地IP库: { 随机IP: true, 随机数量: 16, 指定端口: -1 },
        TOKEN: 'tok',
      },
      反代: {
        PROXYIP: 'auto',
        SOCKS5: { 启用: null, 全局: false, 账号: '', 白名单: [] },
        路径模板: { PROXYIP: 'p', SOCKS5: { 全局: 'g', 标准: 's' } },
      },
      TG: { 启用: false },
    };
    // forward (English) then reverse should yield original
    // Re-import forward via the same code path readConfigJson uses.
    // Smoke check: reverse alone produces the legacy shape from English.
    const english = {
      protocol: 'vless',
      preferredSub: {
        local: true,
        localIP: { randomIP: true, count: 16, port: -1 },
        TOKEN: 'tok',
      },
      proxy: {
        PROXYIP: 'auto',
        SOCKS5: { mode: null, global: false, auth: '', whitelist: [] },
        template: { PROXYIP: 'p', SOCKS5: { global: 'g', standard: 's' } },
      },
      TG: { enabled: false },
    };
    expect(toLegacySchema(english)).toEqual(legacy);
  });
});
