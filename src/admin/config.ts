// Subscription / proxy configuration loader.
//
// Reads `config.json` from KV (creating defaults on first run), merges
// in env-var overrides, derives the final node path / subscription URI,
// and returns the unified config object used by all subscription generation
// and admin endpoints.
//
// Schema migration: older deployments stored config.json with Chinese
// field names (协议类型, 反代, 优选订阅生成, …). On read we transparently
// migrate to the current English schema and write the new shape back to KV.

import { md5x2 } from '../crypto/md5.js';
import { maskSensitive } from '../utils/log.js';
import { getCloudflareUsage } from './cloudflare-api.js';
import { getTransportConfig, getTransportPath } from './transport.js';
import { toArray } from '../utils/url.js';
import { validateConfig, formatIssues, type ValidationIssue } from './config-schema.js';
import type { ProxyContext } from '../state.js';

const PROXYIP_KEY = atob('UFJPWFlJUA=='); // "PROXYIP" — kept obfuscated like original

// Old (Chinese) → new (English) key map applied recursively to legacy configs.
const SCHEMA_MIGRATION: Record<string, string> = {
  '协议类型': 'protocol',
  '传输协议': 'transport',
  'gRPC模式': 'grpcMode',
  '随机路径': 'randomPath',
  '跳过证书验证': 'skipCertVerify',
  '启用0RTT': 'enable0RTT',
  'TLS分片': 'tlsFragment',
  '完整节点路径': 'fullNodePath',
  '加载时间': 'loadTime',
  '优选订阅生成': 'preferredSub',
  '本地IP库': 'localIP',
  '随机IP': 'randomIP',
  '随机数量': 'count',
  '指定端口': 'port',
  '订阅转换配置': 'subConverter',
  '反代': 'proxy',
  '路径模板': 'template',
  '全局': 'global',
  '标准': 'standard',
  '账号': 'auth',
  '白名单': 'whitelist',
};

// Context-dependent: 启用 means different things under different parents.
const SCOPED_MIGRATION: Record<string, Record<string, string>> = {
  TG: { '启用': 'enabled' },
  SOCKS5: { '启用': 'mode' },
};

/** Recursively rename legacy Chinese keys to the new English schema. */
function migrateLegacySchema(value: any, parentKey: string = ''): any {
  if (Array.isArray(value)) return value.map((v) => migrateLegacySchema(v, ''));
  if (!value || typeof value !== 'object') return value;
  const out: Record<string, any> = {};
  const scoped = SCOPED_MIGRATION[parentKey];
  for (const [k, v] of Object.entries(value)) {
    const newKey = scoped?.[k] ?? SCHEMA_MIGRATION[k] ?? k;
    out[newKey] = migrateLegacySchema(v, newKey);
  }
  return out;
}

interface ConfigEnv {
  KV: KVNamespace;
  HOST?: string;
  PATH?: string;
}

/**
 * Read (or create) config.json from KV, populate derived fields, and
 * return the unified subscription config.
 *
 * Mutates `ctx.configJson` as a side effect.
 */
export async function readConfigJson(
  ctx: ProxyContext,
  env: ConfigEnv,
  hostname: string,
  userID: string,
  ua: string = 'Mozilla/5.0',
  resetConfig: boolean = false
): Promise<any> {
  const host = hostname;
  const aliDoH = 'https://dns.alidns.com/dns-query';
  const echSni = 'cloudflare-ech.com';
  const placeholder = '{{IP:PORT}}';
  const startTime = performance.now();

  const defaultConfig: any = {
    TIME: new Date().toISOString(),
    HOST: host,
    HOSTS: [hostname],
    UUID: userID,
    PATH: '/',
    protocol: 'v' + 'le' + 'ss',
    transport: 'ws',
    grpcMode: 'gun',
    gRPCUserAgent: ua,
    skipCertVerify: false,
    enable0RTT: false,
    tlsFragment: null,
    randomPath: false,
    ECH: false,
    ECHConfig: { DNS: aliDoH, SNI: echSni },
    Fingerprint: 'chrome',
    preferredSub: {
      local: true,
      localIP: { randomIP: true, count: 16, port: -1 },
      SUB: null,
      SUBNAME: 'edge' + 'tunnel',
      SUBUpdateTime: 3,
      TOKEN: await md5x2(hostname + userID),
    },
    subConverter: {
      SUBAPI: 'https://SUBAPI.cmliussss.net',
      SUBCONFIG:
        'https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini',
      SUBEMOJI: false,
    },
    proxy: {
      [PROXYIP_KEY]: 'auto',
      SOCKS5: {
        mode: ctx.socks5Mode,
        global: ctx.socks5GlobalEnabled,
        auth: ctx.socks5Auth,
        whitelist: ctx.socks5Whitelist,
      },
      template: {
        [PROXYIP_KEY]: 'proxyip=' + placeholder,
        SOCKS5: { global: 'socks5://' + placeholder, standard: 'socks5=' + placeholder },
        HTTP: { global: 'http://' + placeholder, standard: 'http=' + placeholder },
      },
    },
    TG: { enabled: false, BotToken: null, ChatID: null },
    CF: {
      Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null,
      Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 },
    },
  };

  let configJson: any;
  let validationIssues: ValidationIssue[] = [];
  try {
    const stored = await env.KV.get('config.json');
    if (!stored || resetConfig) {
      await env.KV.put('config.json', JSON.stringify(defaultConfig, null, 2));
      configJson = defaultConfig;
    } else {
      const parsed = JSON.parse(stored);
      const migrated = migrateLegacySchema(parsed);
      // Validate the migrated shape: bad-typed fields are coerced to known
      // defaults in place; issues are surfaced via console.warn and attached
      // to configJson.__validation for the admin UI to read.
      const { config: validated, issues } = validateConfig(migrated);
      validationIssues = issues;
      if (issues.length > 0) {
        console.warn(formatIssues(issues));
      }
      configJson = validated;
      // Persist the migrated+validated shape so subsequent reads skip both passes.
      if (JSON.stringify(parsed) !== JSON.stringify(validated)) {
        await env.KV.put('config.json', JSON.stringify(validated, null, 2));
      }
    }
  } catch (error: any) {
    console.error(`readConfigJson error: ${error.message}`);
    configJson = defaultConfig;
  }
  ctx.configJson = configJson;
  // Surface validation results so admin UI can display them. Always set,
  // even when empty, so the UI can distinguish "not validated yet" from "clean".
  configJson.__validation = { issues: validationIssues };

  // Apply env overrides + defaults
  if (!configJson.gRPCUserAgent) configJson.gRPCUserAgent = ua;
  configJson.HOST = host;
  if (!configJson.HOSTS) configJson.HOSTS = [hostname];
  if (env.HOST) {
    configJson.HOSTS = toArray(env.HOST).map((h) =>
      h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]
    );
  }
  configJson.UUID = userID;
  if (!configJson.randomPath) configJson.randomPath = false;
  if (!configJson.enable0RTT) configJson.enable0RTT = false;
  if (env.PATH) {
    configJson.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
  } else if (!configJson.PATH) {
    configJson.PATH = '/';
  }
  if (!configJson.grpcMode) configJson.grpcMode = 'gun';

  // Backfill proxy.template if missing
  if (!configJson.proxy.template?.[PROXYIP_KEY]) {
    configJson.proxy.template = {
      [PROXYIP_KEY]: 'proxyip=' + placeholder,
      SOCKS5: { global: 'socks5://' + placeholder, standard: 'socks5=' + placeholder },
      HTTP: { global: 'http://' + placeholder, standard: 'http=' + placeholder },
    };
  }

  // Build the path with proxy params
  const proxyTemplate =
    configJson.proxy.template[configJson.proxy.SOCKS5.mode?.toUpperCase()];

  let pathProxyParam = '';
  if (proxyTemplate && configJson.proxy.SOCKS5.auth) {
    pathProxyParam = (configJson.proxy.SOCKS5.global ? proxyTemplate.global : proxyTemplate.standard)
      .replace(placeholder, configJson.proxy.SOCKS5.auth);
  } else if (configJson.proxy[PROXYIP_KEY] !== 'auto') {
    pathProxyParam = configJson.proxy.template[PROXYIP_KEY].replace(
      placeholder,
      configJson.proxy[PROXYIP_KEY]
    );
  }

  let proxyQuery = '';
  if (pathProxyParam.includes('?')) {
    const [pathPart, queryPart] = pathProxyParam.split('?');
    pathProxyParam = pathPart;
    proxyQuery = queryPart;
  }

  configJson.PATH = configJson.PATH.replace(pathProxyParam, '').replace('//', '/');
  const normalizedPath =
    configJson.PATH === '/'
      ? ''
      : configJson.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
  const [pathPart, ...queryParts] = normalizedPath.split('?');
  const queryPart = queryParts.length ? '?' + queryParts.join('?') : '';
  const finalQuery = proxyQuery
    ? queryPart
      ? queryPart + '&' + proxyQuery
      : '?' + proxyQuery
    : queryPart;
  configJson.fullNodePath =
    (pathPart || '/') +
    (pathPart && pathProxyParam ? '/' : '') +
    pathProxyParam +
    finalQuery +
    (configJson.enable0RTT ? (finalQuery ? '&' : '?') + 'ed=2560' : '');

  // TLS fragment / fingerprint / ECH defaults
  if (!configJson.tlsFragment && configJson.tlsFragment !== null) configJson.tlsFragment = null;
  const tlsFragmentParam =
    configJson.tlsFragment == 'Shadowrocket'
      ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}`
      : configJson.tlsFragment == 'Happ'
        ? `&fragment=${encodeURIComponent('3,1,tlshello')}`
        : '';
  if (!configJson.Fingerprint) configJson.Fingerprint = 'chrome';
  if (!configJson.ECH) configJson.ECH = false;
  if (!configJson.ECHConfig) configJson.ECHConfig = { DNS: aliDoH, SNI: echSni };
  const echLinkParam = configJson.ECH
    ? `&ech=${encodeURIComponent((configJson.ECHConfig.SNI ? configJson.ECHConfig.SNI + '+' : '') + configJson.ECHConfig.DNS)}`
    : '';

  const { type: transportProto, pathField: pathFieldName, hostField: hostFieldName } =
    getTransportConfig(configJson);
  const transportPathValue = getTransportPath(configJson, configJson.fullNodePath);

  // Build the VLESS link
  configJson.LINK = `${configJson.protocol}://${userID}@${host}:443?security=tls&type=${transportProto + echLinkParam}&${hostFieldName}=${host}&fp=${configJson.Fingerprint}&sni=${host}&${pathFieldName}=${encodeURIComponent(transportPathValue) + tlsFragmentParam}&encryption=none${configJson.skipCertVerify ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(configJson.preferredSub.SUBNAME)}`;

  configJson.preferredSub.TOKEN = await md5x2(hostname + userID);

  // tg.json: load + mask BotToken
  const initTgJson = { BotToken: null, ChatID: null };
  configJson.TG = {
    enabled: configJson.TG.enabled ? configJson.TG.enabled : false,
    ...initTgJson,
  };
  try {
    const tgText = await env.KV.get('tg.json');
    if (!tgText) {
      await env.KV.put('tg.json', JSON.stringify(initTgJson, null, 2));
    } else {
      const tg = JSON.parse(tgText);
      configJson.TG.ChatID = tg.ChatID ? tg.ChatID : null;
      configJson.TG.BotToken = tg.BotToken ? maskSensitive(tg.BotToken) : null;
    }
  } catch (error: any) {
    console.error(`tg.json read error: ${error.message}`);
  }

  // cf.json: load credentials, fetch usage stats
  const initCfJson = {
    Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null,
  };
  configJson.CF = {
    ...initCfJson,
    Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 },
  };
  try {
    const cfText = await env.KV.get('cf.json');
    if (!cfText) {
      await env.KV.put('cf.json', JSON.stringify(initCfJson, null, 2));
    } else {
      const cf = JSON.parse(cfText);
      if (cf.UsageAPI) {
        try {
          const response = await fetch(cf.UsageAPI);
          configJson.CF.Usage = await response.json();
        } catch (err: any) {
          console.error(`UsageAPI fetch failed: ${err.message}`);
        }
      } else {
        configJson.CF.Email = cf.Email ? cf.Email : null;
        configJson.CF.GlobalAPIKey = cf.GlobalAPIKey ? maskSensitive(cf.GlobalAPIKey) : null;
        configJson.CF.AccountID = cf.AccountID ? maskSensitive(cf.AccountID) : null;
        configJson.CF.APIToken = cf.APIToken ? maskSensitive(cf.APIToken) : null;
        configJson.CF.UsageAPI = null;
        configJson.CF.Usage = await getCloudflareUsage(
          cf.Email, cf.GlobalAPIKey, cf.AccountID, cf.APIToken
        );
      }
    }
  } catch (error: any) {
    console.error(`cf.json read error: ${error.message}`);
  }

  configJson.loadTime = (performance.now() - startTime).toFixed(2) + 'ms';
  ctx.configJson = configJson;
  return configJson;
}
