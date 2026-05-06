// Sing-box subscription post-processor.
//
// Migrates pre-1.12 Sing-box config schema to 1.12+ format:
//   - Replaces 1.1.1.1 default DNS with 8.8.8.8 (better availability in CN)
//   - Migrates legacy geoip/geosite arrays to rule_set entries
//   - Migrates DNS server URLs (tcp://, https:// etc.) to typed objects
//   - Migrates legacy fakeip block to fakeip server entry
//   - Patches matching outbound nodes with utls + ECH options

import { getECH } from '../utils/dns.js';

interface SingboxConfig {
  UUID?: string;
  Fingerprint?: string;
  ECH?: boolean;
  ECHConfig?: { SNI?: string };
}

const DNS_PROTOCOL_MAP: Record<string, string> = {
  'tcp:': 'tcp',
  'udp:': 'udp',
  'tls:': 'tls',
  'quic:': 'quic',
  'https:': 'https',
  'h3:': 'h3',
};

const RCODE_MAP: Record<string, string> = {
  success: 'NOERROR',
  format_error: 'FORMERR',
  server_failure: 'SERVFAIL',
  name_error: 'NXDOMAIN',
  not_implemented: 'NOTIMP',
  refused: 'REFUSED',
};

/**
 * Patch a Sing-box JSON subscription. Returns the modified JSON as string.
 *
 * If JSON parse fails, falls back to the input unchanged (apart from
 * the initial DNS substitution).
 */
export async function patchSingboxSubscription(
  originalContent: string,
  configIn: SingboxConfig = {}
): Promise<string> {
  const uuid = configIn?.UUID || null;
  const fingerprint = configIn?.Fingerprint || 'chrome';
  const echEnabled = Boolean(configIn?.ECH);
  const echSni = configIn?.ECHConfig?.SNI || 'cloudflare-ech.com';
  const sbJsonText = originalContent
    .replace('1.1.1.1', '8.8.8.8')
    .replace('1.0.0.1', '8.8.4.4');

  try {
    const config: any = JSON.parse(sbJsonText);

    const arrayify = (v: any): any[] => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);
    const ensureRoute = () => {
      config.route =
        config.route && typeof config.route === 'object' ? config.route : {};
      return config.route;
    };
    const getDnsRuleServer = (rule: any): string | null =>
      rule && typeof rule === 'object' && !Array.isArray(rule) && typeof rule.server === 'string'
        ? rule.server
        : null;

    const addRuleSet = (type: 'geoip' | 'geosite', code: string): string | null => {
      if (!code || typeof code !== 'string') return null;
      const route = ensureRoute();
      const tag = `${type}-${code}`;
      const ruleSet = Array.isArray(route.rule_set) ? route.rule_set : arrayify(route.rule_set);
      if (!ruleSet.some((item: any) => item?.tag === tag)) {
        const legacyOptions = type === 'geoip' ? route.geoip : route.geosite;
        ruleSet.push({
          tag,
          type: 'remote',
          format: 'binary',
          url: `https://raw.githubusercontent.com/SagerNet/sing-${type}/rule-set/${tag}.srs`,
          ...(legacyOptions?.download_detour
            ? { download_detour: legacyOptions.download_detour }
            : {}),
        });
        config.experimental =
          config.experimental && typeof config.experimental === 'object'
            ? config.experimental
            : {};
        config.experimental.cache_file =
          config.experimental.cache_file && typeof config.experimental.cache_file === 'object'
            ? config.experimental.cache_file
            : {};
        config.experimental.cache_file.enabled ??= true;
      }
      route.rule_set = ruleSet;
      return tag;
    };

    const migrateRuleSetFields = (rule: any): any => {
      if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
      if (rule.type === 'logical' && Array.isArray(rule.rules)) {
        rule.rules = rule.rules.map(migrateRuleSetFields);
        return rule;
      }
      const tags: (string | null)[] = [];
      for (const geoip of arrayify(rule.geoip)) {
        if (typeof geoip !== 'string') continue;
        if (geoip.toLowerCase() === 'private') rule.ip_is_private = true;
        else tags.push(addRuleSet('geoip', geoip));
      }
      for (const sourceGeoip of arrayify(rule.source_geoip)) {
        if (typeof sourceGeoip !== 'string') continue;
        tags.push(addRuleSet('geoip', sourceGeoip));
        rule.rule_set_ip_cidr_match_source = true;
      }
      for (const geosite of arrayify(rule.geosite)) {
        if (typeof geosite === 'string') tags.push(addRuleSet('geosite', geosite));
      }
      if (tags.length) {
        rule.rule_set = [...new Set([...arrayify(rule.rule_set), ...tags].filter(Boolean))];
      }
      delete rule.geoip;
      delete rule.source_geoip;
      delete rule.geosite;
      return rule;
    };

    const migrateDnsRule = (rule: any, rcodeServerMap: Map<string, string>): any => {
      rule = migrateRuleSetFields(rule);
      if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
      if (rule.type === 'logical' && Array.isArray(rule.rules)) {
        rule.rules = rule.rules.map((c: any) => migrateDnsRule(c, rcodeServerMap));
        return rule;
      }
      const serverTag = getDnsRuleServer(rule);
      if (serverTag && rcodeServerMap.has(serverTag)) {
        for (const key of [
          'server', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout',
        ]) delete rule[key];
        rule.action = 'predefined';
        rule.rcode = rcodeServerMap.get(serverTag);
      } else if (serverTag && !rule.action) {
        rule.action = 'route';
      }
      return rule;
    };

    // Migrate inbound TUN options
    if (Array.isArray(config.inbounds)) {
      for (const inbound of config.inbounds) {
        if (!inbound || typeof inbound !== 'object' || inbound.type !== 'tun') continue;
        for (const migration of [
          { targetKey: 'address', sourceKeys: ['inet4_address', 'inet6_address'] },
          { targetKey: 'route_address', sourceKeys: ['inet4_route_address', 'inet6_route_address'] },
          {
            targetKey: 'route_exclude_address',
            sourceKeys: ['inet4_route_exclude_address', 'inet6_route_exclude_address'],
          },
        ]) {
          const values = arrayify(inbound[migration.targetKey]);
          for (const sourceKey of migration.sourceKeys) values.push(...arrayify(inbound[sourceKey]));
          if (values.length) inbound[migration.targetKey] = [...new Set(values)];
          for (const sourceKey of migration.sourceKeys) delete inbound[sourceKey];
        }
        if (inbound.tag) {
          const addedRules: any[] = [];
          if (inbound.domain_strategy) {
            addedRules.push({ inbound: inbound.tag, action: 'resolve', strategy: inbound.domain_strategy });
          }
          if (inbound.sniff) {
            const sniffRule: any = { inbound: inbound.tag, action: 'sniff' };
            if (inbound.sniff_timeout) sniffRule.timeout = inbound.sniff_timeout;
            addedRules.push(sniffRule);
          }
          if (addedRules.length) {
            const route = ensureRoute();
            route.rules = [...addedRules, ...arrayify(route.rules)];
          }
        }
        delete inbound.sniff;
        delete inbound.sniff_timeout;
        delete inbound.domain_strategy;
      }
    }

    // Migrate route rules
    if (config?.route && typeof config.route === 'object' && Array.isArray(config.route.rules)) {
      const patchRoute = (rule: any): any => {
        rule = migrateRuleSetFields(rule);
        if (rule?.type === 'logical' && Array.isArray(rule.rules)) {
          rule.rules = rule.rules.map(patchRoute);
        } else if (
          rule &&
          typeof rule === 'object' &&
          !Array.isArray(rule) &&
          rule.outbound &&
          !rule.action
        ) {
          rule.action = 'route';
        }
        return rule;
      };
      config.route.rules = config.route.rules.map(patchRoute);
    }

    // Migrate DNS section
    const dns = config?.dns;
    if (dns && typeof dns === 'object') {
      const legacyFakeIP =
        dns.fakeip && typeof dns.fakeip === 'object' ? dns.fakeip : null;
      const rcodeServerMap = new Map<string, string>();
      let hasFakeIPServer = false;

      if (Array.isArray(dns.servers)) {
        const migratedServers: any[] = [];
        for (const originalServer of dns.servers) {
          if (!originalServer || typeof originalServer !== 'object' || Array.isArray(originalServer)) {
            migratedServers.push(originalServer);
            continue;
          }
          const server: any = { ...originalServer };
          let parsedAddress: any = null;
          let parsedRCode = '';
          const rawAddress = typeof server.address === 'string' ? server.address.trim() : '';
          if (rawAddress) {
            const lower = rawAddress.toLowerCase();
            if (lower === 'fakeip') parsedAddress = { type: 'fakeip' };
            else if (lower === 'local') parsedAddress = { type: 'local' };
            else if (lower.startsWith('rcode://')) {
              parsedAddress = { type: 'rcode' };
              parsedRCode = rawAddress.slice('rcode://'.length).toLowerCase();
            } else if (lower.startsWith('dhcp://')) {
              const iface = rawAddress.slice('dhcp://'.length);
              parsedAddress =
                iface && iface.toLowerCase() !== 'auto'
                  ? { type: 'dhcp', interface: iface }
                  : { type: 'dhcp' };
            } else {
              try {
                const u = new URL(rawAddress);
                const t = DNS_PROTOCOL_MAP[u.protocol.toLowerCase()];
                if (t) {
                  const ps =
                    u.hostname?.startsWith('[') && u.hostname.endsWith(']')
                      ? u.hostname.slice(1, -1)
                      : u.hostname;
                  parsedAddress = {
                    type: t,
                    server: ps || u.host || rawAddress,
                    ...(u.port ? { server_port: Number(u.port) } : {}),
                    ...((t === 'https' || t === 'h3') && u.pathname && u.pathname !== '/dns-query'
                      ? { path: u.pathname }
                      : {}),
                  };
                }
              } catch (_) {
                /* */
              }
              if (!parsedAddress) parsedAddress = { type: 'udp', server: rawAddress };
            }
          }

          if (parsedAddress?.type === 'rcode') {
            const rcode = RCODE_MAP[parsedRCode] || 'NOERROR';
            if (typeof server.tag === 'string' && server.tag) {
              rcodeServerMap.set(server.tag, rcode);
              rcodeServerMap.set(
                server.tag.startsWith('dns_') ? server.tag.slice(4) : `dns_${server.tag}`,
                rcode
              );
            }
            continue;
          }

          if (parsedAddress) {
            delete server.address;
            Object.assign(server, parsedAddress);
          }
          if (server.address_resolver !== undefined && server.domain_resolver === undefined)
            server.domain_resolver = server.address_resolver;
          if (server.address_strategy !== undefined && server.domain_strategy === undefined)
            server.domain_strategy = server.address_strategy;
          delete server.address_resolver;
          delete server.address_strategy;
          if (server.detour === 'DIRECT') delete server.detour;

          if (server.type === 'fakeip') {
            hasFakeIPServer = true;
            if (legacyFakeIP) {
              for (const key of ['inet4_range', 'inet6_range']) {
                if (legacyFakeIP[key] !== undefined && server[key] === undefined)
                  server[key] = legacyFakeIP[key];
              }
            }
          }
          migratedServers.push(server);
        }
        dns.servers = migratedServers;
      }

      if (legacyFakeIP && !hasFakeIPServer && legacyFakeIP.enabled !== false) {
        const fakeIPServer: any = { type: 'fakeip', tag: 'fakeip' };
        for (const rule of Array.isArray(dns.rules) ? dns.rules : []) {
          const serverTag = getDnsRuleServer(rule);
          if (serverTag && serverTag.toLowerCase().includes('fakeip')) {
            fakeIPServer.tag = serverTag;
            break;
          }
        }
        for (const key of ['inet4_range', 'inet6_range']) {
          if (legacyFakeIP[key] !== undefined) fakeIPServer[key] = legacyFakeIP[key];
        }
        if (Array.isArray(dns.servers)) dns.servers.push(fakeIPServer);
        else dns.servers = [fakeIPServer];
      }

      if (Array.isArray(dns.rules)) {
        const dnsRouteFields = new Set([
          'outbound', 'server', 'action', 'strategy', 'disable_cache',
          'rewrite_ttl', 'client_subnet', 'timeout',
        ]);
        const migratedRules: any[] = [];
        for (const rule of dns.rules) {
          const serverTag = getDnsRuleServer(rule);
          const outbound = arrayify(rule?.outbound);
          const isOutboundAnyDNSRule =
            rule &&
            typeof rule === 'object' &&
            !Array.isArray(rule) &&
            rule.type !== 'logical' &&
            serverTag &&
            outbound.includes('any') &&
            Object.keys(rule).every((key) => dnsRouteFields.has(key));
          if (isOutboundAnyDNSRule) {
            const route = ensureRoute();
            if (route.default_domain_resolver === undefined) {
              const resolver: any = { server: serverTag };
              for (const key of [
                'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout',
              ]) {
                if (rule[key] !== undefined) resolver[key] = rule[key];
              }
              route.default_domain_resolver =
                Object.keys(resolver).length === 1 ? resolver.server : resolver;
            }
            continue;
          }
          migratedRules.push(migrateDnsRule(rule, rcodeServerMap));
        }
        dns.rules = migratedRules;
      }

      delete dns.fakeip;
      delete dns.independent_cache;
    }

    if (config?.route && typeof config.route === 'object') {
      delete config.route.geoip;
      delete config.route.geosite;
    }
    if (config?.ntp?.detour === 'DIRECT') delete config.ntp.detour;

    if (Array.isArray(config.outbounds)) {
      const outboundTags = new Set(
        config.outbounds.map((o: any) => o?.tag).filter(Boolean)
      );
      const refsReject = (value: any): boolean =>
        value === 'REJECT' ||
        (value &&
          typeof value === 'object' &&
          (Array.isArray(value)
            ? value.some(refsReject)
            : Object.values(value).some(refsReject)));
      if (
        !outboundTags.has('REJECT') &&
        refsReject({ outbounds: config.outbounds, route: config.route })
      ) {
        config.outbounds.push({ type: 'block', tag: 'REJECT' });
      }
    }

    // Patch matching nodes with utls + ECH options
    if (uuid) {
      config.outbounds?.forEach((outbound: any) => {
        if (
          (outbound.uuid && outbound.uuid === uuid) ||
          (outbound.password && outbound.password === uuid)
        ) {
          if (!outbound.tls) outbound.tls = { enabled: true };
          if (fingerprint) {
            outbound.tls.utls = { enabled: true, fingerprint };
          }
          if (echEnabled) {
            outbound.tls.ech = { enabled: true, query_server_name: echSni };
          }
        }
      });
    }

    return JSON.stringify(config, null, 2);
  } catch (e) {
    console.error('Singbox patch failed:', e);
    return JSON.stringify(JSON.parse(sbJsonText), null, 2);
  }
}
