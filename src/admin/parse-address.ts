// Resolve a "proxyIP" specification string into a list of (host, port) pairs
// to try in round-robin.
//
// The input can be:
//   - A literal IPv4: "1.2.3.4"  → [["1.2.3.4", 443]]
//   - With port: "1.2.3.4:8443"  → [["1.2.3.4", 8443]]
//   - IPv6: "[::1]:443"           → [["[::1]", 443]]
//   - Domain: "proxy.example.com" → resolves via DoH to A/AAAA list
//   - Multiple, comma-separated
//   - Special ".tpNNNN" suffix encoding port
//   - Special ".william" domain → look up TXT record
//
// Results are sorted alphabetically then deterministically shuffled
// using a seed derived from the target domain + UUID, so different users
// get different orderings but the same user gets stable results across
// requests within the cache window.

import { toArray } from '../utils/url.js';
import { dohQuery } from '../utils/dns.js';
import type { LogFn } from '../utils/logger.js';
import type { ProxyContext } from '../state.js';

export type ProxyIPArray = Array<[string, number]>;

/** Split "host:port" / "[ipv6]:port" / bare host into (host, port) tuple. */
function splitAddressPort(str: string, defaultPort = 443): [string, number] {
  let address = str;
  let port = defaultPort;
  if (str.includes(']:')) {
    const parts = str.split(']:');
    address = parts[0] + ']';
    port = parseInt(parts[1], 10) || defaultPort;
  } else if (str.includes(':') && !str.startsWith('[')) {
    const colonIndex = str.lastIndexOf(':');
    address = str.slice(0, colonIndex);
    port = parseInt(str.slice(colonIndex + 1), 10) || defaultPort;
  }
  return [address, port];
}

const IPV4_REGEX = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const IPV6_REGEX = /^\[?([a-fA-F0-9:]+)\]?$/;

/**
 * Resolve a proxy IP spec string into a list of (host, port) candidates.
 *
 * Caches results in `ctx.cachedProxyArray` keyed by `ctx.cachedProxyIP` —
 * subsequent calls with the same proxyIP return the cached array
 * (keeps the round-robin index meaningful across requests).
 *
 * Implements original behaviour: alphabetical sort + deterministic shuffle
 * by hash of (target root domain + UUID), keep top 8 candidates.
 */
export async function parseAddressPort(
  ctx: ProxyContext,
  proxyIP: string,
  targetDomain: string = 'dash.cloudflare.com',
  uuid: string = '00000000-0000-4000-8000-000000000000',
  log: LogFn = () => {}
): Promise<ProxyIPArray> {
  // Cache hit
  if (
    ctx.cachedProxyIP &&
    ctx.cachedProxyArray &&
    ctx.cachedProxyIP === proxyIP
  ) {
    log(`[proxy-resolve] cache hit, ${ctx.cachedProxyArray.length} candidates`);
    return ctx.cachedProxyArray;
  }

  proxyIP = proxyIP.toLowerCase();
  const proxyIPArray = toArray(proxyIP);
  let allCandidates: ProxyIPArray = [];

  for (const single of proxyIPArray) {
    if (single.includes('.william')) {
      // .william special domain: TXT record contains comma-separated proxy IPs
      try {
        let txtRecords = await dohQuery(single, 'TXT', undefined, log);
        let txtData = txtRecords.filter((r) => r.type === 16).map((r) => r.data);
        if (txtData.length === 0) {
          log(`[proxy-resolve] default DoH found no TXT, retry via Google DoH for ${single}`);
          txtRecords = await dohQuery(single, 'TXT', 'https://dns.google/dns-query', log);
          txtData = txtRecords.filter((r) => r.type === 16).map((r) => r.data);
        }
        if (txtData.length > 0) {
          let data = txtData[0];
          if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
          const prefixes = data
            .replace(/\\010/g, ',')
            .replace(/\n/g, ',')
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);
          allCandidates.push(...prefixes.map((prefix) => splitAddressPort(prefix)));
        }
      } catch (error) {
        console.error('[proxy-resolve] william domain failed:', error);
      }
    } else {
      let [address, port] = splitAddressPort(single);

      // .tpNNNN suffix encodes port in the hostname
      if (single.includes('.tp')) {
        const tpMatch = single.match(/\.tp(\d+)/);
        if (tpMatch) port = parseInt(tpMatch[1], 10);
      }

      const isIp = IPV4_REGEX.test(address) || IPV6_REGEX.test(address);
      if (!isIp) {
        // Domain: resolve A + AAAA
        let [aRecords, aaaaRecords] = await Promise.all([
          dohQuery(address, 'A', undefined, log),
          dohQuery(address, 'AAAA', undefined, log),
        ]);
        let ipv4List = aRecords.filter((r) => r.type === 1).map((r) => r.data);
        let ipv6List = aaaaRecords.filter((r) => r.type === 28).map((r) => `[${r.data}]`);
        let ipAddresses = [...ipv4List, ...ipv6List];

        // Fallback to Google DoH if default resolver returned nothing
        if (ipAddresses.length === 0) {
          log(`[proxy-resolve] default DoH found no records, retry via Google DoH for ${address}`);
          [aRecords, aaaaRecords] = await Promise.all([
            dohQuery(address, 'A', 'https://dns.google/dns-query', log),
            dohQuery(address, 'AAAA', 'https://dns.google/dns-query', log),
          ]);
          ipv4List = aRecords.filter((r) => r.type === 1).map((r) => r.data);
          ipv6List = aaaaRecords.filter((r) => r.type === 28).map((r) => `[${r.data}]`);
          ipAddresses = [...ipv4List, ...ipv6List];
        }

        if (ipAddresses.length > 0) {
          allCandidates.push(...ipAddresses.map((ip): [string, number] => [ip, port]));
        } else {
          allCandidates.push([address, port]);
        }
      } else {
        allCandidates.push([address, port]);
      }
    }
  }

  // Sort + deterministic shuffle by (target root domain + UUID) seed
  const sorted = [...allCandidates].sort((a, b) => a[0].localeCompare(b[0]));
  const targetRootDomain = targetDomain.includes('.')
    ? targetDomain.split('.').slice(-2).join('.')
    : targetDomain;
  let seed = [...(targetRootDomain + uuid)].reduce((a, c) => a + c.charCodeAt(0), 0);
  log(`[proxy-resolve] seed=${seed}, target root=${targetRootDomain}`);
  const shuffled = [...sorted].sort(() => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed / 0x7fffffff - 0.5;
  });

  const top8 = shuffled.slice(0, 8);
  log(
    `[proxy-resolve] resolved ${top8.length} candidates:\n` +
      top8.map(([ip, p], i) => `${i + 1}. ${ip}:${p}`).join('\n')
  );

  ctx.cachedProxyArray = top8;
  ctx.cachedProxyIP = proxyIP;
  return top8;
}
