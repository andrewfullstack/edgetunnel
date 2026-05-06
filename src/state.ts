// Per-request state shared across handlers.
//
// The original _worker.js uses module-level mutable globals (proxyIP,
// socks5 mode toggles, debug-log flag, etc.). This is workable in Cloudflare
// Workers because the fetch handler resets them on every request, but fragile.
//
// We replace those with an explicit ProxyContext that's created per-request
// and passed down through the handler chain.

export interface Socks5Address {
  username?: string;
  password?: string;
  hostname: string;
  port: number;
}

export type Socks5Mode = 'socks5' | 'http' | null;

export interface ProxyContext {
  /** Currently selected proxy IP (or hostname like "lax.PrOxYIp.example.net"). */
  proxyIP: string;

  /** Mode of upstream proxying: SOCKS5, HTTP-CONNECT, or none. */
  socks5Mode: Socks5Mode;

  /** When true, all traffic is forced through SOCKS5 regardless of destination. */
  socks5GlobalEnabled: boolean;

  /** Raw SOCKS5 auth string (user:pass@host:port). */
  socks5Auth: string;

  /** Parsed form of socks5Auth. */
  parsedSocks5: Socks5Address;

  /** Domains forced to route through SOCKS5 (from GO2SOCKS5 env var). */
  socks5Whitelist: string[];

  /**
   * If proxy IP fails, fall back to direct connection.
   * False when user has explicitly configured PROXYIP.
   */
  proxyFallbackEnabled: boolean;

  /** Cached round-robin state for the proxy IP array. */
  cachedProxyIP: string | null;
  cachedProxyArray: Array<[string, number]> | null;
  cachedProxyIndex: number;

  /** Verbose logging switch (DEBUG env var). */
  debugLogEnabled: boolean;

  /** Active subscription configuration loaded from KV. */
  configJson: any;
}

/**
 * Default empty context. Each request mutates fields in place.
 */
export function createDefaultContext(): ProxyContext {
  return {
    proxyIP: '',
    socks5Mode: null,
    socks5GlobalEnabled: false,
    socks5Auth: '',
    parsedSocks5: { hostname: '', port: 0 },
    socks5Whitelist: [
      '*tapecontent.net',
      '*cloudatacdn.com',
      '*loadshare.org',
      '*cdn-centaurus.com',
      'scholar.google.com',
    ],
    proxyFallbackEnabled: true,
    cachedProxyIP: null,
    cachedProxyArray: null,
    cachedProxyIndex: 0,
    debugLogEnabled: false,
    configJson: null,
  };
}
