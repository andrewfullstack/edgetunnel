// SOCKS5 / HTTP / HTTPS proxy address parsing.
//
// Parses strings like "user:pass@host:port" or "user:pass@[ipv6]:port"
// (with optional base64-encoded auth) into structured form.
//
// Also: parseProxyParams() reads URL query/path for proxy config and
// mutates ProxyContext accordingly.

import type { ProxyContext } from '../state.js';

const SOCKS5_AUTH_BASE64_PATTERN = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
const IPV6_BRACKETS_PATTERN = /^\[.*\]$/;

export interface ParsedSocks5Address {
  username?: string;
  password?: string;
  hostname: string;
  port: number;
}

/**
 * Parse a SOCKS5 / HTTP / HTTPS proxy address string into components.
 *
 * Supported syntaxes:
 *   "host"
 *   "host:port"
 *   "[ipv6]:port"
 *   "user:pass@host:port"
 *   "<base64(user:pass)>@host:port" (auth gets base64-decoded)
 *
 * @throws on malformed input (port non-numeric, missing password, etc.)
 */
export function parseSocks5Auth(
  address: string,
  defaultPort: number = 80
): ParsedSocks5Address {
  // If there's an @ separator, optionally base64-decode the auth half
  const firstAt = address.lastIndexOf('@');
  if (firstAt !== -1) {
    let auth = address.slice(0, firstAt).replaceAll('%3D', '=');
    // If auth looks base64-encoded (no colon, valid base64 chars), decode it
    if (!auth.includes(':') && SOCKS5_AUTH_BASE64_PATTERN.test(auth)) {
      auth = atob(auth);
    }
    address = `${auth}@${address.slice(firstAt + 1)}`;
  }

  const atIndex = address.lastIndexOf('@');
  const hostPart = atIndex === -1 ? address : address.slice(atIndex + 1);
  const authPart = atIndex === -1 ? '' : address.slice(0, atIndex);
  const [username, password] = authPart ? authPart.split(':') : [];
  if (authPart && !password) {
    throw new Error('Invalid SOCKS auth format: must be "user:password"');
  }

  let hostname = hostPart;
  let port = defaultPort;

  if (hostPart.includes(']:')) {
    // IPv6 with port: [::1]:1080
    const [ipv6Host, ipv6Port = ''] = hostPart.split(']:');
    hostname = ipv6Host + ']';
    port = Number(ipv6Port.replace(/[^\d]/g, ''));
  } else if (!hostPart.startsWith('[')) {
    // hostname:port or just hostname
    const parts = hostPart.split(':');
    if (parts.length === 2) {
      hostname = parts[0];
      port = Number(parts[1].replace(/[^\d]/g, ''));
    }
  }

  if (isNaN(port)) {
    throw new Error('Invalid SOCKS address: port must be numeric');
  }
  if (hostname.includes(':') && !IPV6_BRACKETS_PATTERN.test(hostname)) {
    throw new Error('Invalid SOCKS address: IPv6 must be wrapped in brackets like [2001:db8::1]');
  }
  return { username, password, hostname, port };
}

/**
 * Parse a request URL's query parameters and pathname for proxy
 * configuration markers, and mutate `ctx` accordingly.
 *
 * Recognised forms:
 *   ?socks5=user:pass@host:port          → SOCKS5 proxy
 *   ?http=...                            → HTTP CONNECT proxy
 *   ?https=...                           → HTTPS-wrapped CONNECT proxy
 *   ?globalproxy                         → force global mode
 *   ?proxyip=host:port                   → static reverse proxy IP
 *   /socks5://...   /http://...          → in pathname
 *   /socks5=...     /http=...            → in pathname (= form)
 *   /proxyip=host:port                   → static reverse proxy IP
 */
export async function parseProxyParams(ctx: ProxyContext, url: URL): Promise<void> {
  const { searchParams } = url;
  const pathname = decodeURIComponent(url.pathname);
  const pathLower = pathname.toLowerCase();

  ctx.socks5Auth =
    searchParams.get('socks5') ||
    searchParams.get('http') ||
    searchParams.get('https') ||
    '';
  ctx.socks5GlobalEnabled = searchParams.has('globalproxy');
  if (searchParams.get('socks5')) ctx.socks5Mode = 'socks5';
  else if (searchParams.get('http')) ctx.socks5Mode = 'http';
  else if (searchParams.get('https')) (ctx.socks5Mode as any) = 'https';

  const parseProxyURL = (value: string, forceGlobal: boolean = true): boolean => {
    const match = /^(socks5|http|https):\/\/(.+)$/i.exec(value || '');
    if (!match) return false;
    (ctx.socks5Mode as any) = match[1].toLowerCase();
    ctx.socks5Auth = match[2].split('/')[0];
    if (forceGlobal) ctx.socks5GlobalEnabled = true;
    return true;
  };

  const setProxyIP = (value: string): void => {
    ctx.proxyIP = value;
    ctx.socks5Mode = null;
    ctx.proxyFallbackEnabled = false;
  };

  const extractPathValue = (value: string): string => {
    if (!value.includes('://')) {
      const slashIdx = value.indexOf('/');
      return slashIdx > 0 ? value.slice(0, slashIdx) : value;
    }
    const split = value.split('://');
    if (split.length !== 2) return value;
    const slashIdx = split[1].indexOf('/');
    return slashIdx > 0 ? `${split[0]}://${split[1].slice(0, slashIdx)}` : value;
  };

  const queryProxyIP = searchParams.get('proxyip');
  if (queryProxyIP !== null) {
    if (!parseProxyURL(queryProxyIP)) {
      setProxyIP(queryProxyIP);
      return;
    }
  } else {
    let match: RegExpExecArray | null;
    if ((match = /\/(socks5?|http|https):\/?\/?([^/?#\s]+)/i.exec(pathname))) {
      const type = match[1].toLowerCase();
      (ctx.socks5Mode as any) =
        type === 'http' ? 'http' : type === 'https' ? 'https' : 'socks5';
      ctx.socks5Auth = match[2].split('/')[0];
      ctx.socks5GlobalEnabled = true;
    } else if ((match = /\/(g?s5|socks5|g?http|g?https)=([^/?#\s]+)/i.exec(pathname))) {
      const type = match[1].toLowerCase();
      ctx.socks5Auth = match[2].split('/')[0];
      (ctx.socks5Mode as any) = type.includes('https')
        ? 'https'
        : type.includes('http')
          ? 'http'
          : 'socks5';
      if (type.startsWith('g')) ctx.socks5GlobalEnabled = true;
    } else if ((match = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
      const pathProxyValue = extractPathValue(match[2]);
      if (!parseProxyURL(pathProxyValue)) {
        setProxyIP(pathProxyValue);
        return;
      }
    }
  }

  if (!ctx.socks5Auth) {
    ctx.socks5Mode = null;
    return;
  }

  try {
    ctx.parsedSocks5 = parseSocks5Auth(
      ctx.socks5Auth,
      (ctx.socks5Mode as any) === 'https' ? 443 : 80
    );
    if (searchParams.get('socks5')) ctx.socks5Mode = 'socks5';
    else if (searchParams.get('http')) ctx.socks5Mode = 'http';
    else if (searchParams.get('https')) (ctx.socks5Mode as any) = 'https';
    else (ctx.socks5Mode as any) = ctx.socks5Mode || 'socks5';
  } catch (err: any) {
    console.error('parseProxyParams: socks5 auth parse failed:', err.message);
    ctx.socks5Mode = null;
  }
}
