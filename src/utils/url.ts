// URL and string utilities.

/**
 * Sanitise an incoming request URL: remove backslash escapes and fix
 * %3F-encoded query separators.
 *
 * Some clients double-encode the '?' between path and query as '%3F', which
 * Workers' URL parser doesn't recognise as a separator. We rewrite the first
 * occurrence to a real '?' so URLSearchParams works.
 */
export function normalizeRequestUrl(rawUrl: string): string {
  let url = rawUrl.replace(/%5[Cc]/g, '').replace(/\\/g, '');
  const fragmentIndex = url.indexOf('#');
  const body = fragmentIndex === -1 ? url : url.slice(0, fragmentIndex);
  if (body.includes('?') || !/%3f/i.test(body)) return url;
  const fragment = fragmentIndex === -1 ? '' : url.slice(fragmentIndex);
  return body.replace(/%3f/i, '?') + fragment;
}

/**
 * Split a comma/whitespace/quote-delimited string into a clean array.
 *
 * Used for parsing env vars that hold lists (PROXYIP, GO2SOCKS5, HOST, etc.).
 * Handles tabs, quotes, CR/LF, and trims empties.
 */
export function toArray(content: string): string[] {
  let cleaned = content.replace(/[\t"'\r\n]+/g, ',').replace(/,+/g, ',');
  if (cleaned.charAt(0) === ',') cleaned = cleaned.slice(1);
  if (cleaned.charAt(cleaned.length - 1) === ',')
    cleaned = cleaned.slice(0, cleaned.length - 1);
  return cleaned.split(',');
}
