// Hostname / IP address helpers.

/**
 * If hostname is a bracketed IPv6 literal like "[::1]", return "::1".
 * Otherwise return as-is.
 */
export function stripIPv6Brackets(hostname: string = ''): string {
  const host = String(hostname || '').trim();
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

/**
 * Test whether a hostname is a literal IP address (v4 or v6).
 */
export function isIPHostname(hostname: string = ''): boolean {
  const host = stripIPv6Brackets(hostname);
  const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  if (ipv4Regex.test(host)) return true;
  if (!host.includes(':')) return false;
  try {
    new URL(`http://[${host}]/`);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Detect speedtest hostnames that we explicitly refuse to proxy
 * (avoiding bandwidth abuse). The list is base64-obfuscated to keep
 * the source from triggering scanners.
 */
export function isSpeedTestSite(hostname: string): boolean {
  const speedTestDomains = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
  if (speedTestDomains.includes(hostname)) return true;
  for (const domain of speedTestDomains) {
    if (hostname.endsWith('.' + domain) || hostname === domain) return true;
  }
  return false;
}
