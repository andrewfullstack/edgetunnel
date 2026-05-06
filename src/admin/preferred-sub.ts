// Preferred-IP subscription fetcher.
//
// Two functions:
//
//   fetchPreferredSubData(host) — fetches a "subscription generator"
//     endpoint (sub://...) which returns a base64 subscription. Extracts
//     IP:port lines from VLESS-style links with a placeholder UUID,
//     and forwards other links separately.
//
//   requestPreferredApi(urls, defaultPort) — fetches a list of preferred-IP
//     APIs (HTTP CSV/text). Auto-detects encoding (UTF-8 / GB2312),
//     parses CSV with various column conventions, and returns
//     [ipResults, plaintextLinks, needConvertUrls, proxyIPPool].

interface SubGenResult {
  preferredIPs: string[];
  otherNodeLinks: string;
}

/**
 * Fetch a single "subscription generator" host (sub://...).
 * Extracts preferred IP:port entries (lines with placeholder UUID +
 * placeholder host "example.com") from the returned subscription.
 */
export async function fetchPreferredSubData(generatorHost: string): Promise<[string[], string]> {
  const preferredIPs: string[] = [];
  let otherNodeLinks = '';

  let formattedHost = generatorHost
    .replace(/^sub:\/\//i, 'https://')
    .split('#')[0]
    .split('?')[0];
  if (!/^https?:\/\//i.test(formattedHost)) formattedHost = `https://${formattedHost}`;

  try {
    const u = new URL(formattedHost);
    formattedHost = u.origin;
  } catch (error: any) {
    preferredIPs.push(`127.0.0.1:1234#${generatorHost}generator format error: ${error.message}`);
    return [preferredIPs, otherNodeLinks];
  }

  const generatorURL = `${formattedHost}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

  try {
    const response = await fetch(generatorURL, {
      headers: {
        'User-Agent': 'v2rayN/edge' + 'tunnel (https://github.com/cmliu/edge' + 'tunnel)',
      },
    });
    if (!response.ok) {
      preferredIPs.push(`127.0.0.1:1234#${generatorHost}generator error: ${response.statusText}`);
      return [preferredIPs, otherNodeLinks];
    }

    const subContent = atob(await response.text());
    const lines = subContent.includes('\r\n') ? subContent.split('\r\n') : subContent.split('\n');

    for (const line of lines) {
      if (!line.trim()) continue;
      if (
        line.includes('00000000-0000-4000-8000-000000000000') &&
        line.includes('example.com')
      ) {
        // Preferred-IP line: extract domain:port#remark
        const match = line.match(/:\/\/[^@]+@([^?]+)/);
        if (match) {
          let addrPort = match[1];
          let remark = '';
          const remarkMatch = line.match(/#(.+)$/);
          if (remarkMatch) remark = '#' + decodeURIComponent(remarkMatch[1]);
          preferredIPs.push(addrPort + remark);
        }
      } else {
        otherNodeLinks += line + '\n';
      }
    }
  } catch (error: any) {
    preferredIPs.push(`127.0.0.1:1234#${generatorHost}generator error: ${error.message}`);
  }

  return [preferredIPs, otherNodeLinks];
}

/**
 * Fetch and aggregate from a list of preferred-IP API URLs.
 *
 * Each URL can be:
 *   - sub://...           → subscription-generator format
 *   - http(s)://...       → plaintext / base64 / CSV with various conventions
 *   - Optional #remark    → annotation appended to each entry
 *   - Optional ?proxyip=true → also collect IPs into the reverse-proxy pool
 *
 * Returns [results, plaintextLinks, needConvertUrls, proxyIPPool].
 */
export async function requestPreferredApi(
  urls: string[],
  defaultPort: string = '443',
  timeoutMs: number = 3000
): Promise<[string[], string[], string[], string[]]> {
  if (!urls?.length) return [[], [], [], []];

  const results = new Set<string>();
  const proxyIPPool = new Set<string>();
  let plaintextLinks = '';
  const needConvertUrls: string[] = [];

  const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;

  await Promise.allSettled(
    urls.map(async (url) => {
      const hashIndex = url.indexOf('#');
      const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
      const apiRemark = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
      const ipsAsProxyIP = url.toLowerCase().includes('proxyip=true');

      // Subscription-generator path
      if (urlWithoutHash.toLowerCase().startsWith('sub://')) {
        try {
          const [preferredIPs, otherLinks] = await fetchPreferredSubData(urlWithoutHash);
          if (apiRemark) {
            for (const ip of preferredIPs) {
              const tagged = ip.includes('#') ? `${ip} [${apiRemark}]` : `${ip}#[${apiRemark}]`;
              results.add(tagged);
              if (ipsAsProxyIP) proxyIPPool.add(ip.split('#')[0]);
            }
          } else {
            for (const ip of preferredIPs) {
              results.add(ip);
              if (ipsAsProxyIP) proxyIPPool.add(ip.split('#')[0]);
            }
          }
          if (otherLinks && typeof otherLinks === 'string' && apiRemark) {
            const taggedLinks = otherLinks.replace(
              /([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi,
              (match, link, lineEnd) => {
                const full = link.includes('#')
                  ? `${link}${encodeURIComponent(` [${apiRemark}]`)}`
                  : `${link}${encodeURIComponent(`#[${apiRemark}]`)}`;
                return `${full}${lineEnd}`;
              }
            );
            plaintextLinks += taggedLinks;
          } else if (otherLinks && typeof otherLinks === 'string') {
            plaintextLinks += otherLinks;
          }
        } catch (e) {
          /* */
        }
        return;
      }

      // Plain URL fetch
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
        const response = await fetch(urlWithoutHash, { signal: controller.signal });
        clearTimeout(timeoutId);

        // Auto-detect encoding (UTF-8 / GB2312)
        let text = '';
        try {
          const buffer = await response.arrayBuffer();
          const contentType = (response.headers.get('content-type') || '').toLowerCase();
          const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';
          let decoders = ['utf-8', 'gb2312'];
          if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
            decoders = ['gb2312', 'utf-8'];
          }

          let decodeSuccess = false;
          for (const dec of decoders) {
            try {
              const decoded = new TextDecoder(dec).decode(buffer);
              if (decoded && decoded.length > 0 && !decoded.includes('�')) {
                text = decoded;
                decodeSuccess = true;
                break;
              }
            } catch (e) {
              continue;
            }
          }
          if (!decodeSuccess) text = await response.text();
          if (!text || text.trim().length === 0) return;
        } catch (e) {
          console.error('Failed to decode response:', e);
          return;
        }

        // Try base64 → plaintext if it looks like one
        let processedText = text;
        const cleanText = typeof text === 'string' ? text.replace(/\s/g, '') : '';
        if (cleanText.length > 0 && cleanText.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanText)) {
          try {
            const bytes = new Uint8Array(atob(cleanText).split('').map((c) => c.charCodeAt(0)));
            processedText = new TextDecoder('utf-8').decode(bytes);
          } catch {
            /* */
          }
        }

        // If body contains protocol links → return as-is
        if (processedText.split('#')[0].includes('://')) {
          if (apiRemark) {
            const tagged = processedText.replace(
              /([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi,
              (match, link, lineEnd) => {
                const full = link.includes('#')
                  ? `${link}${encodeURIComponent(` [${apiRemark}]`)}`
                  : `${link}${encodeURIComponent(`#[${apiRemark}]`)}`;
                return `${full}${lineEnd}`;
              }
            );
            plaintextLinks += tagged + '\n';
          } else {
            plaintextLinks += processedText + '\n';
          }
          return;
        }

        // Otherwise parse as line-based or CSV
        const lines = text.trim().split('\n').map((l) => l.trim()).filter((l) => l);
        const isCSV = lines.length > 1 && lines[0].includes(',');
        const parsedUrl = new URL(urlWithoutHash);

        if (!isCSV) {
          lines.forEach((line) => {
            const lineHashIndex = line.indexOf('#');
            const [hostPart, remark] =
              lineHashIndex > -1
                ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)]
                : [line, ''];
            let hasPort = false;
            if (hostPart.startsWith('[')) {
              hasPort = /\]:(\d+)$/.test(hostPart);
            } else {
              const colonIndex = hostPart.lastIndexOf(':');
              hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
            }
            const port = parsedUrl.searchParams.get('port') || defaultPort;
            const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
            if (apiRemark) {
              const tagged = ipItem.includes('#')
                ? `${ipItem} [${apiRemark}]`
                : `${ipItem}#[${apiRemark}]`;
              results.add(tagged);
            } else {
              results.add(ipItem);
            }
            if (ipsAsProxyIP) proxyIPPool.add(ipItem.split('#')[0]);
          });
        } else {
          const headers = lines[0].split(',').map((h) => h.trim());
          const dataLines = lines.slice(1);
          if (
            headers.includes('IP地址') &&
            headers.includes('端口') &&
            headers.includes('数据中心')
          ) {
            const ipIdx = headers.indexOf('IP地址');
            const portIdx = headers.indexOf('端口');
            const remarkIdx =
              headers.indexOf('国家') > -1
                ? headers.indexOf('国家')
                : headers.indexOf('城市') > -1
                  ? headers.indexOf('城市')
                  : headers.indexOf('数据中心');
            const tlsIdx = headers.indexOf('TLS');
            dataLines.forEach((line) => {
              const cols = line.split(',').map((c) => c.trim());
              if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
              const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
              const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
              if (apiRemark) {
                results.add(`${ipItem} [${apiRemark}]`);
              } else {
                results.add(ipItem);
              }
              if (ipsAsProxyIP) proxyIPPool.add(`${wrappedIP}:${cols[portIdx]}`);
            });
          } else if (
            headers.some((h) => h.includes('IP')) &&
            headers.some((h) => h.includes('延迟')) &&
            headers.some((h) => h.includes('下载速度'))
          ) {
            const ipIdx = headers.findIndex((h) => h.includes('IP'));
            const delayIdx = headers.findIndex((h) => h.includes('延迟'));
            const speedIdx = headers.findIndex((h) => h.includes('下载速度'));
            const port = parsedUrl.searchParams.get('port') || defaultPort;
            dataLines.forEach((line) => {
              const cols = line.split(',').map((c) => c.trim());
              const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
              const ipItem = `${wrappedIP}:${port}#CF优选 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
              if (apiRemark) {
                results.add(`${ipItem} [${apiRemark}]`);
              } else {
                results.add(ipItem);
              }
              if (ipsAsProxyIP) proxyIPPool.add(`${wrappedIP}:${port}`);
            });
          }
        }
      } catch (e) {
        /* */
      }
    })
  );

  const linkArray = plaintextLinks.trim()
    ? [...new Set(plaintextLinks.split(/\r?\n/).filter((line) => line.trim() !== ''))]
    : [];
  return [Array.from(results), linkArray, needConvertUrls, Array.from(proxyIPPool)];
}
