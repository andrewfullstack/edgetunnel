// DNS-over-HTTPS (DoH) query + ECH (Encrypted Client Hello) extraction.
//
// Used by the proxy-IP resolver and admin endpoints to look up DNS records
// without going through the local resolver (which may be polluted by GFW).

import type { LogFn } from './logger.js';

const DEFAULT_DOH_SERVICE = 'https://cloudflare-dns.com/dns-query';

const RECORD_TYPE_MAP: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  HTTPS: 65,
};

export interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
  rdata: Uint8Array;
}

/**
 * Encode a domain name as a DNS wire-format labels sequence.
 *   "example.com" → [7]example[3]com[0]
 */
function encodeDnsName(name: string): Uint8Array {
  const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
  const bufs: Uint8Array[] = [];
  for (const label of parts) {
    const enc = new TextEncoder().encode(label);
    bufs.push(new Uint8Array([enc.length]), enc);
  }
  bufs.push(new Uint8Array([0]));
  const total = bufs.reduce((s, b) => s + b.length, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const b of bufs) {
    result.set(b, off);
    off += b.length;
  }
  return result;
}

/**
 * Parse a DNS-encoded name starting at `pos` (handling pointer compression).
 * Returns [decoded name, end-of-record offset].
 */
function parseDnsName(buf: Uint8Array, pos: number): [string, number] {
  const labels: string[] = [];
  let p = pos;
  let jumped = false;
  let endPos = -1;
  let safe = 128;
  while (p < buf.length && safe-- > 0) {
    const len = buf[p];
    if (len === 0) {
      if (!jumped) endPos = p + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      // Pointer
      if (!jumped) endPos = p + 2;
      p = ((len & 0x3f) << 8) | buf[p + 1];
      jumped = true;
      continue;
    }
    labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
    p += len + 1;
  }
  if (endPos === -1) endPos = p + 1;
  return [labels.join('.'), endPos];
}

/**
 * Query a DNS record over HTTPS (RFC 8484).
 *
 * @param domain      hostname to query
 * @param recordType  'A' | 'AAAA' | 'TXT' | 'CNAME' | 'MX' | 'NS' | 'SRV' | 'HTTPS'
 * @param dohService  DoH endpoint URL (default: Cloudflare 1.1.1.1)
 * @param log         logger callback
 *
 * Returns an array of parsed answers; empty array on error or no results.
 */
export async function dohQuery(
  domain: string,
  recordType: string,
  dohService: string = DEFAULT_DOH_SERVICE,
  log: LogFn = () => {}
): Promise<DohAnswer[]> {
  const startTime = performance.now();
  log(`[DoH] querying ${domain} ${recordType} via ${dohService}`);
  try {
    const qtype = RECORD_TYPE_MAP[recordType.toUpperCase()] || 1;
    const qname = encodeDnsName(domain);

    // Build DNS query message
    const query = new Uint8Array(12 + qname.length + 4);
    const qview = new DataView(query.buffer);
    qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]); // ID
    qview.setUint16(2, 0x0100); // Flags: RD=1
    qview.setUint16(4, 1); // QDCOUNT = 1
    query.set(qname, 12);
    qview.setUint16(12 + qname.length, qtype);
    qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

    const response = await fetch(dohService, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        Accept: 'application/dns-message',
      },
      body: query as any,
    });
    if (!response.ok) {
      console.warn(`[DoH] request failed ${domain} ${recordType}: ${response.status}`);
      return [];
    }

    const buf = new Uint8Array(await response.arrayBuffer());
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const qdcount = dv.getUint16(4);
    const ancount = dv.getUint16(6);
    log(`[DoH] response ${domain} ${recordType}: ${buf.length}B, ${ancount} answers`);

    // Skip Question section
    let offset = 12;
    for (let i = 0; i < qdcount; i++) {
      const [, end] = parseDnsName(buf, offset);
      offset = end + 4;
    }

    // Parse Answer section
    const answers: DohAnswer[] = [];
    for (let i = 0; i < ancount && offset < buf.length; i++) {
      const [name, nameEnd] = parseDnsName(buf, offset);
      offset = nameEnd;
      const type = dv.getUint16(offset);
      offset += 2;
      offset += 2; // CLASS
      const ttl = dv.getUint32(offset);
      offset += 4;
      const rdlen = dv.getUint16(offset);
      offset += 2;
      const rdata = buf.slice(offset, offset + rdlen);
      offset += rdlen;

      let data: string;
      if (type === 1 && rdlen === 4) {
        data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
      } else if (type === 28 && rdlen === 16) {
        const segs: string[] = [];
        for (let j = 0; j < 16; j += 2) {
          segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
        }
        data = segs.join(':');
      } else if (type === 16) {
        // TXT record (length-prefixed strings)
        let tOff = 0;
        const parts: string[] = [];
        while (tOff < rdlen) {
          const tLen = rdata[tOff++];
          parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
          tOff += tLen;
        }
        data = parts.join('');
      } else if (type === 5) {
        // CNAME record
        const [cname] = parseDnsName(buf, offset - rdlen);
        data = cname;
      } else {
        data = Array.from(rdata).map((b) => b.toString(16).padStart(2, '0')).join('');
      }
      answers.push({ name, type, TTL: ttl, data, rdata });
    }

    const elapsed = (performance.now() - startTime).toFixed(2);
    log(`[DoH] complete ${domain} ${recordType}: ${elapsed}ms, ${answers.length} results`);
    return answers;
  } catch (error: any) {
    const elapsed = (performance.now() - startTime).toFixed(2);
    console.error(`[DoH] error ${domain} ${recordType} ${elapsed}ms:`, error);
    return [];
  }
}

/**
 * Look up the ECH (Encrypted Client Hello) configuration for a host
 * via its HTTPS DNS record. Returns base64-encoded ECH config or empty
 * string if not found.
 *
 * SVCB/HTTPS rdata format:
 *   [SvcPriority(2)] [TargetName(variable)] [SvcParams(key,len,value)*]
 *
 * The ECH config lives under SvcParam key=5.
 */
export async function getECH(host: string, log: LogFn = () => {}): Promise<string> {
  try {
    const answers = await dohQuery(host, 'HTTPS', DEFAULT_DOH_SERVICE, log);
    if (!answers.length) return '';
    for (const ans of answers) {
      if (ans.type !== 65 || !ans.rdata) continue;
      const bytes = ans.rdata;
      let offset = 2; // skip SvcPriority
      // Skip TargetName (DNS-encoded)
      while (offset < bytes.length) {
        const len = bytes[offset];
        if (len === 0) {
          offset++;
          break;
        }
        offset += len + 1;
      }
      // Iterate SvcParams key/value pairs
      while (offset + 4 <= bytes.length) {
        const key = (bytes[offset] << 8) | bytes[offset + 1];
        const len = (bytes[offset + 2] << 8) | bytes[offset + 3];
        offset += 4;
        // key=5 is ECH
        if (key === 5) {
          return btoa(String.fromCharCode(...bytes.slice(offset, offset + len)));
        }
        offset += len;
      }
    }
    return '';
  } catch (error) {
    console.error('[getECH] error:', error);
    return '';
  }
}
