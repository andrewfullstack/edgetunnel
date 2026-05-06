// Generate a list of random IPs from CIDR ranges, biased to the user's
// ISP if they're on a recognised Chinese carrier ASN.
//
// Used by the subscription generator when "use random IPs" is enabled
// instead of a curated preferred-IP list.

import { toArray } from '../utils/url.js';

interface IspConfig {
  file: string;
  name: string;
}

const ISP_BY_ASN: Record<string, IspConfig> = {
  '9808':  { file: 'cmcc', name: 'CF移动优选' },
  '4837':  { file: 'cu',   name: 'CF联通优选' },
  '17623': { file: 'cu',   name: 'CF联通优选' },
  '17816': { file: 'cu',   name: 'CF联通优选' },
  '4134':  { file: 'ct',   name: 'CF电信优选' },
};

const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
const NOTLS_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];

const CIDR_BASE_URL = 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR';
const FALLBACK_CIDR = ['104.16.0.0/13'];

interface CfRequestProps {
  cf?: { asn?: number };
}

/** Pick a random IP from a CIDR like "1.2.3.0/24". */
function generateRandomIPFromCIDR(cidr: string): string {
  const [baseIP, prefixLength] = cidr.split('/');
  const prefix = parseInt(prefixLength, 10);
  const hostBits = 32 - prefix;
  const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p, 10) << (24 - i * 8)), 0);
  const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
  const mask = (0xffffffff << hostBits) >>> 0;
  const randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
  return [
    (randomIP >>> 24) & 0xff,
    (randomIP >>> 16) & 0xff,
    (randomIP >>> 8) & 0xff,
    randomIP & 0xff,
  ].join('.');
}

/**
 * Generate a list of random Cloudflare-edge IPs with port + remark suffix.
 *
 * Returns a tuple [array, joined-by-newline]:
 *   [["1.2.3.4:443#CF官方优选1", ...], "1.2.3.4:443#CF官方优选1\n..."]
 *
 * @param request   Cloudflare Request (cf.asn is used to pick CIDR file)
 * @param count     how many IPs to generate (default 16)
 * @param fixedPort -1 for random; otherwise that exact port (with TLS/non-TLS swap)
 * @param tls       TLS mode picks ports from TLS list, else non-TLS
 */
export async function generateRandomIPs(
  request: CfRequestProps,
  count: number = 16,
  fixedPort: number = -1,
  tls: boolean = true
): Promise<[string[], string]> {
  const asn = String(request.cf?.asn || '');
  const isp = ISP_BY_ASN[asn];
  const cidrUrl = isp ? `${CIDR_BASE_URL}/${isp.file}.txt` : `${CIDR_BASE_URL}.txt`;
  const cfname = isp?.name || 'CF官方优选';
  const cfport = tls ? TLS_PORTS : NOTLS_PORTS;

  let cidrList: string[] = [];
  try {
    const res = await fetch(cidrUrl);
    cidrList = res.ok ? toArray(await res.text()) : FALLBACK_CIDR;
  } catch {
    cidrList = FALLBACK_CIDR;
  }
  if (cidrList.length === 0) cidrList = FALLBACK_CIDR;

  const randomIPs = Array.from({ length: count }, (_, index) => {
    const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
    let targetPort: number;
    if (fixedPort === -1) {
      targetPort = cfport[Math.floor(Math.random() * cfport.length)];
    } else if (tls) {
      targetPort = fixedPort;
    } else {
      const tlsIndex = TLS_PORTS.indexOf(Number(fixedPort));
      targetPort = tlsIndex >= 0 ? NOTLS_PORTS[tlsIndex] : fixedPort;
    }
    return `${ip}:${targetPort}#${cfname}${index + 1}`;
  });
  return [randomIPs, randomIPs.join('\n')];
}
