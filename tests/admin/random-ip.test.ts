import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock global fetch before importing the module under test
const fetchMock = vi.fn();
(globalThis as any).fetch = fetchMock;

const { generateRandomIPs } = await import('../../src/admin/random-ip.js');

beforeEach(() => {
  fetchMock.mockReset();
});

describe('generateRandomIPs', () => {
  it('generates the requested count of IPs', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      text: async () => '104.16.0.0/13\n104.18.0.0/15\n',
    });
    const [ips] = await generateRandomIPs({ cf: { asn: 1 } }, 16);
    expect(ips).toHaveLength(16);
  });

  it('falls back to default CIDR if fetch fails', async () => {
    fetchMock.mockRejectedValueOnce(new Error('network down'));
    const [ips] = await generateRandomIPs({ cf: { asn: 1 } }, 4);
    expect(ips).toHaveLength(4);
    // All IPs should be in 104.16.0.0/13 (the fallback CIDR)
    for (const entry of ips) {
      const ip = entry.split(':')[0];
      const firstOctet = parseInt(ip.split('.')[0], 10);
      expect(firstOctet).toBe(104);
    }
  });

  it('uses ISP-specific CIDR file based on cf.asn', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      text: async () => '1.2.3.0/24\n',
    });
    await generateRandomIPs({ cf: { asn: 9808 } }, 1);
    expect(fetchMock).toHaveBeenCalledWith(
      'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/cmcc.txt'
    );
  });

  it('uses generic CIDR file for unknown ASN', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      text: async () => '104.16.0.0/13\n',
    });
    await generateRandomIPs({ cf: { asn: 999999 } }, 1);
    expect(fetchMock).toHaveBeenCalledWith(
      'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt'
    );
  });

  it('uses TLS ports when tls=true', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      text: async () => '104.16.0.0/24\n',
    });
    const [ips] = await generateRandomIPs({ cf: { asn: 1 } }, 30, -1, true);
    const tlsPorts = [443, 2053, 2083, 2087, 2096, 8443];
    for (const ipEntry of ips) {
      const port = parseInt(ipEntry.split(':')[1].split('#')[0], 10);
      expect(tlsPorts).toContain(port);
    }
  });

  it('uses non-TLS ports when tls=false', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      text: async () => '104.16.0.0/24\n',
    });
    const [ips] = await generateRandomIPs({ cf: { asn: 1 } }, 30, -1, false);
    const notlsPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
    for (const ipEntry of ips) {
      const port = parseInt(ipEntry.split(':')[1].split('#')[0], 10);
      expect(notlsPorts).toContain(port);
    }
  });

  it('uses fixed port when provided', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      text: async () => '104.16.0.0/24\n',
    });
    const [ips] = await generateRandomIPs({ cf: { asn: 1 } }, 5, 443, true);
    for (const ipEntry of ips) {
      expect(ipEntry).toContain(':443#');
    }
  });

  it('swaps to non-TLS port when fixed TLS port given but tls=false', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      text: async () => '104.16.0.0/24\n',
    });
    const [ips] = await generateRandomIPs({ cf: { asn: 1 } }, 5, 443, false);
    // 443 is at index 0 of TLS_PORTS, so should map to NOTLS_PORTS[0] = 80
    for (const ipEntry of ips) {
      expect(ipEntry).toContain(':80#');
    }
  });

  it('returns both array and joined-newline forms', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      text: async () => '104.16.0.0/24\n',
    });
    const [ips, joined] = await generateRandomIPs({ cf: { asn: 1 } }, 3);
    expect(ips).toHaveLength(3);
    expect(joined.split('\n')).toHaveLength(3);
    expect(joined.split('\n')[0]).toBe(ips[0]);
  });

  it('uses correct ISP name in remark', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      text: async () => '104.16.0.0/24\n',
    });
    const [ips] = await generateRandomIPs({ cf: { asn: 4837 } }, 2); // Unicom ASN
    for (const ipEntry of ips) {
      expect(ipEntry).toContain('#CF联通优选');
    }
  });
});
