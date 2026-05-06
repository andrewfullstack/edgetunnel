import { describe, it, expect } from 'vitest';
import { parseSsTargetHeader } from '../../src/handlers/ss-inbound.js';

describe('parseSsTargetHeader', () => {
  it('parses IPv4 address (atype=1)', () => {
    const data = new Uint8Array([
      1, // atype = IPv4
      8, 8, 8, 8, // address
      0x01, 0xbb, // port = 443
      0xaa, 0xbb, 0xcc, // payload
    ]);
    const result = parseSsTargetHeader(data);
    expect(result.hostname).toBe('8.8.8.8');
    expect(result.port).toBe(443);
    expect(Array.from(result.rawData)).toEqual([0xaa, 0xbb, 0xcc]);
  });

  it('parses domain name (atype=3)', () => {
    const domain = new TextEncoder().encode('www.google.com');
    const data = new Uint8Array(2 + domain.length + 2);
    let off = 0;
    data[off++] = 3; // atype = domain
    data[off++] = domain.length;
    data.set(domain, off); off += domain.length;
    data[off++] = 0x01; data[off++] = 0xbb; // port

    const result = parseSsTargetHeader(data);
    expect(result.hostname).toBe('www.google.com');
    expect(result.port).toBe(443);
    expect(result.rawData.byteLength).toBe(0);
  });

  it('parses IPv6 address (atype=4)', () => {
    const data = new Uint8Array(1 + 16 + 2);
    data[0] = 4; // atype = IPv6
    // Set ::1 (last byte = 1, rest 0)
    data[1 + 15] = 1;
    data[1 + 16] = 0; data[1 + 17] = 80; // port 80

    const result = parseSsTargetHeader(data);
    expect(result.hostname).toBe('0:0:0:0:0:0:0:1');
    expect(result.port).toBe(80);
  });

  it('throws for too-short input', () => {
    expect(() => parseSsTargetHeader(new Uint8Array([1, 2]))).toThrow('invalid ss data');
  });

  it('throws for invalid address type', () => {
    const data = new Uint8Array([99, 1, 2, 3, 4, 5, 6, 7]);
    expect(() => parseSsTargetHeader(data)).toThrow(/invalid ss addressType/);
  });

  it('throws for incomplete IPv4', () => {
    const data = new Uint8Array([1, 1, 2]); // only 2 of 4 IPv4 bytes
    expect(() => parseSsTargetHeader(data)).toThrow(/invalid ss ipv4/);
  });

  it('throws for incomplete domain', () => {
    const data = new Uint8Array([3, 10, 0x77, 0x77, 0x77]); // claims 10 bytes but only 3
    expect(() => parseSsTargetHeader(data)).toThrow(/invalid ss domain/);
  });

  it('rejects speedtest target', () => {
    const domain = new TextEncoder().encode('speed.cloudflare.com');
    const data = new Uint8Array(2 + domain.length + 2);
    let off = 0;
    data[off++] = 3;
    data[off++] = domain.length;
    data.set(domain, off); off += domain.length;
    data[off++] = 0x01; data[off++] = 0xbb;

    expect(() => parseSsTargetHeader(data)).toThrow('Speedtest site is blocked');
  });

  it('returns rawData payload after target header', () => {
    const data = new Uint8Array([
      1, // IPv4
      127, 0, 0, 1, // 127.0.0.1
      0x00, 0x50, // port 80
      0x47, 0x45, 0x54, // "GET"
    ]);
    const result = parseSsTargetHeader(data);
    expect(result.hostname).toBe('127.0.0.1');
    expect(result.port).toBe(80);
    expect(new TextDecoder().decode(result.rawData)).toBe('GET');
  });
});
