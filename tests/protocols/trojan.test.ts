import { describe, it, expect } from 'vitest';
import {
  parseTrojanRequest,
  tryParseTrojanFirstPacket,
} from '../../src/protocols/trojan.js';
import { sha224 } from '../../src/crypto/sha224.js';

const TEST_PASSWORD = 'SuperSecret123';

/**
 * Build a Trojan frame.
 *
 *   [SHA224(pwd) hex(56)] [\r\n]
 *   [cmd] [atype] [addr] [port(2)] [\r\n]
 *   [data...]
 */
function buildTrojanFrame(opts: {
  password?: string;
  cmd: 1 | 3;
  atype: 1 | 3 | 4;
  addr: Uint8Array;
  port: number;
  data?: Uint8Array;
}): Uint8Array {
  const pwd = opts.password ?? TEST_PASSWORD;
  const hashHex = sha224(pwd);
  const hashBytes = new TextEncoder().encode(hashHex);
  const data = opts.data ?? new Uint8Array(0);

  // Build SOCKS5-style addressing region
  const socksRegion = new Uint8Array(
    2 + opts.addr.length + 2 + 2 // cmd + atype + addr + port + CRLF
  );
  let off = 0;
  socksRegion[off++] = opts.cmd;
  socksRegion[off++] = opts.atype;
  socksRegion.set(opts.addr, off); off += opts.addr.length;
  socksRegion[off++] = (opts.port >> 8) & 0xff;
  socksRegion[off++] = opts.port & 0xff;
  socksRegion[off++] = 0x0d;
  socksRegion[off++] = 0x0a;

  const frame = new Uint8Array(56 + 2 + socksRegion.length + data.length);
  let p = 0;
  frame.set(hashBytes, p); p += 56;
  frame[p++] = 0x0d;
  frame[p++] = 0x0a;
  frame.set(socksRegion, p); p += socksRegion.length;
  frame.set(data, p);
  return frame;
}

describe('parseTrojanRequest', () => {
  it('parses TCP frame with IPv4', () => {
    const frame = buildTrojanFrame({
      cmd: 1,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      port: 443,
    });
    const result = parseTrojanRequest(frame, TEST_PASSWORD);

    expect(result.hasError).toBe(false);
    if (result.hasError) return;
    expect(result.hostname).toBe('1.2.3.4');
    expect(result.port).toBe(443);
    expect(result.isUDP).toBe(false);
    expect(result.addressType).toBe(1);
  });

  it('parses TCP frame with domain', () => {
    const domain = new TextEncoder().encode('www.google.com');
    const addr = new Uint8Array(1 + domain.length);
    addr[0] = domain.length;
    addr.set(domain, 1);

    const frame = buildTrojanFrame({
      cmd: 1,
      atype: 3,
      addr,
      port: 443,
    });
    const result = parseTrojanRequest(frame, TEST_PASSWORD);

    expect(result.hasError).toBe(false);
    if (result.hasError) return;
    expect(result.hostname).toBe('www.google.com');
    expect(result.addressType).toBe(3);
  });

  it('parses UDP frame', () => {
    const frame = buildTrojanFrame({
      cmd: 3,
      atype: 1,
      addr: new Uint8Array([8, 8, 8, 8]),
      port: 53,
    });
    const result = parseTrojanRequest(frame, TEST_PASSWORD);
    expect(result.hasError).toBe(false);
    if (result.hasError) return;
    expect(result.isUDP).toBe(true);
  });

  it('rejects wrong password', () => {
    const frame = buildTrojanFrame({
      cmd: 1,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      port: 443,
    });
    const result = parseTrojanRequest(frame, 'WrongPassword');
    expect(result.hasError).toBe(true);
    if (!result.hasError) return;
    expect(result.message).toBe('invalid password');
  });

  it('rejects missing CRLF separator', () => {
    const frame = buildTrojanFrame({
      cmd: 1,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      port: 443,
    });
    // Corrupt CRLF at position 56-57
    frame[56] = 0x00;
    const result = parseTrojanRequest(frame, TEST_PASSWORD);
    expect(result.hasError).toBe(true);
    if (!result.hasError) return;
    expect(result.message).toBe('invalid header format');
  });

  it('rejects too-short input', () => {
    const result = parseTrojanRequest(new Uint8Array(20), TEST_PASSWORD);
    expect(result.hasError).toBe(true);
  });

  it('rejects unsupported command', () => {
    const frame = buildTrojanFrame({
      cmd: 99 as any,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      port: 443,
    });
    const result = parseTrojanRequest(frame, TEST_PASSWORD);
    expect(result.hasError).toBe(true);
    if (!result.hasError) return;
    expect(result.message).toMatch(/unsupported command/);
  });
});

// ─── Buffered variant ───────────────────────────────────────────────────

describe('tryParseTrojanFirstPacket', () => {
  it('returns "ok" on full frame', () => {
    const frame = buildTrojanFrame({
      cmd: 1,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      port: 443,
      data: new Uint8Array([0xaa, 0xbb]),
    });
    const result = tryParseTrojanFirstPacket(frame, TEST_PASSWORD);
    expect(result.status).toBe('ok');
    if (result.status !== 'ok') return;
    expect(result.result.hostname).toBe('1.2.3.4');
    expect(result.result.port).toBe(443);
    expect(Array.from(result.result.rawData)).toEqual([0xaa, 0xbb]);
  });

  it('returns "need_more" on partial input', () => {
    expect(tryParseTrojanFirstPacket(new Uint8Array(20), TEST_PASSWORD).status).toBe('need_more');
  });

  it('returns "invalid" on wrong CRLF after hash', () => {
    const frame = buildTrojanFrame({
      cmd: 1,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      port: 443,
    });
    frame[56] = 0xff; // corrupt
    expect(tryParseTrojanFirstPacket(frame, TEST_PASSWORD).status).toBe('invalid');
  });

  it('returns "invalid" on wrong password', () => {
    const frame = buildTrojanFrame({
      cmd: 1,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      port: 443,
    });
    expect(tryParseTrojanFirstPacket(frame, 'WrongPassword').status).toBe('invalid');
  });

  it('returns "invalid" on unsupported command', () => {
    const frame = buildTrojanFrame({
      cmd: 99 as any,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      port: 443,
    });
    expect(tryParseTrojanFirstPacket(frame, TEST_PASSWORD).status).toBe('invalid');
  });

  it('respHeader is null (Trojan has no version echo)', () => {
    const frame = buildTrojanFrame({
      cmd: 1,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      port: 443,
    });
    const result = tryParseTrojanFirstPacket(frame, TEST_PASSWORD);
    if (result.status !== 'ok') throw new Error('expected ok');
    expect(result.result.respHeader).toBeNull();
  });
});
