import { describe, it, expect } from 'vitest';
import {
  parseVlessRequest,
  tryParseVlessFirstPacket,
} from '../../src/protocols/vless.js';

const TEST_UUID = '550e8400-e29b-41d4-a716-446655440000';

const TEST_UUID_BYTES = new Uint8Array([
  0x55, 0x0e, 0x84, 0x00,
  0xe2, 0x9b,
  0x41, 0xd4,
  0xa7, 0x16,
  0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
]);

/**
 * Build a VLESS frame with the given parameters.
 *
 * Layout:
 *   [version(1)] [UUID(16)] [optLen(1)] [opt(N)] [cmd(1)] [port(2)]
 *   [atype(1)] [addr(N)] [data...]
 */
function buildVlessFrame(opts: {
  version?: number;
  uuid?: Uint8Array;
  optBytes?: Uint8Array;
  cmd: 1 | 2;
  port: number;
  atype: 1 | 2 | 3;
  addr: Uint8Array;
  data?: Uint8Array;
}): Uint8Array {
  const version = opts.version ?? 0;
  const uuid = opts.uuid ?? TEST_UUID_BYTES;
  const opt = opts.optBytes ?? new Uint8Array(0);
  const data = opts.data ?? new Uint8Array(0);
  const headerLen = 1 + 16 + 1 + opt.length + 1 + 2 + 1 + opts.addr.length;
  const frame = new Uint8Array(headerLen + data.length);
  let off = 0;
  frame[off++] = version;
  frame.set(uuid, off); off += 16;
  frame[off++] = opt.length;
  frame.set(opt, off); off += opt.length;
  frame[off++] = opts.cmd;
  frame[off++] = (opts.port >> 8) & 0xff;
  frame[off++] = opts.port & 0xff;
  frame[off++] = opts.atype;
  frame.set(opts.addr, off); off += opts.addr.length;
  frame.set(data, off);
  return frame;
}

// ─── parseVlessRequest (full-frame parser) ────────────────────────────────

describe('parseVlessRequest', () => {
  it('parses a TCP frame with IPv4 address', () => {
    const frame = buildVlessFrame({
      cmd: 1,
      port: 443,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      data: new TextEncoder().encode('GET /'),
    });
    const result = parseVlessRequest(frame, TEST_UUID);

    expect(result.hasError).toBe(false);
    if (result.hasError) return;
    expect(result.hostname).toBe('1.2.3.4');
    expect(result.port).toBe(443);
    expect(result.isUDP).toBe(false);
    expect(result.addressType).toBe(1);
  });

  it('parses a TCP frame with domain address', () => {
    const domain = new TextEncoder().encode('www.google.com');
    const addr = new Uint8Array(1 + domain.length);
    addr[0] = domain.length;
    addr.set(domain, 1);
    const frame = buildVlessFrame({
      cmd: 1,
      port: 443,
      atype: 2,
      addr,
    });
    const result = parseVlessRequest(frame, TEST_UUID);

    expect(result.hasError).toBe(false);
    if (result.hasError) return;
    expect(result.hostname).toBe('www.google.com');
    expect(result.port).toBe(443);
    expect(result.addressType).toBe(2);
  });

  it('parses a UDP frame', () => {
    const frame = buildVlessFrame({
      cmd: 2,
      port: 53,
      atype: 1,
      addr: new Uint8Array([8, 8, 8, 8]),
    });
    const result = parseVlessRequest(frame, TEST_UUID);

    expect(result.hasError).toBe(false);
    if (result.hasError) return;
    expect(result.isUDP).toBe(true);
    expect(result.port).toBe(53);
    expect(result.hostname).toBe('8.8.8.8');
  });

  it('parses an IPv6 frame', () => {
    // 2001:db8::1
    const ipv6Bytes = new Uint8Array([
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ]);
    const frame = buildVlessFrame({
      cmd: 1,
      port: 443,
      atype: 3,
      addr: ipv6Bytes,
    });
    const result = parseVlessRequest(frame, TEST_UUID);

    expect(result.hasError).toBe(false);
    if (result.hasError) return;
    expect(result.hostname).toBe('2001:db8:0:0:0:0:0:1');
    expect(result.addressType).toBe(3);
  });

  it('rejects too-short input', () => {
    const result = parseVlessRequest(new Uint8Array(10), TEST_UUID);
    expect(result.hasError).toBe(true);
  });

  it('rejects wrong UUID', () => {
    const wrongUuid = new Uint8Array(16);
    const frame = buildVlessFrame({
      uuid: wrongUuid,
      cmd: 1,
      port: 443,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
    });
    const result = parseVlessRequest(frame, TEST_UUID);
    expect(result.hasError).toBe(true);
    if (!result.hasError) return;
    expect(result.message).toBe('Invalid uuid');
  });

  it('rejects invalid command', () => {
    const frame = buildVlessFrame({
      cmd: 99 as any,
      port: 443,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
    });
    const result = parseVlessRequest(frame, TEST_UUID);
    expect(result.hasError).toBe(true);
    if (!result.hasError) return;
    expect(result.message).toBe('Invalid command');
  });

  it('rejects invalid address type', () => {
    const frame = buildVlessFrame({
      cmd: 1,
      port: 443,
      atype: 99 as any,
      addr: new Uint8Array([1, 2, 3, 4]),
    });
    const result = parseVlessRequest(frame, TEST_UUID);
    expect(result.hasError).toBe(true);
    if (!result.hasError) return;
    expect(result.message).toMatch(/Invalid address type/);
  });

  it('returns rawIndex pointing to start of payload', () => {
    const payload = new TextEncoder().encode('payload');
    const frame = buildVlessFrame({
      cmd: 1,
      port: 443,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      data: payload,
    });
    const result = parseVlessRequest(frame, TEST_UUID);
    expect(result.hasError).toBe(false);
    if (result.hasError) return;
    // 1 + 16 + 1 + 0 (opt) + 1 + 2 + 1 + 4 = 26
    expect(result.rawIndex).toBe(26);
    const payloadBytes = new Uint8Array(frame.buffer.slice(result.rawIndex));
    expect(new TextDecoder().decode(payloadBytes)).toBe('payload');
  });
});

// ─── tryParseVlessFirstPacket (incremental parser) ────────────────────────

describe('tryParseVlessFirstPacket', () => {
  it('returns "ok" with parsed fields on full input', () => {
    const frame = buildVlessFrame({
      cmd: 1,
      port: 443,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
      data: new Uint8Array([0xaa, 0xbb]),
    });
    const result = tryParseVlessFirstPacket(frame, TEST_UUID);
    expect(result.status).toBe('ok');
    if (result.status !== 'ok') return;
    expect(result.result.hostname).toBe('1.2.3.4');
    expect(result.result.port).toBe(443);
    expect(Array.from(result.result.rawData)).toEqual([0xaa, 0xbb]);
  });

  it('returns "need_more" on partial input', () => {
    expect(tryParseVlessFirstPacket(new Uint8Array(5), TEST_UUID).status).toBe('need_more');
  });

  it('returns "need_more" when address bytes are truncated', () => {
    // Build a domain frame but truncate it before the full domain
    const domain = new TextEncoder().encode('example.com');
    const addr = new Uint8Array(1 + domain.length);
    addr[0] = domain.length;
    addr.set(domain, 1);
    const fullFrame = buildVlessFrame({
      cmd: 1,
      port: 443,
      atype: 2,
      addr,
    });
    // Truncate to before the domain finishes
    const partial = fullFrame.subarray(0, fullFrame.length - 5);
    expect(tryParseVlessFirstPacket(partial, TEST_UUID).status).toBe('need_more');
  });

  it('returns "invalid" for wrong UUID', () => {
    const frame = buildVlessFrame({
      uuid: new Uint8Array(16),
      cmd: 1,
      port: 443,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
    });
    expect(tryParseVlessFirstPacket(frame, TEST_UUID).status).toBe('invalid');
  });

  it('returns "invalid" for unsupported address type', () => {
    const frame = buildVlessFrame({
      cmd: 1,
      port: 443,
      atype: 99 as any,
      addr: new Uint8Array([1, 2, 3, 4]),
    });
    expect(tryParseVlessFirstPacket(frame, TEST_UUID).status).toBe('invalid');
  });

  it('respHeader echoes the version byte with trailing 0', () => {
    const frame = buildVlessFrame({
      version: 0x42,
      cmd: 1,
      port: 443,
      atype: 1,
      addr: new Uint8Array([1, 2, 3, 4]),
    });
    const result = tryParseVlessFirstPacket(frame, TEST_UUID);
    if (result.status !== 'ok') throw new Error('expected ok');
    expect(Array.from(result.result.respHeader)).toEqual([0x42, 0]);
  });
});
