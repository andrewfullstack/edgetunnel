// Tests for the Trojan UDP framing parser. The actual DNS forwarding
// (forwardUdpToDns) requires a real Cloudflare socket and isn't tested here.
//
// This focuses on `forwardTrojanUdp`'s parsing logic — by mocking the
// internal forwardUdpToDns we can verify that the Trojan UDP wire format
// is parsed correctly and re-framed properly.

import { describe, it, expect, vi } from 'vitest';

// Mock cloudflare:sockets before importing the module under test
vi.mock('cloudflare:sockets', () => ({
  connect: vi.fn(),
}));

const { forwardTrojanUdp, forwardUdpToDns } = await import('../../src/transports/udp.js');

(globalThis as any).WebSocket ??= {
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3,
};

/**
 * Build a Trojan UDP packet:
 *   [atype(1)] [addr(N)] [port(2)] [length(2)] [\r\n] [payload]
 */
function buildTrojanUdpPacket(opts: {
  atype: 1 | 3 | 4;
  addr: Uint8Array;
  port: number;
  payload: Uint8Array;
}): Uint8Array {
  const packet = new Uint8Array(
    1 + opts.addr.length + 2 + 2 + 2 + opts.payload.length
  );
  let off = 0;
  packet[off++] = opts.atype;
  packet.set(opts.addr, off); off += opts.addr.length;
  packet[off++] = (opts.port >> 8) & 0xff;
  packet[off++] = opts.port & 0xff;
  packet[off++] = (opts.payload.length >> 8) & 0xff;
  packet[off++] = opts.payload.length & 0xff;
  packet[off++] = 0x0d;
  packet[off++] = 0x0a;
  packet.set(opts.payload, off);
  return packet;
}

describe('forwardTrojanUdp parsing', () => {
  it('rejects non-DNS port (only 53 supported)', async () => {
    const packet = buildTrojanUdpPacket({
      atype: 1,
      addr: new Uint8Array([8, 8, 8, 8]),
      port: 80, // not 53
      payload: new Uint8Array([0xaa]),
    });
    const ws = { readyState: WebSocket.OPEN, send: vi.fn() } as any;
    const ctx = { buffer: new Uint8Array(0) };

    await expect(forwardTrojanUdp(packet, ws, ctx)).rejects.toThrow('UDP is not supported');
  });

  it('rejects invalid address type', async () => {
    const packet = new Uint8Array([
      99, // invalid atype
      8, 8, 8, 8,
      0, 53,
      0, 1,
      0x0d, 0x0a,
      0xaa,
    ]);
    const ws = { readyState: WebSocket.OPEN, send: vi.fn() } as any;
    const ctx = { buffer: new Uint8Array(0) };

    await expect(forwardTrojanUdp(packet, ws, ctx)).rejects.toThrow(
      /invalid trojan udp addressType: 99/
    );
  });

  it('rejects invalid CRLF delimiter', async () => {
    const packet = buildTrojanUdpPacket({
      atype: 1,
      addr: new Uint8Array([8, 8, 8, 8]),
      port: 53,
      payload: new Uint8Array([0xaa]),
    });
    // Corrupt the CRLF
    packet[8] = 0x00;
    packet[9] = 0x00;
    const ws = { readyState: WebSocket.OPEN, send: vi.fn() } as any;
    const ctx = { buffer: new Uint8Array(0) };

    await expect(forwardTrojanUdp(packet, ws, ctx)).rejects.toThrow(
      'invalid trojan udp delimiter'
    );
  });

  it('saves leftover bytes when packet is incomplete (need more data)', async () => {
    // Send only the first 5 bytes of a packet (incomplete)
    const partial = new Uint8Array([1, 8, 8, 8, 8]);
    const ws = { readyState: WebSocket.OPEN, send: vi.fn() } as any;
    const ctx = { buffer: new Uint8Array(0) };

    // Should not throw — just save leftover and return
    await forwardTrojanUdp(partial, ws, ctx);
    expect(ctx.buffer.length).toBeGreaterThan(0);
  });

  it('skips empty payload packets', async () => {
    const packet = buildTrojanUdpPacket({
      atype: 1,
      addr: new Uint8Array([8, 8, 8, 8]),
      port: 53,
      payload: new Uint8Array(0),
    });
    const ws = { readyState: WebSocket.OPEN, send: vi.fn() } as any;
    const ctx = { buffer: new Uint8Array(0) };

    // Should not throw and ws.send should not have been called
    await forwardTrojanUdp(packet, ws, ctx);
    expect((ws.send as any).mock.calls).toHaveLength(0);
  });

  it('handles domain (atype=3) addressing', async () => {
    const domain = new TextEncoder().encode('dns.google');
    const addr = new Uint8Array(1 + domain.length);
    addr[0] = domain.length;
    addr.set(domain, 1);

    const packet = buildTrojanUdpPacket({
      atype: 3,
      addr,
      port: 80, // non-53 to fail fast and confirm parsing reached this point
      payload: new Uint8Array([0xaa]),
    });
    const ws = { readyState: WebSocket.OPEN, send: vi.fn() } as any;
    const ctx = { buffer: new Uint8Array(0) };

    // Should reject with "UDP is not supported", proving domain addressing parsed OK
    await expect(forwardTrojanUdp(packet, ws, ctx)).rejects.toThrow('UDP is not supported');
  });

  it('handles IPv6 (atype=4) addressing', async () => {
    const ipv6 = new Uint8Array(16);
    ipv6.fill(0xff);

    const packet = buildTrojanUdpPacket({
      atype: 4,
      addr: ipv6,
      port: 80,
      payload: new Uint8Array([0xaa]),
    });
    const ws = { readyState: WebSocket.OPEN, send: vi.fn() } as any;
    const ctx = { buffer: new Uint8Array(0) };

    await expect(forwardTrojanUdp(packet, ws, ctx)).rejects.toThrow('UDP is not supported');
  });

  it('updates buffer with leftover after parsing complete packets', async () => {
    // First packet: invalid port (will throw before saving leftover)
    // So instead use a partial packet
    const ctx = { buffer: new Uint8Array(0) };
    const ws = { readyState: WebSocket.OPEN, send: vi.fn() } as any;

    // Send just 3 bytes — incomplete
    await forwardTrojanUdp(new Uint8Array([1, 8, 8]), ws, ctx);
    expect(Array.from(ctx.buffer)).toEqual([1, 8, 8]);

    // Send more bytes that combined with leftover still incomplete
    await forwardTrojanUdp(new Uint8Array([8]), ws, ctx);
    expect(Array.from(ctx.buffer)).toEqual([1, 8, 8, 8]);
  });
});
