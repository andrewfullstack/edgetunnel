import { describe, it, expect } from 'vitest';
import { readFirstPacket } from '../../src/protocols/dispatch.js';
import { sha224 } from '../../src/crypto/sha224.js';

const TEST_UUID = '550e8400-e29b-41d4-a716-446655440000';
const TEST_UUID_BYTES = new Uint8Array([
  0x55, 0x0e, 0x84, 0x00,
  0xe2, 0x9b,
  0x41, 0xd4,
  0xa7, 0x16,
  0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
]);

/** Wrap a sequence of chunks as a ReadableStream and return its reader. */
function makeReader(chunks: Uint8Array[]): ReadableStreamDefaultReader<Uint8Array> {
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index < chunks.length) {
        controller.enqueue(chunks[index++]);
      } else {
        controller.close();
      }
    },
  }).getReader();
}

function buildVlessFrame(): Uint8Array {
  // Minimal: TCP, IPv4 1.2.3.4:443, no payload
  const frame = new Uint8Array(26);
  let off = 0;
  frame[off++] = 0; // version
  frame.set(TEST_UUID_BYTES, off); off += 16;
  frame[off++] = 0; // optLen
  frame[off++] = 1; // cmd=TCP
  frame[off++] = 0x01; // port high
  frame[off++] = 0xbb; // port low (443)
  frame[off++] = 1; // atype=IPv4
  frame[off++] = 1; frame[off++] = 2; frame[off++] = 3; frame[off++] = 4;
  return frame;
}

function buildTrojanFrame(password: string): Uint8Array {
  const hashHex = sha224(password);
  const hashBytes = new TextEncoder().encode(hashHex);
  // Body: cmd=1 atype=1 ipv4 port=443 CRLF
  const body = new Uint8Array([1, 1, 1, 2, 3, 4, 0x01, 0xbb, 0x0d, 0x0a]);
  const frame = new Uint8Array(56 + 2 + body.length);
  frame.set(hashBytes, 0);
  frame[56] = 0x0d;
  frame[57] = 0x0a;
  frame.set(body, 58);
  return frame;
}

describe('readFirstPacket', () => {
  it('detects a complete VLESS frame in a single chunk', async () => {
    const frame = buildVlessFrame();
    const reader = makeReader([frame]);
    const result = await readFirstPacket(reader, TEST_UUID);

    expect(result).not.toBeNull();
    expect(result?.protocol).toBe('vless');
    expect(result?.hostname).toBe('1.2.3.4');
    expect(result?.port).toBe(443);
  });

  it('detects a complete Trojan frame in a single chunk', async () => {
    const frame = buildTrojanFrame(TEST_UUID); // Trojan password = userID in this project
    const reader = makeReader([frame]);
    const result = await readFirstPacket(reader, TEST_UUID);

    expect(result).not.toBeNull();
    expect(result?.protocol).toBe('trojan');
    expect(result?.hostname).toBe('1.2.3.4');
    expect(result?.port).toBe(443);
  });

  it('handles a VLESS frame split across multiple chunks', async () => {
    const frame = buildVlessFrame();
    // Split arbitrarily
    const chunks = [
      frame.slice(0, 5),
      frame.slice(5, 10),
      frame.slice(10, 18),
      frame.slice(18),
    ];
    const reader = makeReader(chunks);
    const result = await readFirstPacket(reader, TEST_UUID);

    expect(result?.protocol).toBe('vless');
    expect(result?.hostname).toBe('1.2.3.4');
  });

  it('handles a Trojan frame split byte-by-byte', async () => {
    const frame = buildTrojanFrame(TEST_UUID);
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < frame.length; i++) {
      chunks.push(frame.slice(i, i + 1));
    }
    const reader = makeReader(chunks);
    const result = await readFirstPacket(reader, TEST_UUID);

    expect(result?.protocol).toBe('trojan');
  });

  it('returns null for invalid data (neither VLESS nor Trojan)', async () => {
    const garbage = new Uint8Array(200);
    crypto.getRandomValues(garbage);
    const reader = makeReader([garbage]);
    const result = await readFirstPacket(reader, TEST_UUID);

    expect(result).toBeNull();
  });

  it('returns null for empty stream', async () => {
    const reader = makeReader([]);
    const result = await readFirstPacket(reader, TEST_UUID);
    expect(result).toBeNull();
  });

  it('returns null when token is wrong', async () => {
    const frame = buildVlessFrame();
    const reader = makeReader([frame]);
    const result = await readFirstPacket(reader, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
    expect(result).toBeNull();
  });
});
