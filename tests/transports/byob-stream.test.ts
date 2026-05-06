// Tests for the BYOB streaming pipe (connectStreams).
//
// We construct mock Cloudflare-Socket-like and WebSocket-like objects
// to drive the pipe end-to-end without actual networking.

import { describe, it, expect, vi } from 'vitest';
import { connectStreams } from '../../src/transports/byob-stream.js';

(globalThis as any).WebSocket ??= {
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3,
};

interface MockWS {
  readyState: number;
  sent: ArrayBuffer[];
  send: (data: ArrayBuffer | Uint8Array) => void;
  close?: () => void;
}

function makeMockWebSocket(): MockWS {
  const ws: MockWS = {
    readyState: WebSocket.OPEN,
    sent: [],
    send: function (data: any) {
      // Normalise to ArrayBuffer for comparison
      if (data instanceof ArrayBuffer) {
        this.sent.push(data);
      } else if (data instanceof Uint8Array) {
        this.sent.push(data.slice().buffer);
      } else {
        this.sent.push(data);
      }
    },
    close: vi.fn(),
  };
  return ws;
}

/**
 * Build a mock socket whose readable yields the given chunks then EOF.
 * Disables BYOB by throwing on `getReader({mode:'byob'})` so we exercise
 * the standard reader code path.
 */
function makeMockSocketStandard(chunks: Uint8Array[]) {
  let index = 0;
  const readable = {
    getReader: (opts?: any) => {
      if (opts?.mode === 'byob') {
        throw new TypeError('BYOB not supported');
      }
      return {
        async read() {
          if (index < chunks.length) {
            return { done: false, value: chunks[index++] };
          }
          return { done: true, value: undefined };
        },
        cancel: vi.fn(),
        releaseLock: vi.fn(),
      };
    },
  };
  return { readable };
}

const concatArrayBuffers = (buffers: ArrayBuffer[]): Uint8Array => {
  const total = buffers.reduce((a, b) => a + b.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const b of buffers) {
    out.set(new Uint8Array(b), off);
    off += b.byteLength;
  }
  return out;
};

describe('connectStreams (standard reader path)', () => {
  it('forwards a single chunk to the WebSocket', async () => {
    const ws = makeMockWebSocket();
    const sock = makeMockSocketStandard([new Uint8Array([1, 2, 3])]);

    await connectStreams(sock, ws as any, null, null);

    const combined = concatArrayBuffers(ws.sent);
    expect(Array.from(combined)).toEqual([1, 2, 3]);
  });

  it('prepends headerData to the FIRST send only', async () => {
    const ws = makeMockWebSocket();
    const sock = makeMockSocketStandard([
      new Uint8Array([1, 2]),
      new Uint8Array([3, 4]),
    ]);
    const header = new Uint8Array([0x99]);

    await connectStreams(sock, ws as any, header, null);

    const combined = concatArrayBuffers(ws.sent);
    // 0x99 prepended once at the start
    expect(combined[0]).toBe(0x99);
    expect(Array.from(combined).slice(1)).toEqual([1, 2, 3, 4]);
  });

  it('skips empty chunks', async () => {
    const ws = makeMockWebSocket();
    const sock = makeMockSocketStandard([
      new Uint8Array([1]),
      new Uint8Array(0),
      new Uint8Array([2]),
    ]);

    await connectStreams(sock, ws as any, null, null);
    const combined = concatArrayBuffers(ws.sent);
    expect(Array.from(combined)).toEqual([1, 2]);
  });

  it('calls retryFunc when stream has no data', async () => {
    const ws = makeMockWebSocket();
    const sock = makeMockSocketStandard([]); // no data
    const retryFunc = vi.fn(() => Promise.resolve());

    await connectStreams(sock, ws as any, null, retryFunc);
    expect(retryFunc).toHaveBeenCalledTimes(1);
  });

  it('does NOT call retryFunc when stream has data', async () => {
    const ws = makeMockWebSocket();
    const sock = makeMockSocketStandard([new Uint8Array([1])]);
    const retryFunc = vi.fn(() => Promise.resolve());

    await connectStreams(sock, ws as any, null, retryFunc);
    expect(retryFunc).not.toHaveBeenCalled();
  });

  it('aggregates multiple small chunks before sending', async () => {
    const ws = makeMockWebSocket();
    // Many small chunks - should be batched
    const chunks = Array.from({ length: 10 }, (_, i) => new Uint8Array([i]));
    const sock = makeMockSocketStandard(chunks);

    await connectStreams(sock, ws as any, null, null);
    const combined = concatArrayBuffers(ws.sent);
    expect(Array.from(combined)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });
});
