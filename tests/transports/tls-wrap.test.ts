import { describe, it, expect } from 'vitest';
import { wrapTlsSocket } from '../../src/transports/tls-wrap.js';

interface MockTlsSocket {
  read(): Promise<Uint8Array | null>;
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
}

function makeMockTls(reads: (Uint8Array | null)[]): {
  socket: MockTlsSocket;
  writes: Uint8Array[];
  closeCount: number;
  getCloseCount: () => number;
} {
  const writes: Uint8Array[] = [];
  let closeCount = 0;
  let readIndex = 0;
  return {
    socket: {
      async read() {
        if (readIndex < reads.length) return reads[readIndex++];
        return null;
      },
      async write(data) {
        writes.push(data);
      },
      async close() {
        closeCount++;
      },
    },
    writes,
    get closeCount() { return closeCount; },
    getCloseCount: () => closeCount,
  };
}

describe('wrapTlsSocket', () => {
  it('exposes readable / writable / closed / close', () => {
    const mock = makeMockTls([]);
    const wrapped = wrapTlsSocket(mock.socket);
    expect(wrapped.readable).toBeInstanceOf(ReadableStream);
    expect(wrapped.writable).toBeInstanceOf(WritableStream);
    expect(wrapped.closed).toBeInstanceOf(Promise);
    expect(typeof wrapped.close).toBe('function');
  });

  it('streams reads through the readable', async () => {
    const mock = makeMockTls([
      new Uint8Array([1, 2]),
      new Uint8Array([3, 4]),
      null, // EOF
    ]);
    const wrapped = wrapTlsSocket(mock.socket);
    const reader = wrapped.readable.getReader();

    const r1 = await reader.read();
    expect(Array.from(r1.value!)).toEqual([1, 2]);

    const r2 = await reader.read();
    expect(Array.from(r2.value!)).toEqual([3, 4]);

    const r3 = await reader.read();
    expect(r3.done).toBe(true);

    await wrapped.closed;
  });

  it('prepends bufferedData to the readable stream', async () => {
    const mock = makeMockTls([new Uint8Array([3, 4]), null]);
    const buffered = new Uint8Array([1, 2]);
    const wrapped = wrapTlsSocket(mock.socket, buffered);
    const reader = wrapped.readable.getReader();

    // First read should be the buffered data
    const r1 = await reader.read();
    expect(Array.from(r1.value!)).toEqual([1, 2]);

    const r2 = await reader.read();
    expect(Array.from(r2.value!)).toEqual([3, 4]);
  });

  it('writes through the writable to the underlying socket', async () => {
    const mock = makeMockTls([null]);
    const wrapped = wrapTlsSocket(mock.socket);
    const writer = wrapped.writable.getWriter();
    await writer.write(new Uint8Array([5, 6, 7]));
    await writer.close();
    expect(mock.writes).toHaveLength(1);
    expect(Array.from(mock.writes[0])).toEqual([5, 6, 7]);
  });

  it('close() calls underlying close()', () => {
    const mock = makeMockTls([new Uint8Array([1])]);
    const wrapped = wrapTlsSocket(mock.socket);
    wrapped.close();
    expect(mock.getCloseCount()).toBe(1);
  });

  it('skips empty bufferedData', async () => {
    const mock = makeMockTls([new Uint8Array([1]), null]);
    const wrapped = wrapTlsSocket(mock.socket, new Uint8Array(0));
    const reader = wrapped.readable.getReader();
    const r = await reader.read();
    expect(Array.from(r.value!)).toEqual([1]);
  });
});
