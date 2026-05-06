import { describe, it, expect } from 'vitest';
import {
  closeSocketQuietly,
  wsSendAndWait,
  waitConnect,
  CONNECT_TIMEOUT_MS,
} from '../../src/transports/socket-utils.js';

// Provide WebSocket constants since we're in node test env.
(globalThis as any).WebSocket ??= {
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3,
};

describe('closeSocketQuietly', () => {
  it('closes a socket in OPEN state', () => {
    let closed = false;
    const sock = {
      readyState: WebSocket.OPEN,
      close: () => { closed = true; },
    };
    closeSocketQuietly(sock);
    expect(closed).toBe(true);
  });

  it('closes a socket in CLOSING state', () => {
    let closed = false;
    const sock = {
      readyState: WebSocket.CLOSING,
      close: () => { closed = true; },
    };
    closeSocketQuietly(sock);
    expect(closed).toBe(true);
  });

  it('does nothing for sockets in CLOSED state', () => {
    let closed = false;
    const sock = {
      readyState: WebSocket.CLOSED,
      close: () => { closed = true; },
    };
    closeSocketQuietly(sock);
    expect(closed).toBe(false);
  });

  it('does not throw when socket is null', () => {
    expect(() => closeSocketQuietly(null)).not.toThrow();
    expect(() => closeSocketQuietly(undefined)).not.toThrow();
  });

  it('does not throw if close() throws', () => {
    const sock = {
      readyState: WebSocket.OPEN,
      close: () => { throw new Error('boom'); },
    };
    expect(() => closeSocketQuietly(sock)).not.toThrow();
  });
});

describe('wsSendAndWait', () => {
  it('sends synchronously when send() returns undefined', async () => {
    const sent: any[] = [];
    const ws = { send: (data: any) => { sent.push(data); return undefined; } } as any;
    const payload = new Uint8Array([1, 2, 3]);
    await wsSendAndWait(ws, payload);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toBe(payload);
  });

  it('awaits when send() returns a Promise', async () => {
    let resolved = false;
    const ws = {
      send: () => Promise.resolve().then(() => { resolved = true; }),
    } as any;
    await wsSendAndWait(ws, new Uint8Array([1]));
    expect(resolved).toBe(true);
  });

  it('handles ArrayBuffer payload', async () => {
    const sent: any[] = [];
    const ws = { send: (data: any) => { sent.push(data); } } as any;
    const buf = new ArrayBuffer(4);
    await wsSendAndWait(ws, buf);
    expect(sent[0]).toBe(buf);
  });
});

describe('waitConnect', () => {
  it('resolves when socket.opened resolves before timeout', async () => {
    const sock = { opened: Promise.resolve() };
    await expect(waitConnect(sock, 100)).resolves.toBeUndefined();
  });

  it('rejects on timeout when socket.opened never resolves', async () => {
    const sock = { opened: new Promise(() => {}) };
    await expect(waitConnect(sock, 50)).rejects.toThrow('connection timeout');
  });

  it('rejects when socket.opened rejects', async () => {
    const sock = { opened: Promise.reject(new Error('connect refused')) };
    await expect(waitConnect(sock, 100)).rejects.toThrow('connect refused');
  });

  it('default timeout is exposed as a constant', () => {
    expect(CONNECT_TIMEOUT_MS).toBe(1000);
  });
});
