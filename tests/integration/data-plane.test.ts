// Data-plane end-to-end test.
//
// Spins up:
//   1. A node TCP echo server on a random port.
//   2. The bundled _worker.js inside workerd via wrangler unstable_dev.
//
// Drives a real VLESS frame through a real WebSocket connection to the
// worker, asks it to forward to localhost:<echoPort>, and verifies the
// echoed bytes come back through the WebSocket. This is the only test
// that exercises:
//   - The WebSocket upgrade path (handlers/websocket.ts)
//   - VLESS frame parsing (protocols/vless.ts)
//   - forwardTcp's direct mode (transports/direct.ts)
//   - cloudflare:sockets connect() to a real TCP target
//
// Workerd allows outbound to localhost by default — no special config
// required. If this test ever starts failing on `connect()` errors,
// check whether workerd's network policy was tightened upstream.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';
import { existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as net from 'node:net';
// Node's built-in WebSocket is only stable from 22+; CI runs Node 20.
// Use the `ws` package for a constructor that works on every supported
// Node version.
import WebSocket from 'ws';

const ADMIN_PASSWORD = 'data-plane-test-pw';
const DEFAULT_ENCRYPT_KEY = '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';

let worker: Unstable_DevWorker;
let echoServer: net.Server;
let echoPort: number;
let userID: string;
let userIDBytes: Uint8Array;

function md5x2(text: string): string {
  const firstHex = createHash('md5').update(text).digest('hex');
  return createHash('md5').update(firstHex.slice(7, 27)).digest('hex').toLowerCase();
}

function deriveUserID(password: string, encryptKey: string): string {
  const md5 = md5x2(password + encryptKey);
  return [
    md5.slice(0, 8),
    md5.slice(8, 12),
    '4' + md5.slice(13, 16),
    '8' + md5.slice(17, 20),
    md5.slice(20),
  ].join('-');
}

function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, '');
  if (hex.length !== 32) throw new Error(`bad uuid: ${uuid}`);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Build a VLESS first-packet frame for TCP forwarding to (ipv4, port)
 * carrying `payload` as application data.
 *
 * Frame layout per src/protocols/vless.ts:
 *   [version(1)] [UUID(16)] [optLen(1)] [cmd(1)] [port(2BE)] [atype(1)]
 *   [addr(4 for IPv4)] [payload...]
 */
function buildVlessFrame(
  uuidBytes: Uint8Array,
  ipv4: [number, number, number, number],
  port: number,
  payload: Uint8Array
): Uint8Array {
  const headerLen = 1 + 16 + 1 + 1 + 2 + 1 + 4;
  const frame = new Uint8Array(headerLen + payload.byteLength);
  let p = 0;
  frame[p++] = 0; // version
  frame.set(uuidBytes, p); p += 16;
  frame[p++] = 0; // optLen
  frame[p++] = 1; // cmd = TCP
  frame[p++] = (port >> 8) & 0xff;
  frame[p++] = port & 0xff;
  frame[p++] = 1; // atype = IPv4
  frame[p++] = ipv4[0];
  frame[p++] = ipv4[1];
  frame[p++] = ipv4[2];
  frame[p++] = ipv4[3];
  frame.set(payload, p);
  return frame;
}

beforeAll(async () => {
  if (!existsSync('_worker.js')) {
    throw new Error('_worker.js not found — run `npm run build` first');
  }

  // Boot a TCP echo server on a random port. Each connection mirrors
  // its input straight back out.
  echoServer = net.createServer((sock) => {
    sock.on('data', (chunk) => sock.write(chunk));
    sock.on('error', () => { /* swallow */ });
  });
  await new Promise<void>((resolve) => echoServer.listen(0, '127.0.0.1', () => resolve()));
  echoPort = (echoServer.address() as net.AddressInfo).port;

  worker = await unstable_dev('_worker.js', {
    experimental: { disableExperimentalWarning: true },
    vars: { ADMIN: ADMIN_PASSWORD },
    kv: [{ binding: 'KV', id: 'data-plane-test-kv' }],
    logLevel: 'warn',
  });

  userID = deriveUserID(ADMIN_PASSWORD, DEFAULT_ENCRYPT_KEY);
  userIDBytes = uuidToBytes(userID);
}, 30_000);

afterAll(async () => {
  await new Promise<void>((resolve) => echoServer?.close(() => resolve()));
  await worker?.stop();
});

/** Open a real WebSocket to the running workerd, exchange one message, and
 *  collect all binary frames the worker sends back until either we hit
 *  `expectedBytes` or the socket closes / times out. */
async function vlessRoundTrip(
  frame: Uint8Array,
  expectedBytes: number,
  timeoutMs = 5000
): Promise<{ data: Uint8Array; closed: boolean }> {
  const url = `ws://${worker.address}:${worker.port}/`;
  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';

  const received: Uint8Array[] = [];
  let total = 0;
  let closed = false;

  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', (e: any) =>
      reject(new Error(`ws open failed: ${e?.message || e}`))
    );
  });

  const done = new Promise<void>((resolve) => {
    const timer = setTimeout(() => resolve(), timeoutMs);
    ws.on('message', (data: Buffer | ArrayBuffer | Buffer[]) => {
      // ws delivers a node Buffer by default for binary frames.
      const buf =
        data instanceof Buffer
          ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
          : data instanceof ArrayBuffer
            ? new Uint8Array(data)
            : new Uint8Array(Buffer.concat(data as Buffer[]));
      received.push(buf);
      total += buf.byteLength;
      if (total >= expectedBytes) {
        clearTimeout(timer);
        resolve();
      }
    });
    ws.on('close', () => {
      closed = true;
      clearTimeout(timer);
      resolve();
    });
  });

  ws.send(frame);
  await done;
  try { ws.close() } catch { /* */ }

  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of received) { merged.set(c, off); off += c.byteLength }
  return { data: merged, closed };
}

describe('data plane (real workerd + real TCP echo upstream)', () => {
  it('VLESS frame to localhost echo server round-trips through the worker', async () => {
    const payload = new TextEncoder().encode('hello-from-test');
    const frame = buildVlessFrame(userIDBytes, [127, 0, 0, 1], echoPort, payload);

    // Worker prepends a 2-byte VLESS response header [version, addonsLen=0]
    // before relaying upstream bytes.
    const expectedLen = 2 + payload.byteLength;
    const { data } = await vlessRoundTrip(frame, expectedLen);

    expect(data.byteLength).toBeGreaterThanOrEqual(expectedLen);
    expect(data[0]).toBe(0);
    expect(data[1]).toBe(0);
    expect(new TextDecoder().decode(data.slice(2, expectedLen))).toBe('hello-from-test');
  }, 15_000);

  it('VLESS frame with wrong UUID does not echo data through the worker', async () => {
    const wrongUuidBytes = new Uint8Array(16); // all zeros — will never match userID
    const frame = buildVlessFrame(
      wrongUuidBytes, [127, 0, 0, 1], echoPort, new Uint8Array([0])
    );

    // Wait for either an explicit close OR a timeout with no data.
    // The important property is "no echo from the worker"; whether the
    // worker's close packet reaches node within the timeout is incidental
    // and was flaky on slower CI runners.
    const { data } = await vlessRoundTrip(frame, 999_999, 1500);

    expect(data.byteLength).toBe(0);
  }, 15_000);
});
