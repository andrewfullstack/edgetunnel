// HTTP CONNECT tunnel client.
//
// Establishes a tunnel through an HTTP/HTTPS forward proxy by sending a
// `CONNECT host:port HTTP/1.1` request and waiting for a 2xx response.

import { connect } from 'cloudflare:sockets';
import { byteLength } from '../utils/bytes.js';
import type { ProxyContext } from '../state.js';

interface HttpConnectResult {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  closed: Promise<void>;
  close: () => void;
}

/**
 * Open an HTTP-CONNECT tunnel to (targetHost, targetPort) via the configured
 * upstream HTTP proxy.
 *
 * @param httpsProxy - if true, the connection to the proxy itself is wrapped
 *                     in TLS (HTTPS proxy mode).
 */
export async function httpConnect(
  ctx: ProxyContext,
  targetHost: string,
  targetPort: number,
  initialData: Uint8Array | null,
  httpsProxy = false
): Promise<any | HttpConnectResult> {
  const { username, password, hostname, port } = ctx.parsedSocks5;
  const socket = httpsProxy
    ? connect({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
    : connect({ hostname, port });

  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  try {
    if (httpsProxy) await socket.opened;

    const auth =
      username && password
        ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n`
        : '';
    const request =
      `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n` +
      `Host: ${targetHost}:${targetPort}\r\n` +
      auth +
      `User-Agent: Mozilla/5.0\r\n` +
      `Connection: keep-alive\r\n\r\n`;

    await writer.write(encoder.encode(request));
    writer.releaseLock();

    // Read response headers until \r\n\r\n.
    let responseBuffer = new Uint8Array(0);
    let headerEndIndex = -1;
    let bytesRead = 0;
    while (headerEndIndex === -1 && bytesRead < 8192) {
      const { done, value } = await reader.read();
      if (done || !value) {
        throw new Error(
          `${httpsProxy ? 'HTTPS' : 'HTTP'} proxy closed connection before CONNECT response`
        );
      }
      responseBuffer = new Uint8Array([...responseBuffer, ...value]);
      bytesRead = responseBuffer.length;

      const idx = responseBuffer.findIndex(
        (_, i) =>
          i < responseBuffer.length - 3 &&
          responseBuffer[i] === 0x0d &&
          responseBuffer[i + 1] === 0x0a &&
          responseBuffer[i + 2] === 0x0d &&
          responseBuffer[i + 3] === 0x0a
      );
      if (idx !== -1) headerEndIndex = idx + 4;
    }

    if (headerEndIndex === -1) {
      throw new Error('Proxy CONNECT response too long or invalid');
    }

    const statusLine = decoder
      .decode(responseBuffer.slice(0, headerEndIndex))
      .split('\r\n')[0];
    const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
    const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
    if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
      throw new Error(`Connection failed: HTTP ${statusCode}`);
    }

    reader.releaseLock();

    if (byteLength(initialData) > 0 && initialData) {
      const w = socket.writable.getWriter();
      await w.write(initialData);
      w.releaseLock();
    }

    // Some proxies stream tunnel data appended to the CONNECT response.
    // Replay the leftover bytes onto the readable stream so the first
    // application packet isn't swallowed.
    if (bytesRead > headerEndIndex) {
      const { readable, writable } = new TransformStream<Uint8Array>();
      const transformWriter = writable.getWriter();
      await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
      transformWriter.releaseLock();
      socket.readable.pipeTo(writable).catch(() => { /* */ });
      return {
        readable,
        writable: socket.writable,
        closed: socket.closed,
        close: () => socket.close(),
      };
    }

    return socket;
  } catch (error) {
    try { writer.releaseLock(); } catch (e) { /* */ }
    try { reader.releaseLock(); } catch (e) { /* */ }
    try { socket.close(); } catch (e) { /* */ }
    throw error;
  }
}
