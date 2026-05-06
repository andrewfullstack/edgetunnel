// HTTPS-CONNECT (TLS-wrapped HTTP CONNECT) tunnel client.
//
// Used when the upstream proxy itself speaks TLS — the connection from
// us to the proxy is wrapped in our own TLS client, then we send a
// standard HTTP CONNECT inside that TLS tunnel.
//
// Phase 4 module — depends on TlsClient.

import { connect } from 'cloudflare:sockets';
import { byteLength, concatByteArrays, toUint8Array } from '../utils/bytes.js';
import { isIPHostname, stripIPv6Brackets } from '../utils/hostname.js';
import type { LogFn } from '../utils/logger.js';
import type { ProxyContext } from '../state.js';
import { TlsClient } from '../crypto/tls-client.js';
import { wrapTlsSocket, type WrappedTlsSocket } from './tls-wrap.js';

/**
 * Open an HTTPS proxy CONNECT tunnel: TLS handshake to proxy, then HTTP
 * CONNECT inside that TLS tunnel.
 *
 * Implements the AES → ChaCha cipher fallback: if the initial handshake
 * (advertising both AES-GCM and ChaCha20-Poly1305) fails with a
 * cipher/handshake error, retry with ChaCha-only.
 */
export async function httpsConnect(
  ctx: ProxyContext,
  targetHost: string,
  targetPort: number,
  initialData: Uint8Array | null,
  log: LogFn = () => {}
): Promise<WrappedTlsSocket> {
  const { username, password, hostname, port } = ctx.parsedSocks5;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let tlsSocket: TlsClient | null = null;
  const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);

  const needsChachaFallback = (error: any): boolean =>
    /cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(
      error?.message || `${error || ''}`
    );

  const openProxyTls = async (allowChacha = false): Promise<TlsClient> => {
    const proxySocket = connect({ hostname, port });
    try {
      await proxySocket.opened;
      const socket = new TlsClient(proxySocket, {
        serverName: tlsServerName,
        insecure: true,
        allowChacha,
      });
      await socket.handshake();
      log(
        `[HTTPS-PROXY] TLS ${socket.isTls13 ? '1.3' : '1.2'} | cipher: 0x${socket.cipherSuite?.toString(16)}${socket.cipherConfig?.chacha ? ' (ChaCha20)' : ' (AES-GCM)'}`
      );
      return socket;
    } catch (error) {
      try { proxySocket.close() } catch (e) { /* */ }
      throw error;
    }
  };

  try {
    try {
      tlsSocket = await openProxyTls(false);
    } catch (error) {
      if (!needsChachaFallback(error)) throw error;
      log(
        `[HTTPS-PROXY] AES-GCM TLS handshake failed, falling back to ChaCha20: ${(error as any)?.message || error}`
      );
      tlsSocket = await openProxyTls(true);
    }

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
    await tlsSocket!.write(encoder.encode(request));

    let responseBuffer = new Uint8Array(0);
    let headerEndIndex = -1;
    let bytesRead = 0;
    while (headerEndIndex === -1 && bytesRead < 8192) {
      const value = await tlsSocket!.read();
      if (!value) throw new Error('HTTPS proxy closed connection before CONNECT response');
      responseBuffer = concatByteArrays(responseBuffer, value);
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
      throw new Error('HTTPS proxy CONNECT response too long or invalid');
    }

    const statusLine = decoder
      .decode(responseBuffer.slice(0, headerEndIndex))
      .split('\r\n')[0];
    const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
    const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
    if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
      throw new Error(`Connection failed: HTTP ${statusCode}`);
    }

    if (byteLength(initialData) > 0 && initialData) {
      await tlsSocket!.write(toUint8Array(initialData));
    }

    const bufferedData =
      bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
    return wrapTlsSocket(tlsSocket!, bufferedData);
  } catch (error) {
    try { tlsSocket?.close() } catch (e) { /* */ }
    throw error;
  }
}
