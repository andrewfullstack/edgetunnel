// WebSocket handler — the data plane for VLESS.
//
// Flow:
//   1. Accept the WebSocket upgrade.
//   2. Wrap the WS into a ReadableStream (handling early-data via
//      sec-websocket-protocol header for some clients).
//   3. Parse the first chunk as a VLESS frame.
//   4. Open upstream via forwardTcp (TCP) or forwardUdpToDns (UDP, DNS only).
//   5. Pump bytes until close.
//
// Trojan and Shadowsocks were dropped — VLESS-only keeps the worker focused
// and slimmer; Cloudflare Workers fronting handles user-facing fallbacks.

import { isSpeedTestSite } from '../utils/hostname.js';
import { parseVlessRequest } from '../protocols/vless.js';
import {
  forwardTcp,
  type ForwardTcpDeps,
  type RemoteConnWrapper,
} from '../transports/direct.js';
import { forwardUdpToDns } from '../transports/udp.js';
import { closeSocketQuietly } from '../transports/socket-utils.js';

/**
 * Top-level WebSocket handler. Accepts the upgrade and returns a 101
 * response with the client side of the WebSocketPair.
 *
 * The actual byte pumping happens asynchronously via .pipeTo() — the
 * Response is returned immediately so Cloudflare completes the upgrade.
 */
export async function handleWebSocketRequest(
  deps: ForwardTcpDeps,
  request: Request,
  yourUUID: string,
  url: URL
): Promise<Response> {
  const wsPair = new WebSocketPair();
  const [clientSock, serverSock] = Object.values(wsPair);
  serverSock.accept();
  serverSock.binaryType = 'arraybuffer';

  const remoteConnWrapper: RemoteConnWrapper = {
    socket: null,
    connectingPromise: null,
    retryConnect: null,
  };
  let isDnsQuery = false;
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  let cancelled = false;
  let streamFinished = false;

  // Build a ReadableStream from the WebSocket message events
  const readable = new ReadableStream<ArrayBuffer>({
    start(controller) {
      const isClosedError = (err: any): boolean => {
        const msg = err?.message || `${err || ''}`;
        return (
          msg.includes('ReadableStream is closed') ||
          msg.includes('The stream is closed') ||
          msg.includes('already closed')
        );
      };
      const safeEnqueue = (data: ArrayBuffer) => {
        if (cancelled || streamFinished) return;
        try {
          controller.enqueue(data);
        } catch (err) {
          streamFinished = true;
          if (!isClosedError(err)) {
            try { controller.error(err) } catch (_) { /* */ }
          }
        }
      };
      const safeClose = () => {
        if (cancelled || streamFinished) return;
        streamFinished = true;
        try {
          controller.close();
        } catch (err) {
          if (!isClosedError(err)) {
            try { controller.error(err) } catch (_) { /* */ }
          }
        }
      };
      const safeError = (err: any) => {
        if (cancelled || streamFinished) return;
        streamFinished = true;
        try { controller.error(err) } catch (_) { /* */ }
      };

      serverSock.addEventListener('message', (event: any) => {
        safeEnqueue(event.data);
      });
      serverSock.addEventListener('close', () => {
        closeSocketQuietly(serverSock);
        safeClose();
      });
      serverSock.addEventListener('error', (err: any) => {
        safeError(err);
        closeSocketQuietly(serverSock);
      });

      if (!earlyDataHeader) return;
      try {
        const binaryString = atob(
          earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/')
        );
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        safeEnqueue(bytes.buffer);
      } catch (error) {
        safeError(error);
      }
    },
    cancel() {
      cancelled = true;
      streamFinished = true;
      closeSocketQuietly(serverSock);
    },
  });

  // ─── Forwarding state ─────────────────────────────────────────────

  let firstPacketParsed = false;
  let currentWriteSocket: any = null;
  let remoteWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;

  const releaseRemoteWriter = () => {
    if (remoteWriter) {
      try { remoteWriter.releaseLock() } catch (e) { /* */ }
      remoteWriter = null;
    }
    currentWriteSocket = null;
  };

  const writeRemote = async (chunk: any, allowRetry = true): Promise<boolean> => {
    const socket = remoteConnWrapper.socket;
    if (!socket) return false;
    if (socket !== currentWriteSocket) {
      releaseRemoteWriter();
      currentWriteSocket = socket;
      remoteWriter = socket.writable.getWriter();
    }
    try {
      await remoteWriter!.write(chunk);
      return true;
    } catch (err) {
      releaseRemoteWriter();
      if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') {
        await remoteConnWrapper.retryConnect();
        return await writeRemote(chunk, false);
      }
      throw err;
    }
  };

  // ─── Main message-handling pipeline ───────────────────────────────

  readable.pipeTo(
    new WritableStream({
      async write(chunk) {
        // DNS-over-UDP forwarding (VLESS UDP for port 53 only)
        if (isDnsQuery) {
          return await forwardUdpToDns(chunk, serverSock, null, null, deps.log);
        }

        // After first packet, just forward to remote
        if (await writeRemote(chunk)) return;

        // First chunk: parse VLESS frame
        if (!firstPacketParsed) {
          firstPacketParsed = true;
          deps.log(
            `[WS] vless first chunk | host: ${url.host} | UA: ${request.headers.get('user-agent') || 'unknown'}`
          );

          const result = parseVlessRequest(chunk, yourUUID);
          if (result.hasError) {
            throw new Error(result.message || 'Invalid VLESS request');
          }
          const { port, hostname, rawIndex, version, isUDP } = result;
          if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
          if (isUDP) {
            if (port === 53) isDnsQuery = true;
            else throw new Error('UDP is not supported');
          }
          const respHeader = new Uint8Array([version[0], 0]);
          const rawData = new Uint8Array((chunk as ArrayBuffer).slice(rawIndex));
          if (isDnsQuery) {
            return forwardUdpToDns(rawData, serverSock, respHeader, null, deps.log);
          }
          await forwardTcp(
            deps,
            hostname,
            port,
            rawData,
            serverSock,
            respHeader,
            remoteConnWrapper,
            yourUUID
          );
        }
      },
      close() {
        releaseRemoteWriter();
      },
      abort() {
        releaseRemoteWriter();
      },
    })
  ).catch((err: any) => {
    const msg = err?.message || `${err}`;
    if (
      msg.includes('Network connection lost') ||
      msg.includes('ReadableStream is closed')
    ) {
      deps.log(`[WS] connection ended: ${msg}`);
    } else {
      deps.log(`[WS] handler failed: ${msg}`);
    }
    releaseRemoteWriter();
    closeSocketQuietly(serverSock);
  });

  return new Response(null, { status: 101, webSocket: clientSock } as any);
}
