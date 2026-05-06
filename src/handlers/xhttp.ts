// XHTTP request handler.
//
// XHTTP is a transport that uses standard HTTP POST + chunked response
// streaming to tunnel proxy traffic. This handler:
//   1. Reads the first packet to identify VLESS or Trojan
//   2. Opens an upstream connection via forwardTcp / forwardUdpToDns / forwardTrojanUdp
//   3. Returns a streaming Response, with a "bridge" object mimicking
//      WebSocket's interface so existing transport code can be reused.

import { byteLength } from '../utils/bytes.js';
import { isSpeedTestSite } from '../utils/hostname.js';
import { readFirstPacket } from '../protocols/dispatch.js';
import {
  forwardTcp,
  type ForwardTcpDeps,
  type RemoteConnWrapper,
} from '../transports/direct.js';
import { forwardUdpToDns, forwardTrojanUdp, type TrojanUdpContext } from '../transports/udp.js';
import { closeSocketQuietly } from '../transports/socket-utils.js';

/**
 * Handle an XHTTP request. The body is read as a stream of packets;
 * each packet is forwarded to the upstream socket. Responses stream
 * back as the body of the returned Response.
 */
export async function handleXhttpRequest(
  deps: ForwardTcpDeps,
  request: Request,
  yourUUID: string
): Promise<Response> {
  if (!request.body) return new Response('Bad Request', { status: 400 });

  const reader = request.body.getReader();
  const firstPacket = await readFirstPacket(reader, yourUUID);

  if (!firstPacket) {
    try { reader.releaseLock() } catch (e) { /* */ }
    return new Response('Invalid request', { status: 400 });
  }
  if (isSpeedTestSite(firstPacket.hostname)) {
    try { reader.releaseLock() } catch (e) { /* */ }
    return new Response('Forbidden', { status: 403 });
  }
  if (firstPacket.isUDP && firstPacket.protocol !== 'trojan' && firstPacket.port !== 53) {
    try { reader.releaseLock() } catch (e) { /* */ }
    return new Response('UDP is not supported', { status: 400 });
  }

  const remoteConnWrapper: RemoteConnWrapper = {
    socket: null,
    connectingPromise: null,
    retryConnect: null,
  };
  let currentWriteSocket: any = null;
  let remoteWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;

  const responseHeaders = new Headers({
    'Content-Type': 'application/octet-stream',
    'X-Accel-Buffering': 'no',
    'Cache-Control': 'no-store',
  });

  const releaseRemoteWriter = () => {
    if (remoteWriter) {
      try { remoteWriter.releaseLock() } catch (e) { /* */ }
      remoteWriter = null;
    }
    currentWriteSocket = null;
  };

  const getRemoteWriter = () => {
    const socket = remoteConnWrapper.socket;
    if (!socket) return null;
    if (socket !== currentWriteSocket) {
      releaseRemoteWriter();
      currentWriteSocket = socket;
      remoteWriter = socket.writable.getWriter();
    }
    return remoteWriter;
  };

  return new Response(
    new ReadableStream<Uint8Array>({
      async start(controller) {
        let closed = false;
        let udpRespHeader = firstPacket.respHeader;
        const trojanUdpCtx: TrojanUdpContext = { buffer: new Uint8Array(0) };

        // Bridge: WebSocket-like interface that pushes into the response stream
        const xhttpBridge = {
          readyState: WebSocket.OPEN,
          send(data: any) {
            if (closed) return;
            try {
              const chunk = data instanceof Uint8Array
                ? data
                : data instanceof ArrayBuffer
                  ? new Uint8Array(data)
                  : ArrayBuffer.isView(data)
                    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
                    : new Uint8Array(data);
              controller.enqueue(chunk);
            } catch (e) {
              closed = true;
              this.readyState = WebSocket.CLOSED;
            }
          },
          close() {
            if (closed) return;
            closed = true;
            this.readyState = WebSocket.CLOSED;
            try { controller.close() } catch (e) { /* */ }
          },
        };

        const writeRemote = async (
          payload: Uint8Array,
          allowRetry = true
        ): Promise<boolean> => {
          const writer = getRemoteWriter();
          if (!writer) return false;
          try {
            await writer.write(payload);
            return true;
          } catch (err) {
            releaseRemoteWriter();
            if (allowRetry && typeof remoteConnWrapper.retryConnect === 'function') {
              await remoteConnWrapper.retryConnect();
              return await writeRemote(payload, false);
            }
            throw err;
          }
        };

        try {
          // Forward initial packet's payload (rawData)
          if (firstPacket.isUDP) {
            if (firstPacket.rawData?.byteLength) {
              if (firstPacket.protocol === 'trojan') {
                await forwardTrojanUdp(firstPacket.rawData, xhttpBridge as any, trojanUdpCtx, deps.log);
              } else {
                await forwardUdpToDns(firstPacket.rawData, xhttpBridge as any, udpRespHeader, null, deps.log);
              }
              udpRespHeader = null;
            }
          } else {
            await forwardTcp(
              deps,
              firstPacket.hostname,
              firstPacket.port,
              firstPacket.rawData,
              xhttpBridge as any,
              firstPacket.respHeader,
              remoteConnWrapper,
              yourUUID
            );
          }

          // Pump remaining body bytes from request body to remote
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!value || value.byteLength === 0) continue;
            if (firstPacket.isUDP) {
              if (firstPacket.protocol === 'trojan') {
                await forwardTrojanUdp(value, xhttpBridge as any, trojanUdpCtx, deps.log);
              } else {
                await forwardUdpToDns(value, xhttpBridge as any, udpRespHeader, null, deps.log);
              }
              udpRespHeader = null;
            } else {
              if (!(await writeRemote(value))) {
                throw new Error('Remote socket is not ready');
              }
            }
          }

          // TCP path: close upstream writer when client request body ends
          if (!firstPacket.isUDP) {
            const writer = getRemoteWriter();
            if (writer) {
              try { await writer.close() } catch (e) { /* */ }
            }
          }
        } catch (err: any) {
          deps.log(`[XHTTP] error: ${err?.message || err}`);
          closeSocketQuietly(xhttpBridge);
        } finally {
          releaseRemoteWriter();
          try { reader.releaseLock() } catch (e) { /* */ }
        }
      },
      cancel() {
        releaseRemoteWriter();
        try { remoteConnWrapper.socket?.close() } catch (e) { /* */ }
        try { reader.releaseLock() } catch (e) { /* */ }
      },
    }),
    { status: 200, headers: responseHeaders }
  );
}
