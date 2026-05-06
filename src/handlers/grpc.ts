// gRPC request handler.
//
// gRPC is similar to XHTTP — POST request with chunked response — but the
// payload is wrapped in gRPC frames:
//
//   [compressionFlag(1)] [length(4 BE)] [protobuf message]
//
// The protobuf message starts with a tag byte (0x0a) + varint-encoded
// length + raw payload bytes. We parse those wrappers off, then treat
// the inner bytes as a VLESS first packet.

import { concatBytes } from '../utils/bytes.js';
import { isSpeedTestSite } from '../utils/hostname.js';
import { parseVlessRequest } from '../protocols/vless.js';
import {
  forwardTcp,
  type ForwardTcpDeps,
  type RemoteConnWrapper,
} from '../transports/direct.js';
import { forwardUdpToDns } from '../transports/udp.js';

const DOWNSTREAM_BUFFER_LIMIT = 64 * 1024;
const DOWNSTREAM_FLUSH_INTERVAL_MS = 20;

/**
 * Handle a gRPC tunnel request.
 *
 * The request body is parsed as a stream of gRPC frames. The first inner
 * payload is auto-classified as VLESS or Trojan (by the byte pattern at
 * offset 56-57), parsed, and used to open the upstream connection.
 * Subsequent frames are forwarded as application data.
 */
export async function handleGrpcRequest(
  deps: ForwardTcpDeps,
  request: Request,
  yourUUID: string
): Promise<Response> {
  if (!request.body) return new Response('Bad Request', { status: 400 });

  const reader = request.body.getReader();
  const remoteConnWrapper: RemoteConnWrapper = {
    socket: null,
    connectingPromise: null,
    retryConnect: null,
  };
  let isDnsQuery = false;
  let currentWriteSocket: any = null;
  let remoteWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;

  const grpcHeaders = new Headers({
    'Content-Type': 'application/grpc',
    'grpc-status': '0',
    'X-Accel-Buffering': 'no',
    'Cache-Control': 'no-store',
  });

  return new Response(
    new ReadableStream<Uint8Array>({
      async start(controller) {
        let closed = false;
        let sendQueue: Uint8Array[] = [];
        let queueBytes = 0;
        let flushTimer: any = null;

        const flushQueue = (force = false) => {
          if (flushTimer) {
            clearTimeout(flushTimer);
            flushTimer = null;
          }
          if ((!force && closed) || queueBytes === 0) return;
          const out = new Uint8Array(queueBytes);
          let offset = 0;
          for (const item of sendQueue) {
            out.set(item, offset);
            offset += item.byteLength;
          }
          sendQueue = [];
          queueBytes = 0;
          try {
            controller.enqueue(out);
          } catch (e) {
            closed = true;
            grpcBridge.readyState = WebSocket.CLOSED;
          }
        };

        // Bridge: wraps each `send()` payload in a gRPC frame and queues for flush
        const grpcBridge = {
          readyState: WebSocket.OPEN,
          send(data: any) {
            if (closed) return;
            const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
            // Build gRPC framing: [0][len-be32][0x0a varint(len) chunk]
            const lenBytes: number[] = [];
            let remaining = chunk.byteLength >>> 0;
            while (remaining > 127) {
              lenBytes.push((remaining & 0x7f) | 0x80);
              remaining >>>= 7;
            }
            lenBytes.push(remaining);
            const protobufLen = 1 + lenBytes.length + chunk.byteLength;
            const frame = new Uint8Array(5 + protobufLen);
            frame[0] = 0;
            frame[1] = (protobufLen >>> 24) & 0xff;
            frame[2] = (protobufLen >>> 16) & 0xff;
            frame[3] = (protobufLen >>> 8) & 0xff;
            frame[4] = protobufLen & 0xff;
            frame[5] = 0x0a; // protobuf field tag
            frame.set(new Uint8Array(lenBytes), 6);
            frame.set(chunk, 6 + lenBytes.length);
            sendQueue.push(frame);
            queueBytes += frame.byteLength;
            if (queueBytes >= DOWNSTREAM_BUFFER_LIMIT) flushQueue();
            else if (!flushTimer) flushTimer = setTimeout(flushQueue, DOWNSTREAM_FLUSH_INTERVAL_MS);
          },
          close() {
            if (this.readyState === WebSocket.CLOSED) return;
            flushQueue(true);
            closed = true;
            this.readyState = WebSocket.CLOSED;
            try { controller.close() } catch (e) { /* */ }
          },
        };

        const closeAll = () => {
          if (closed) return;
          flushQueue(true);
          closed = true;
          grpcBridge.readyState = WebSocket.CLOSED;
          if (flushTimer) clearTimeout(flushTimer);
          if (remoteWriter) {
            try { remoteWriter.releaseLock() } catch (e) { /* */ }
            remoteWriter = null;
          }
          currentWriteSocket = null;
          try { reader.releaseLock() } catch (e) { /* */ }
          try { remoteConnWrapper.socket?.close() } catch (e) { /* */ }
          try { controller.close() } catch (e) { /* */ }
        };

        const releaseRemoteWriter = () => {
          if (remoteWriter) {
            try { remoteWriter.releaseLock() } catch (e) { /* */ }
            remoteWriter = null;
          }
          currentWriteSocket = null;
        };

        const writeRemote = async (
          payload: Uint8Array,
          allowRetry = true
        ): Promise<boolean> => {
          const socket = remoteConnWrapper.socket;
          if (!socket) return false;
          if (socket !== currentWriteSocket) {
            releaseRemoteWriter();
            currentWriteSocket = socket;
            remoteWriter = socket.writable.getWriter();
          }
          try {
            await remoteWriter!.write(payload);
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
          let pending = new Uint8Array(0);

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!value || value.byteLength === 0) continue;

            const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
            const merged = new Uint8Array(pending.length + chunk.length);
            merged.set(pending, 0);
            merged.set(chunk, pending.length);
            pending = merged;

            // Parse complete gRPC frames out of `pending`
            while (pending.byteLength >= 5) {
              const grpcLen =
                ((pending[1] << 24) >>> 0) |
                (pending[2] << 16) |
                (pending[3] << 8) |
                pending[4];
              const frameSize = 5 + grpcLen;
              if (pending.byteLength < frameSize) break;
              const grpcPayload = pending.slice(5, frameSize);
              pending = pending.slice(frameSize);
              if (!grpcPayload.byteLength) continue;

              // Strip protobuf tag + varint length wrapper
              let payload = grpcPayload;
              if (payload.byteLength >= 2 && payload[0] === 0x0a) {
                let shift = 0;
                let offset = 1;
                let varintValid = false;
                while (offset < payload.length) {
                  const cur = payload[offset++];
                  if ((cur & 0x80) === 0) {
                    varintValid = true;
                    break;
                  }
                  shift += 7;
                  if (shift > 35) break;
                }
                if (varintValid) payload = payload.slice(offset);
              }
              if (!payload.byteLength) continue;

              if (isDnsQuery) {
                await forwardUdpToDns(payload, grpcBridge as any, null, null, deps.log);
                continue;
              }

              if (remoteConnWrapper.socket) {
                if (!(await writeRemote(payload))) {
                  throw new Error('Remote socket is not ready');
                }
              } else {
                // First packet — parse VLESS frame and open upstream
                const firstBuf = payload.buffer.slice(
                  payload.byteOffset,
                  payload.byteOffset + payload.byteLength
                ) as ArrayBuffer;

                const result = parseVlessRequest(firstBuf, yourUUID);
                if (result.hasError) {
                  throw new Error(result.message || 'Invalid VLESS request');
                }
                const { port, hostname, rawIndex, version, isUDP } = result;
                deps.log(`[gRPC] vless first: ${hostname}:${port} | UDP: ${isUDP}`);
                if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
                if (isUDP) {
                  if (port !== 53) throw new Error('UDP is not supported');
                  isDnsQuery = true;
                }
                const respHeader = new Uint8Array([version[0], 0]);
                grpcBridge.send(respHeader);
                const rawData = new Uint8Array(firstBuf.slice(rawIndex));
                if (isDnsQuery) {
                  await forwardUdpToDns(rawData, grpcBridge as any, null, null, deps.log);
                } else {
                  await forwardTcp(
                    deps,
                    hostname,
                    port,
                    rawData,
                    grpcBridge as any,
                    null,
                    remoteConnWrapper,
                    yourUUID
                  );
                }
              }
            }
            flushQueue();
          }
        } catch (err: any) {
          deps.log(`[gRPC] error: ${err?.message || err}`);
        } finally {
          releaseRemoteWriter();
          closeAll();
        }
      },
      cancel() {
        try { remoteConnWrapper.socket?.close() } catch (e) { /* */ }
        try { reader.releaseLock() } catch (e) { /* */ }
      },
    }),
    { status: 200, headers: grpcHeaders }
  );
}
