// WebSocket handler — the primary data plane for VLESS / Trojan / SS.
//
// Flow:
//   1. Accept the WebSocket upgrade.
//   2. Wrap the WS into a ReadableStream (handling early-data via
//      sec-websocket-protocol header for some clients).
//   3. On the first chunk, identify the protocol:
//        - URL has ?enc= → Shadowsocks (encrypted from byte 0)
//        - chunk[56..58] == \r\n → Trojan
//        - else → VLESS
//   4. Parse the first packet to get (hostname, port, isUDP, payload).
//   5. Open upstream via forwardTcp / forwardTrojanUdp / forwardUdpToDns.
//   6. Pump bytes until close.

import { byteLength } from '../utils/bytes.js';
import { isSpeedTestSite } from '../utils/hostname.js';
import { parseVlessRequest } from '../protocols/vless.js';
import { parseTrojanRequest } from '../protocols/trojan.js';
import {
  forwardTcp,
  type ForwardTcpDeps,
  type RemoteConnWrapper,
} from '../transports/direct.js';
import { forwardUdpToDns, forwardTrojanUdp, type TrojanUdpContext } from '../transports/udp.js';
import { closeSocketQuietly } from '../transports/socket-utils.js';
import { createSsInbound, parseSsTargetHeader, type SsInboundContext } from './ss-inbound.js';

type Protocol = 'ss' | 'trojan' | 'vless' | null;

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
  let isTrojan: boolean | null = null;
  const trojanUdpCtx: TrojanUdpContext = { buffer: new Uint8Array(0) };
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const ssMode = !!url.searchParams.get('enc');
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

      // SS mode disables sec-websocket-protocol early-data: subprotocol values
      // like "binary" can otherwise be misinterpreted as base64 first-packet
      // bytes and confuse the AEAD decrypter.
      if (ssMode || !earlyDataHeader) return;
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

  let detectedProtocol: Protocol = null;
  let currentWriteSocket: any = null;
  let remoteWriter: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let ssContext: SsInboundContext | null = null;
  let ssInitTask: Promise<SsInboundContext> | null = null;

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

  // ─── SS handling ──────────────────────────────────────────────────

  const getSsContext = async (): Promise<SsInboundContext> => {
    if (ssContext) return ssContext;
    if (!ssInitTask) {
      ssInitTask = (async () => {
        const requestedEnc = (url.searchParams.get('enc') || '').toLowerCase();
        ssContext = createSsInbound(serverSock, yourUUID, requestedEnc, deps.log);
        return ssContext;
      })().finally(() => { ssInitTask = null });
    }
    return ssInitTask;
  };

  const handleSsData = async (chunk: any): Promise<void> => {
    const ctx = await getSsContext();
    let plaintextBlocks: Uint8Array[] = [];
    try {
      plaintextBlocks = await ctx.decryptInput(chunk);
    } catch (err: any) {
      const msg = err?.message || `${err}`;
      if (
        msg.includes('Decryption failed') ||
        msg.includes('SS handshake decrypt failed') ||
        msg.includes('SS length decrypt failed')
      ) {
        deps.log(`[SS-IN] decrypt failed, closing: ${msg}`);
        closeSocketQuietly(serverSock);
        return;
      }
      throw err;
    }

    for (const block of plaintextBlocks) {
      // Try writing through existing upstream first
      let written = false;
      try {
        written = await writeRemote(block, false);
      } catch (_) {
        written = false;
      }
      if (written) continue;

      // If first packet already established, retry through proxy chain
      if (ctx.firstPacketEstablished && ctx.targetHost && ctx.targetPort > 0) {
        await forwardTcp(
          deps,
          ctx.targetHost,
          ctx.targetPort,
          block,
          ctx.bridge as any,
          null,
          remoteConnWrapper,
          yourUUID
        );
        continue;
      }

      // First plaintext block — parse SS target header
      const { hostname, port, rawData } = parseSsTargetHeader(block);
      ctx.firstPacketEstablished = true;
      ctx.targetHost = hostname;
      ctx.targetPort = port;
      await forwardTcp(
        deps,
        hostname,
        port,
        rawData,
        ctx.bridge as any,
        null,
        remoteConnWrapper,
        yourUUID
      );
    }
  };

  // ─── Main message-handling pipeline ───────────────────────────────

  readable.pipeTo(
    new WritableStream({
      async write(chunk) {
        // DNS forwarding mode (UDP via TCP-DNS)
        if (isDnsQuery) {
          if (isTrojan) {
            return await forwardTrojanUdp(chunk, serverSock, trojanUdpCtx, deps.log);
          }
          return await forwardUdpToDns(chunk, serverSock, null, null, deps.log);
        }

        // SS path — all data goes through SS decrypt/encrypt pipelines
        if (detectedProtocol === 'ss') {
          await handleSsData(chunk);
          return;
        }

        // After first packet, just forward to remote
        if (await writeRemote(chunk)) return;

        // Detect protocol from first chunk's byte pattern
        if (detectedProtocol === null) {
          if (url.searchParams.get('enc')) {
            detectedProtocol = 'ss';
          } else {
            const bytes = new Uint8Array(chunk);
            detectedProtocol =
              bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a
                ? 'trojan'
                : 'vless';
          }
          isTrojan = detectedProtocol === 'trojan';
          deps.log(
            `[WS] protocol: ${detectedProtocol} | host: ${url.host} | UA: ${request.headers.get('user-agent') || 'unknown'}`
          );
        }

        if (detectedProtocol === 'ss') {
          await handleSsData(chunk);
          return;
        }
        if (await writeRemote(chunk)) return;

        if (detectedProtocol === 'trojan') {
          const result = parseTrojanRequest(chunk, yourUUID);
          if (result.hasError) {
            throw new Error(result.message || 'Invalid trojan request');
          }
          const { port, hostname, rawClientData, isUDP } = result;
          if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');
          if (isUDP) {
            isDnsQuery = true;
            if (byteLength(rawClientData) > 0) {
              return forwardTrojanUdp(rawClientData as any, serverSock, trojanUdpCtx, deps.log);
            }
            return;
          }
          await forwardTcp(
            deps,
            hostname,
            port,
            new Uint8Array(rawClientData),
            serverSock,
            null,
            remoteConnWrapper,
            yourUUID
          );
        } else {
          isTrojan = false;
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
            if (isTrojan) {
              return forwardTrojanUdp(rawData, serverSock, trojanUdpCtx, deps.log);
            }
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
