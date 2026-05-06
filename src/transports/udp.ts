// UDP transport — DNS-only.
//
// Cloudflare Workers' connect() doesn't support UDP. This project supports
// "UDP via DNS" by tunnelling DNS queries through TCP to 8.8.4.4:53.
//
// Two flavours:
//   - forwardUdpToDns: bare DNS query → response (used by VLESS UDP path)
//   - forwardTrojanUdp: parses Trojan's UDP frame format (cmd=3) and
//     extracts DNS queries to forward, then re-frames responses for the
//     Trojan client.

import { connect } from 'cloudflare:sockets';
import { byteLength, concatByteArrays, toUint8Array } from '../utils/bytes.js';
import type { LogFn } from '../utils/logger.js';
import { wsSendAndWait } from './socket-utils.js';

/**
 * Forward a DNS query (raw UDP packet bytes) to 8.8.4.4:53 over TCP and
 * stream the responses back through `webSocket`.
 *
 * Optional `responseWrapper` lets the caller transform each response chunk
 * (e.g. to re-frame it for the Trojan UDP wire format).
 *
 * @param respHeader  - prepended to the FIRST response only (e.g. VLESS
 *                      version-echo header). After the first send, set to null.
 */
export async function forwardUdpToDns(
  udpChunk: ArrayBuffer | Uint8Array,
  webSocket: WebSocket,
  respHeader: Uint8Array | null,
  responseWrapper:
    | ((raw: Uint8Array) => Uint8Array | Uint8Array[] | Promise<Uint8Array | Uint8Array[]>)
    | null = null,
  log: LogFn = () => {}
): Promise<void> {
  const requestData = toUint8Array(udpChunk);
  const requestBytes = requestData.byteLength;
  log(`[UDP] DNS query: ${requestBytes}B -> 8.8.4.4:53`);
  try {
    const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
    let pendingHeader = respHeader;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(requestData);
    log(`[UDP] DNS query written: ${requestBytes}B`);
    writer.releaseLock();

    await tcpSocket.readable.pipeTo(
      new WritableStream<Uint8Array>({
        async write(chunk) {
          const rawResponse = toUint8Array(chunk);
          log(`[UDP] DNS response: ${rawResponse.byteLength}B`);
          const wrapped = responseWrapper ? await responseWrapper(rawResponse) : rawResponse;
          const fragments = Array.isArray(wrapped) ? wrapped : [wrapped];
          if (!fragments.length) return;
          if (webSocket.readyState !== WebSocket.OPEN) return;

          for (const fragment of fragments) {
            const out = toUint8Array(fragment);
            if (!out.byteLength) continue;
            if (pendingHeader) {
              const merged = new Uint8Array(pendingHeader.length + out.byteLength);
              merged.set(pendingHeader, 0);
              merged.set(out, pendingHeader.length);
              await wsSendAndWait(webSocket, merged.buffer);
              pendingHeader = null;
            } else {
              await wsSendAndWait(webSocket, out);
            }
          }
        },
      })
    );
  } catch (error: any) {
    log(`[UDP] DNS forwarding failed: ${error?.message || error}`);
  }
}

/**
 * Buffer state for incremental Trojan-UDP packet parsing.
 * Trojan UDP frames can span multiple WS messages, so we keep leftover bytes
 * across calls.
 */
export interface TrojanUdpContext {
  buffer: Uint8Array;
}

/**
 * Forward Trojan-format UDP data. The Trojan UDP wire format is:
 *
 *   [atype(1)] [addr(N)] [port(2)] [length(2)] [\r\n] [payload(length)]
 *
 * Multiple packets can be concatenated. Only DNS (port 53) is supported;
 * other ports throw "UDP is not supported".
 *
 * Each parsed packet's payload is forwarded via forwardUdpToDns, with a
 * responseWrapper that re-frames the DNS reply in the Trojan UDP wire format.
 */
export async function forwardTrojanUdp(
  chunk: ArrayBuffer | Uint8Array,
  webSocket: WebSocket,
  ctx: TrojanUdpContext,
  log: LogFn = () => {}
): Promise<void> {
  const currentChunk = toUint8Array(chunk);
  const cached = ctx?.buffer instanceof Uint8Array ? ctx.buffer : new Uint8Array(0);
  const input = cached.byteLength ? concatByteArrays(cached, currentChunk) : currentChunk;
  let cursor = 0;

  while (cursor < input.byteLength) {
    const packetStart = cursor;
    const atype = input[cursor];
    let addrCursor = cursor + 1;
    let addrLen = 0;
    if (atype === 1) addrLen = 4;
    else if (atype === 4) addrLen = 16;
    else if (atype === 3) {
      if (input.byteLength < addrCursor + 1) break;
      addrLen = 1 + input[addrCursor];
    } else {
      throw new Error(`invalid trojan udp addressType: ${atype}`);
    }

    const portCursor = addrCursor + addrLen;
    if (input.byteLength < portCursor + 6) break;

    const port = (input[portCursor] << 8) | input[portCursor + 1];
    const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
    if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) {
      throw new Error('invalid trojan udp delimiter');
    }

    const payloadStart = portCursor + 6;
    const payloadEnd = payloadStart + payloadLength;
    if (input.byteLength < payloadEnd) break;

    const addrPortHeader = input.slice(packetStart, portCursor + 2);
    const payload = input.slice(payloadStart, payloadEnd);
    cursor = payloadEnd;

    if (port !== 53) throw new Error('UDP is not supported');
    if (!payload.byteLength) continue;

    // Build TCP-DNS query (length-prefixed if not already)
    let tcpDnsQuery: Uint8Array = payload;
    if (
      payload.byteLength < 2 ||
      ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2
    ) {
      tcpDnsQuery = new Uint8Array(payload.byteLength + 2);
      tcpDnsQuery[0] = (payload.byteLength >>> 8) & 0xff;
      tcpDnsQuery[1] = payload.byteLength & 0xff;
      tcpDnsQuery.set(payload, 2);
    }

    const responseCtx: TrojanUdpContext = { buffer: new Uint8Array(0) };
    await forwardUdpToDns(
      tcpDnsQuery,
      webSocket,
      null,
      (dnsRespChunk) => {
        const respChunk = toUint8Array(dnsRespChunk);
        const respInput = responseCtx.buffer.byteLength
          ? concatByteArrays(responseCtx.buffer, respChunk)
          : respChunk;
        const frames: Uint8Array[] = [];
        let respCursor = 0;
        while (respCursor + 2 <= respInput.byteLength) {
          const dnsLen = (respInput[respCursor] << 8) | respInput[respCursor + 1];
          const dnsStart = respCursor + 2;
          const dnsEnd = dnsStart + dnsLen;
          if (dnsEnd > respInput.byteLength) break;
          const dnsPayload = respInput.slice(dnsStart, dnsEnd);
          // Re-frame in Trojan UDP wire format
          const frame = new Uint8Array(addrPortHeader.byteLength + 4 + dnsPayload.byteLength);
          frame.set(addrPortHeader, 0);
          frame[addrPortHeader.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
          frame[addrPortHeader.byteLength + 1] = dnsPayload.byteLength & 0xff;
          frame[addrPortHeader.byteLength + 2] = 0x0d;
          frame[addrPortHeader.byteLength + 3] = 0x0a;
          frame.set(dnsPayload, addrPortHeader.byteLength + 4);
          frames.push(frame);
          respCursor = dnsEnd;
        }
        responseCtx.buffer = respInput.slice(respCursor);
        return frames.length ? frames : new Uint8Array(0);
      },
      log
    );
  }

  if (ctx) ctx.buffer = input.slice(cursor);
}
