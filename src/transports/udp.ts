// UDP transport — DNS-only.
//
// Cloudflare Workers' connect() doesn't support UDP. This project supports
// "UDP via DNS" by tunnelling DNS queries through TCP to 8.8.4.4:53.
//
// forwardUdpToDns: bare DNS query → response (used by VLESS UDP path).

import { connect } from 'cloudflare:sockets';
import { toUint8Array } from '../utils/bytes.js';
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

