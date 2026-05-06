// Buffered protocol dispatcher for XHTTP / gRPC paths.
//
// XHTTP and gRPC don't have the WebSocket "first message" boundary —
// bytes can arrive in arbitrarily small chunks. This dispatcher reads
// from the request body stream and runs the VLESS probe parser until
// it returns 'ok'. If it says 'invalid', the request is rejected.

import {
  tryParseVlessFirstPacket,
  type BufferedVlessFrame,
} from './vless.js';

export type DispatchedFrame = BufferedVlessFrame & {
  reader: ReadableStreamDefaultReader<Uint8Array>;
};

/**
 * Read the first packet from a stream and identify it as VLESS.
 *
 * Reads bytes from `reader`, accumulating into a buffer. After each chunk
 * arrives, tries the VLESS parser. Returns as soon as it succeeds. If the
 * parser says invalid, returns null.
 *
 * @param token - VLESS UUID string.
 */
export async function readFirstPacket(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  token: string
): Promise<DispatchedFrame | null> {
  let buffer = new Uint8Array(1024);
  let offset = 0;

  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      if (offset === 0) return null;
      break;
    }

    const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
    if (offset + chunk.byteLength > buffer.byteLength) {
      const newBuffer = new Uint8Array(
        Math.max(buffer.byteLength * 2, offset + chunk.byteLength)
      );
      newBuffer.set(buffer.subarray(0, offset));
      buffer = newBuffer;
    }

    buffer.set(chunk, offset);
    offset += chunk.byteLength;
    const current = buffer.subarray(0, offset);

    const vless = tryParseVlessFirstPacket(current, token);
    if (vless.status === 'ok') return { ...vless.result, reader };
    if (vless.status === 'invalid') return null;
    // 'need_more' → keep reading.
  }

  // Stream ended; one final attempt with whatever we have.
  const finalBuffer = buffer.subarray(0, offset);
  const vless = tryParseVlessFirstPacket(finalBuffer, token);
  if (vless.status === 'ok') return { ...vless.result, reader };
  return null;
}
