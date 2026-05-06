// Buffered protocol dispatcher for XHTTP / gRPC paths.
//
// XHTTP and gRPC don't have the WebSocket "first message" boundary —
// bytes can arrive in arbitrarily small chunks. This dispatcher reads
// from the request body stream and runs the VLESS and Trojan probe
// parsers in parallel until one of them returns 'ok'. If both say
// 'invalid', the request is rejected.

import {
  tryParseVlessFirstPacket,
  type BufferedVlessFrame,
} from './vless.js';
import {
  tryParseTrojanFirstPacket,
  type BufferedTrojanFrame,
} from './trojan.js';

export type DispatchedFrame =
  | (BufferedVlessFrame & { reader: ReadableStreamDefaultReader<Uint8Array> })
  | (BufferedTrojanFrame & { reader: ReadableStreamDefaultReader<Uint8Array> });

/**
 * Read the first packet from a stream and identify the protocol.
 *
 * Reads bytes from `reader`, accumulating into a buffer. After each chunk
 * arrives, tries both Trojan and VLESS parsers. Returns as soon as either
 * succeeds. If both say invalid, returns null.
 *
 * @param token - For VLESS this is the UUID string; for Trojan this is
 *                the password (parser internally hashes it).
 *                In this project the same userID is used for both.
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

    // Try Trojan first (matches original ordering — Trojan has stricter prefix
    // requirements so it short-circuits faster on non-Trojan input).
    const trojan = tryParseTrojanFirstPacket(current, token);
    if (trojan.status === 'ok') return { ...trojan.result, reader };

    const vless = tryParseVlessFirstPacket(current, token);
    if (vless.status === 'ok') return { ...vless.result, reader };

    // Both definitely-invalid → bail.
    if (trojan.status === 'invalid' && vless.status === 'invalid') return null;
    // Otherwise (at least one says 'need_more') keep reading.
  }

  // Stream ended; one final attempt with whatever we have.
  const finalBuffer = buffer.subarray(0, offset);
  const trojan = tryParseTrojanFirstPacket(finalBuffer, token);
  if (trojan.status === 'ok') return { ...trojan.result, reader };
  const vless = tryParseVlessFirstPacket(finalBuffer, token);
  if (vless.status === 'ok') return { ...vless.result, reader };
  return null;
}
