// Tiny utilities for working with WebSockets and Cloudflare sockets.

/** Default per-attempt connection timeout in milliseconds. */
export const CONNECT_TIMEOUT_MS = 1000;

/**
 * Close a socket-or-websocket without throwing. Tolerates ALREADY_CLOSED,
 * malformed objects, etc. — used in cleanup paths where we just want best-effort.
 */
export function closeSocketQuietly(socket: any): void {
  try {
    if (
      socket?.readyState === WebSocket.OPEN ||
      socket?.readyState === WebSocket.CLOSING
    ) {
      socket.close();
    }
  } catch (error) {
    /* ignore */
  }
}

/**
 * Send data on a WebSocket and await the result if the implementation
 * returns a Promise (Cloudflare Workers' WebSocketPair returns one in
 * some cases; standard browsers return undefined).
 */
export async function wsSendAndWait(webSocket: WebSocket, payload: ArrayBuffer | Uint8Array): Promise<void> {
  const sendResult = (webSocket as any).send(payload);
  if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

/**
 * Wait for a socket to be `opened`, with a timeout. Throws on timeout.
 *
 * Cloudflare's `connect()` returns a Socket whose `opened` resolves once
 * the TCP connection is established (or rejects on connect failure).
 * Without a timeout, slow/dead destinations can hang indefinitely.
 */
export async function waitConnect(
  remoteSock: any,
  timeoutMs: number = CONNECT_TIMEOUT_MS
): Promise<void> {
  await Promise.race([
    remoteSock.opened,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('connection timeout')), timeoutMs)
    ),
  ]);
}
