// Wrap a TlsClient instance in a "socket-like" interface with readable/
// writable streams + closed promise — so it can be used interchangeably
// with raw Cloudflare sockets.
//
// The TlsClient (defined in src/crypto/tls-client.ts, Phase 4) exposes
// .read() / .write() / .close() but not stream interfaces. This wrapper
// builds ReadableStream and WritableStream around it.

import { byteLength, toUint8Array } from '../utils/bytes.js';

interface TlsLikeSocket {
  read(): Promise<Uint8Array | null | undefined>;
  write(data: Uint8Array): Promise<void> | void;
  close(): Promise<void> | void;
}

export interface WrappedTlsSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  closed: Promise<void>;
  close(): void;
}

/**
 * Wrap a TLS-client-like object in stream interfaces.
 *
 * @param tlsSocket   - object with read() / write() / close()
 * @param bufferedData - optional bytes to enqueue before starting reads
 *                       (e.g. CONNECT response leftover that contained
 *                       the first tunnel data byte)
 */
export function wrapTlsSocket(
  tlsSocket: TlsLikeSocket,
  bufferedData: Uint8Array | null = null
): WrappedTlsSocket {
  let closedSettled = false;
  let resolveClosed!: () => void;
  let rejectClosed!: (err: any) => void;

  const settleClosed = (settle: any, value?: any) => {
    if (!closedSettled) {
      closedSettled = true;
      settle(value);
    }
  };

  const closed = new Promise<void>((resolve, reject) => {
    resolveClosed = resolve;
    rejectClosed = reject;
  });

  const close = () => {
    try { tlsSocket.close() } catch (e) { /* */ }
    settleClosed(resolveClosed);
  };

  const readable = new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        if (byteLength(bufferedData) > 0 && bufferedData) {
          controller.enqueue(bufferedData);
        }
        while (true) {
          const data = await tlsSocket.read();
          if (!data) break;
          if (data.byteLength > 0) controller.enqueue(data);
        }
        try { controller.close() } catch (e) { /* */ }
        settleClosed(resolveClosed);
      } catch (error) {
        try { controller.error(error) } catch (e) { /* */ }
        settleClosed(rejectClosed, error);
      }
    },
    cancel() {
      close();
    },
  });

  const writable = new WritableStream<Uint8Array>({
    async write(chunk) {
      await tlsSocket.write(toUint8Array(chunk));
    },
    close,
    abort(error) {
      close();
      if (error) settleClosed(rejectClosed, error);
    },
  });

  return { readable, writable, closed, close };
}
