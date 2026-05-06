// Bidirectional streaming with adaptive BYOB (Bring Your Own Buffer) support.
//
// Pumps bytes from a Cloudflare Socket's readable stream into a WebSocket
// (the data plane back to the client). Uses BYOB mode if available to
// avoid per-chunk allocation; falls back to standard ReadableStream reads
// otherwise.
//
// Adaptive flush:
//   - Below ~50 MB/s throughput → flush every 2ms (low latency)
//   - Above 50 MB/s            → flush every 20ms (higher batch efficiency)
//
// This is what the project markets as "BYOB optimization" — see the
// recent beta2.1-BYOB PR.

import { concatByteArrays, toUint8Array } from '../utils/bytes.js';
import type { LogFn } from '../utils/logger.js';
import { closeSocketQuietly, wsSendAndWait } from './socket-utils.js';

export const BYOB_BUFFER_SIZE = 512 * 1024;
export const BYOB_READ_LIMIT = 64 * 1024;
export const BYOB_HIGH_THROUGHPUT_THRESHOLD = 50 * 1024 * 1024;

const NORMAL_AGGREGATION_THRESHOLD = 128 * 1024;
const NORMAL_FLUSH_INTERVAL = 2;
const BYOB_SLOW_FLUSH_INTERVAL = 20;
const BYOB_FAST_FLUSH_INTERVAL = 2;
const BYOB_SAFE_THRESHOLD = BYOB_BUFFER_SIZE - BYOB_READ_LIMIT;

type RetryFn = (() => Promise<void>) | null;

/**
 * Stream `remoteSocket.readable` into `webSocket`, prepending `headerData`
 * (typically the VLESS response header `[version, 0]`) on the first frame.
 *
 * If the stream ends without yielding any data and `retryFunc` is provided,
 * we call retryFunc() to attempt reconnection via the proxy chain.
 *
 * The BYOB / non-BYOB choice is automatic: we try `getReader({ mode: 'byob' })`
 * first and fall through to a normal reader if that throws.
 */
export async function connectStreams(
  remoteSocket: any,
  webSocket: WebSocket,
  headerData: Uint8Array | null,
  retryFunc: RetryFn,
  log: LogFn = () => {}
): Promise<void> {
  let header = headerData;
  let hasData = false;
  let reader: ReadableStreamDefaultReader<Uint8Array> | ReadableStreamBYOBReader;
  let useBYOB = false;

  const sendChunk = async (chunk: Uint8Array): Promise<void> => {
    if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
    if (header) {
      const merged = new Uint8Array(header.length + chunk.byteLength);
      merged.set(header, 0);
      merged.set(chunk, header.length);
      await wsSendAndWait(webSocket, merged.buffer);
      header = null;
    } else {
      await wsSendAndWait(webSocket, chunk);
    }
  };

  try {
    reader = remoteSocket.readable.getReader({ mode: 'byob' });
    useBYOB = true;
  } catch (e) {
    reader = remoteSocket.readable.getReader();
  }

  try {
    if (!useBYOB) {
      await runNormalLoop(reader as ReadableStreamDefaultReader<Uint8Array>, sendChunk, webSocket, () => { hasData = true; });
    } else {
      await runByobLoop(reader as ReadableStreamBYOBReader, sendChunk, webSocket, log, () => { hasData = true; });
    }
  } catch (err) {
    closeSocketQuietly(webSocket);
  } finally {
    try { reader!.cancel() } catch (e) { /* */ }
    try { reader!.releaseLock() } catch (e) { /* */ }
  }

  if (!hasData && retryFunc) await retryFunc();
}

// ─── Standard (non-BYOB) reader loop ─────────────────────────────────

async function runNormalLoop(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  sendChunk: (chunk: Uint8Array) => Promise<void>,
  webSocket: WebSocket,
  markHasData: () => void
): Promise<void> {
  let pendingChunks: Uint8Array[] = [];
  let pendingBytes = 0;
  let flushTimer: any = null;
  let flushTask: Promise<void> | null = null;

  const flush = async (): Promise<void> => {
    if (flushTask) return flushTask;
    flushTask = (async () => {
      if (flushTimer) {
        clearTimeout(flushTimer);
        flushTimer = null;
      }
      if (pendingBytes <= 0) return;
      const chunks = pendingChunks;
      const bytes = pendingBytes;
      pendingChunks = [];
      pendingBytes = 0;
      const payload = chunks.length === 1 ? chunks[0] : concatByteArrays(...chunks);
      if (payload.byteLength || bytes > 0) await sendChunk(payload);
    })().finally(() => {
      flushTask = null;
    });
    return flushTask;
  };

  const pushChunk = async (chunk: Uint8Array): Promise<void> => {
    const bytes = toUint8Array(chunk);
    if (!bytes.byteLength) return;
    pendingChunks.push(bytes);
    pendingBytes += bytes.byteLength;
    if (pendingBytes >= NORMAL_AGGREGATION_THRESHOLD) {
      await flush();
      if (pendingBytes >= NORMAL_AGGREGATION_THRESHOLD) await flush();
    } else if (!flushTimer) {
      flushTimer = setTimeout(() => {
        flush().catch(() => closeSocketQuietly(webSocket));
      }, NORMAL_FLUSH_INTERVAL);
    }
  };

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value || value.byteLength === 0) continue;
    markHasData();
    await pushChunk(value);
  }
  await flush();
}

// ─── BYOB reader loop ────────────────────────────────────────────────

async function runByobLoop(
  reader: ReadableStreamBYOBReader,
  sendChunk: (chunk: Uint8Array) => Promise<void>,
  webSocket: WebSocket,
  log: LogFn,
  markHasData: () => void
): Promise<void> {
  let mainBuf = new ArrayBuffer(BYOB_BUFFER_SIZE);
  let offset = 0;
  let totalBytes = 0;
  let flushIntervalMs = BYOB_FAST_FLUSH_INTERVAL;
  let flushTimer: any = null;
  let resumeFlush: (() => void) | null = null;
  let isReading = false;
  let pendingFlushDuringRead = false;

  const flush = async (): Promise<void> => {
    if (isReading) {
      pendingFlushDuringRead = true;
      return;
    }
    try {
      if (offset > 0) {
        const payload = new Uint8Array(mainBuf.slice(0, offset));
        offset = 0;
        await sendChunk(payload);
      }
    } finally {
      pendingFlushDuringRead = false;
      if (flushTimer) {
        clearTimeout(flushTimer);
        flushTimer = null;
      }
      if (resumeFlush) {
        const r = resumeFlush;
        resumeFlush = null;
        r();
      }
    }
  };

  while (true) {
    isReading = true;
    const { done, value } = await reader.read(new Uint8Array(mainBuf, offset, BYOB_READ_LIMIT));
    isReading = false;
    if (done) break;
    if (!value || value.byteLength === 0) {
      if (pendingFlushDuringRead) await flush();
      continue;
    }
    markHasData();
    mainBuf = value.buffer as ArrayBuffer;
    const len = value.byteLength;

    if (value.byteOffset !== offset) {
      log(`[BYOB] offset mismatch: expected=${offset}, actual=${value.byteOffset}`);
      await sendChunk(new Uint8Array(value.buffer, value.byteOffset, len).slice());
      mainBuf = new ArrayBuffer(BYOB_BUFFER_SIZE);
      offset = 0;
      totalBytes = 0;
      continue;
    }

    if (len < BYOB_READ_LIMIT) {
      flushIntervalMs = BYOB_FAST_FLUSH_INTERVAL;
      if (len < 4096) totalBytes = 0;
      if (offset > 0) {
        offset += len;
        await flush();
      } else {
        await sendChunk(value.slice());
      }
    } else {
      totalBytes += len;
      offset += len;
      if (!flushTimer) {
        flushTimer = setTimeout(() => {
          flush().catch(() => closeSocketQuietly(webSocket));
        }, flushIntervalMs);
      }
      if (pendingFlushDuringRead) await flush();
      if (offset > BYOB_SAFE_THRESHOLD) {
        if (totalBytes > BYOB_HIGH_THROUGHPUT_THRESHOLD) {
          flushIntervalMs = BYOB_SLOW_FLUSH_INTERVAL;
        }
        await new Promise<void>((r) => {
          resumeFlush = r;
        });
      }
    }
  }
  isReading = false;
  await flush();
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
}
