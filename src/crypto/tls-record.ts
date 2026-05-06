// TLS record / handshake layer parsers + AEAD helpers.
//
// Record format (RFC 5246 / 8446 §5.1):
//   [contentType(1)] [version(2)] [length(2)] [fragment(length)]
//
// Handshake message format (§4):
//   [type(1)] [length(3)] [body(length)]

import {
  concatBytes,
  readUint16,
  readUint24,
  textEncoder,
  toUint8Array,
  uint16be,
  uint64be,
  EMPTY_BYTES,
  tlsBytes,
} from '../utils/bytes.js';
import {
  TLS_VERSION_12,
  ALERT_LEVEL_WARNING,
  ALERT_UNRECOGNIZED_NAME,
} from '../constants.js';
import { hkdfExpandLabel, type HashName } from './hmac-hkdf.js';

// ─── Record building ─────────────────────────────────────────────────

/**
 * Build a TLS record: [contentType] [version] [length(2)] [fragment].
 */
export function buildTlsRecord(
  contentType: number,
  fragment: ArrayBuffer | Uint8Array,
  version: number = TLS_VERSION_12
): Uint8Array {
  const data = toUint8Array(fragment);
  const record = new Uint8Array(5 + data.byteLength);
  record[0] = contentType;
  record[1] = (version >> 8) & 0xff;
  record[2] = version & 0xff;
  record[3] = (data.byteLength >> 8) & 0xff;
  record[4] = data.byteLength & 0xff;
  record.set(data, 5);
  return record;
}

/**
 * Build a TLS handshake message: [type(1)] [length(3)] [body(length)].
 */
export function buildHandshakeMessage(
  handshakeType: number,
  body: Uint8Array
): Uint8Array {
  const lengthBytes = [
    (body.length >> 16) & 0xff,
    (body.length >> 8) & 0xff,
    body.length & 0xff,
  ];
  return tlsBytes(handshakeType, lengthBytes, body);
}

// ─── Streaming parsers (handle partial buffers) ──────────────────────

export interface TlsRecord {
  type: number;
  version: number;
  length: number;
  fragment: Uint8Array;
}

/**
 * Stateful TLS record parser. Feed bytes via `feed()`, pull complete
 * records via `next()`. Handles fragmentation across multiple feeds.
 */
export class TlsRecordParser {
  private buffer: Uint8Array = new Uint8Array(0);

  feed(chunk: ArrayBuffer | Uint8Array): void {
    const bytes = toUint8Array(chunk);
    this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes;
  }

  next(): TlsRecord | null {
    if (this.buffer.length < 5) return null;
    const type = this.buffer[0];
    const version = readUint16(this.buffer, 1);
    const length = readUint16(this.buffer, 3);
    if (this.buffer.length < 5 + length) return null;
    const fragment = this.buffer.subarray(5, 5 + length);
    this.buffer = this.buffer.subarray(5 + length);
    return { type, version, length, fragment };
  }
}

export interface HandshakeMessage {
  type: number;
  length: number;
  body: Uint8Array;
  raw: Uint8Array;
}

/**
 * Stateful TLS handshake-message parser.
 * Operates on the *fragments* of CONTENT_TYPE_HANDSHAKE records.
 */
export class TlsHandshakeParser {
  private buffer: Uint8Array = new Uint8Array(0);

  feed(chunk: ArrayBuffer | Uint8Array): void {
    const bytes = toUint8Array(chunk);
    this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes;
  }

  next(): HandshakeMessage | null {
    if (this.buffer.length < 4) return null;
    const type = this.buffer[0];
    const length = readUint24(this.buffer, 1);
    if (this.buffer.length < 4 + length) return null;
    const body = this.buffer.subarray(4, 4 + length);
    const raw = this.buffer.subarray(0, 4 + length);
    this.buffer = this.buffer.subarray(4 + length);
    return { type, length, body, raw };
  }
}

// ─── TLS Alert helpers ───────────────────────────────────────────────

/**
 * "warning + unrecognized_name" alerts are spurious and should be ignored.
 * Some servers emit them when SNI doesn't match their cert.
 */
export const shouldIgnoreTlsAlert = (fragment: Uint8Array | undefined): boolean =>
  fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;

// ─── AEAD helpers (for TLS 1.2 / 1.3 record-layer encryption) ────────

/**
 * Construct a per-record nonce by XOR-ing the record-layer sequence number
 * into the static IV (RFC 8446 §5.3).
 */
export function xorSequenceIntoIv(iv: Uint8Array, sequenceNumber: bigint): Uint8Array {
  const nonce = iv.slice();
  const seqBytes = uint64be(sequenceNumber);
  for (let i = 0; i < 8; i++) {
    nonce[nonce.length - 8 + i] ^= seqBytes[i];
  }
  return nonce;
}

/**
 * Derive (write_key, write_iv) from a TLS 1.3 traffic secret.
 */
export async function deriveTrafficKeys(
  hash: HashName,
  secret: Uint8Array,
  keyLen: number,
  ivLen: number
): Promise<[Uint8Array, Uint8Array]> {
  return Promise.all([
    hkdfExpandLabel(hash, secret, 'key', EMPTY_BYTES, keyLen),
    hkdfExpandLabel(hash, secret, 'iv', EMPTY_BYTES, ivLen),
  ]) as Promise<[Uint8Array, Uint8Array]>;
}
