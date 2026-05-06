import { describe, it, expect } from 'vitest';
import {
  buildTlsRecord,
  buildHandshakeMessage,
  TlsRecordParser,
  TlsHandshakeParser,
  shouldIgnoreTlsAlert,
  xorSequenceIntoIv,
} from '../../src/crypto/tls-record.js';
import {
  CONTENT_TYPE_HANDSHAKE,
  CONTENT_TYPE_APPLICATION_DATA,
  TLS_VERSION_12,
  HANDSHAKE_TYPE_CLIENT_HELLO,
  ALERT_LEVEL_WARNING,
  ALERT_UNRECOGNIZED_NAME,
} from '../../src/constants.js';

describe('buildTlsRecord', () => {
  it('builds a TLS record with header + fragment', () => {
    const fragment = new Uint8Array([0xaa, 0xbb, 0xcc]);
    const record = buildTlsRecord(CONTENT_TYPE_HANDSHAKE, fragment);
    expect(record[0]).toBe(CONTENT_TYPE_HANDSHAKE);
    expect(record[1]).toBe(0x03);
    expect(record[2]).toBe(0x03); // TLS 1.2
    expect(record[3]).toBe(0x00);
    expect(record[4]).toBe(0x03); // length = 3
    expect(Array.from(record.slice(5))).toEqual([0xaa, 0xbb, 0xcc]);
  });

  it('uses default version TLS 1.2', () => {
    const record = buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, new Uint8Array([1]));
    expect((record[1] << 8) | record[2]).toBe(TLS_VERSION_12);
  });

  it('respects custom version', () => {
    const record = buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, new Uint8Array([1]), 0x0301);
    expect((record[1] << 8) | record[2]).toBe(0x0301);
  });
});

describe('buildHandshakeMessage', () => {
  it('builds a handshake message with type + 24-bit length + body', () => {
    const body = new Uint8Array([1, 2, 3]);
    const msg = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, body);
    expect(msg[0]).toBe(HANDSHAKE_TYPE_CLIENT_HELLO);
    // Length = 3 in 3 bytes big-endian
    expect(msg[1]).toBe(0);
    expect(msg[2]).toBe(0);
    expect(msg[3]).toBe(3);
    expect(Array.from(msg.slice(4))).toEqual([1, 2, 3]);
  });
});

describe('TlsRecordParser', () => {
  it('parses a complete record from a single feed', () => {
    const parser = new TlsRecordParser();
    const record = buildTlsRecord(CONTENT_TYPE_HANDSHAKE, new Uint8Array([0xaa, 0xbb]));
    parser.feed(record);
    const r = parser.next();
    expect(r).not.toBeNull();
    expect(r!.type).toBe(CONTENT_TYPE_HANDSHAKE);
    expect(r!.length).toBe(2);
    expect(Array.from(r!.fragment)).toEqual([0xaa, 0xbb]);
  });

  it('handles fragmented input across multiple feeds', () => {
    const parser = new TlsRecordParser();
    const record = buildTlsRecord(CONTENT_TYPE_HANDSHAKE, new Uint8Array([0xaa, 0xbb, 0xcc]));
    parser.feed(record.slice(0, 4));
    expect(parser.next()).toBeNull(); // not enough data yet
    parser.feed(record.slice(4));
    const r = parser.next();
    expect(r).not.toBeNull();
    expect(Array.from(r!.fragment)).toEqual([0xaa, 0xbb, 0xcc]);
  });

  it('parses multiple records sequentially', () => {
    const parser = new TlsRecordParser();
    const r1 = buildTlsRecord(CONTENT_TYPE_HANDSHAKE, new Uint8Array([1]));
    const r2 = buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, new Uint8Array([2, 3]));
    parser.feed(new Uint8Array([...r1, ...r2]));

    const result1 = parser.next();
    expect(result1!.type).toBe(CONTENT_TYPE_HANDSHAKE);
    expect(Array.from(result1!.fragment)).toEqual([1]);

    const result2 = parser.next();
    expect(result2!.type).toBe(CONTENT_TYPE_APPLICATION_DATA);
    expect(Array.from(result2!.fragment)).toEqual([2, 3]);

    expect(parser.next()).toBeNull();
  });

  it('returns null when buffer is shorter than 5-byte header', () => {
    const parser = new TlsRecordParser();
    parser.feed(new Uint8Array([0x16, 0x03, 0x03])); // only 3 bytes
    expect(parser.next()).toBeNull();
  });
});

describe('TlsHandshakeParser', () => {
  it('parses a complete handshake message', () => {
    const parser = new TlsHandshakeParser();
    const msg = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, new Uint8Array([1, 2, 3]));
    parser.feed(msg);
    const m = parser.next();
    expect(m).not.toBeNull();
    expect(m!.type).toBe(HANDSHAKE_TYPE_CLIENT_HELLO);
    expect(m!.length).toBe(3);
    expect(Array.from(m!.body)).toEqual([1, 2, 3]);
    expect(Array.from(m!.raw)).toEqual([HANDSHAKE_TYPE_CLIENT_HELLO, 0, 0, 3, 1, 2, 3]);
  });

  it('handles fragmentation', () => {
    const parser = new TlsHandshakeParser();
    const msg = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, new Uint8Array([1, 2, 3, 4, 5]));
    parser.feed(msg.slice(0, 3));
    expect(parser.next()).toBeNull();
    parser.feed(msg.slice(3));
    const m = parser.next();
    expect(m).not.toBeNull();
    expect(Array.from(m!.body)).toEqual([1, 2, 3, 4, 5]);
  });
});

describe('shouldIgnoreTlsAlert', () => {
  it('ignores warning unrecognized_name', () => {
    expect(
      shouldIgnoreTlsAlert(new Uint8Array([ALERT_LEVEL_WARNING, ALERT_UNRECOGNIZED_NAME]))
    ).toBe(true);
  });

  it('does not ignore fatal alerts', () => {
    expect(
      shouldIgnoreTlsAlert(new Uint8Array([2, ALERT_UNRECOGNIZED_NAME])) // level=fatal
    ).toBe(false);
  });

  it('does not ignore other warning codes', () => {
    expect(
      shouldIgnoreTlsAlert(new Uint8Array([ALERT_LEVEL_WARNING, 0])) // close_notify
    ).toBe(false);
  });
});

describe('xorSequenceIntoIv', () => {
  it('xors sequence number into the last 8 bytes of the IV', () => {
    const iv = new Uint8Array([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0]);
    const nonce = xorSequenceIntoIv(iv, 1n);
    // IV[11] (last byte) gets xor with low byte of seqNum (1)
    expect(nonce[11]).toBe(0xc0 ^ 0x01);
    // First 4 bytes unchanged
    expect(nonce[0]).toBe(0x10);
    expect(nonce[3]).toBe(0x40);
  });

  it('does not modify the input IV', () => {
    const iv = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    const original = iv.slice();
    xorSequenceIntoIv(iv, 42n);
    expect(Array.from(iv)).toEqual(Array.from(original));
  });
});
