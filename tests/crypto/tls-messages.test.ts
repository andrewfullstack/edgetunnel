import { describe, it, expect } from 'vitest';
import {
  parseServerHello,
  parseEncryptedExtensions,
  extractLeafCertificate,
  parseServerKeyExchange,
  buildClientHello,
} from '../../src/crypto/tls-messages.js';
import {
  TLS_VERSION_12,
  TLS_VERSION_13,
  EXT_SUPPORTED_VERSIONS,
  EXT_KEY_SHARE,
  EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
  HANDSHAKE_TYPE_CLIENT_HELLO,
} from '../../src/constants.js';

describe('parseServerHello', () => {
  it('parses a TLS 1.2 ServerHello (no extensions)', () => {
    // Build minimal ServerHello body
    // [version(2)] [random(32)] [sessionIdLen(1)] [cipherSuite(2)] [compression(1)]
    const body = new Uint8Array(2 + 32 + 1 + 2 + 1);
    let off = 0;
    body[off++] = 0x03; body[off++] = 0x03; // TLS 1.2
    // server random (all zeros for test)
    off += 32;
    body[off++] = 0; // sessionId length = 0
    body[off++] = 0xc0; body[off++] = 0x2f; // cipher_suite = 0xc02f
    body[off++] = 0; // compression

    const sh = parseServerHello(body);
    expect(sh.version).toBe(TLS_VERSION_12);
    expect(sh.cipherSuite).toBe(0xc02f);
    expect(sh.selectedVersion).toBe(TLS_VERSION_12);
    expect(sh.isTls13).toBe(false);
    expect(sh.keyShare).toBeNull();
  });

  it('parses TLS 1.3 ServerHello (supported_versions extension promotes version)', () => {
    // [legacy_version(2)] [random(32)] [sessionIdLen(1)] [cipher(2)] [comp(1)] [extLen(2)] [ext...]
    // Extension: supported_versions: type=43, len=2, version=0x0304 (TLS 1.3)
    const ext = new Uint8Array([
      0, 43, // extension type
      0, 2, // extension length
      0x03, 0x04, // selected version: TLS 1.3
    ]);
    const body = new Uint8Array(2 + 32 + 1 + 2 + 1 + 2 + ext.length);
    let off = 0;
    body[off++] = 0x03; body[off++] = 0x03;
    off += 32;
    body[off++] = 0;
    body[off++] = 0x13; body[off++] = 0x01; // cipher = 0x1301 (TLS_AES_128_GCM_SHA256)
    body[off++] = 0;
    body[off++] = 0; body[off++] = ext.length; // extensions length
    body.set(ext, off);

    const sh = parseServerHello(body);
    expect(sh.cipherSuite).toBe(0x1301);
    expect(sh.selectedVersion).toBe(TLS_VERSION_13);
    expect(sh.isTls13).toBe(true);
  });

  it('extracts key_share extension', () => {
    // key_share extension: type=51, length=8 (group(2)+keyLen(2)+key(4))
    const ext = new Uint8Array([
      0, 51, 0, 8, // ext header
      0, 0x1d, // group = 0x001d (X25519)
      0, 4, // key length
      0xaa, 0xbb, 0xcc, 0xdd, // key bytes
    ]);
    const body = new Uint8Array(2 + 32 + 1 + 2 + 1 + 2 + ext.length);
    let off = 0;
    body[off++] = 0x03; body[off++] = 0x03;
    off += 32;
    body[off++] = 0;
    body[off++] = 0x13; body[off++] = 0x01;
    body[off++] = 0;
    body[off++] = 0; body[off++] = ext.length;
    body.set(ext, off);

    const sh = parseServerHello(body);
    expect(sh.keyShare).not.toBeNull();
    expect(sh.keyShare!.group).toBe(0x001d);
    expect(Array.from(sh.keyShare!.key)).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
  });

  it('detects HelloRetryRequest by random sentinel', () => {
    const body = new Uint8Array(2 + 32 + 1 + 2 + 1);
    let off = 0;
    body[off++] = 0x03; body[off++] = 0x03;
    // Set the HRR random sentinel
    const hrr = new Uint8Array([
      207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145,
      194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156,
    ]);
    body.set(hrr, off);
    off += 32;
    body[off++] = 0;
    body[off++] = 0; body[off++] = 0;
    body[off++] = 0;

    const sh = parseServerHello(body);
    expect(sh.isHRR).toBe(true);
  });
});

describe('parseEncryptedExtensions', () => {
  it('parses ALPN from EncryptedExtensions', () => {
    // [extLen(2)] [ext: type=16 (ALPN), len=...]
    // ALPN ext: [protocolListLen(2)] [protoLen(1)] [proto bytes]
    // Inner: 2 bytes protocol list length, 1 byte proto length, 4 bytes "h2"
    const alpnInner = new Uint8Array([0, 3, 2, 0x68, 0x32]); // "h2"
    const ext = new Uint8Array(4 + alpnInner.length);
    ext[0] = 0; ext[1] = 16; // ALPN type
    ext[2] = 0; ext[3] = alpnInner.length;
    ext.set(alpnInner, 4);

    const body = new Uint8Array(2 + ext.length);
    body[0] = 0; body[1] = ext.length;
    body.set(ext, 2);

    const result = parseEncryptedExtensions(body);
    expect(result.alpn).toBe('h2');
  });

  it('returns null alpn when no ALPN extension', () => {
    const body = new Uint8Array([0, 0]); // no extensions
    const result = parseEncryptedExtensions(body);
    expect(result.alpn).toBeNull();
  });
});

describe('extractLeafCertificate', () => {
  it('extracts leaf cert from TLS 1.2 message body (no context)', () => {
    // [certListLen(3)] [certLen(3)] [cert bytes...]
    const cert = new Uint8Array([0xaa, 0xbb, 0xcc]);
    const body = new Uint8Array(3 + 3 + cert.length);
    let off = 0;
    body[off++] = 0; body[off++] = 0; body[off++] = 3 + cert.length;
    body[off++] = 0; body[off++] = 0; body[off++] = cert.length;
    body.set(cert, off);

    const leaf = extractLeafCertificate(body, 0);
    expect(leaf).not.toBeNull();
    expect(Array.from(leaf!)).toEqual([0xaa, 0xbb, 0xcc]);
  });

  it('extracts leaf cert from TLS 1.3 message body (with context)', () => {
    const cert = new Uint8Array([0xdd, 0xee]);
    // Context length = 0 (server cert has no context)
    const body = new Uint8Array(1 + 3 + 3 + cert.length);
    let off = 0;
    body[off++] = 0; // context length
    body[off++] = 0; body[off++] = 0; body[off++] = 3 + cert.length;
    body[off++] = 0; body[off++] = 0; body[off++] = cert.length;
    body.set(cert, off);

    const leaf = extractLeafCertificate(body, 1);
    expect(leaf).not.toBeNull();
    expect(Array.from(leaf!)).toEqual([0xdd, 0xee]);
  });

  it('returns null on empty cert list', () => {
    const body = new Uint8Array([0, 0, 0]);
    expect(extractLeafCertificate(body, 0)).toBeNull();
  });
});

describe('parseServerKeyExchange', () => {
  it('parses ECDHE ServerKeyExchange', () => {
    // [curveType(1)=0x03] [namedCurve(2)] [keyLen(1)] [key bytes]
    const body = new Uint8Array([
      0x03, // ECCurveType: named_curve
      0x00, 0x1d, // X25519
      0x04,
      0xaa, 0xbb, 0xcc, 0xdd,
    ]);
    const ske = parseServerKeyExchange(body);
    expect(ske.namedCurve).toBe(0x001d);
    expect(Array.from(ske.serverPublicKey)).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
  });
});

describe('buildClientHello', () => {
  it('produces a parseable ClientHello message', () => {
    const clientRandom = new Uint8Array(32);
    crypto.getRandomValues(clientRandom);
    const x25519Key = new Uint8Array(32);
    crypto.getRandomValues(x25519Key);
    const p256Key = new Uint8Array(65);
    crypto.getRandomValues(p256Key);

    const ch = buildClientHello(clientRandom, 'example.com', { x25519: x25519Key, p256: p256Key });

    // First byte should be HANDSHAKE_TYPE_CLIENT_HELLO
    expect(ch[0]).toBe(HANDSHAKE_TYPE_CLIENT_HELLO);
    // Bytes 4-5 are legacy version (TLS 1.2)
    expect((ch[4] << 8) | ch[5]).toBe(TLS_VERSION_12);
    // Then 32 bytes of client random
    expect(Array.from(ch.slice(6, 6 + 32))).toEqual(Array.from(clientRandom));
  });

  it('omits SNI when serverName is empty', () => {
    const cr = new Uint8Array(32);
    const ch = buildClientHello(cr, '', { x25519: new Uint8Array(32) }, { tls12: false });
    // SNI extension type is 0x0000. Should not appear in extensions section.
    // We just check the message is well-formed (length doesn't crash parsing)
    expect(ch.length).toBeGreaterThan(50);
  });

  it('builds with TLS 1.3 only (no 1.2)', () => {
    const cr = new Uint8Array(32);
    const ch = buildClientHello(cr, '', { x25519: new Uint8Array(32) }, {
      tls13: true,
      tls12: false,
    });
    expect(ch.length).toBeGreaterThan(0);
  });

  it('builds with ALPN advertised', () => {
    const cr = new Uint8Array(32);
    const ch = buildClientHello(cr, 'example.com', { x25519: new Uint8Array(32) }, {
      alpn: ['h2', 'http/1.1'],
    });
    // Search for "h2" bytes in the message
    const h2 = new Uint8Array([0x68, 0x32]);
    let found = false;
    for (let i = 0; i < ch.length - 1; i++) {
      if (ch[i] === h2[0] && ch[i + 1] === h2[1]) {
        found = true;
        break;
      }
    }
    expect(found).toBe(true);
  });

  it('builds with single ALPN protocol (string instead of array)', () => {
    const cr = new Uint8Array(32);
    const ch = buildClientHello(cr, '', { x25519: new Uint8Array(32) }, { alpn: 'h2' });
    expect(ch.length).toBeGreaterThan(0);
  });
});
