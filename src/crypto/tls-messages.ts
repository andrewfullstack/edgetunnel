// TLS handshake message parsers + ClientHello builder.
//
// Each function takes/produces the *body* of a handshake message
// (after the 4-byte handshake type/length header).

import {
  concatBytes,
  readUint16,
  readUint24,
  textDecoder,
  textEncoder,
  uint16be,
  EMPTY_BYTES,
  tlsBytes,
} from '../utils/bytes.js';
import { constantTimeEqual } from '../utils/bytes.js';
import {
  TLS_VERSION_12,
  TLS_VERSION_13,
  HANDSHAKE_TYPE_CLIENT_HELLO,
  EXT_SERVER_NAME,
  EXT_SUPPORTED_GROUPS,
  EXT_EC_POINT_FORMATS,
  EXT_SIGNATURE_ALGORITHMS,
  EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
  EXT_SUPPORTED_VERSIONS,
  EXT_PSK_KEY_EXCHANGE_MODES,
  EXT_KEY_SHARE,
  SUPPORTED_SIGNATURE_ALGORITHMS,
} from '../constants.js';
import { buildHandshakeMessage } from './tls-record.js';

// ─── ServerHello ─────────────────────────────────────────────────────

export interface ServerHello {
  version: number;
  serverRandom: Uint8Array;
  sessionId: Uint8Array;
  cipherSuite: number;
  compression: number;
  selectedVersion: number;
  keyShare: { group: number; key: Uint8Array } | null;
  alpn: string | null;
  isHRR: boolean;
  isTls13: boolean;
}

/**
 * The "magic" SHA-256 random value that signals a HelloRetryRequest
 * (RFC 8446 §4.1.4). If the server's random equals this, we got HRR
 * instead of a normal ServerHello.
 */
const HELLO_RETRY_REQUEST_RANDOM = new Uint8Array([
  207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145,
  194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156,
]);

/**
 * Parse a ServerHello message body.
 * Extracts cipher suite, server random, key_share, ALPN, and detects
 * whether this is a TLS 1.3 negotiation or a HelloRetryRequest.
 */
export function parseServerHello(body: Uint8Array): ServerHello {
  let offset = 0;
  const legacyVersion = readUint16(body, offset);
  offset += 2;
  const serverRandom = body.slice(offset, offset + 32);
  offset += 32;

  const sessionIdLength = body[offset++];
  const sessionId = body.slice(offset, offset + sessionIdLength);
  offset += sessionIdLength;

  const cipherSuite = readUint16(body, offset);
  offset += 2;
  const compression = body[offset++];

  let selectedVersion = legacyVersion;
  let keyShare: { group: number; key: Uint8Array } | null = null;
  let alpn: string | null = null;

  if (offset < body.length) {
    const extensionsLength = readUint16(body, offset);
    offset += 2;
    const extensionsEnd = offset + extensionsLength;

    while (offset + 4 <= extensionsEnd) {
      const extType = readUint16(body, offset);
      offset += 2;
      const extLen = readUint16(body, offset);
      offset += 2;
      const extData = body.slice(offset, offset + extLen);
      offset += extLen;

      if (extType === EXT_SUPPORTED_VERSIONS && extLen >= 2) {
        selectedVersion = readUint16(extData, 0);
      } else if (extType === EXT_KEY_SHARE && extLen >= 4) {
        const group = readUint16(extData, 0);
        const keyLength = readUint16(extData, 2);
        keyShare = { group, key: extData.slice(4, 4 + keyLength) };
      } else if (
        extType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION &&
        extLen >= 3
      ) {
        alpn = textDecoder.decode(extData.slice(3, 3 + extData[2]));
      }
    }
  }

  return {
    version: legacyVersion,
    serverRandom,
    sessionId,
    cipherSuite,
    compression,
    selectedVersion,
    keyShare,
    alpn,
    isHRR: constantTimeEqual(serverRandom, HELLO_RETRY_REQUEST_RANDOM),
    isTls13: selectedVersion === TLS_VERSION_13,
  };
}

// ─── TLS 1.2 ServerKeyExchange ───────────────────────────────────────

export interface ServerKeyExchange {
  namedCurve: number;
  serverPublicKey: Uint8Array;
}

/**
 * Parse a TLS 1.2 ServerKeyExchange (ECDHE) message body.
 */
export function parseServerKeyExchange(body: Uint8Array): ServerKeyExchange {
  let offset = 1; // skip ECCurveType (named_curve = 0x03)
  const namedCurve = readUint16(body, offset);
  offset += 2;
  const keyLength = body[offset++];
  return {
    namedCurve,
    serverPublicKey: body.slice(offset, offset + keyLength),
  };
}

// ─── Certificate ─────────────────────────────────────────────────────

/**
 * Extract the leaf certificate (DER bytes) from a Certificate message body.
 *
 * @param hasContext - 1 for TLS 1.3 (has certificate_request_context prefix),
 *                     0 for TLS 1.2.
 */
export function extractLeafCertificate(
  body: Uint8Array,
  hasContext = 0
): Uint8Array | null {
  let offset = 0;
  if (hasContext) {
    const contextLength = body[offset++];
    offset += contextLength;
  }
  if (offset + 3 > body.length) return null;
  const certListLength = readUint24(body, offset);
  offset += 3;
  if (!certListLength || offset + 3 > body.length) return null;
  const certLength = readUint24(body, offset);
  offset += 3;
  return certLength ? body.slice(offset, offset + certLength) : null;
}

// ─── EncryptedExtensions (TLS 1.3) ───────────────────────────────────

export interface EncryptedExtensions {
  alpn: string | null;
}

/**
 * Parse a TLS 1.3 EncryptedExtensions message body.
 * Currently we only extract negotiated ALPN.
 */
export function parseEncryptedExtensions(body: Uint8Array): EncryptedExtensions {
  const parsed: EncryptedExtensions = { alpn: null };
  let offset = 2;
  const extensionsEnd = 2 + readUint16(body, 0);

  while (offset + 4 <= extensionsEnd) {
    const extType = readUint16(body, offset);
    offset += 2;
    const extLen = readUint16(body, offset);
    offset += 2;

    if (
      extType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION &&
      extLen >= 3
    ) {
      const protocolLength = body[offset + 2];
      if (protocolLength > 0 && 3 + protocolLength <= extLen) {
        parsed.alpn = textDecoder.decode(
          body.slice(offset + 3, offset + 3 + protocolLength)
        );
      }
    }
    offset += extLen;
  }

  return parsed;
}

// ─── ClientHello builder ─────────────────────────────────────────────

export interface ClientHelloKeyShares {
  x25519?: Uint8Array;
  p256?: Uint8Array;
}

export interface ClientHelloOptions {
  tls13?: boolean;
  tls12?: boolean;
  alpn?: string | string[] | null;
  chacha?: boolean;
}

/**
 * Build a TLS ClientHello message (full body + handshake header).
 *
 * @param keyShares    - X25519 and/or P-256 raw public keys for key_share extension
 * @param options.tls13   - offer TLS 1.3 (default true)
 * @param options.tls12   - offer TLS 1.2 (default true)
 * @param options.alpn    - ALPN protocol(s) to advertise (null = none)
 * @param options.chacha  - include ChaCha20-Poly1305 cipher suites (default true)
 */
export function buildClientHello(
  clientRandom: Uint8Array,
  serverName: string,
  keyShares: ClientHelloKeyShares | Uint8Array,
  {
    tls13: enableTls13 = true,
    tls12: enableTls12 = true,
    alpn = null,
    chacha = true,
  }: ClientHelloOptions = {}
): Uint8Array {
  // Cipher suites to offer
  const cipherIds: number[] = [];
  if (enableTls13) {
    cipherIds.push(4865, 4866);
    if (chacha) cipherIds.push(4867);
  }
  if (enableTls12) {
    cipherIds.push(49199, 49200, 49195, 49196);
    if (chacha) cipherIds.push(52392, 52393);
  }
  const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be));

  // Renegotiation info (always include the empty marker)
  const extensions: Uint8Array[] = [tlsBytes(255, 1, 0, 1, 0)];

  // SNI
  if (serverName) {
    const snBytes = textEncoder.encode(serverName);
    const snList = tlsBytes(0, uint16be(snBytes.length), snBytes);
    extensions.push(
      tlsBytes(
        uint16be(EXT_SERVER_NAME),
        uint16be(snList.length + 2),
        uint16be(snList.length),
        snList
      )
    );
  }

  // EC point formats: uncompressed only
  extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0));
  // Supported groups: X25519 (29) + P-256 (23)
  extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));

  // Signature algorithms
  const sigBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
  extensions.push(
    tlsBytes(
      uint16be(EXT_SIGNATURE_ALGORITHMS),
      uint16be(sigBytes.length + 2),
      uint16be(sigBytes.length),
      sigBytes
    )
  );

  // ALPN
  const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
  if (protocols.length) {
    const alpnBytes = concatBytes(
      ...protocols.map((p) => {
        const pBytes = textEncoder.encode(p);
        return tlsBytes(pBytes.length, pBytes);
      })
    );
    extensions.push(
      tlsBytes(
        uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
        uint16be(alpnBytes.length + 2),
        uint16be(alpnBytes.length),
        alpnBytes
      )
    );
  }

  // TLS 1.3-specific extensions
  if (enableTls13 && keyShares) {
    extensions.push(
      enableTls12
        ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3)
        : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4)
    );
    extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1));

    let keyShareBytes: Uint8Array;
    if (
      typeof keyShares === 'object' &&
      !(keyShares instanceof Uint8Array) &&
      keyShares.x25519 &&
      keyShares.p256
    ) {
      keyShareBytes = concatBytes(
        tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519),
        tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256)
      );
    } else if (typeof keyShares === 'object' && !(keyShares instanceof Uint8Array) && keyShares.x25519) {
      keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
    } else if (typeof keyShares === 'object' && !(keyShares instanceof Uint8Array) && keyShares.p256) {
      keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
    } else if (keyShares instanceof Uint8Array) {
      keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares);
    } else {
      throw new Error('Invalid keyShares');
    }

    extensions.push(
      tlsBytes(
        uint16be(EXT_KEY_SHARE),
        uint16be(keyShareBytes.length + 2),
        uint16be(keyShareBytes.length),
        keyShareBytes
      )
    );
  }

  const extensionsBytes = concatBytes(...extensions);

  return buildHandshakeMessage(
    HANDSHAKE_TYPE_CLIENT_HELLO,
    tlsBytes(
      uint16be(TLS_VERSION_12),
      clientRandom,
      0, // legacy session ID length
      uint16be(cipherBytes.length),
      cipherBytes,
      1, 0, // legacy compression methods: [null]
      uint16be(extensionsBytes.length),
      extensionsBytes
    )
  );
}
