// Project-wide constants: external URLs, TLS protocol numbers,
// Shadowsocks cipher configurations.

/** External CDN serving the admin UI HTML/JS. */
export const PAGES_STATIC_URL = 'https://edt-pages.github.io';

// ─── TLS protocol versions ──────────────────────────────────────────
export const TLS_VERSION_10 = 0x0301;
export const TLS_VERSION_12 = 0x0303;
export const TLS_VERSION_13 = 0x0304;

// ─── TLS record content types ───────────────────────────────────────
export const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;
export const CONTENT_TYPE_ALERT = 21;
export const CONTENT_TYPE_HANDSHAKE = 22;
export const CONTENT_TYPE_APPLICATION_DATA = 23;

// ─── TLS handshake message types ────────────────────────────────────
export const HANDSHAKE_TYPE_CLIENT_HELLO = 1;
export const HANDSHAKE_TYPE_SERVER_HELLO = 2;
export const HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4;
export const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8;
export const HANDSHAKE_TYPE_CERTIFICATE = 11;
export const HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12;
export const HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13;
export const HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14;
export const HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15;
export const HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16;
export const HANDSHAKE_TYPE_FINISHED = 20;
export const HANDSHAKE_TYPE_KEY_UPDATE = 24;

// ─── TLS extension type IDs ─────────────────────────────────────────
export const EXT_SERVER_NAME = 0;
export const EXT_SUPPORTED_GROUPS = 10;
export const EXT_EC_POINT_FORMATS = 11;
export const EXT_SIGNATURE_ALGORITHMS = 13;
export const EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16;
export const EXT_SUPPORTED_VERSIONS = 43;
export const EXT_PSK_KEY_EXCHANGE_MODES = 45;
export const EXT_KEY_SHARE = 51;

// ─── TLS alert codes ────────────────────────────────────────────────
export const ALERT_CLOSE_NOTIFY = 0;
export const ALERT_LEVEL_WARNING = 1;
export const ALERT_UNRECOGNIZED_NAME = 112;

/** Spec-mandated max plaintext size for a TLS record. */
export const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;

/**
 * Cipher suite configuration used by the TLS client.
 * Limited to the suites the implementation actually supports.
 */
export interface CipherConfig {
  id: number;
  keyLen: number;
  ivLen: number;
  hash: 'SHA-256' | 'SHA-384' | 'SHA-512';
  tls13?: boolean;
  chacha?: boolean;
  kex?: 'ECDHE';
}

export const CIPHER_SUITES_BY_ID = new Map<number, CipherConfig>([
  // TLS 1.3 suites
  [4865, { id: 4865, keyLen: 16, ivLen: 12, hash: 'SHA-256', tls13: true }], // TLS_AES_128_GCM_SHA256
  [4866, { id: 4866, keyLen: 32, ivLen: 12, hash: 'SHA-384', tls13: true }], // TLS_AES_256_GCM_SHA384
  [4867, { id: 4867, keyLen: 32, ivLen: 12, hash: 'SHA-256', tls13: true, chacha: true }], // TLS_CHACHA20_POLY1305_SHA256
  // TLS 1.2 ECDHE-RSA suites
  [49199, { id: 49199, keyLen: 16, ivLen: 4, hash: 'SHA-256', kex: 'ECDHE' }],
  [49200, { id: 49200, keyLen: 32, ivLen: 4, hash: 'SHA-384', kex: 'ECDHE' }],
  [52392, { id: 52392, keyLen: 32, ivLen: 12, hash: 'SHA-256', kex: 'ECDHE', chacha: true }],
  // TLS 1.2 ECDHE-ECDSA suites
  [49195, { id: 49195, keyLen: 16, ivLen: 4, hash: 'SHA-256', kex: 'ECDHE' }],
  [49196, { id: 49196, keyLen: 32, ivLen: 4, hash: 'SHA-384', kex: 'ECDHE' }],
  [52393, { id: 52393, keyLen: 32, ivLen: 12, hash: 'SHA-256', kex: 'ECDHE', chacha: true }],
]);

/** Supported ECDHE groups (X25519, P-256). */
export const GROUPS_BY_ID = new Map<number, string>([
  [29, 'X25519'],
  [23, 'P-256'],
]);

/** Signature algorithms we offer to the server. */
export const SUPPORTED_SIGNATURE_ALGORITHMS = [
  2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539,
];

// ─── Shadowsocks AEAD configuration ─────────────────────────────────
export interface ShadowsocksCipher {
  method: string;
  keyLen: number;
  saltLen: number;
  maxChunk: number;
  aesLength: 128 | 256;
}

export const SS_CIPHERS: Record<string, ShadowsocksCipher> = {
  'aes-128-gcm': {
    method: 'aes-128-gcm',
    keyLen: 16,
    saltLen: 16,
    maxChunk: 0x3fff,
    aesLength: 128,
  },
  'aes-256-gcm': {
    method: 'aes-256-gcm',
    keyLen: 32,
    saltLen: 32,
    maxChunk: 0x3fff,
    aesLength: 256,
  },
};

/** Shadowsocks AEAD parameters fixed by spec. */
export const SS_AEAD_TAG_LENGTH = 16;
export const SS_NONCE_LENGTH = 12;
export const SS_SUBKEY_INFO = new TextEncoder().encode('ss-subkey');
