// Shadowsocks inbound state machine for the WebSocket handler.
//
// SS over WebSocket is unique among the protocols this project supports:
// instead of a plaintext frame header (like VLESS / Trojan), the entire
// stream from byte 0 is AEAD-encrypted. We have to:
//
//   1. Receive enough bytes to identify the cipher and recover the salt
//      (auto-detecting the cipher among configured candidates).
//   2. Derive the session key via HKDF-SHA1 with info "ss-subkey".
//   3. AEAD-decrypt subsequent length-prefixed chunks.
//   4. Maintain a parallel outbound encryption pipeline to encrypt
//      response data before sending back over the WebSocket.

import { concatByteArrays, toUint8Array } from '../utils/bytes.js';
import { isSpeedTestSite } from '../utils/hostname.js';
import {
  SS_CIPHERS,
  SS_AEAD_TAG_LENGTH,
  SS_NONCE_LENGTH,
  type ShadowsocksCipher,
} from '../constants.js';
import {
  ssDeriveMasterKey,
  ssDeriveSessionKey,
  ssAeadEncrypt,
  ssAeadDecrypt,
} from '../protocols/shadowsocks.js';
import { closeSocketQuietly, wsSendAndWait } from '../transports/socket-utils.js';
import type { LogFn } from '../utils/logger.js';

const ssTextDecoder = new TextDecoder();

interface InboundState {
  buffer: Uint8Array;
  hasSalt: boolean;
  waitPayloadLength: number | null;
  decryptKey: CryptoKey | null;
  nonceCounter: Uint8Array;
  cipherConfig: ShadowsocksCipher | null;
}

export interface SsInboundContext {
  /** Decrypt incoming bytes, return any newly-decoded plaintext chunks. */
  decryptInput(chunk: Uint8Array | ArrayBuffer): Promise<Uint8Array[]>;
  /** WebSocket-like façade that re-encrypts outgoing data. */
  bridge: { readyState: number; send(data: any): Promise<void>; close(): void };
  /** Parsed target after first plaintext block. Mutated by the WS handler. */
  firstPacketEstablished: boolean;
  targetHost: string;
  targetPort: number;
}

/**
 * Build an SS inbound context for a freshly-accepted WebSocket. The cipher
 * is auto-detected from the first frame (within configured candidates).
 *
 * @param requestedEnc - URL-specified encryption ("aes-128-gcm", etc).
 *                       Tried first; remaining ciphers tried if it fails.
 */
export function createSsInbound(
  serverSock: WebSocket,
  yourUUID: string,
  requestedEnc: string,
  log: LogFn
): SsInboundContext {
  const preferredCipher = SS_CIPHERS[requestedEnc] || SS_CIPHERS['aes-128-gcm'];
  const candidateCiphers = [
    preferredCipher,
    ...Object.values(SS_CIPHERS).filter((c) => c.method !== preferredCipher.method),
  ];

  // Cache master keys by cipher method so we don't re-derive
  const masterKeyTaskCache = new Map<string, Promise<Uint8Array>>();
  const getMasterKeyTask = (config: ShadowsocksCipher) => {
    if (!masterKeyTaskCache.has(config.method)) {
      masterKeyTaskCache.set(config.method, ssDeriveMasterKey(yourUUID, config.keyLen));
    }
    return masterKeyTaskCache.get(config.method)!;
  };

  const inboundState: InboundState = {
    buffer: new Uint8Array(0),
    hasSalt: false,
    waitPayloadLength: null,
    decryptKey: null,
    nonceCounter: new Uint8Array(SS_NONCE_LENGTH),
    cipherConfig: null,
  };

  const initInboundDecryption = async (): Promise<boolean> => {
    const lengthCipherTotalLen = 2 + SS_AEAD_TAG_LENGTH;
    const maxSaltLen = Math.max(...candidateCiphers.map((c) => c.saltLen));
    const minSaltLen = Math.min(...candidateCiphers.map((c) => c.saltLen));
    const maxAlignmentScan = 16;
    const scanLimit = Math.min(
      maxAlignmentScan,
      Math.max(0, inboundState.buffer.byteLength - (lengthCipherTotalLen + minSaltLen))
    );

    for (let offset = 0; offset <= scanLimit; offset++) {
      for (const config of candidateCiphers) {
        const minBytes = offset + config.saltLen + lengthCipherTotalLen;
        if (inboundState.buffer.byteLength < minBytes) continue;
        const salt = inboundState.buffer.subarray(offset, offset + config.saltLen);
        const lengthCipher = inboundState.buffer.subarray(
          offset + config.saltLen,
          minBytes
        );
        const masterKey = await getMasterKeyTask(config);
        const decryptKey = await ssDeriveSessionKey(config, masterKey, salt, ['decrypt']);
        const nonceCounter = new Uint8Array(SS_NONCE_LENGTH);
        try {
          const lengthPlain = await ssAeadDecrypt(decryptKey, nonceCounter, lengthCipher);
          if (lengthPlain.byteLength !== 2) continue;
          const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
          if (payloadLength < 0 || payloadLength > config.maxChunk) continue;

          if (offset > 0) log(`[SS-IN] leading noise ${offset}B aligned`);
          if (config.method !== preferredCipher.method) {
            log(`[SS-IN] requested enc=${requestedEnc || preferredCipher.method} but actual ${config.method}, switched`);
          }
          inboundState.buffer = inboundState.buffer.subarray(minBytes);
          inboundState.decryptKey = decryptKey;
          inboundState.nonceCounter = nonceCounter;
          inboundState.waitPayloadLength = payloadLength;
          inboundState.cipherConfig = config;
          inboundState.hasSalt = true;
          return true;
        } catch (_) {
          /* try next candidate */
        }
      }
    }

    const failureThreshold = maxSaltLen + lengthCipherTotalLen + maxAlignmentScan;
    if (inboundState.buffer.byteLength >= failureThreshold) {
      throw new Error(
        `SS handshake decrypt failed (enc=${requestedEnc || 'auto'}, candidates=${candidateCiphers.map((c) => c.method).join('/')})`
      );
    }
    return false;
  };

  const decryptInput = async (chunkInput: Uint8Array | ArrayBuffer): Promise<Uint8Array[]> => {
    const chunk = toUint8Array(chunkInput);
    if (chunk.byteLength > 0) {
      inboundState.buffer = concatByteArrays(inboundState.buffer, chunk);
    }
    if (!inboundState.hasSalt) {
      const ok = await initInboundDecryption();
      if (!ok) return [];
    }
    const plaintextChunks: Uint8Array[] = [];
    while (true) {
      if (inboundState.waitPayloadLength === null) {
        const lenTotal = 2 + SS_AEAD_TAG_LENGTH;
        if (inboundState.buffer.byteLength < lenTotal) break;
        const lengthCipher = inboundState.buffer.subarray(0, lenTotal);
        inboundState.buffer = inboundState.buffer.subarray(lenTotal);
        const lengthPlain = await ssAeadDecrypt(
          inboundState.decryptKey!,
          inboundState.nonceCounter,
          lengthCipher
        );
        if (lengthPlain.byteLength !== 2) throw new Error('SS length decrypt failed');
        const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
        if (payloadLength < 0 || payloadLength > inboundState.cipherConfig!.maxChunk) {
          throw new Error(`SS payload length invalid: ${payloadLength}`);
        }
        inboundState.waitPayloadLength = payloadLength;
      }
      const payloadTotal = inboundState.waitPayloadLength + SS_AEAD_TAG_LENGTH;
      if (inboundState.buffer.byteLength < payloadTotal) break;
      const payloadCipher = inboundState.buffer.subarray(0, payloadTotal);
      inboundState.buffer = inboundState.buffer.subarray(payloadTotal);
      const payloadPlain = await ssAeadDecrypt(
        inboundState.decryptKey!,
        inboundState.nonceCounter,
        payloadCipher
      );
      plaintextChunks.push(payloadPlain);
      inboundState.waitPayloadLength = null;
    }
    return plaintextChunks;
  };

  // ─── Outbound encryption pipeline ─────────────────────────────────

  let outboundEncryptor: { encryptAndSend: (chunk: Uint8Array, send: (b: Uint8Array) => Promise<void>) => Promise<void> } | null = null;
  const SS_BATCH_LIMIT = 32 * 1024;

  const getOutboundEncryptor = async () => {
    if (outboundEncryptor) return outboundEncryptor;
    if (!inboundState.cipherConfig) throw new Error('SS cipher is not negotiated');
    const cfg = inboundState.cipherConfig;
    const masterKey = await ssDeriveMasterKey(yourUUID, cfg.keyLen);
    const salt = crypto.getRandomValues(new Uint8Array(cfg.saltLen));
    const encryptKey = await ssDeriveSessionKey(cfg, masterKey, salt, ['encrypt']);
    const nonceCounter = new Uint8Array(SS_NONCE_LENGTH);
    let saltSent = false;

    outboundEncryptor = {
      async encryptAndSend(dataChunk, send) {
        const plaintext = toUint8Array(dataChunk);
        if (!saltSent) {
          await send(salt);
          saltSent = true;
        }
        if (plaintext.byteLength === 0) return;
        let offset = 0;
        while (offset < plaintext.byteLength) {
          const end = Math.min(offset + cfg.maxChunk, plaintext.byteLength);
          const payloadPlain = plaintext.subarray(offset, end);
          const lengthPlain = new Uint8Array(2);
          lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
          lengthPlain[1] = payloadPlain.byteLength & 0xff;
          const lengthCipher = await ssAeadEncrypt(encryptKey, nonceCounter, lengthPlain);
          const payloadCipher = await ssAeadEncrypt(encryptKey, nonceCounter, payloadPlain);
          const frame = new Uint8Array(lengthCipher.byteLength + payloadCipher.byteLength);
          frame.set(lengthCipher, 0);
          frame.set(payloadCipher, lengthCipher.byteLength);
          await send(frame);
          offset = end;
        }
      },
    };
    return outboundEncryptor;
  };

  // Serialise the outbound send queue so AEAD nonces stay sequential
  let sendQueue: Promise<void> = Promise.resolve();
  const enqueueSend = (chunk: Uint8Array): Promise<void> => {
    sendQueue = sendQueue
      .then(async () => {
        if (serverSock.readyState !== WebSocket.OPEN) return;
        const enc = await getOutboundEncryptor();
        await enc.encryptAndSend(chunk, async (encryptedChunk) => {
          if (encryptedChunk.byteLength > 0 && serverSock.readyState === WebSocket.OPEN) {
            await wsSendAndWait(serverSock, encryptedChunk.buffer as ArrayBuffer);
          }
        });
      })
      .catch((error: any) => {
        log(`[SS-OUT] encryption failed: ${error?.message || error}`);
        closeSocketQuietly(serverSock);
      });
    return sendQueue;
  };

  const bridge = {
    get readyState() {
      return serverSock.readyState;
    },
    async send(data: any) {
      const chunk = toUint8Array(data);
      if (chunk.byteLength <= SS_BATCH_LIMIT) {
        await enqueueSend(chunk);
        return;
      }
      let lastPromise: Promise<void> = Promise.resolve();
      for (let i = 0; i < chunk.byteLength; i += SS_BATCH_LIMIT) {
        lastPromise = enqueueSend(chunk.subarray(i, Math.min(i + SS_BATCH_LIMIT, chunk.byteLength)));
      }
      await lastPromise;
    },
    close() {
      closeSocketQuietly(serverSock);
    },
  };

  return {
    decryptInput,
    bridge,
    firstPacketEstablished: false,
    targetHost: '',
    targetPort: 0,
  };
}

/**
 * Parse the first-packet plaintext after SS handshake to extract the
 * SOCKS5-style destination header. Updates `ctx.firstPacketEstablished`,
 * `targetHost`, `targetPort` and returns the remaining payload bytes.
 */
export function parseSsTargetHeader(plaintext: Uint8Array): {
  hostname: string;
  port: number;
  rawData: Uint8Array;
} {
  if (plaintext.byteLength < 3) throw new Error('invalid ss data');
  const addressType = plaintext[0];
  let cursor = 1;
  let hostname = '';

  if (addressType === 1) {
    if (plaintext.byteLength < cursor + 4 + 2) throw new Error('invalid ss ipv4 length');
    hostname = `${plaintext[cursor]}.${plaintext[cursor + 1]}.${plaintext[cursor + 2]}.${plaintext[cursor + 3]}`;
    cursor += 4;
  } else if (addressType === 3) {
    if (plaintext.byteLength < cursor + 1) throw new Error('invalid ss domain length');
    const domainLength = plaintext[cursor];
    cursor += 1;
    if (plaintext.byteLength < cursor + domainLength + 2) throw new Error('invalid ss domain data');
    hostname = ssTextDecoder.decode(plaintext.subarray(cursor, cursor + domainLength));
    cursor += domainLength;
  } else if (addressType === 4) {
    if (plaintext.byteLength < cursor + 16 + 2) throw new Error('invalid ss ipv6 length');
    const view = new DataView(plaintext.buffer, plaintext.byteOffset + cursor, 16);
    const groups: string[] = [];
    for (let i = 0; i < 8; i++) groups.push(view.getUint16(i * 2).toString(16));
    hostname = groups.join(':');
    cursor += 16;
  } else {
    throw new Error(`invalid ss addressType: ${addressType}`);
  }

  if (!hostname) throw new Error(`invalid ss address: ${addressType}`);
  if (isSpeedTestSite(hostname)) throw new Error('Speedtest site is blocked');

  const port = (plaintext[cursor] << 8) | plaintext[cursor + 1];
  cursor += 2;
  const rawData = plaintext.subarray(cursor);
  return { hostname, port, rawData };
}
