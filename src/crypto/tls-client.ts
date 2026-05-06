// Minimal TLS 1.2 / 1.3 client.
//
// Implements just enough of the TLS protocol to wrap a raw Cloudflare
// socket and tunnel application data through it. Used when the proxy
// needs to speak TLS to an upstream HTTPS proxy server (Cloudflare Workers
// can't use fetch() for this — fetch hides the underlying socket).
//
// What's supported:
//   - TLS 1.2 ECDHE-RSA / ECDHE-ECDSA (AES-GCM and ChaCha20-Poly1305)
//   - TLS 1.3 (AES-GCM and ChaCha20-Poly1305)
//   - SNI, ALPN, X25519/P-256 ECDHE
//
// What's NOT supported:
//   - HelloRetryRequest (tries to fail fast)
//   - Client certificates
//   - 0-RTT data
//   - TLS 1.3 KeyUpdate
//   - Session resumption
//
// The simplifications are intentional — this is a client for outbound
// proxy tunnels, not a general-purpose TLS implementation.

import {
  concatBytes,
  constantTimeEqual,
  randomBytes,
  readUint24,
  toUint8Array,
  uint16be,
  EMPTY_BYTES,
  tlsBytes,
} from '../utils/bytes.js';
import {
  CIPHER_SUITES_BY_ID,
  GROUPS_BY_ID,
  type CipherConfig,
  TLS_VERSION_10,
  TLS_VERSION_12,
  CONTENT_TYPE_CHANGE_CIPHER_SPEC,
  CONTENT_TYPE_ALERT,
  CONTENT_TYPE_HANDSHAKE,
  CONTENT_TYPE_APPLICATION_DATA,
  HANDSHAKE_TYPE_SERVER_HELLO,
  HANDSHAKE_TYPE_NEW_SESSION_TICKET,
  HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS,
  HANDSHAKE_TYPE_CERTIFICATE,
  HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE,
  HANDSHAKE_TYPE_CERTIFICATE_REQUEST,
  HANDSHAKE_TYPE_SERVER_HELLO_DONE,
  HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
  HANDSHAKE_TYPE_FINISHED,
  HANDSHAKE_TYPE_KEY_UPDATE,
  TLS_MAX_PLAINTEXT_FRAGMENT,
  ALERT_CLOSE_NOTIFY,
} from '../constants.js';
import { generateKeyShare, deriveSharedSecret, type KeyShare } from './ecdh.js';
import {
  hmac,
  digestBytes,
  hkdfExtract,
  hkdfExpandLabel,
  tls12Prf,
  hashByteLength,
  type HashName,
} from './hmac-hkdf.js';
import { importAesGcmKey, aesGcmEncrypt, aesGcmDecrypt } from './aes-gcm.js';
import {
  chacha20Poly1305Encrypt,
  chacha20Poly1305Decrypt,
} from './chacha20-poly1305.js';
import {
  TlsRecordParser,
  TlsHandshakeParser,
  shouldIgnoreTlsAlert,
  buildTlsRecord,
  buildHandshakeMessage,
  xorSequenceIntoIv,
  deriveTrafficKeys,
  type TlsRecord,
  type HandshakeMessage,
} from './tls-record.js';
import {
  parseServerHello,
  parseServerKeyExchange,
  extractLeafCertificate,
  parseEncryptedExtensions,
  buildClientHello,
  type ServerHello,
} from './tls-messages.js';

export interface TlsClientOptions {
  /** SNI hostname (omit for IP-based connections). */
  serverName?: string;
  /** Enable TLS 1.3 in offer. Default: true. */
  tls13?: boolean;
  /** Enable TLS 1.2 in offer. Default: true. */
  tls12?: boolean;
  /** ALPN protocol(s) to advertise. */
  alpn?: string | string[] | null;
  /** Allow ChaCha20-Poly1305 cipher suites. Default: true. */
  allowChacha?: boolean;
  /** Insecure mode — accept any certificate without validation. */
  insecure?: boolean;
  /** Per-read timeout in ms. Default: 30s. */
  timeout?: number;
}

interface TlsLikeSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close(): void | Promise<void>;
}

export class TlsClient {
  socket: TlsLikeSocket;
  serverName: string;
  supportTls13: boolean;
  supportTls12: boolean;
  alpnProtocols: string[] | null;
  allowChacha: boolean;
  timeout: number;

  clientRandom: Uint8Array;
  serverRandom: Uint8Array | null = null;
  handshakeChunks: Uint8Array[] = [];
  handshakeComplete = false;
  negotiatedAlpn: string | null = null;
  cipherSuite: number | null = null;
  cipherConfig: CipherConfig | null = null;
  isTls13 = false;

  // Secrets / keys
  masterSecret: Uint8Array | null = null;
  handshakeSecret: Uint8Array | null = null;
  clientWriteKey: Uint8Array | null = null;
  serverWriteKey: Uint8Array | null = null;
  clientWriteIv: Uint8Array | null = null;
  serverWriteIv: Uint8Array | null = null;
  clientHandshakeKey: Uint8Array | null = null;
  serverHandshakeKey: Uint8Array | null = null;
  clientHandshakeIv: Uint8Array | null = null;
  serverHandshakeIv: Uint8Array | null = null;
  clientAppKey: Uint8Array | null = null;
  serverAppKey: Uint8Array | null = null;
  clientAppIv: Uint8Array | null = null;
  serverAppIv: Uint8Array | null = null;

  // Cached CryptoKey objects (lazily imported) for AES-GCM paths
  clientWriteCryptoKey: CryptoKey | null = null;
  serverWriteCryptoKey: CryptoKey | null = null;
  clientHandshakeCryptoKey: CryptoKey | null = null;
  serverHandshakeCryptoKey: CryptoKey | null = null;
  clientAppCryptoKey: CryptoKey | null = null;
  serverAppCryptoKey: CryptoKey | null = null;

  clientSeqNum: bigint = 0n;
  serverSeqNum: bigint = 0n;

  recordParser = new TlsRecordParser();
  handshakeParser = new TlsHandshakeParser();
  keyPairs: Map<number, KeyShare> = new Map();
  ecdhKeyPair: CryptoKeyPair | null = null;
  sawCert = false;

  constructor(socket: TlsLikeSocket, options: TlsClientOptions = {}) {
    this.socket = socket;
    this.serverName = options.serverName || '';
    this.supportTls13 = options.tls13 !== false;
    this.supportTls12 = options.tls12 !== false;
    if (!this.supportTls13 && !this.supportTls12) {
      throw new Error('At least one TLS version must be enabled');
    }
    this.alpnProtocols = Array.isArray(options.alpn)
      ? options.alpn
      : options.alpn
        ? [options.alpn]
        : null;
    this.allowChacha = options.allowChacha !== false;
    this.timeout = options.timeout ?? 30000;
    this.clientRandom = randomBytes(32);
  }

  // ─── Internal helpers ─────────────────────────────────────────────

  private recordHandshake(chunk: Uint8Array): void {
    this.handshakeChunks.push(chunk);
  }

  private transcript(): Uint8Array {
    return this.handshakeChunks.length === 1
      ? this.handshakeChunks[0]
      : concatBytes(...this.handshakeChunks);
  }

  private getCipherConfig(cipherSuite: number): CipherConfig | null {
    return CIPHER_SUITES_BY_ID.get(cipherSuite) || null;
  }

  private async readChunk(reader: ReadableStreamDefaultReader<Uint8Array>) {
    if (this.timeout) {
      return Promise.race([
        reader.read(),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('TLS read timeout')), this.timeout)
        ),
      ]);
    }
    return reader.read();
  }

  private async readRecordsUntil(
    reader: ReadableStreamDefaultReader<Uint8Array>,
    predicate: (record: TlsRecord) => Promise<boolean | void | undefined | number>,
    closedError: string
  ): Promise<void> {
    while (true) {
      let record: TlsRecord | null;
      while ((record = this.recordParser.next())) {
        if (await predicate(record)) return;
      }
      const { value, done } = await this.readChunk(reader);
      if (done) throw new Error(closedError);
      if (value) this.recordParser.feed(value);
    }
  }

  private async readHandshakeUntil(
    reader: ReadableStreamDefaultReader<Uint8Array>,
    predicate: (msg: HandshakeMessage) => Promise<boolean | void | undefined | number>,
    closedError: string
  ): Promise<void> {
    let message: HandshakeMessage | null;
    while ((message = this.handshakeParser.next())) {
      if (await predicate(message)) return;
    }
    return this.readRecordsUntil(
      reader,
      async (record) => {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (shouldIgnoreTlsAlert(record.fragment)) return;
          throw new Error(`TLS Alert: ${record.fragment[1]}`);
        }
        if (record.type === CONTENT_TYPE_HANDSHAKE) {
          this.handshakeParser.feed(record.fragment);
          let m: HandshakeMessage | null;
          while ((m = this.handshakeParser.next())) {
            if (await predicate(m)) return 1;
          }
        }
      },
      closedError
    );
  }

  private async acceptCertificate(certificate: Uint8Array | null): Promise<void> {
    if (!certificate?.length) throw new Error('Empty certificate');
    this.sawCert = true;
  }

  // ─── Public handshake driver ──────────────────────────────────────

  async handshake(): Promise<void> {
    const [p256Share, x25519Share] = await Promise.all([
      generateKeyShare('P-256'),
      generateKeyShare('X25519'),
    ]);
    this.keyPairs = new Map([
      [23, p256Share],
      [29, x25519Share],
    ]);
    this.ecdhKeyPair = p256Share.keyPair;

    const reader = this.socket.readable.getReader();
    const writer = this.socket.writable.getWriter();
    try {
      const clientHello = buildClientHello(
        this.clientRandom,
        this.serverName,
        { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw },
        {
          tls13: this.supportTls13,
          tls12: this.supportTls12,
          alpn: this.alpnProtocols,
          chacha: this.allowChacha,
        }
      );
      this.recordHandshake(clientHello);
      await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));

      const serverHello = await this.receiveServerHello(reader);
      if (serverHello.isHRR) {
        throw new Error('HelloRetryRequest is not supported by TlsClient');
      }
      if (serverHello.keyShare?.group != null && this.keyPairs.has(serverHello.keyShare.group)) {
        const selected = this.keyPairs.get(serverHello.keyShare.group)!;
        this.ecdhKeyPair = selected.keyPair;
      }

      if (serverHello.isTls13) {
        await this.handshakeTls13(reader, writer, serverHello);
      } else {
        await this.handshakeTls12(reader, writer);
      }
      this.handshakeComplete = true;
    } finally {
      reader.releaseLock();
      writer.releaseLock();
    }
  }

  private async receiveServerHello(
    reader: ReadableStreamDefaultReader<Uint8Array>
  ): Promise<ServerHello> {
    while (true) {
      const { value, done } = await this.readChunk(reader);
      if (done) throw new Error('Connection closed waiting for ServerHello');
      if (value) this.recordParser.feed(value);

      let record: TlsRecord | null;
      while ((record = this.recordParser.next())) {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (shouldIgnoreTlsAlert(record.fragment)) continue;
          throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
        }
        if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;

        this.handshakeParser.feed(record.fragment);
        let message: HandshakeMessage | null;
        while ((message = this.handshakeParser.next())) {
          if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
          this.recordHandshake(message.raw);
          const sh = parseServerHello(message.body);
          this.serverRandom = sh.serverRandom;
          this.cipherSuite = sh.cipherSuite;
          this.cipherConfig = this.getCipherConfig(sh.cipherSuite);
          this.isTls13 = sh.isTls13;
          this.negotiatedAlpn = sh.alpn || null;
          if (!this.cipherConfig) {
            throw new Error(`Unsupported cipher suite: 0x${sh.cipherSuite.toString(16)}`);
          }
          return sh;
        }
      }
    }
  }

  // ─── TLS 1.2 handshake ────────────────────────────────────────────

  private async handshakeTls12(
    reader: ReadableStreamDefaultReader<Uint8Array>,
    writer: WritableStreamDefaultWriter<Uint8Array>
  ): Promise<void> {
    let serverKeyExchange: { namedCurve: number; serverPublicKey: Uint8Array } | null = null;
    let sawServerHelloDone = false;

    await this.readHandshakeUntil(
      reader,
      async (message) => {
        switch (message.type) {
          case HANDSHAKE_TYPE_CERTIFICATE: {
            this.recordHandshake(message.raw);
            const cert = extractLeafCertificate(message.body, 1);
            if (!cert) throw new Error('Missing TLS 1.2 certificate');
            await this.acceptCertificate(cert);
            break;
          }
          case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
            this.recordHandshake(message.raw);
            serverKeyExchange = parseServerKeyExchange(message.body);
            break;
          case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
            this.recordHandshake(message.raw);
            sawServerHelloDone = true;
            return 1;
          case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
            throw new Error('Client certificate is not supported');
          default:
            this.recordHandshake(message.raw);
        }
      },
      'Connection closed during TLS 1.2 handshake'
    );

    if (!this.sawCert) throw new Error('Missing TLS 1.2 leaf certificate');
    if (!serverKeyExchange) throw new Error('Missing TLS 1.2 ServerKeyExchange');
    const ske: { namedCurve: number; serverPublicKey: Uint8Array } = serverKeyExchange;

    const curveName = GROUPS_BY_ID.get(ske.namedCurve);
    if (!curveName) {
      throw new Error(`Unsupported named curve: 0x${ske.namedCurve.toString(16)}`);
    }
    const keyShare = this.keyPairs.get(ske.namedCurve);
    if (!keyShare) {
      throw new Error(`Missing key pair for curve: 0x${ske.namedCurve.toString(16)}`);
    }

    const preMasterSecret = await deriveSharedSecret(
      keyShare.keyPair.privateKey,
      ske.serverPublicKey,
      curveName as any
    );
    const clientKeyExchange = buildHandshakeMessage(
      HANDSHAKE_TYPE_CERTIFICATE_REQUEST + 3, // CLIENT_KEY_EXCHANGE = 16
      tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw)
    );
    this.recordHandshake(clientKeyExchange);

    const config = this.cipherConfig!;
    const hashName = config.hash as HashName;
    this.masterSecret = await tls12Prf(
      preMasterSecret,
      'master secret',
      concatBytes(this.clientRandom, this.serverRandom!),
      48,
      hashName
    );

    const keyLen = config.keyLen;
    const ivLen = config.ivLen;
    const keyBlock = await tls12Prf(
      this.masterSecret,
      'key expansion',
      concatBytes(this.serverRandom!, this.clientRandom),
      2 * keyLen + 2 * ivLen,
      hashName
    );
    this.clientWriteKey = keyBlock.slice(0, keyLen);
    this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen);
    this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen);
    this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);

    if (!config.chacha) {
      [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([
        importAesGcmKey(this.clientWriteKey, ['encrypt']),
        importAesGcmKey(this.serverWriteKey, ['decrypt']),
      ]);
    }

    await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange));
    await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));

    const clientVerifyData = await tls12Prf(
      this.masterSecret,
      'client finished',
      await digestBytes(hashName, this.transcript()),
      12,
      hashName
    );
    const finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
    this.recordHandshake(finishedMessage);
    await writer.write(
      buildTlsRecord(
        CONTENT_TYPE_HANDSHAKE,
        await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)
      )
    );

    let sawChangeCipherSpec = false;
    await this.readRecordsUntil(
      reader,
      async (record) => {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (shouldIgnoreTlsAlert(record.fragment)) return;
          throw new Error(`TLS Alert: ${record.fragment[1]}`);
        }
        if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) {
          sawChangeCipherSpec = true;
          return;
        }
        if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
        const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
        if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
        const verifyLen = readUint24(decrypted, 1);
        const verifyData = decrypted.slice(4, 4 + verifyLen);
        const expected = await tls12Prf(
          this.masterSecret!,
          'server finished',
          await digestBytes(hashName, this.transcript()),
          12,
          hashName
        );
        if (!constantTimeEqual(verifyData, expected)) {
          throw new Error('TLS 1.2 server Finished verify failed');
        }
        return 1;
      },
      'Connection closed waiting for TLS 1.2 Finished'
    );
  }

  // ─── TLS 1.3 handshake ────────────────────────────────────────────

  private async handshakeTls13(
    reader: ReadableStreamDefaultReader<Uint8Array>,
    writer: WritableStreamDefaultWriter<Uint8Array>,
    serverHello: ServerHello
  ): Promise<void> {
    const groupId = serverHello.keyShare?.group;
    const groupName = groupId != null ? GROUPS_BY_ID.get(groupId) : undefined;
    if (!groupName || !serverHello.keyShare?.key?.length) {
      throw new Error('Missing TLS 1.3 key_share');
    }

    const config = this.cipherConfig!;
    const hashName = config.hash as HashName;
    const hashLen = hashByteLength(hashName);
    const keyLen = config.keyLen;
    const ivLen = config.ivLen;

    const sharedSecret = await deriveSharedSecret(
      this.ecdhKeyPair!.privateKey,
      serverHello.keyShare.key,
      groupName as any
    );
    const earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen));
    const derivedSecret = await hkdfExpandLabel(
      hashName,
      earlySecret,
      'derived',
      await digestBytes(hashName, EMPTY_BYTES),
      hashLen
    );
    this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);

    const transcriptHash = await digestBytes(hashName, this.transcript());
    const clientHsTrafficSecret = await hkdfExpandLabel(
      hashName,
      this.handshakeSecret,
      'c hs traffic',
      transcriptHash,
      hashLen
    );
    const serverHsTrafficSecret = await hkdfExpandLabel(
      hashName,
      this.handshakeSecret,
      's hs traffic',
      transcriptHash,
      hashLen
    );

    [this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(
      hashName, clientHsTrafficSecret, keyLen, ivLen
    );
    [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(
      hashName, serverHsTrafficSecret, keyLen, ivLen
    );

    if (!config.chacha) {
      [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([
        importAesGcmKey(this.clientHandshakeKey, ['encrypt']),
        importAesGcmKey(this.serverHandshakeKey, ['decrypt']),
      ]);
    }

    const serverFinishedKey = await hkdfExpandLabel(
      hashName,
      serverHsTrafficSecret,
      'finished',
      EMPTY_BYTES,
      hashLen
    );
    let serverFinishedReceived = false;

    const handleHandshakeMessage = async (message: HandshakeMessage) => {
      switch (message.type) {
        case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
          const ee = parseEncryptedExtensions(message.body);
          if (ee.alpn) this.negotiatedAlpn = ee.alpn;
          this.recordHandshake(message.raw);
          break;
        }
        case HANDSHAKE_TYPE_CERTIFICATE: {
          const cert = extractLeafCertificate(message.body);
          if (!cert) throw new Error('Missing TLS 1.3 certificate');
          await this.acceptCertificate(cert);
          this.recordHandshake(message.raw);
          break;
        }
        case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
          throw new Error('Client certificate is not supported');
        case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
          this.recordHandshake(message.raw);
          break;
        case HANDSHAKE_TYPE_FINISHED: {
          const expected = await hmac(
            hashName,
            serverFinishedKey,
            await digestBytes(hashName, this.transcript())
          );
          if (!constantTimeEqual(expected, message.body)) {
            throw new Error('TLS 1.3 server Finished verify failed');
          }
          this.recordHandshake(message.raw);
          serverFinishedReceived = true;
          break;
        }
        default:
          this.recordHandshake(message.raw);
      }
    };

    await this.readRecordsUntil(
      reader,
      async (record) => {
        if (
          record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC ||
          record.type === CONTENT_TYPE_HANDSHAKE
        ) {
          return;
        }
        if (record.type === CONTENT_TYPE_ALERT) {
          if (shouldIgnoreTlsAlert(record.fragment)) return;
          throw new Error(`TLS Alert: ${record.fragment[1]}`);
        }
        if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;

        const decrypted = await this.decryptTls13Handshake(record.fragment);
        const innerType = decrypted[decrypted.length - 1];
        const plaintext = decrypted.slice(0, -1);

        if (innerType === CONTENT_TYPE_HANDSHAKE) {
          this.handshakeParser.feed(plaintext);
          let message: HandshakeMessage | null;
          while ((message = this.handshakeParser.next())) {
            await handleHandshakeMessage(message);
            if (serverFinishedReceived) return 1;
          }
        }
      },
      'Connection closed during TLS 1.3 handshake'
    );

    // Derive application traffic secrets
    const appTranscriptHash = await digestBytes(hashName, this.transcript());
    const masterDerivedSecret = await hkdfExpandLabel(
      hashName,
      this.handshakeSecret,
      'derived',
      await digestBytes(hashName, EMPTY_BYTES),
      hashLen
    );
    const masterSecret = await hkdfExtract(
      hashName,
      masterDerivedSecret,
      new Uint8Array(hashLen)
    );
    const clientAppTrafficSecret = await hkdfExpandLabel(
      hashName, masterSecret, 'c ap traffic', appTranscriptHash, hashLen
    );
    const serverAppTrafficSecret = await hkdfExpandLabel(
      hashName, masterSecret, 's ap traffic', appTranscriptHash, hashLen
    );

    [this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(
      hashName, clientAppTrafficSecret, keyLen, ivLen
    );
    [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(
      hashName, serverAppTrafficSecret, keyLen, ivLen
    );

    if (!config.chacha) {
      [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([
        importAesGcmKey(this.clientAppKey, ['encrypt']),
        importAesGcmKey(this.serverAppKey, ['decrypt']),
      ]);
    }

    // Send our Finished
    const clientFinishedKey = await hkdfExpandLabel(
      hashName, clientHsTrafficSecret, 'finished', EMPTY_BYTES, hashLen
    );
    const clientFinishedVerifyData = await hmac(
      hashName,
      clientFinishedKey,
      await digestBytes(hashName, this.transcript())
    );
    const clientFinishedMessage = buildHandshakeMessage(
      HANDSHAKE_TYPE_FINISHED,
      clientFinishedVerifyData
    );
    this.recordHandshake(clientFinishedMessage);

    await writer.write(
      buildTlsRecord(
        CONTENT_TYPE_APPLICATION_DATA,
        await this.encryptTls13Handshake(
          concatBytes(clientFinishedMessage, new Uint8Array([CONTENT_TYPE_HANDSHAKE]))
        )
      )
    );

    // Reset sequence numbers for application data
    this.clientSeqNum = 0n;
    this.serverSeqNum = 0n;
  }

  // ─── Record-layer encrypt/decrypt ─────────────────────────────────

  private async encryptTls12(plaintext: Uint8Array, contentType: number): Promise<Uint8Array> {
    const seqNum = this.clientSeqNum++;
    const aad = concatBytes(
      // sequence number bytes
      new Uint8Array(new Uint8Array(new BigInt64Array([seqNum]).buffer).reverse()),
      new Uint8Array([contentType]),
      new Uint8Array(uint16be(TLS_VERSION_12)),
      new Uint8Array(uint16be(plaintext.length))
    );

    if (this.cipherConfig!.chacha) {
      const nonce = xorSequenceIntoIv(this.clientWriteIv!, seqNum);
      return chacha20Poly1305Encrypt(this.clientWriteKey!, nonce, plaintext, aad);
    }

    const explicitNonce = randomBytes(8);
    if (!this.clientWriteCryptoKey) {
      this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey!, ['encrypt']);
    }
    return concatBytes(
      explicitNonce,
      await aesGcmEncrypt(
        this.clientWriteCryptoKey,
        concatBytes(this.clientWriteIv!, explicitNonce),
        plaintext,
        aad
      )
    );
  }

  private async decryptTls12(ciphertext: Uint8Array, contentType: number): Promise<Uint8Array> {
    const seqNum = this.serverSeqNum++;
    const seqBytes = new Uint8Array(new Uint8Array(new BigInt64Array([seqNum]).buffer).reverse());

    if (this.cipherConfig!.chacha) {
      const nonce = xorSequenceIntoIv(this.serverWriteIv!, seqNum);
      const aad = concatBytes(
        seqBytes,
        new Uint8Array([contentType]),
        new Uint8Array(uint16be(TLS_VERSION_12)),
        new Uint8Array(uint16be(ciphertext.length - 16))
      );
      return chacha20Poly1305Decrypt(this.serverWriteKey!, nonce, ciphertext, aad);
    }

    const explicitNonce = ciphertext.subarray(0, 8);
    const encryptedData = ciphertext.subarray(8);
    if (!this.serverWriteCryptoKey) {
      this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey!, ['decrypt']);
    }
    return aesGcmDecrypt(
      this.serverWriteCryptoKey,
      concatBytes(this.serverWriteIv!, explicitNonce),
      encryptedData,
      concatBytes(
        seqBytes,
        new Uint8Array([contentType]),
        new Uint8Array(uint16be(TLS_VERSION_12)),
        new Uint8Array(uint16be(encryptedData.length - 16))
      )
    );
  }

  private async encryptTls13Handshake(plaintext: Uint8Array): Promise<Uint8Array> {
    const nonce = xorSequenceIntoIv(this.clientHandshakeIv!, this.clientSeqNum++);
    const aad = tlsBytes(
      CONTENT_TYPE_APPLICATION_DATA, 3, 3,
      uint16be(plaintext.length + 16)
    );
    if (this.cipherConfig!.chacha) {
      return chacha20Poly1305Encrypt(this.clientHandshakeKey!, nonce, plaintext, aad);
    }
    if (!this.clientHandshakeCryptoKey) {
      this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey!, ['encrypt']);
    }
    return aesGcmEncrypt(this.clientHandshakeCryptoKey, nonce, plaintext, aad);
  }

  private async decryptTls13Handshake(ciphertext: Uint8Array): Promise<Uint8Array> {
    const nonce = xorSequenceIntoIv(this.serverHandshakeIv!, this.serverSeqNum++);
    const aad = tlsBytes(
      CONTENT_TYPE_APPLICATION_DATA, 3, 3,
      uint16be(ciphertext.length)
    );
    const decrypted = this.cipherConfig!.chacha
      ? await chacha20Poly1305Decrypt(this.serverHandshakeKey!, nonce, ciphertext, aad)
      : await aesGcmDecrypt(
          this.serverHandshakeCryptoKey ||
            (this.serverHandshakeCryptoKey = await importAesGcmKey(
              this.serverHandshakeKey!,
              ['decrypt']
            )),
          nonce,
          ciphertext,
          aad
        );
    // Strip trailing zero padding
    let innerTypeIndex = decrypted.length - 1;
    while (innerTypeIndex >= 0 && !decrypted[innerTypeIndex]) innerTypeIndex--;
    return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1);
  }

  private async encryptTls13(data: Uint8Array): Promise<Uint8Array> {
    const plaintext = concatBytes(data, new Uint8Array([CONTENT_TYPE_APPLICATION_DATA]));
    const nonce = xorSequenceIntoIv(this.clientAppIv!, this.clientSeqNum++);
    const aad = tlsBytes(
      CONTENT_TYPE_APPLICATION_DATA, 3, 3,
      uint16be(plaintext.length + 16)
    );
    if (this.cipherConfig!.chacha) {
      return chacha20Poly1305Encrypt(this.clientAppKey!, nonce, plaintext, aad);
    }
    if (!this.clientAppCryptoKey) {
      this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey!, ['encrypt']);
    }
    return aesGcmEncrypt(this.clientAppCryptoKey, nonce, plaintext, aad);
  }

  private async decryptTls13(ciphertext: Uint8Array): Promise<{ data: Uint8Array; type: number }> {
    const nonce = xorSequenceIntoIv(this.serverAppIv!, this.serverSeqNum++);
    const aad = tlsBytes(
      CONTENT_TYPE_APPLICATION_DATA, 3, 3,
      uint16be(ciphertext.length)
    );
    const plaintext = this.cipherConfig!.chacha
      ? await chacha20Poly1305Decrypt(this.serverAppKey!, nonce, ciphertext, aad)
      : await aesGcmDecrypt(
          this.serverAppCryptoKey ||
            (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey!, ['decrypt'])),
          nonce,
          ciphertext,
          aad
        );
    let innerTypeIndex = plaintext.length - 1;
    while (innerTypeIndex >= 0 && !plaintext[innerTypeIndex]) innerTypeIndex--;
    if (innerTypeIndex < 0) return { data: EMPTY_BYTES, type: 0 };
    return { data: plaintext.slice(0, innerTypeIndex), type: plaintext[innerTypeIndex] };
  }

  // ─── Public application-data API ──────────────────────────────────

  async write(data: ArrayBuffer | Uint8Array): Promise<void> {
    if (!this.handshakeComplete) throw new Error('Handshake not complete');
    const plaintext = toUint8Array(data);
    if (!plaintext.byteLength) return;

    const writer = this.socket.writable.getWriter();
    try {
      const records: Uint8Array[] = [];
      for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
        const chunk = plaintext.subarray(
          offset,
          Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength)
        );
        const encrypted = this.isTls13
          ? await this.encryptTls13(chunk)
          : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
        records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
      }
      await writer.write(records.length === 1 ? records[0] : concatBytes(...records));
    } finally {
      writer.releaseLock();
    }
  }

  async read(): Promise<Uint8Array | null> {
    while (true) {
      let record: TlsRecord | null;
      while ((record = this.recordParser.next())) {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
          throw new Error(`TLS Alert: ${record.fragment[1]}`);
        }
        if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;

        if (!this.isTls13) {
          return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
        }

        const { data, type } = await this.decryptTls13(record.fragment);
        if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
        if (type === CONTENT_TYPE_ALERT) {
          if (data[1] === ALERT_CLOSE_NOTIFY) return null;
          throw new Error(`TLS Alert: ${data[1]}`);
        }
        if (type !== CONTENT_TYPE_HANDSHAKE) continue;

        // Handle post-handshake messages (NewSessionTicket is fine, KeyUpdate isn't)
        this.handshakeParser.feed(data);
        let message: HandshakeMessage | null;
        while ((message = this.handshakeParser.next())) {
          if (
            message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET &&
            message.type === HANDSHAKE_TYPE_KEY_UPDATE
          ) {
            throw new Error('TLS 1.3 KeyUpdate is not supported by TlsClient');
          }
        }
      }

      const reader = this.socket.readable.getReader();
      try {
        const { value, done } = await this.readChunk(reader);
        if (done) return null;
        if (value) this.recordParser.feed(value);
      } finally {
        reader.releaseLock();
      }
    }
  }

  close(): void {
    this.socket.close();
  }
}
