// VLESS protocol frame parser.
//
// Wire format (no encryption — VLESS relies on outer transport for that):
//
//   [version(1B)] [UUID(16B)] [optLen(1B)] [opt(N)]
//   [cmd(1B)] [port(2B)] [atype(1B)] [addr(N)] [data...]
//
// version: typically 0x00 (echoed back as response header [version, 0])
// UUID: 16-byte raw UUID, must equal MD5(adminPassword) reformatted
// cmd:   1=TCP, 2=UDP
// atype: 1=IPv4 (4B), 2=domain (1B length + N), 3=IPv6 (16B)
// port:  big-endian uint16
//
// Two parsing flavours:
//   1. parseVlessRequest:        called when full first packet is in hand (WS path)
//   2. tryParseVlessFirstPacket: incremental, returns 'need_more' on partial input

import { formatUuid } from '../crypto/md5.js';

export type VlessAddressType = 1 | 2 | 3; // IPv4 | domain | IPv6

export type VlessParseResult =
  | { hasError: true; message: string }
  | {
      hasError: false;
      addressType: VlessAddressType;
      port: number;
      hostname: string;
      isUDP: boolean;
      rawIndex: number;
      version: Uint8Array;
    };

/**
 * Parse a complete VLESS first packet. Used on the WebSocket data path
 * where the client is expected to send the full frame in one chunk.
 *
 * Returns either an error object or the parsed fields plus `rawIndex`
 * — the offset where the application payload begins.
 */
export function parseVlessRequest(chunk: ArrayBuffer | Uint8Array, token: string): VlessParseResult {
  const buffer: ArrayBuffer = chunk instanceof Uint8Array
    ? (chunk.buffer.slice(chunk.byteOffset, chunk.byteOffset + chunk.byteLength) as ArrayBuffer)
    : chunk;
  if (buffer.byteLength < 24) return { hasError: true, message: 'Invalid data' };

  const version = new Uint8Array(buffer.slice(0, 1));
  if (formatUuid(new Uint8Array(buffer.slice(1, 17))) !== token) {
    return { hasError: true, message: 'Invalid uuid' };
  }

  const optLen = new Uint8Array(buffer.slice(17, 18))[0];
  const cmd = new Uint8Array(buffer.slice(18 + optLen, 19 + optLen))[0];

  let isUDP = false;
  if (cmd === 1) { /* TCP */ }
  else if (cmd === 2) isUDP = true;
  else return { hasError: true, message: 'Invalid command' };

  const portIdx = 19 + optLen;
  const port = new DataView(buffer.slice(portIdx, portIdx + 2)).getUint16(0);

  const addrTypeIdx = portIdx + 2;
  let addrValIdx = addrTypeIdx + 1;
  let addrLen = 0;
  let hostname = '';
  const addressType = new Uint8Array(buffer.slice(addrTypeIdx, addrValIdx))[0] as VlessAddressType;

  switch (addressType) {
    case 1: // IPv4
      addrLen = 4;
      hostname = new Uint8Array(buffer.slice(addrValIdx, addrValIdx + addrLen)).join('.');
      break;
    case 2: // Domain (length-prefixed)
      addrLen = new Uint8Array(buffer.slice(addrValIdx, addrValIdx + 1))[0];
      addrValIdx += 1;
      hostname = new TextDecoder().decode(buffer.slice(addrValIdx, addrValIdx + addrLen) as ArrayBuffer);
      break;
    case 3: { // IPv6
      addrLen = 16;
      const view = new DataView(buffer.slice(addrValIdx, addrValIdx + addrLen));
      const groups: string[] = [];
      for (let i = 0; i < 8; i++) groups.push(view.getUint16(i * 2).toString(16));
      hostname = groups.join(':');
      break;
    }
    default:
      return { hasError: true, message: `Invalid address type: ${addressType}` };
  }

  if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };

  return {
    hasError: false,
    addressType,
    port,
    hostname,
    isUDP,
    rawIndex: addrValIdx + addrLen,
    version,
  };
}

// ─── Buffered (incremental) variant ──────────────────────────────────────

export type BufferedParseStatus = 'ok' | 'need_more' | 'invalid';

export interface BufferedVlessFrame {
  protocol: 'vless';
  hostname: string;
  port: number;
  isUDP: boolean;
  rawData: Uint8Array;
  respHeader: Uint8Array;
}

export type BufferedVlessResult =
  | { status: 'ok'; result: BufferedVlessFrame }
  | { status: 'need_more' }
  | { status: 'invalid' };

/**
 * Try to parse a VLESS first packet from a possibly-incomplete buffer.
 *
 * Returns:
 *   - 'need_more' if we need more bytes to finish parsing
 *   - 'invalid' if the buffer definitely isn't VLESS (e.g. UUID mismatch)
 *   - 'ok' with parsed fields once the header is fully consumed
 *
 * Used by the XHTTP/gRPC dispatcher to probe the protocol incrementally.
 */
export function tryParseVlessFirstPacket(data: Uint8Array, token: string): BufferedVlessResult {
  const length = data.byteLength;
  if (length < 18) return { status: 'need_more' };
  if (formatUuid(data.subarray(1, 17)) !== token) return { status: 'invalid' };

  const optLen = data[17];
  const cmdIndex = 18 + optLen;
  if (length < cmdIndex + 1) return { status: 'need_more' };

  const cmd = data[cmdIndex];
  if (cmd !== 1 && cmd !== 2) return { status: 'invalid' };

  const portIndex = cmdIndex + 1;
  if (length < portIndex + 3) return { status: 'need_more' };

  const port = (data[portIndex] << 8) | data[portIndex + 1];
  const addressType = data[portIndex + 2];
  const addressIndex = portIndex + 3;

  let headerLen = -1;
  let hostname = '';

  if (addressType === 1) {
    if (length < addressIndex + 4) return { status: 'need_more' };
    hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
    headerLen = addressIndex + 4;
  } else if (addressType === 2) {
    if (length < addressIndex + 1) return { status: 'need_more' };
    const domainLen = data[addressIndex];
    if (length < addressIndex + 1 + domainLen) return { status: 'need_more' };
    hostname = new TextDecoder().decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
    headerLen = addressIndex + 1 + domainLen;
  } else if (addressType === 3) {
    if (length < addressIndex + 16) return { status: 'need_more' };
    const groups: string[] = [];
    for (let i = 0; i < 8; i++) {
      const base = addressIndex + i * 2;
      groups.push(((data[base] << 8) | data[base + 1]).toString(16));
    }
    hostname = groups.join(':');
    headerLen = addressIndex + 16;
  } else {
    return { status: 'invalid' };
  }

  if (!hostname) return { status: 'invalid' };

  return {
    status: 'ok',
    result: {
      protocol: 'vless',
      hostname,
      port,
      isUDP: cmd === 2,
      rawData: data.subarray(headerLen),
      respHeader: new Uint8Array([data[0], 0]),
    },
  };
}
