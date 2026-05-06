// Trojan protocol frame parser.
//
// Wire format (no encryption — Trojan relies on outer TLS):
//
//   [SHA224(password) ASCII hex (56B)] [\r\n]
//   [cmd(1B)] [atype(1B)] [addr(N)] [port(2B)] [\r\n]
//   [data...]
//
// cmd:   1=TCP, 3=UDP (SOCKS5 style)
// atype: 1=IPv4, 3=domain, 4=IPv6 (SOCKS5 style)
// port:  big-endian uint16

import { sha224 } from '../crypto/sha224.js';

export type TrojanAddressType = 1 | 3 | 4; // IPv4 | domain | IPv6

export type TrojanParseResult =
  | { hasError: true; message: string }
  | {
      hasError: false;
      addressType: TrojanAddressType;
      port: number;
      hostname: string;
      isUDP: boolean;
      rawClientData: ArrayBuffer;
    };

/**
 * Parse a complete Trojan first packet. Used on the WebSocket data path.
 */
export function parseTrojanRequest(buffer: ArrayBuffer | Uint8Array, password: string): TrojanParseResult {
  const buf: ArrayBuffer = buffer instanceof Uint8Array
    ? (buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength) as ArrayBuffer)
    : buffer;

  const expectedHash = sha224(password);
  if (buf.byteLength < 56) return { hasError: true, message: 'invalid data' };

  const crLfIndex = 56;
  const byte56 = new Uint8Array(buf.slice(56, 57))[0];
  const byte57 = new Uint8Array(buf.slice(57, 58))[0];
  if (byte56 !== 0x0d || byte57 !== 0x0a) {
    return { hasError: true, message: 'invalid header format' };
  }

  const presentedHash = new TextDecoder().decode(buf.slice(0, crLfIndex) as ArrayBuffer);
  if (presentedHash !== expectedHash) {
    return { hasError: true, message: 'invalid password' };
  }

  const socks5DataBuffer = buf.slice(crLfIndex + 2);
  if (socks5DataBuffer.byteLength < 6) {
    return { hasError: true, message: 'invalid S5 request data' };
  }

  const view = new DataView(socks5DataBuffer);
  const cmd = view.getUint8(0);
  if (cmd !== 1 && cmd !== 3) {
    return { hasError: true, message: 'unsupported command, only TCP/UDP is allowed' };
  }
  const isUDP = cmd === 3;

  const atype = view.getUint8(1) as TrojanAddressType;
  let addressLength = 0;
  let addressIndex = 2;
  let address = '';

  switch (atype) {
    case 1: // IPv4
      addressLength = 4;
      address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join('.');
      break;
    case 3: // Domain
      addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
      addressIndex += 1;
      address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength) as ArrayBuffer);
      break;
    case 4: { // IPv6
      addressLength = 16;
      const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
      const groups: string[] = [];
      for (let i = 0; i < 8; i++) groups.push(dataView.getUint16(i * 2).toString(16));
      address = groups.join(':');
      break;
    }
    default:
      return { hasError: true, message: `invalid addressType is ${atype}` };
  }

  if (!address) {
    return { hasError: true, message: `address is empty, addressType is ${atype}` };
  }

  const portIndex = addressIndex + addressLength;
  const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  return {
    hasError: false,
    addressType: atype,
    port: portRemote,
    hostname: address,
    isUDP,
    rawClientData: socks5DataBuffer.slice(portIndex + 4) as ArrayBuffer,
  };
}

// ─── Buffered (incremental) variant ──────────────────────────────────────

export interface BufferedTrojanFrame {
  protocol: 'trojan';
  hostname: string;
  port: number;
  isUDP: boolean;
  rawData: Uint8Array;
  respHeader: null;
}

export type BufferedTrojanResult =
  | { status: 'ok'; result: BufferedTrojanFrame }
  | { status: 'need_more' }
  | { status: 'invalid' };

/**
 * Incremental Trojan parser. Used by the XHTTP/gRPC dispatcher.
 * Returns 'need_more' if more bytes are needed, 'invalid' if it's
 * definitely not a valid Trojan frame, 'ok' with parsed fields otherwise.
 */
export function tryParseTrojanFirstPacket(data: Uint8Array, password: string): BufferedTrojanResult {
  const expectedHash = sha224(password);
  const expectedHashBytes = new TextEncoder().encode(expectedHash);

  const length = data.byteLength;
  if (length < 58) return { status: 'need_more' };

  // CRLF after 56-byte hash
  if (data[56] !== 0x0d || data[57] !== 0x0a) return { status: 'invalid' };

  // Compare 56 bytes of ASCII hex
  for (let i = 0; i < 56; i++) {
    if (data[i] !== expectedHashBytes[i]) return { status: 'invalid' };
  }

  const socksStart = 58;
  if (length < socksStart + 2) return { status: 'need_more' };

  const cmd = data[socksStart];
  if (cmd !== 1 && cmd !== 3) return { status: 'invalid' };
  const isUDP = cmd === 3;

  const atype = data[socksStart + 1];
  let cursor = socksStart + 2;
  let hostname = '';

  if (atype === 1) {
    if (length < cursor + 4) return { status: 'need_more' };
    hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
    cursor += 4;
  } else if (atype === 3) {
    if (length < cursor + 1) return { status: 'need_more' };
    const domainLen = data[cursor];
    if (length < cursor + 1 + domainLen) return { status: 'need_more' };
    hostname = new TextDecoder().decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
    cursor += 1 + domainLen;
  } else if (atype === 4) {
    if (length < cursor + 16) return { status: 'need_more' };
    const groups: string[] = [];
    for (let i = 0; i < 8; i++) {
      const base = cursor + i * 2;
      groups.push(((data[base] << 8) | data[base + 1]).toString(16));
    }
    hostname = groups.join(':');
    cursor += 16;
  } else {
    return { status: 'invalid' };
  }

  if (!hostname) return { status: 'invalid' };
  if (length < cursor + 4) return { status: 'need_more' };

  const port = (data[cursor] << 8) | data[cursor + 1];
  if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { status: 'invalid' };
  const dataOffset = cursor + 4;

  return {
    status: 'ok',
    result: {
      protocol: 'trojan',
      hostname,
      port,
      isUDP,
      rawData: data.subarray(dataOffset),
      respHeader: null,
    },
  };
}
