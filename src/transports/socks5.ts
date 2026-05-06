// SOCKS5 client implementation.
//
// Speaks the standard SOCKS5 wire protocol over a Cloudflare Worker socket
// to forward through an upstream SOCKS5 proxy.

import { connect } from 'cloudflare:sockets';
import { byteLength } from '../utils/bytes.js';
import type { ProxyContext } from '../state.js';

/**
 * Open a SOCKS5 tunnel to (targetHost, targetPort) via the configured
 * upstream SOCKS5 proxy. Returns the connected Socket once the tunnel is
 * established, with optional initial data already written.
 *
 * @throws on auth failure or connect refusal
 */
export async function socks5Connect(
  ctx: ProxyContext,
  targetHost: string,
  targetPort: number,
  initialData: Uint8Array | null
): Promise<any> {
  const { username, password, hostname, port } = ctx.parsedSocks5;
  const socket = connect({ hostname, port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();

  try {
    // Step 1: Method selection.
    // Offer either [no-auth] or [no-auth, user/pass] depending on credentials.
    const authMethods =
      username && password
        ? new Uint8Array([0x05, 0x02, 0x00, 0x02])
        : new Uint8Array([0x05, 0x01, 0x00]);
    await writer.write(authMethods);

    let response = await reader.read();
    if (response.done || response.value.byteLength < 2) {
      throw new Error('S5 method selection failed');
    }

    const selectedMethod = new Uint8Array(response.value)[1];

    // Step 2: If server picked user/pass auth, send credentials.
    if (selectedMethod === 0x02) {
      if (!username || !password) throw new Error('S5 requires authentication');
      const userBytes = new TextEncoder().encode(username);
      const passBytes = new TextEncoder().encode(password);
      const authPacket = new Uint8Array([
        0x01,
        userBytes.length,
        ...userBytes,
        passBytes.length,
        ...passBytes,
      ]);
      await writer.write(authPacket);
      response = await reader.read();
      if (response.done || new Uint8Array(response.value)[1] !== 0x00) {
        throw new Error('S5 authentication failed');
      }
    } else if (selectedMethod !== 0x00) {
      throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
    }

    // Step 3: CONNECT request — domain-name address type.
    const hostBytes = new TextEncoder().encode(targetHost);
    const connectPacket = new Uint8Array([
      0x05, 0x01, 0x00, 0x03,
      hostBytes.length,
      ...hostBytes,
      targetPort >> 8,
      targetPort & 0xff,
    ]);
    await writer.write(connectPacket);
    response = await reader.read();
    if (response.done || new Uint8Array(response.value)[1] !== 0x00) {
      throw new Error('S5 connection failed');
    }

    if (byteLength(initialData) > 0 && initialData) {
      await writer.write(initialData);
    }

    writer.releaseLock();
    reader.releaseLock();
    return socket;
  } catch (error) {
    try { writer.releaseLock(); } catch (e) { /* */ }
    try { reader.releaseLock(); } catch (e) { /* */ }
    try { socket.close(); } catch (e) { /* */ }
    throw error;
  }
}
