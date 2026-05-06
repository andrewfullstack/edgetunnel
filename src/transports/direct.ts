// Direct TCP forwarding orchestrator.
//
// This is the heart of the data plane: given a target (host, port) and
// the initial bytes (rawData), open a connection through the right path
// (direct, SOCKS5, HTTP CONNECT, or proxy-IP fallback) and pump bytes
// bidirectionally between the WebSocket and the remote socket.
//
// The chain logic:
//   1. If SOCKS5/HTTP global mode OR target matches socks5 whitelist:
//      route through configured upstream proxy (SOCKS5 / HTTP / HTTPS).
//   2. Otherwise: try direct connect first.
//      On failure, fall back to the proxy-IP chain.
//
// Retries: if the first packet sent through direct doesn't elicit any
// response (server didn't accept), we retry through the proxy chain
// — but only the first attempt sends rawData (so we don't double-write).

import { connect } from 'cloudflare:sockets';
import { byteLength } from '../utils/bytes.js';
import type { LogFn } from '../utils/logger.js';
import type { ProxyContext } from '../state.js';
import { socks5Connect } from './socks5.js';
import { httpConnect } from './http-connect.js';
import { connectStreams } from './byob-stream.js';
import {
  closeSocketQuietly,
  waitConnect,
  CONNECT_TIMEOUT_MS,
} from './socket-utils.js';

export interface RemoteConnWrapper {
  socket: any;
  connectingPromise: Promise<void> | null;
  retryConnect: (() => Promise<void>) | null;
}

/** A resolved proxy-IP candidate as `[hostname, port]`. */
export type ProxyIPArray = Array<[string, number]>;

/**
 * Resolver that converts the configured proxyIP string into a list of
 * candidate (hostname, port) pairs to try in round-robin.
 *
 * Equivalent to the legacy `parseAddressPort` routine — it performs DNS
 * lookups, Cloudflare colo-aware hostname expansion, etc. We pass it as
 * a callback so direct.ts doesn't depend on the resolver (it lives in admin/).
 */
export type ProxyResolver = (
  proxyIPSpec: string,
  targetHost: string,
  uuid: string
) => Promise<ProxyIPArray>;

export interface ForwardTcpDeps {
  ctx: ProxyContext;
  log: LogFn;
  /** Resolves proxyIP to round-robin list. Required. */
  resolveProxyIPs: ProxyResolver;
}

/**
 * Open a connection directly to (address, port) — or, if a list of
 * proxy-IP candidates is provided, try them in round-robin first.
 *
 * On any candidate's connect+initial-write success, returns the socket.
 * If the proxy-IP list is exhausted and `fallbackToDirect` is true,
 * falls through to direct. If fallback is disabled, throws.
 *
 * @param fallbackToDirect - mirrors `proxyFallbackEnabled` from the legacy
 *                            global. When PROXYIP env var is explicitly set,
 *                            this is false (don't bypass user config).
 */
export async function connectDirect(
  ctx: ProxyContext,
  log: LogFn,
  ws: WebSocket,
  address: string,
  port: number,
  data: Uint8Array | null = null,
  proxyArray: ProxyIPArray | null = null,
  fallbackToDirect = true
): Promise<any> {
  let remoteSock: any;

  if (proxyArray && proxyArray.length > 0) {
    for (let i = 0; i < proxyArray.length; i++) {
      const idx = (ctx.cachedProxyIndex + i) % proxyArray.length;
      const [proxyHost, proxyPort] = proxyArray[idx];
      try {
        log(`[proxy] connect attempt: ${proxyHost}:${proxyPort} (idx=${idx})`);
        remoteSock = connect({ hostname: proxyHost, port: proxyPort });
        await waitConnect(remoteSock);
        if (byteLength(data) > 0 && data) {
          const w = remoteSock.writable.getWriter();
          await w.write(data);
          w.releaseLock();
        }
        log(`[proxy] connected to: ${proxyHost}:${proxyPort}`);
        ctx.cachedProxyIndex = idx;
        return remoteSock;
      } catch (err: any) {
        log(`[proxy] connect failed: ${proxyHost}:${proxyPort}, error: ${err?.message}`);
        try { remoteSock?.close?.() } catch (e) { /* */ }
        continue;
      }
    }
  }

  if (fallbackToDirect) {
    remoteSock = connect({ hostname: address, port });
    await waitConnect(remoteSock);
    if (byteLength(data) > 0 && data) {
      const w = remoteSock.writable.getWriter();
      await w.write(data);
      w.releaseLock();
    }
    return remoteSock;
  }

  closeSocketQuietly(ws);
  throw new Error('[proxy] all proxy connections failed and fallback disabled');
}

/** Test if hostname matches any pattern in SOCKS5whitelist (glob-like '*'). */
function matchSocks5Whitelist(hostname: string, whitelist: string[]): boolean {
  return whitelist.some((pattern) => {
    const regex = new RegExp(`^${pattern.replace(/\*/g, '.*')}$`, 'i');
    return regex.test(hostname);
  });
}

/**
 * High-level entry: forward TCP traffic from `ws` to `host:portNum`.
 *
 * Handles:
 *   - Direct vs proxy-chain decision (based on socks5 mode + whitelist)
 *   - First-packet attempts and retry
 *   - Stream pumping via connectStreams (BYOB-aware)
 *
 * `remoteConnWrapper.retryConnect` is set to a function that callers
 * (e.g. the WS write handler) can invoke if the direct send fails.
 */
export async function forwardTcp(
  deps: ForwardTcpDeps,
  host: string,
  portNum: number,
  rawData: Uint8Array,
  ws: WebSocket,
  respHeader: Uint8Array | null,
  remoteConnWrapper: RemoteConnWrapper,
  yourUUID: string
): Promise<void> {
  const { ctx, log, resolveProxyIPs } = deps;
  log(
    `[TCP] target: ${host}:${portNum} | proxyIP: ${ctx.proxyIP} | fallback: ${ctx.proxyFallbackEnabled ? 'yes' : 'no'} | mode: ${ctx.socks5Mode || 'proxyip'} | global: ${ctx.socks5GlobalEnabled ? 'yes' : 'no'}`
  );

  let firstPacketSentViaProxy = false;

  /** Connect through configured upstream proxy chain or proxyIP fallback. */
  async function connectThroughProxy(allowSendFirstPacket = true): Promise<void> {
    if (remoteConnWrapper.connectingPromise) {
      await remoteConnWrapper.connectingPromise;
      return;
    }

    const sendFirstThisAttempt =
      allowSendFirstPacket && !firstPacketSentViaProxy && byteLength(rawData) > 0;
    const firstPacketData = sendFirstThisAttempt ? rawData : null;

    const task = (async () => {
      let newSocket: any;
      if (ctx.socks5Mode === 'socks5') {
        log(`[SOCKS5] forwarding to: ${host}:${portNum}`);
        newSocket = await socks5Connect(ctx, host, portNum, firstPacketData);
      } else if (ctx.socks5Mode === 'http') {
        log(`[HTTP-CONNECT] forwarding to: ${host}:${portNum}`);
        newSocket = await httpConnect(ctx, host, portNum, firstPacketData);
      } else {
        log(`[proxyIP] forwarding to: ${host}:${portNum}`);
        const proxyArray = await resolveProxyIPs(ctx.proxyIP, host, yourUUID);
        // The opaque destination "PROXYIP.tp1.090227.xyz" is base64-decoded
        // from the original — it's a marker, never actually connected to;
        // connectDirect picks from the proxyArray instead.
        const placeholderHost = atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg==');
        newSocket = await connectDirect(
          ctx,
          log,
          ws,
          placeholderHost,
          1,
          firstPacketData,
          proxyArray,
          ctx.proxyFallbackEnabled
        );
      }
      if (sendFirstThisAttempt) firstPacketSentViaProxy = true;
      remoteConnWrapper.socket = newSocket;
      newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
      connectStreams(newSocket, ws, respHeader, null, log);
    })();

    remoteConnWrapper.connectingPromise = task;
    try {
      await task;
    } finally {
      if (remoteConnWrapper.connectingPromise === task) {
        remoteConnWrapper.connectingPromise = null;
      }
    }
  }

  remoteConnWrapper.retryConnect = async () => connectThroughProxy(!firstPacketSentViaProxy);

  // Decide initial path: proxy chain vs direct
  const useProxyChain =
    ctx.socks5Mode &&
    (ctx.socks5GlobalEnabled || matchSocks5Whitelist(host, ctx.socks5Whitelist));

  if (useProxyChain) {
    log('[TCP] using SOCKS5/HTTP/HTTPS proxy chain');
    try {
      await connectThroughProxy();
    } catch (err: any) {
      log(`[TCP] proxy chain failed: ${err?.message}`);
      throw err;
    }
  } else {
    try {
      log(`[TCP] direct connect: ${host}:${portNum}`);
      const initialSocket = await connectDirect(ctx, log, ws, host, portNum, rawData);
      remoteConnWrapper.socket = initialSocket;
      connectStreams(initialSocket, ws, respHeader, async () => {
        if (remoteConnWrapper.socket !== initialSocket) return;
        await connectThroughProxy();
      }, log);
    } catch (err: any) {
      log(`[TCP] direct connect failed ${host}:${portNum}: ${err?.message}`);
      await connectThroughProxy();
    }
  }
}
