// EdgeTunnel main fetch handler entry point.
//
// Dispatches incoming requests to the appropriate handler:
//   - WebSocket upgrade   → WS proxy (VLESS / Trojan / SS)
//   - POST + grpc         → gRPC proxy
//   - POST other          → XHTTP proxy
//   - GET /version        → version info
//   - GET /login          → login page
//   - GET /admin/*        → admin panel (cookie-gated)
//   - GET /sub            → subscription generator
//   - GET /robots.txt     → SEO blocker
//   - GET /locations      → speed.cloudflare.com proxy
//   - GET /                → fallback / disguise page
//
// The "disguise" handling (env.URL or default nginx welcome) is what lets
// the worker domain look like an innocuous website to anyone without
// the correct credentials.

import { md5x2 } from './crypto/md5.js';
import { normalizeRequestUrl, toArray } from './utils/url.js';
import { createDefaultContext, type ProxyContext } from './state.js';
import { makeLogger } from './utils/logger.js';
import { PAGES_STATIC_URL } from './constants.js';
import { handleLogin, verifyAuthCookie } from './handlers/login.js';
import { handleAdmin } from './handlers/admin.js';
import { handleSubscription } from './handlers/sub.js';
import { handleWebSocketRequest } from './handlers/websocket.js';
import { handleGrpcRequest } from './handlers/grpc.js';
import { handleXhttpRequest } from './handlers/xhttp.js';
import { parseProxyParams } from './admin/proxy-resolver.js';
import { parseAddressPort } from './admin/parse-address.js';
import { httpsConnect } from './transports/https-proxy.js';
import { nginx, html1101 } from './admin/pages.js';
import type { ForwardTcpDeps } from './transports/direct.js';

const VERSION = '2026-05-03 01:19:25';

interface WorkerEnv {
  KV: KVNamespace;
  ADMIN?: string;
  admin?: string;
  PASSWORD?: string;
  password?: string;
  pswd?: string;
  TOKEN?: string;
  KEY?: string;
  UUID?: string;
  uuid?: string;
  HOST?: string;
  PATH?: string;
  PROXYIP?: string;
  GO2SOCKS5?: string;
  URL?: string;
  DEBUG?: string;
  OFF_LOG?: string;
  BEST_SUB?: string;
}

const UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

export default {
  async fetch(
    request: Request,
    env: WorkerEnv,
    workerCtx: { waitUntil(p: Promise<any>): void; passThroughOnException(): void }
  ): Promise<Response> {
    const url = new URL(normalizeRequestUrl(request.url));
    const ua = request.headers.get('User-Agent') || 'null';
    const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();
    const contentType = (request.headers.get('content-type') || '').toLowerCase();

    const adminPassword =
      env.ADMIN || env.admin || env.PASSWORD || env.password ||
      env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid || '';
    const encryptKey = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';

    const userIDMD5 = await md5x2(adminPassword + encryptKey);
    const envUUID = env.UUID || env.uuid;
    const userID =
      envUUID && UUID_REGEX.test(envUUID)
        ? envUUID.toLowerCase()
        : [
            userIDMD5.slice(0, 8),
            userIDMD5.slice(8, 12),
            '4' + userIDMD5.slice(13, 16),
            '8' + userIDMD5.slice(17, 20),
            userIDMD5.slice(20),
          ].join('-');

    const hosts = env.HOST
      ? toArray(env.HOST).map((h) =>
          h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]
        )
      : [url.hostname];
    const host = hosts[0];
    const accessPath = url.pathname.slice(1).toLowerCase();
    const casePreservingPath = url.pathname.slice(1);

    // Build the per-request ProxyContext
    const ctx: ProxyContext = createDefaultContext();
    ctx.debugLogEnabled = ['1', 'true'].includes(env.DEBUG || '');
    if (env.PROXYIP) {
      const proxyIPs = toArray(env.PROXYIP);
      ctx.proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
      ctx.proxyFallbackEnabled = false;
    } else {
      ctx.proxyIP = ((request as any).cf?.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
    }
    if (env.GO2SOCKS5) ctx.socks5Whitelist = toArray(env.GO2SOCKS5);

    const accessIP =
      request.headers.get('CF-Connecting-IP') ||
      request.headers.get('True-Client-IP') ||
      request.headers.get('X-Real-IP') ||
      request.headers.get('X-Forwarded-For') ||
      request.headers.get('Fly-Client-IP') ||
      request.headers.get('X-Appengine-Remote-Addr') ||
      request.headers.get('X-Cluster-Client-IP') ||
      'unknown-IP';

    const log = makeLogger(ctx);
    const tcpDeps: ForwardTcpDeps = {
      ctx,
      log,
      resolveProxyIPs: (proxyIP, target, uuid) =>
        parseAddressPort(ctx, proxyIP, target, uuid, log),
      httpsConnect: (c, h, p, d) => httpsConnect(c, h, p, d, log),
    };

    // ─── Version endpoint ───────────────────────────────────────────
    if (accessPath === 'version' && url.searchParams.get('uuid') === userID) {
      return new Response(
        JSON.stringify({ Version: Number(String(VERSION).replace(/\D+/g, '')) }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        }
      );
    }

    // ─── WebSocket data plane ───────────────────────────────────────
    if (adminPassword && upgradeHeader === 'websocket') {
      await parseProxyParams(ctx, url);
      log(`[WS] hit: ${url.pathname}${url.search}`);
      return await handleWebSocketRequest(tcpDeps, request, userID, url);
    }

    // ─── gRPC / XHTTP data plane ────────────────────────────────────
    if (
      adminPassword &&
      !accessPath.startsWith('admin/') &&
      accessPath !== 'login' &&
      request.method === 'POST'
    ) {
      await parseProxyParams(ctx, url);
      const referer = request.headers.get('Referer') || '';
      const isXhttpHint =
        referer.includes('x_padding', 14) || referer.includes('x_padding=');
      if (!isXhttpHint && contentType.startsWith('application/grpc')) {
        log(`[gRPC] hit: ${url.pathname}${url.search}`);
        return await handleGrpcRequest(tcpDeps, request, userID);
      }
      log(`[XHTTP] hit: ${url.pathname}${url.search}`);
      return await handleXhttpRequest(tcpDeps, request, userID);
    }

    // ─── HTTP redirect to HTTPS ─────────────────────────────────────
    // Skip for local dev hostnames: wrangler dev binds to localhost/127.0.0.1,
    // and `unstable_dev` (used by integration tests) uses 'placeholder'.
    if (
      url.protocol === 'http:' &&
      url.hostname !== 'localhost' &&
      url.hostname !== '127.0.0.1' &&
      url.hostname !== 'placeholder'
    ) {
      return Response.redirect(
        url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`),
        301
      );
    }

    // ─── No admin password → "noADMIN" page ─────────────────────────
    if (!adminPassword) {
      const r = await fetch(PAGES_STATIC_URL + '/noADMIN');
      const headers = new Headers(r.headers);
      headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      headers.set('Pragma', 'no-cache');
      headers.set('Expires', '0');
      return new Response(r.body, {
        status: 404,
        statusText: r.statusText,
        headers,
      });
    }

    // ─── KV-required endpoints ──────────────────────────────────────
    if (env.KV && typeof env.KV.get === 'function') {
      // Quick subscription path: /<KEY> redirects to /sub?token=…
      if (
        casePreservingPath === encryptKey &&
        encryptKey !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改'
      ) {
        const params = new URLSearchParams(url.search);
        params.set('token', await md5x2(host + userID));
        return new Response('Redirecting...', {
          status: 302,
          headers: { Location: `/sub?${params.toString()}` },
        });
      }

      // /login
      if (accessPath === 'login') {
        return handleLogin(request, ua, adminPassword, encryptKey);
      }

      // /admin/*
      if (accessPath === 'admin' || accessPath.startsWith('admin/')) {
        const ok = await verifyAuthCookie(request, ua, adminPassword, encryptKey);
        if (!ok) {
          return new Response('Redirecting...', {
            status: 302,
            headers: { Location: '/login' },
          });
        }
        return handleAdmin(
          ctx, env, request, url,
          accessPath, casePreservingPath,
          host, userID, ua, accessIP, workerCtx
        );
      }

      // /logout or /<uuid>
      if (accessPath === 'logout' || UUID_REGEX.test(accessPath)) {
        const response = new Response('Redirecting...', {
          status: 302,
          headers: { Location: '/login' },
        });
        response.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
        return response;
      }

      // /sub
      if (accessPath === 'sub') {
        const subResponse = await handleSubscription(
          ctx, env, request, url, host, userID, ua, accessIP, workerCtx
        );
        if (subResponse) return subResponse;
      }

      // /locations - speed.cloudflare.com proxy (cookie-gated)
      if (accessPath === 'locations') {
        const ok = await verifyAuthCookie(request, ua, adminPassword, encryptKey);
        if (ok) {
          return fetch(
            new Request('https://speed.cloudflare.com/locations', {
              headers: { Referer: 'https://speed.cloudflare.com/' },
            })
          );
        }
      }

      // /robots.txt
      if (accessPath === 'robots.txt') {
        return new Response('User-agent: *\nDisallow: /', {
          status: 200,
          headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
        });
      }
    } else if (!envUUID) {
      // No KV binding: serve "noKV" page from CDN
      const r = await fetch(PAGES_STATIC_URL + '/noKV');
      const headers = new Headers(r.headers);
      headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      headers.set('Pragma', 'no-cache');
      headers.set('Expires', '0');
      return new Response(r.body, {
        status: 404,
        statusText: r.statusText,
        headers,
      });
    }

    // ─── Disguise / fallback ───────────────────────────────────────
    let disguiseUrl = env.URL || 'nginx';
    if (disguiseUrl && disguiseUrl !== 'nginx' && disguiseUrl !== '1101') {
      disguiseUrl = disguiseUrl.trim().replace(/\/$/, '');
      if (!disguiseUrl.match(/^https?:\/\//i)) disguiseUrl = 'https://' + disguiseUrl;
      if (disguiseUrl.toLowerCase().startsWith('http://')) {
        disguiseUrl = 'https://' + disguiseUrl.substring(7);
      }
      try {
        const u = new URL(disguiseUrl);
        disguiseUrl = u.protocol + '//' + u.host;
      } catch (e) {
        disguiseUrl = 'nginx';
      }
    }

    if (disguiseUrl === '1101') {
      return new Response(html1101(url.host, accessIP), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=UTF-8' },
      });
    }

    if (disguiseUrl !== 'nginx') {
      try {
        const targetURL = new URL(disguiseUrl);
        const newHeaders = new Headers(request.headers);
        newHeaders.set('Host', targetURL.host);
        newHeaders.set('Referer', targetURL.origin);
        newHeaders.set('Origin', targetURL.origin);
        if (!newHeaders.has('User-Agent') && ua && ua !== 'null') {
          newHeaders.set('User-Agent', ua);
        }
        const proxyResponse = await fetch(
          targetURL.origin + url.pathname + url.search,
          {
            method: request.method,
            headers: newHeaders,
            body: request.body,
            cf: (request as any).cf,
          } as any
        );
        const respContentType = proxyResponse.headers.get('content-type') || '';
        if (/text|javascript|json|xml/.test(respContentType)) {
          const body = (await proxyResponse.text()).replaceAll(targetURL.host, url.host);
          return new Response(body, {
            status: proxyResponse.status,
            headers: {
              ...Object.fromEntries(proxyResponse.headers),
              'Cache-Control': 'no-store',
            },
          });
        }
        return proxyResponse;
      } catch (error) {
        /* fall through to nginx */
      }
    }

    return new Response(nginx(), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=UTF-8' },
    });
  },
};
