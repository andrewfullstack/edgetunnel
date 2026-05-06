# Platform Limits

This document answers the questions that come up repeatedly in proxy-on-
Workers projects. If you're about to file an issue requesting one of the
features below, read this first — most of these are **platform-level
constraints, not project decisions**, and no amount of clever code can
work around them.

## "Add Hysteria2 / TUIC support"

**Not possible on Cloudflare Workers.** Both Hysteria2 and TUIC are
QUIC/UDP-based protocols. Workers gives you an outbound TCP socket via
`cloudflare:sockets` `connect()` — there is **no UDP socket API**.

The only UDP this project does is DNS, and even that is faked: DNS
queries are tunnelled through TCP to `8.8.4.4:53` (TCP-DNS, RFC 1035 §4.2.2)
and the responses re-framed for the client. That works for VLESS UDP-mode
to port 53; it cannot work for general UDP traffic.

If you need UDP-based protocols, you need a different runtime — VPS with
Xray/sing-box, Deno Deploy (which has UDP), or similar.

## "Add REALITY support"

**Not possible on Cloudflare Workers.** REALITY needs to:

1. Receive an inbound TCP connection
2. Read the client's TLS ClientHello byte-by-byte
3. Either forward it to a real upstream (e.g. microsoft.com) for non-
   authorised clients, or hijack the handshake and complete it locally
4. After hijack, communicate using REALITY's own derived keys instead of
   the negotiated TLS session keys

Workers receives a fully-decrypted HTTP request from Cloudflare's edge.
The Worker code never sees TLS bytes. There is no inbound socket API.
Therefore there is no way to inspect or hijack a TLS handshake.

REALITY requires a runtime that owns the TCP listener. That means a VPS
running Xray/sing-box, not a Workers/Pages deployment.

## "Why is account suspension a real risk?"

Cloudflare's Workers Terms of Service include a clause prohibiting use as
a "general proxy". Enforcement is inconsistent — small personal use is
typically tolerated; large-scale or commercial operation gets the entire
Cloudflare account banned. Account ban means **all your services on that
account go offline**: domains, DNS, R2, email routing, Pages, the lot.

Treat this project as a personal tool. To minimise blast-radius:

- Use a dedicated Cloudflare account for the worker, not your main one
- Don't share access publicly (no "free public worker" mass distribution)
- Keep traffic patterns reasonable (<100k requests/day on free tier; the
  hard cap is 100k/day anyway)
- Don't run it on a domain you care about

If you're past those scales, run it on a VPS. The economics work out — a
$5/month VPS can sustain real proxy load that would get a Workers account
banned within hours.

## "Why is the bundle JavaScript instead of WASM?"

Workers supports WASM imports, but:

1. The hot path is mostly I/O (read VLESS frame, open socket, copy bytes).
   WASM doesn't speed up I/O.
2. The crypto we use (just MD5 for UUID derivation) goes through Web
   Crypto, which is native on Workers regardless of language.
3. WASM bundles are bigger than equivalent JS for code of this size, and
   bundle size is the only resource we actually optimize for here.

There's no realistic JS→WASM migration that wins anything.

## "Add Multi-tenant / per-user accounts"

**Possible, but not implemented.** Today: one `ADMIN` env var → one
password → one UUID. So a household/team has to share credentials.

The design is: `users.json` in KV with per-user `{password, uuid, label,
expiry}` records, plus an admin UI for managing them. Existing single-
user mode would stay the default if no `users.json` exists.

This is genuinely on the roadmap. It's not a platform limit, just an
unfinished feature.

## "Add metrics / observability"

`console.log` evaporates after a few minutes on the Workers free tier.
For real metrics, the right plumbing is **Workers Analytics Engine** —
free tier, queryable from a Grafana-style dashboard, supports
high-cardinality data. Per request you'd emit `{hostname, port,
bytes_up, bytes_down, duration_ms, status}` and get historical trends.

Not implemented. On the roadmap.

## "Add a custom domain"

That's a Cloudflare configuration question, not a project question. See
the README's deployment section. Briefly: bind a custom domain to your
Worker (or CNAME a subdomain to `*.workers.dev`), and the worker
responds on it. Cloudflare's edge handles TLS termination automatically.

## "Why does the worker need MD5? It's broken."

MD5 is used for **identity derivation only**, not security. The UUID is
deterministically derived from `md5x2(ADMIN + KEY)` so users don't have
to remember a separate UUID — they just remember their admin password.

There is no security claim on this MD5 use. Collision attacks against
MD5 don't help an attacker here: the input space (admin password) is
attacker-controlled in a useful way only if they already know the
password, in which case they can authenticate directly.

## "Add support for IPv6 dual-stack"

IPv6 already works for inbound (Cloudflare handles dual-stack at the
edge) and outbound (`cloudflare:sockets` `connect()` accepts IPv6 host
strings). Specific deployment quirks are usually at the DNS or client
layer, not the worker.

## "Make it run on $OTHER_PLATFORM"

Doable in principle, but requires writing a transport adapter for that
platform's TCP/TLS API. The current code is Cloudflare-specific in one
place: `import { connect } from 'cloudflare:sockets'` (used in
`src/transports/direct.ts`, `socks5.ts`, `http-connect.ts`, `udp.ts`).

The realistic port pattern is:

```
src/transports/
├── connect-cf.ts      (cloudflare:sockets)
├── connect-node.ts    (node:net + node:tls)
├── connect-deno.ts    (Deno.connect / Deno.connectTls)
├── connect-bun.ts     (Bun.connect)
└── connect.ts         (re-exports based on env)
```

Every alternative platform has native TLS, so the port shouldn't drag in
any hand-rolled crypto — just the platform's `connect`-equivalent.

This is not on the roadmap. PRs welcome.
