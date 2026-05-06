# edgetunnel

[中文版本 / Chinese version →](./README.zh.md)


A VLESS proxy that runs on Cloudflare Workers / Pages.

This is a TypeScript refactor of [`cmliu/edgetunnel`](https://github.com/cmliu/edgetunnel).
The upstream project is one 4619-line `_worker.js` with Chinese identifiers
and zero tests; this fork splits it into 37 typed modules with 171 unit
tests and 9 integration tests, while preserving runtime and KV-schema
compatibility so existing deployments upgrade seamlessly.

The deployable artefact is still a single `_worker.js` (~80 KB minified).

## What's in scope

- **VLESS** over WebSocket / XHTTP / gRPC. Cloudflare's edge handles
  inbound TLS; this code parses VLESS frames and forwards traffic.
- **Admin panel** (`/admin`) with KV-backed config, log viewer, traffic
  stats, runtime config validation.
- **Subscription generator** (`/sub`) for Clash, Sing-box, Surge,
  Quantumult X, Loon, mihomo, etc. Cached server-side for 5 minutes to
  reduce CPU on client refresh waves.
- **Upstream chaining**: direct, ProxyIP, SOCKS5, HTTP CONNECT.
- **Auto-migration** of legacy Chinese-keyed KV configs.

## What's not in scope

See [`docs/PLATFORM_LIMITS.md`](./docs/PLATFORM_LIMITS.md) for the full
explanation. Briefly:

- Shadowsocks and Trojan support — removed; VLESS covers the same use cases
- HTTPS upstream proxy mode — removed along with the hand-rolled TLS client
- UDP-based protocols (Hysteria2, TUIC) — Workers has no UDP API
- REALITY — Workers can't terminate inbound TLS
- Multi-tenant accounts — deferred until requested

If you need any of the above, run [Xray-core](https://github.com/XTLS/Xray-core)
or [sing-box](https://github.com/SagerNet/sing-box) on a VPS instead. They're
better tools for that environment.

## Deploy

You need a Cloudflare account and a domain (Cloudflare DNS, free is fine).

### Cloudflare Workers (paste-deploy)

1. Create a new Worker in the Cloudflare dashboard.
2. Paste the contents of [`_worker.js`](./_worker.js) into the editor.
3. **Settings → Variables**: add `ADMIN` = your chosen admin password.
4. **Bindings**: add a KV namespace binding named `KV`.
5. **Triggers → Custom Domain**: bind a subdomain.
6. Visit `https://<your-domain>/admin` and log in with `ADMIN`.

### Cloudflare Pages (zip upload)

1. Download [`main.zip`](https://github.com/cmliu/edgetunnel/archive/refs/heads/main.zip).
2. **Pages dashboard → Upload assets** → name the project → upload zip.
3. **Settings → Environment variables**: add `ADMIN`. Re-deploy.
4. **Settings → Bindings**: add KV namespace named `KV`.
5. **Custom domains**: bind a CNAME subdomain.
6. Visit `/admin` and log in.

### Cloudflare Pages (GitHub-connected)

1. Fork this repo.
2. **Pages → Connect to Git** → select your fork → set `ADMIN` env var.
3. Add KV binding and custom domain as above.

## Configuration

### Environment variables

| Name | Required | Example | Notes |
|---|:---:|---|---|
| `ADMIN` | yes | `mypassword` | Admin panel password. The user UUID is derived from this. |
| `KEY` | no | `mykey` | Quick-subscription path: visit `/<KEY>` to fast-fetch nodes. |
| `UUID` | no | `90cd4a77-...` | Force a fixed UUID. Must be UUIDv4. |
| `PROXYIP` | no | `proxyip.example.net:443` | Default reverse-proxy IP. |
| `URL` | no | `https://example.com` | Disguise homepage URL (or `1101`). |
| `GO2SOCKS5` | no | `*.example.com,*.foo.cn` | Hostnames forced through SOCKS5 (`*` = global). |
| `DEBUG` | no | `1` | Enable `console.log`. |
| `OFF_LOG` | no | `1` | Disable access logging. |
| `BEST_SUB` | no | `1` | Act as preferred-subscription generator. |

### Runtime path-based config

The worker accepts upstream-proxy switches via URL path segments:

```
/proxyip=proxyip.example.net
/socks5=user:password@127.0.0.1:1080
/socks5://user:password@127.0.0.1:1080      (global SOCKS5)
/http=user:password@127.0.0.1:8080
/http://user:password@127.0.0.1:8080         (global HTTP CONNECT)
```

The `/https=...` and `/https://...` syntaxes from upstream are not
supported in this fork — see [`docs/PLATFORM_LIMITS.md`](./docs/PLATFORM_LIMITS.md).

### Rotating the subscription token / node UUID

The subscription token and node UUID are derived from `md5x2(ADMIN + KEY)`.
To rotate them:

- Change `ADMIN` or `KEY` → both rotate together.
- Set `UUID` explicitly to fix a UUID (must be valid UUIDv4).

## Client compatibility

| Platform | Recommended clients |
|---|---|
| Windows | v2rayN, FlClash, mihomo-party, Clash Verge Rev |
| macOS | FlClash, mihomo-party, Clash Verge Rev, Surge |
| iOS | Surge, Shadowrocket, Stash |
| Android | ClashMetaForAndroid, FlClash, v2rayNG (Meta core preferred) |

## Development

Requires Node.js 20+.

```bash
npm install
npm run lint              # tsc --noEmit
npm test                  # vitest run (~1s, 171 tests)
npm run test:integration  # build + workerd-based end-to-end (~5s)
npm run build             # esbuild → _worker.js
npm run analyze           # per-module bundle size breakdown
npm run deploy            # build + wrangler deploy
```

The committed `_worker.js` must match a fresh build from `src/`. CI
enforces this with a drift check; if you edit `src/`, **always rebuild
and commit** the resulting bundle alongside.

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the full workflow.

## Documentation

- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to make a PR
- [`REFACTORING.md`](./REFACTORING.md) — architecture, schema migration, rename map
- [`docs/PLATFORM_LIMITS.md`](./docs/PLATFORM_LIMITS.md) — what won't work and why

## Disclaimer

This project is for educational and personal security-testing purposes.
Comply with the laws of your jurisdiction. The maintainers disclaim any
liability for misuse. Cloudflare's Terms of Service prohibit using
Workers as a "general proxy" — enforcement is inconsistent but the risk
of account suspension is real. Use a dedicated CF account, not your main
one. See `docs/PLATFORM_LIMITS.md` for details.
