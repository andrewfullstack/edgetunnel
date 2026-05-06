# edgetunnel

[中文版本 / Chinese version →](./README.zh.md)

A VLESS proxy that runs on Cloudflare Workers / Pages.

📦 **Just want to deploy?** Grab `edgetunnel.zip` from the
[Releases page](https://github.com/andrewfullstack/edgetunnel/releases)
and follow [Cloudflare Pages (zip upload)](#cloudflare-pages-zip-upload--recommended--tested)
below.

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

### Cloudflare Pages (zip upload) — recommended ✅ tested

The most reliable path — the Workers dashboard's "paste-deploy" can
mis-classify the project as static-assets-only and refuse to let you add
environment variables. Pages doesn't have that problem.

1. **Get `edgetunnel.zip`.** Either:
   - Download it from the [Releases page](https://github.com/andrewfullstack/edgetunnel/releases)
     (recommended — built, tested, and signed by CI on every tag), or
   - Build it locally: `npm run build && zip edgetunnel.zip _worker.js`.

   Either way, the zip contains a single `_worker.js` (~80 KB) at the
   root. **Don't use the upstream `cmliu/edgetunnel` archive — its
   `_worker.js` is the original pre-refactor 4619-line file, not what
   this fork's docs describe.**
2. **Pages dashboard → Create → Pages tab → Upload assets** → name the
   project → upload the zip → **Deploy site**.
3. **Settings → Environment variables → Production** → add `ADMIN` =
   your admin password → **Save**.
4. Go back to **Deployments** → **Create new deployment** → re-upload
   the same zip → **Save and deploy**. (This step is required for the
   env var to take effect on the running deployment.)
5. **Settings → Bindings → KV namespace** → add binding with variable
   name `KV` → save → re-deploy once more.
6. **Custom domains** → bind a CNAME subdomain (note: don't use the
   apex; use a subdomain like `vless.your-domain.com`).
7. Visit `https://<your-subdomain>/admin` and log in with `ADMIN`.

### Cloudflare Pages (GitHub-connected)

1. Fork this repo.
2. **Pages → Connect to Git** → select your fork → set `ADMIN` env var.
3. Add KV binding and custom domain as above.

### Cloudflare Workers (CLI deploy via wrangler)

Most reliable Workers path; avoids the dashboard's static-assets
classification trap.

```bash
npm install
npx wrangler login
npx wrangler secret put ADMIN          # paste your admin password
npx wrangler kv namespace create KV    # note the id from the output
# Add the KV binding to wrangler.toml:
#   [[kv_namespaces]]
#   binding = "KV"
#   id = "<id-from-the-create-output>"
npm run deploy
```

Then in the Cloudflare dashboard, bind a custom domain to the worker
under **Triggers → Custom Domain**.

### Cloudflare Workers (dashboard paste) — see warning

> ⚠️ Cloudflare's new dashboard sometimes classifies a paste-deployed
> Worker as "static assets only" and then refuses to let you add
> environment variables (error: *"Variables cannot be added to a
> Worker that only has static assets"*). If you hit this, **delete the
> Worker and use one of the paths above**.

1. **Workers & Pages → Create → Workers tab → Hello World template →
   Deploy.** (Don't use other "create" paths — they may upload your
   code as static assets.)
2. Open the Worker → **Edit Code** → replace the entire content with
   the contents of [`_worker.js`](./_worker.js) → **Save and Deploy**.
3. **Settings → Variables**: add `ADMIN` = your admin password.
4. **Settings → Bindings**: add KV namespace named `KV`.
5. **Triggers → Custom Domain**: bind a subdomain.
6. Visit `https://<your-domain>/admin` and log in.

### Verifying the deployment

After binding the custom domain and DNS has propagated:

1. **`/admin`** loads — confirms the Worker is running and the `ADMIN`
   env var is plumbed in.
2. **`/admin/validation.json`** returns `{"ok": true, "count": 0}` —
   confirms the KV binding is correct and there's no schema problem.
   If `ok` is false, the admin panel will also show a yellow banner
   listing the issues.
3. **Subscription URL** — copy from the admin panel, paste into your
   client (Clash / Sing-box / Surge), confirm nodes show up.
4. **Real connection** — connect through one of the nodes, hit
   `https://ifconfig.me` or similar, confirm the IP is a Cloudflare
   address (proving traffic actually flowed through the worker).
5. **`wrangler tail <project-name>`** (optional) — streams `console.log`
   from the deployed worker. Useful for debugging issues you can't see
   from the client side.

If `/admin` shows a yellow banner ("⚠️ Config has N validation issues"),
visit `/admin/validation.json` for the full list of what's wrong with
your KV config; the validator coerces bad fields to defaults and keeps
serving, so the worker still works while you fix things.

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
