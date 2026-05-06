# EdgeTunnel Refactor Notes

This document explains why the upstream `cmliu/edgetunnel` was forked, what
the refactor changed, and what contributors should know before editing the
code. Translation of this doc to English is part of the fork's stated goal
of lowering the contribution barrier — it used to be Chinese-only.

## Why this fork

[The upstream project `cmliu/edgetunnel`](https://github.com/cmliu/edgetunnel)
is a brilliant Cloudflare Workers edge-proxy implementation — **a great
idea, but very hard to maintain**:

- All logic crammed into a single 4619-line `_worker.js` file
- Variables, functions, fields named in Chinese identifiers
- Zero TypeScript types
- Zero test coverage

Net effect: the contribution barrier is high, the project is effectively
maintained by one person, and even reading the code is hard. The goal of
this refactor is simple — **make the project something anyone can read,
modify, and contribute to** — while preserving runtime behaviour and the
deployment shape so existing users can upgrade seamlessly.

## Current status

```
Source modules           37 .ts files (~7400 lines)
Test modules             16 .ts files
Tests                    173 unit + 6 integration (workerd via wrangler unstable_dev)
TypeScript errors        0
Bundle artefact          _worker.js  ~77 KB (esbuild minified, VLESS-only)
Original single file     git show <initial-commit>:_worker.original.js
```

Common scripts:

```bash
npm install            # install deps
npm run lint           # tsc --noEmit
npm test               # vitest run (unit tests)
npm run test:integration  # build + run integration tests in workerd
npm run build          # esbuild → _worker.js
npm run analyze        # per-module bundle size breakdown
npm run deploy         # build + wrangler deploy
```

## Project layout

```
edgetunnel/
├── _worker.js                   ← build artefact (overwritten by `npm run build`;
│                                  the original single-file source lives in the
│                                  initial commit, not the working tree)
├── package.json                 ← deps + scripts
├── package-lock.json            ← committed for reproducible CI builds
├── tsconfig.json                ← TypeScript config
├── build.mjs                    ← esbuild entry
├── build-analyze.mjs            ← `npm run analyze` (esbuild metafile)
├── vitest.config.ts             ← unit-test config (excludes integration)
├── vitest.config.integration.ts ← integration-test config (workerd)
├── wrangler.toml                ← deployment config
├── REFACTORING.md               ← this document
├── .github/workflows/
│   ├── ci.yml                   ← lint + test + build + drift check on every push
│   └── release.yml              ← publishes _worker.js to Releases on tag push
├── src/
│   ├── index.ts                 ← main fetch handler (route dispatch)
│   ├── constants.ts             ← protocol-layer constants
│   ├── state.ts                 ← ProxyContext (replaces module-level globals)
│   ├── crypto/                  ← only md5.ts remains; the hand-rolled TLS
│   │                              client + cipher suites were removed when
│   │                              the HTTPS upstream proxy mode was dropped
│   ├── protocols/
│   │   ├── dispatch.ts          ← buffered VLESS first-packet probe
│   │   │                          (used by XHTTP/gRPC paths)
│   │   └── vless.ts             ← VLESS frame parser
│   ├── transports/
│   │   ├── byob-stream.ts       ← BYOB stream optimisation
│   │   ├── direct.ts            ← forwardTcp + connectDirect (main forwarder)
│   │   ├── http-connect.ts      ← HTTP CONNECT tunnel
│   │   ├── socket-utils.ts      ← close / wsSend / waitConnect helpers
│   │   ├── socks5.ts            ← SOCKS5 client
│   │   └── udp.ts               ← DNS-over-TCP (Workers can't do real UDP)
│   ├── handlers/
│   │   ├── admin.ts             ← /admin/* routes (KV CRUD + status)
│   │   ├── grpc.ts              ← gRPC data plane
│   │   ├── login.ts             ← /login + cookie verification
│   │   ├── sub.ts               ← /sub subscription generation
│   │   ├── websocket.ts         ← primary WebSocket data plane
│   │   └── xhttp.ts             ← XHTTP data plane
│   ├── subscription/
│   │   ├── clash.ts             ← Clash YAML patcher
│   │   ├── singbox.ts           ← Sing-box JSON schema migrator
│   │   └── surge.ts             ← Surge MANAGED-CONFIG header injector
│   ├── admin/
│   │   ├── cloudflare-api.ts    ← Cloudflare GraphQL usage stats
│   │   ├── config.ts            ← readConfigJson + legacy schema migration
│   │   ├── config-schema.ts     ← runtime validator for KV config
│   │   ├── pages.ts             ← nginx() / html1101() disguise pages
│   │   ├── parse-address.ts     ← proxy IP parse + cache + deterministic shuffle
│   │   ├── preferred-sub.ts     ← preferred-IP API + multi-encoding CSV parser
│   │   ├── proxy-resolver.ts    ← parseSocks5Auth + parseProxyParams
│   │   ├── random-ip.ts         ← ISP-aware random IP generator
│   │   └── transport.ts         ← transport config helpers
│   └── utils/
│       ├── bytes.ts             ← byte-array helpers
│       ├── dns.ts               ← DoH + ECH config extraction
│       ├── hostname.ts          ← IP/hostname classification
│       ├── log.ts               ← access log + Telegram push
│       ├── logger.ts            ← debug log
│       ├── path.ts              ← randomPath / replaceAsterisks / bulkReplaceDomains
│       └── url.ts               ← normalizeRequestUrl / toArray
└── tests/
    ├── admin/                   ← config-schema, proxy-resolver, transport, random-ip
    ├── handlers/                ← (currently empty after SS-inbound removal)
    ├── integration/             ← end-to-end via wrangler unstable_dev
    ├── protocols/               ← VLESS + dispatch boundaries
    ├── subscription/            ← Surge patcher
    ├── transports/              ← socket-utils, byob
    ├── utils/                   ← bytes, url, hostname, path, log
    └── crypto/                  ← md5
```

## Key architectural changes from upstream

### 1. Module-level globals → request-scoped ProxyContext

The original code used module-top-level mutable state (`let 反代IP = ''` and
similar), relying on the fetch handler to reset them on every request. This
is fragile under Cloudflare Workers' isolate reuse + concurrent requests —
state can bleed between requests.

The refactor moves all per-request state into a `ProxyContext` object,
created at the top of the fetch handler and threaded explicitly through
every layer.

```typescript
// Before
let 反代IP = '';
function 处理请求() { 反代IP = '...' }

// After
const ctx = createDefaultContext();
function handleRequest(ctx: ProxyContext) { ctx.proxyIP = '...' }
```

### 2. All Chinese identifiers translated to English

Every variable, function, field, and object key is now English. **String
literals stay in Chinese where they're user-facing data** (Telegram push
templates, ISP labels like `CF移动优选`, default-key prompts, CSV headers
like `IP地址`/`端口`/`数据中心` — these are functional payload, not code).

Notable renames:

| Old (Chinese) | New (English) |
|---|---|
| `反代IP` | `ctx.proxyIP` |
| `启用SOCKS5反代` | `ctx.socks5Mode` |
| `启用SOCKS5全局反代` | `ctx.socks5GlobalEnabled` |
| `我的SOCKS5账号` | `ctx.socks5Auth` |
| `调试日志打印` | `ctx.debugLogEnabled` |
| `SOCKS5白名单` | `ctx.socks5Whitelist` |
| `启用反代兜底` | `ctx.proxyFallbackEnabled` |
| `config_JSON` | `ctx.configJson` |
| `处理WS请求` | `handleWebSocketRequest` |
| `处理XHTTP请求` | `handleXhttpRequest` |
| `处理gRPC请求` | `handleGrpcRequest` |
| `解析魏烈思请求` | `parseVlessRequest` |
| `读取XHTTP首包` | `readFirstPacket` |
| `MD5MD5` | `md5x2` |
| `读取config_JSON` | `readConfigJson` |
| `生成随机IP` | `generateRandomIPs` |
| `获取传输协议配置` | `getTransportConfig` |
| `获取传输路径参数值` | `getTransportPath` |
| `Clash订阅配置文件热补丁` | `patchClashSubscription` |
| `Singbox订阅配置文件热补丁` | `patchSingboxSubscription` |
| `Surge订阅配置文件热补丁` | `patchSurgeSubscription` |
| `请求日志记录` | `logRequest` |
| `掩码敏感信息` | `maskSensitive` |
| `DoH查询` | `dohQuery` |
| `获取优选订阅生成器数据` | `fetchPreferredSubData` |
| `请求优选API` | `requestPreferredApi` |
| `反代参数获取` | `parseProxyParams` |
| `获取SOCKS5账号` | `parseSocks5Auth` |
| `解析地址端口` | `parseAddressPort` |

### 3. config.json schema: Chinese keys → English keys + auto-migration

The `config.json` stored in KV used to have Chinese field names
(`协议类型`, `反代`, `优选订阅生成`, …). The new code uses an all-English
schema, but `readConfigJson` detects legacy shapes and **transparently
migrates and writes back the new shape on first read**. Existing users
upgrading don't need to do anything.

```
协议类型 → protocol               订阅转换配置 → subConverter
传输协议 → transport               反代 → proxy
gRPC模式 → grpcMode                路径模板 → template
随机路径 → randomPath              全局 → global
跳过证书验证 → skipCertVerify      标准 → standard
启用0RTT → enable0RTT              账号 → auth
TLS分片 → tlsFragment              白名单 → whitelist
完整节点路径 → fullNodePath        优选订阅生成 → preferredSub
加载时间 → loadTime                本地IP库 → localIP
随机IP → randomIP                  随机数量 → count
指定端口 → port
SOCKS5.启用 → SOCKS5.mode          TG.启用 → TG.enabled
```

Migration logic lives in `src/admin/config.ts` (`SCHEMA_MIGRATION`,
`SCOPED_MIGRATION`, `migrateLegacySchema()`). After the first read, the
migrated shape is persisted back to KV so subsequent reads skip the rename
pass.

### 4. KV config validation at the boundary

In addition to the schema migration, `readConfigJson` runs a hand-rolled
validator (`src/admin/config-schema.ts`) on the migrated config. Wrong-type
fields are coerced to documented defaults in place; issues are logged via
`console.warn` and attached to `configJson.__validation` so the admin UI
can surface them. Bad config never throws — it produces warnings and
keeps serving.

Validated fields (the ones whose wrong type would crash a downstream
handler): `protocol` (enum), `transport` (enum), `grpcMode` (enum),
`enable0RTT` / `randomPath` / `skipCertVerify` / `ECH` (boolean), `HOSTS`
(string array), `PATH` / `Fingerprint` (string), `tlsFragment`
(`Shadowrocket | Happ | null`), `preferredSub.localIP.{count, port,
randomIP}`. Cosmetic fields are left alone — the admin UI handles its own
input validation.

### 5. Single source file → compiled artefact

Old workflow: edit `_worker.js` directly → deploy.
New workflow: edit `src/**/*.ts` → `npm run build` → produces `_worker.js`
→ deploy.

**Deployment shape is unchanged** — `_worker.js` is still a single file you
can paste into the Workers Dashboard or upload via Pages. It's now an
esbuild bundle (minified, ~77 KB) instead of hand-written source. CI has a
drift check that fails any PR that ships a stale `_worker.js`.

### 6. Protocol simplification: VLESS-only

Shadowsocks, Trojan, and the HTTPS upstream proxy mode (with its hand-rolled
TLS 1.2/1.3 client) were dropped. Reasoning, briefly:

- **VLESS** handles essentially all the use cases this project serves.
  Cloudflare fronts the worker, so user-facing fallback and disguise are
  handled outside the proxy protocol layer.
- **The HTTPS upstream proxy** was the only consumer of `tls-client.ts`,
  which existed because Workers' `connect()` originally didn't support
  outbound TLS. That gap is closed (`connect({ secureTransport: 'on' })`
  works natively now), so the hand-rolled implementation was platform-
  specific debt with zero portability benefit. Native TLS exists on every
  alternative platform (Node `tls.connect`, Deno `Deno.connectTls`, Bun's
  built-in TLS) — a JavaScript TLS implementation helps nowhere.

The bundle dropped from 232 KB → 77 KB across these changes.

## Test coverage

```
crypto/        5 tests   md5 only (the rest of the crypto modules were deleted)
protocols/   ~30 tests   VLESS frame parser + dispatch boundary cases
transports/  ~18 tests   socket-utils, byob-stream
handlers/    no tests yet (the SS inbound suite was removed with SS support)
subscription/ 4 tests   Surge MANAGED-CONFIG header
admin/      ~70 tests   config-schema (35), proxy-resolver, transport, random-ip
utils/      ~50 tests   bytes, url, hostname, path, log
integration/ 6 tests   wrangler unstable_dev — routing surface (robots.txt,
                       /admin auth gate, /version, etc.)
```

**Untested areas** — modules that depend on real network or Workers runtime
and aren't worth unit-testing in node:

- `transports/direct.ts` `forwardTcp` (deeply integrates WebSocket +
  `cloudflare:sockets` `connect()`)
- `handlers/websocket.ts` / `xhttp.ts` / `grpc.ts` data-plane main loops
- Bulk of the Clash / Sing-box subscription patchers

These need integration testing or full deployment to verify.

## Bundle size analysis

`_worker.js` currently ~77 KB minified (CF Workers free tier limit is 1 MB
unzipped; using ~8%). CI enforces a 900 KB hard ceiling.

Run `npm run analyze` for an up-to-date per-module size breakdown via the
esbuild metafile.

### Top contributors (post-cleanup)

| Module | Size | Notes |
|---|---|---|
| `subscription/singbox.ts` | 13.5 KB | only on `/sub` path |
| `admin/config.ts` | ~10 KB | only on `/admin` |
| `admin/preferred-sub.ts` | ~10 KB | only on `/admin` |
| `handlers/sub.ts` | ~10 KB | `/sub` entry |
| `handlers/grpc.ts` | ~8 KB | data-plane hot path |
| `subscription/clash.ts` | ~8 KB | only on `/sub` |
| `handlers/admin.ts` | ~7 KB | only on `/admin` |
| `handlers/websocket.ts` | ~5 KB | data-plane hot path |

### Future shrinking, if needed

If the bundle ever approaches 1 MB (e.g., adding a REALITY-style protocol
or embedded static assets), the cold-path strip order is:

1. **Subscription system** (`handlers/sub.ts` + `subscription/*` ≈ 33 KB).
   If a deployment only needs single-node access, skip the whole thing.
2. **Admin UI** (`handlers/admin.ts` + `admin/pages.ts` +
   `admin/preferred-sub.ts` + `admin/cloudflare-api.ts` ≈ 25 KB). A
   minimal deployment can disable `/admin` entirely and configure the UUID
   via env var.

#### Implementation note

esbuild `bundle: true` does **not** save bundle size via dynamic
`import()` — static imports are inlined regardless. Code splitting only
takes effect with `splitting: true` and multiple output files, which the
project's single-file deployment shape forbids.

The correct strip technique is **build-time aliasing**: use esbuild's
`alias` to point heavy modules at stub files when a `WORKER_LITE` flag is
set; esbuild's DCE then removes the entire subgraph.

`WORKER_LITE` is a cross-cutting change that doubles the test matrix
(full + lite). **Don't do it without real size pressure.**

## Important things to know before editing

1. **The original single file lives in the initial commit.** It was
   removed from the working tree (to avoid noisy diffs every time the
   build artefact changes), but the 4619-line original is preserved as
   a snapshot in the initial commit. To inspect or diff:

   ```bash
   git show <initial-commit>:_worker.original.js > /tmp/_worker.original.js
   diff /tmp/_worker.original.js _worker.js
   ```

2. **`md5.ts` is the only remaining crypto module.** It uses a Cloudflare-
   specific Web Crypto extension (`crypto.subtle.digest('MD5', ...)`),
   which means node tests can't import it — they must use `node:crypto`'s
   `createHash('md5')` if they need the same digest. Integration tests do
   this; see `tests/integration/fetch-handler.test.ts`.

3. **After your first deploy**, verify the routing surface via
   `wrangler tail` or hit `/admin`:
   - WebSocket connection (VLESS only — SS / Trojan removed)
   - Subscription generation (Clash / Sing-box / Surge)
   - Old KV config auto-migration (if upgrading from upstream)

4. **Upstream sync.** Upstream's `.github/workflows/sync.yml` periodically
   pulls `_worker.js` from `cmliu/edgetunnel`. This fork removed that
   workflow — to track upstream changes, manually pull the original from
   the initial commit (`git show <initial-commit>:_worker.original.js`)
   as a baseline, diff against upstream's latest `_worker.js`, and decide
   which differences need to land in `src/`.

5. **CI drift check.** `.github/workflows/ci.yml` snapshots the committed
   `_worker.js`, runs `npm run build`, and fails the workflow if they
   diverge. If your PR touches `src/**/*.ts`, you must rebuild and commit
   the resulting `_worker.js`. Forgetting to rebuild is the most common
   contributor footgun; the drift check exists specifically to catch it.
