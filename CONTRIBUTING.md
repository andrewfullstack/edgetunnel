# Contributing to edgetunnel

Thanks for considering a contribution. This fork was created to make the
project easier to contribute to — the original `cmliu/edgetunnel` is a
single 4619-line file with Chinese identifiers and zero tests, which made
the contribution barrier impossibly high. The goal here is the opposite:
**you should be able to read, modify, and PR a small change without
needing prior context**.

## TL;DR

```bash
npm install            # one-time
# ...edit src/**/*.ts...
npm run lint           # tsc --noEmit
npm test               # vitest run (unit tests)
npm run build          # esbuild → _worker.js (committed!)
git add src/ _worker.js
git commit
```

The committed `_worker.js` must match a fresh build from `src/`. CI
enforces this. **The most common contributor mistake is forgetting to
rebuild after editing `src/`** — the drift check exists specifically to
catch it.

## What you need

- Node.js 20 or later
- npm (project ships `package-lock.json`; use `npm ci` for reproducible
  installs)

That's it. No global tools required.

## Project layout

See [REFACTORING.md](./REFACTORING.md) for the full module map. Briefly:

```
src/
├── index.ts          ← main fetch handler (route dispatch)
├── handlers/         ← /admin /sub /login + WebSocket / XHTTP / gRPC data plane
├── protocols/        ← VLESS frame parser + buffered probe for XHTTP/gRPC
├── transports/       ← socket layer + SOCKS5 + HTTP CONNECT + DNS UDP
├── admin/            ← KV config + validator + subscription helpers
├── subscription/     ← Clash / Sing-box / Surge format adapters
├── crypto/md5.ts     ← only crypto module remaining (UUID derivation)
└── utils/            ← bytes / DoH / log / hostname / path / url helpers
tests/                ← vitest unit tests
tests/integration/    ← end-to-end via wrangler unstable_dev
```

## Workflow

### 1. Fork and branch

```bash
git checkout -b fix/your-feature
```

### 2. Make the change

Edit `src/**/*.ts`. Keep changes focused — small PRs are reviewed faster
and merged faster.

If you add or change behaviour, add a unit test. If you change routing
or auth, add an integration test (`tests/integration/`).

### 3. Run the gates locally

```bash
npm run lint           # type check
npm test               # unit tests (~1 second)
npm run build          # produces _worker.js
npm run test:integration  # end-to-end via workerd (~5 seconds)
```

All four must pass before pushing. CI runs the same gates plus a
**bundle size budget** (900 KB hard cap — currently we're at ~80 KB) and
the **drift check** (committed `_worker.js` must match a fresh build).

### 4. Commit `_worker.js`

The build artefact is tracked in git. After editing `src/`, **always
rebuild and commit** the resulting `_worker.js` alongside your source
changes. Otherwise the drift check fails CI.

```bash
npm run build
git add src/ _worker.js
git commit -m "your message"
```

### 5. Open a PR

Push to your fork and open a PR against `main`. CI will run automatically.

## What kind of changes are welcome

- **Bug fixes** — always
- **Test coverage for untested modules** — especially `transports/direct.ts`,
  `handlers/websocket.ts`, `admin/preferred-sub.ts`
- **Documentation improvements** — particularly translation work
- **Bundle size reductions** — measured by `npm run analyze`
- **New transports / protocols** — but check
  [`docs/PLATFORM_LIMITS.md`](./docs/PLATFORM_LIMITS.md) first; some
  things are fundamentally impossible on Cloudflare Workers (UDP-based
  protocols, REALITY) and should be politely declined.

## What might not be welcome (or needs prior discussion)

- **Adding new top-level features** without an issue first — the project
  has chosen scope (VLESS-only, no HTTPS upstream proxy) deliberately.
  Open an issue to discuss before implementing something large.
- **Re-introducing removed protocols** (Shadowsocks, Trojan, the
  hand-rolled TLS client) — these were removed for clear reasons; see
  the commit history if you want context.
- **Performance "optimisations" without measurements** — submit a
  benchmark with the change.

## Coding style

- TypeScript strict mode is **off** but `strictNullChecks: true` is on.
  Don't fight the type system; do narrow types where it improves
  readability.
- Comments: explain **why**, not what. The code shows what.
- Cross-module file paths use `.js` extensions in imports (TypeScript +
  esbuild needs this for ESM resolution).
- No new dependencies without strong justification — every dep increases
  bundle size and supply-chain risk.

## Release process

Releases happen via tag pushes:

```bash
git tag v2.x.y
git push origin v2.x.y
```

`.github/workflows/release.yml` then publishes the built `_worker.js`
as a GitHub Release artefact. The in-tree `_worker.js` continues to
work for the README's copy-paste deployment flow.

## Questions

Open an issue. Telegram / YouTube channels exist for the upstream
project but **this fork's primary contact channel is GitHub issues**.
