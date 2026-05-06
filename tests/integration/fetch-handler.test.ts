// End-to-end integration tests against the bundled _worker.js.
//
// Spins up the actual worker bundle in workerd via wrangler's unstable_dev
// (one instance shared across all tests). This gives us real MD5 (a Workers
// extension not available in node), real KV (Miniflare-backed), real
// WebSocketPair, and real cloudflare:sockets — closer to production than
// mocked-node tests.
//
// What's tested here intentionally avoids upstream TCP. The data plane
// (WebSocket → forwardTcp → real server) needs an actual proxy target to
// be meaningful, which is out of scope for in-repo CI. These tests cover
// the routing surface: pure HTTP endpoints + auth gates.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { unstable_dev, type Unstable_DevWorker } from 'wrangler';
import { existsSync } from 'node:fs';
import { createHash } from 'node:crypto';

const ADMIN_PASSWORD = 'integration-test-pw';

// Computed in beforeAll once we know the host (workerd assigns localhost:port).
let derivedUserID: string;
let worker: Unstable_DevWorker;

/**
 * Re-derive the userID exactly the way src/index.ts does, so we can
 * exercise endpoints that gate on `?uuid=<userID>`. Node's Web Crypto
 * doesn't expose MD5 (it's a Workers extension), so we use node:crypto.
 */
function md5x2(text: string): string {
  const firstHex = createHash('md5').update(text).digest('hex');
  return createHash('md5').update(firstHex.slice(7, 27)).digest('hex').toLowerCase();
}

function deriveUserID(adminPassword: string, encryptKey: string): string {
  const md5 = md5x2(adminPassword + encryptKey);
  return [
    md5.slice(0, 8),
    md5.slice(8, 12),
    '4' + md5.slice(13, 16),
    '8' + md5.slice(17, 20),
    md5.slice(20),
  ].join('-');
}

beforeAll(async () => {
  if (!existsSync('_worker.js')) {
    throw new Error('_worker.js not found — run `npm run build` first');
  }

  worker = await unstable_dev('_worker.js', {
    experimental: { disableExperimentalWarning: true },
    vars: { ADMIN: ADMIN_PASSWORD },
    kv: [{ binding: 'KV', id: 'integration-test-kv' }],
    logLevel: 'warn',
  });

  // Default encrypt key per src/index.ts:75 — userID derives from md5x2(ADMIN + KEY).
  // We don't set env.KEY in vars, so the worker uses the literal default.
  const defaultEncryptKey = '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
  derivedUserID = deriveUserID(ADMIN_PASSWORD, defaultEncryptKey);
}, 30_000);

afterAll(async () => {
  await worker?.stop();
});

describe('routing surface (real workerd)', () => {
  it('GET /robots.txt returns SEO blocker as plain text', async () => {
    const res = await worker.fetch('/robots.txt');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(/text\/plain/);
    const body = await res.text();
    expect(body).toContain('User-agent: *');
    expect(body).toContain('Disallow: /');
  });

  it('GET /admin without auth cookie redirects to /login', async () => {
    const res = await worker.fetch('/admin', { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/login');
  });

  it('GET /admin/users without auth cookie redirects to /login', async () => {
    const res = await worker.fetch('/admin/users', { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/login');
  });

  it('GET / falls through to disguise page (does not 500)', async () => {
    const res = await worker.fetch('/', { redirect: 'manual' });
    // Without env.URL, falls through to nginx welcome page (status 200)
    // or a redirect. Either way, the worker shouldn't 500 on the root.
    expect(res.status).toBeLessThan(500);
  });

  it('GET /version?uuid=<correct> returns version JSON', async () => {
    const res = await worker.fetch(`/version?uuid=${derivedUserID}`);
    expect(res.status).toBe(200);
    const body = await res.json() as { Version: number };
    expect(typeof body.Version).toBe('number');
    expect(body.Version).toBeGreaterThan(0);
  });

  it('GET /version with wrong uuid does NOT return version JSON', async () => {
    // Wrong UUID should not match the gate; falls through to disguise page.
    const res = await worker.fetch('/version?uuid=00000000-0000-4000-8000-000000000000', {
      redirect: 'manual',
    });
    // Either falls through to disguise or returns non-version content;
    // the version JSON gate should NOT match.
    if (res.status === 200) {
      const text = await res.text();
      expect(text).not.toMatch(/^\s*\{\s*"Version"/);
    }
  });
});
