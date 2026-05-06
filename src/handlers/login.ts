// /login route — display login page or accept POST with password.
//
// On successful POST: sets HttpOnly+Secure auth cookie = MD5(UA+KEY+ADMIN).
// The cookie is the only mechanism that authorises subsequent /admin/* requests.

import { md5x2 } from '../crypto/md5.js';
import { PAGES_STATIC_URL } from '../constants.js';

/**
 * Handle a /login GET or POST request.
 *
 * - GET with valid existing cookie → 302 redirect to /admin
 * - POST with correct password → 200 + JSON success + Set-Cookie
 * - GET (or POST with wrong password) → fetch login HTML from CDN
 *
 * @param request    incoming request
 * @param ua         User-Agent string (for cookie hashing)
 * @param adminPassword admin password (the secret being checked)
 * @param encryptKey    key combined with UA+password to derive cookie value
 */
export async function handleLogin(
  request: Request,
  ua: string,
  adminPassword: string,
  encryptKey: string
): Promise<Response> {
  const cookies = request.headers.get('Cookie') || '';
  const authCookie = cookies
    .split(';')
    .find((c) => c.trim().startsWith('auth='))
    ?.split('=')[1];

  const expectedCookie = await md5x2(ua + encryptKey + adminPassword);

  // Already logged in → redirect to admin panel
  if (authCookie == expectedCookie) {
    return new Response('Redirecting...', {
      status: 302,
      headers: { Location: '/admin' },
    });
  }

  // POST: verify password, set cookie if correct
  if (request.method === 'POST') {
    const formData = await request.text();
    const params = new URLSearchParams(formData);
    const inputPassword = params.get('password');
    if (inputPassword === adminPassword) {
      const response = new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
      });
      response.headers.set(
        'Set-Cookie',
        `auth=${expectedCookie}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`
      );
      return response;
    }
  }

  // GET (or wrong password): serve login HTML from CDN
  return fetch(PAGES_STATIC_URL + '/login');
}

/**
 * Verify that a request's auth cookie matches the expected hash.
 * Used by admin endpoints to gate access.
 */
export async function verifyAuthCookie(
  request: Request,
  ua: string,
  adminPassword: string,
  encryptKey: string
): Promise<boolean> {
  const cookies = request.headers.get('Cookie') || '';
  const authCookie = cookies
    .split(';')
    .find((c) => c.trim().startsWith('auth='))
    ?.split('=')[1];
  if (!authCookie) return false;
  const expected = await md5x2(ua + encryptKey + adminPassword);
  return authCookie === expected;
}
