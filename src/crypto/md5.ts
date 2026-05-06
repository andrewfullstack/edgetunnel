// MD5 helpers.
//
// Cloudflare Workers extends Web Crypto with MD5 digest support
// (not in the W3C spec but supported in Workers runtime).

/**
 * Double-MD5 hash with truncation, used to derive identifiers from
 * the admin password.
 *
 * Algorithm (matches original implementation):
 *   1. md5_hex_1 = hex(MD5(input))
 *   2. md5_hex_2 = hex(MD5(md5_hex_1[7:27]))   -- middle 20 chars
 *   3. return lowercase(md5_hex_2)
 */
export async function md5x2(text: string): Promise<string> {
  const encoder = new TextEncoder();

  const firstHash = await crypto.subtle.digest('MD5', encoder.encode(text));
  const firstHex = Array.from(new Uint8Array(firstHash))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');

  const secondHash = await crypto.subtle.digest(
    'MD5',
    encoder.encode(firstHex.slice(7, 27))
  );
  const secondHex = Array.from(new Uint8Array(secondHash))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');

  return secondHex.toLowerCase();
}

/**
 * Format 16 bytes as a UUID string (8-4-4-4-12 dashed hex).
 * Used to compare VLESS frame's UUID field against the expected user ID.
 */
export function formatUuid(arr: Uint8Array, offset = 0): string {
  const hex = [...arr.slice(offset, offset + 16)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
