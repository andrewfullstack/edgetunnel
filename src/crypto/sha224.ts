// SHA-224 implementation in pure JavaScript.
// Web Crypto does not expose SHA-224 (only SHA-1/256/384/512), but the Trojan
// protocol mandates SHA-224 for password hashing, so we implement it here.

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const rotr = (n: number, b: number): number =>
  ((n >>> b) | (n << (32 - b))) >>> 0;

/**
 * Compute SHA-224 hash of a string. Returns lowercase hex string of 56 chars.
 *
 * Used by the Trojan protocol: the on-wire authenticator is
 * `hex(SHA-224(password))` — exactly 56 ASCII hex characters.
 */
export function sha224(input: string): string {
  let s = unescape(encodeURIComponent(input));
  const messageLengthBits = s.length * 8;
  s += String.fromCharCode(0x80);
  while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);

  const h = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
  ];

  const hi = Math.floor(messageLengthBits / 0x100000000);
  const lo = messageLengthBits & 0xffffffff;
  s += String.fromCharCode(
    (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
    (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff
  );

  const w: number[] = [];
  for (let i = 0; i < s.length; i += 4) {
    w.push(
      (s.charCodeAt(i) << 24) |
      (s.charCodeAt(i + 1) << 16) |
      (s.charCodeAt(i + 2) << 8) |
      s.charCodeAt(i + 3)
    );
  }

  for (let i = 0; i < w.length; i += 16) {
    const x = new Array(64).fill(0);
    for (let j = 0; j < 16; j++) x[j] = w[i + j];
    for (let j = 16; j < 64; j++) {
      const s0 = rotr(x[j - 15], 7) ^ rotr(x[j - 15], 18) ^ (x[j - 15] >>> 3);
      const s1 = rotr(x[j - 2], 17) ^ rotr(x[j - 2], 19) ^ (x[j - 2] >>> 10);
      x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h0] = h;
    for (let j = 0; j < 64; j++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h0 = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }

    const updates = [a, b, c, d, e, f, g, h0];
    for (let j = 0; j < 8; j++) {
      h[j] = (h[j] + updates[j]) >>> 0;
    }
  }

  // SHA-224 truncates to 7 (out of 8) state words = 224 bits = 56 hex chars
  let hex = '';
  for (let i = 0; i < 7; i++) {
    for (let j = 24; j >= 0; j -= 8) {
      hex += ((h[i] >>> j) & 0xff).toString(16).padStart(2, '0');
    }
  }
  return hex;
}
