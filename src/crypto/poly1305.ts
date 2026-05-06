// Poly1305 MAC (RFC 8439 §2.5).
// Implements the 130-bit modular arithmetic using BigInt.

/**
 * Compute the Poly1305 authentication tag for `message` using a 32-byte key.
 *
 * Poly1305 MAC operates over 16-byte chunks of the message, computing a
 * polynomial evaluation modulo the prime 2^130 - 5. The 32-byte key is split
 * into r (clamped) and s (added at the end).
 */
export function poly1305Mac(key: Uint8Array, message: Uint8Array): Uint8Array {
  // Clamp r per RFC 8439 §2.5.1.
  const rBytes = key.slice(0, 16);
  const r = new Uint8Array(rBytes);
  r[3] &= 15;
  r[7] &= 15;
  r[11] &= 15;
  r[15] &= 15;
  r[4] &= 252;
  r[8] &= 252;
  r[12] &= 252;

  const s = key.slice(16, 32);

  // r is split into 5 limbs of 26 bits each (little-endian)
  const accumulator: bigint[] = [0n, 0n, 0n, 0n, 0n];
  const rLimbs: bigint[] = [
    0x3ffffffn & BigInt(r[0] | (r[1] << 8) | (r[2] << 16) | (r[3] << 24)),
    0x3ffffffn & BigInt((r[3] >> 2) | (r[4] << 6) | (r[5] << 14) | (r[6] << 22)),
    0x3ffffffn & BigInt((r[6] >> 4) | (r[7] << 4) | (r[8] << 12) | (r[9] << 20)),
    0x3ffffffn & BigInt((r[9] >> 6) | (r[10] << 2) | (r[11] << 10) | (r[12] << 18)),
    0x3ffffffn & BigInt(r[13] | (r[14] << 8) | (r[15] << 16)),
  ];

  for (let offset = 0; offset < message.length; offset += 16) {
    const chunk = message.slice(offset, offset + 16);
    const padded = new Uint8Array(17);
    padded.set(chunk);
    padded[chunk.length] = 1;

    accumulator[0] += BigInt(
      padded[0] | (padded[1] << 8) | (padded[2] << 16) | ((3 & padded[3]) << 24)
    );
    accumulator[1] += BigInt(
      (padded[3] >> 2) | (padded[4] << 6) | (padded[5] << 14) | ((15 & padded[6]) << 22)
    );
    accumulator[2] += BigInt(
      (padded[6] >> 4) | (padded[7] << 4) | (padded[8] << 12) | ((63 & padded[9]) << 20)
    );
    accumulator[3] += BigInt(
      (padded[9] >> 6) | (padded[10] << 2) | (padded[11] << 10) | (padded[12] << 18)
    );
    accumulator[4] += BigInt(
      padded[13] | (padded[14] << 8) | (padded[15] << 16) | (padded[16] << 24)
    );

    const product: bigint[] = [0n, 0n, 0n, 0n, 0n];
    for (let i = 0; i < 5; i++) {
      for (let j = 0; j < 5; j++) {
        const idx = i + j;
        if (idx < 5) {
          product[idx] += accumulator[i] * rLimbs[j];
        } else {
          // Reduction: 2^130 ≡ 5 (mod 2^130 - 5)
          product[idx - 5] += accumulator[i] * rLimbs[j] * 5n;
        }
      }
    }

    let carry = 0n;
    for (let i = 0; i < 5; i++) {
      product[i] += carry;
      accumulator[i] = 0x3ffffffn & product[i];
      carry = product[i] >> 26n;
    }
    accumulator[0] += 5n * carry;
    carry = accumulator[0] >> 26n;
    accumulator[0] &= 0x3ffffffn;
    accumulator[1] += carry;
  }

  let tagValue =
    accumulator[0] |
    (accumulator[1] << 26n) |
    (accumulator[2] << 52n) |
    (accumulator[3] << 78n) |
    (accumulator[4] << 104n);
  tagValue =
    (tagValue + s.reduce((total, byte, idx) => total + (BigInt(byte) << BigInt(8 * idx)), 0n)) &
    ((1n << 128n) - 1n);

  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    tag[i] = Number((tagValue >> BigInt(8 * i)) & 0xffn);
  }
  return tag;
}
