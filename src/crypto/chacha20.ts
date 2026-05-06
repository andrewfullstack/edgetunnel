// ChaCha20 stream cipher (RFC 8439).
// Web Crypto in Cloudflare Workers does NOT expose ChaCha20-Poly1305 as an
// AEAD algorithm, so we implement it from scratch here.

const rotateLeft32 = (value: number, bits: number): number =>
  ((value << bits) | (value >>> (32 - bits))) >>> 0;

/**
 * One round of the ChaCha20 quarter-round operation.
 * Mutates the state array in place at the 4 given indices.
 */
function quarterRound(
  state: Uint32Array,
  a: number,
  b: number,
  c: number,
  d: number
): void {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotateLeft32(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateLeft32(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotateLeft32(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateLeft32(state[b] ^ state[c], 7);
}

/**
 * ChaCha20 block function. Produces a 64-byte keystream block from
 * a 32-byte key, a 32-bit counter, and a 12-byte nonce.
 *
 * The constants `[1634760805, 857760878, 2036477234, 1797285236]` spell
 * the ASCII "expand 32-byte k" — the standard ChaCha20 nothing-up-my-sleeve.
 */
export function chacha20Block(
  key: Uint8Array,
  counter: number,
  nonce: Uint8Array
): Uint8Array {
  const state = new Uint32Array(16);
  state[0] = 1634760805;
  state[1] = 857760878;
  state[2] = 2036477234;
  state[3] = 1797285236;

  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) state[4 + i] = keyView.getUint32(4 * i, true);

  state[12] = counter;
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  state[13] = nonceView.getUint32(0, true);
  state[14] = nonceView.getUint32(4, true);
  state[15] = nonceView.getUint32(8, true);

  const working = new Uint32Array(state);
  // 20 rounds = 10 column rounds + 10 diagonal rounds (interleaved)
  for (let round = 0; round < 10; round++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  for (let i = 0; i < 16; i++) working[i] = (working[i] + state[i]) >>> 0;
  return new Uint8Array(working.buffer.slice(0));
}

/**
 * Encrypt or decrypt data by XOR-ing it with the ChaCha20 keystream.
 * Counter starts at 1 (block 0 is reserved for Poly1305 key derivation).
 */
export function chacha20Xor(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array
): Uint8Array {
  const output = new Uint8Array(data.length);
  let counter = 1;
  for (let offset = 0; offset < data.length; offset += 64) {
    const block = chacha20Block(key, counter++, nonce);
    const blockLength = Math.min(64, data.length - offset);
    for (let i = 0; i < blockLength; i++) {
      output[offset + i] = data[offset + i] ^ block[i];
    }
  }
  return output;
}
