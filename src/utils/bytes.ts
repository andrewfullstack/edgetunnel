// Byte manipulation utilities used throughout the project.

export const EMPTY_BYTES = new Uint8Array(0);

export const textEncoder = new TextEncoder();
export const textDecoder = new TextDecoder();

/**
 * Recursive byte flattener. Accepts numbers, Uint8Array, and nested arrays.
 * Used to build TLS records / handshake messages from heterogeneous parts.
 */
export const tlsBytes = (...parts: any[]): Uint8Array<ArrayBuffer> => {
  const flatten = (values: any[]): number[] =>
    values.flatMap((value) =>
      value instanceof Uint8Array
        ? Array.from(value)
        : Array.isArray(value)
          ? flatten(value)
          : typeof value === 'number'
            ? [value]
            : []
    );
  return new Uint8Array(flatten(parts));
};

export const uint16be = (value: number): number[] => [
  (value >> 8) & 0xff,
  value & 0xff,
];

export const uint64be = (value: bigint): Uint8Array => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, false);
  return bytes;
};

export const readUint16 = (buffer: Uint8Array, offset: number): number =>
  (buffer[offset] << 8) | buffer[offset + 1];

export const readUint24 = (buffer: Uint8Array, offset: number): number =>
  (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];

/**
 * Concatenate multiple Uint8Array chunks into a single buffer.
 * Filters out empty chunks for efficiency.
 */
export const concatBytes = (...chunks: (Uint8Array | null | undefined)[]): Uint8Array<ArrayBuffer> => {
  const nonEmpty = chunks.filter((c): c is Uint8Array => !!c && c.length > 0);
  const length = nonEmpty.reduce((total, c) => total + c.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of nonEmpty) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
};

/**
 * Generate cryptographically random bytes.
 */
export const randomBytes = (length: number): Uint8Array<ArrayBuffer> =>
  crypto.getRandomValues(new Uint8Array(length));

/**
 * Constant-time equality check for sensitive data (MAC tags, passwords).
 * Avoids timing side-channel leaks.
 */
export const constantTimeEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (!left || !right || left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i];
  return diff === 0;
};

/**
 * Normalise input data into a Uint8Array. Handles ArrayBuffer, typed arrays,
 * raw arrays, or anything iterable.
 */
export const toUint8Array = (data: any): Uint8Array => {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data || 0);
};

/**
 * Concatenate any number of byte-array-like inputs into a single Uint8Array.
 * More permissive than concatBytes - normalises each input first.
 */
export const concatByteArrays = (...chunks: any[]): Uint8Array<ArrayBuffer> => {
  if (!chunks || chunks.length === 0) return EMPTY_BYTES;
  const normalised = chunks.map(toUint8Array);
  const total = normalised.reduce((sum, c) => sum + c.byteLength, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const c of normalised) {
    result.set(c, offset);
    offset += c.byteLength;
  }
  return result;
};

/**
 * Length of a chunk in bytes, robust against both ArrayBuffer-likes and arrays.
 */
export const byteLength = (data: any): number => {
  if (!data) return 0;
  if (typeof data.byteLength === 'number') return data.byteLength;
  if (typeof data.length === 'number') return data.length;
  return 0;
};
