import { describe, it, expect } from 'vitest';
import {
  concatBytes,
  concatByteArrays,
  toUint8Array,
  byteLength,
  uint16be,
  readUint16,
  readUint24,
  tlsBytes,
  constantTimeEqual,
  randomBytes,
  EMPTY_BYTES,
} from '../../src/utils/bytes.js';

describe('concatBytes', () => {
  it('joins multiple Uint8Arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5]);
    const c = new Uint8Array([6]);
    expect(Array.from(concatBytes(a, b, c))).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('skips null and empty inputs', () => {
    const a = new Uint8Array([1, 2]);
    const result = concatBytes(a, null, EMPTY_BYTES, undefined, new Uint8Array([3]));
    expect(Array.from(result)).toEqual([1, 2, 3]);
  });

  it('returns empty array when given nothing', () => {
    expect(concatBytes().byteLength).toBe(0);
  });
});

describe('concatByteArrays', () => {
  it('normalises various inputs', () => {
    const buf = new ArrayBuffer(2);
    new Uint8Array(buf).set([5, 6]);
    const result = concatByteArrays(new Uint8Array([1, 2]), buf, [3, 4]);
    expect(Array.from(result)).toEqual([1, 2, 5, 6, 3, 4]);
  });
});

describe('toUint8Array', () => {
  it('returns input unchanged if already Uint8Array', () => {
    const a = new Uint8Array([1, 2]);
    expect(toUint8Array(a)).toBe(a);
  });

  it('wraps an ArrayBuffer', () => {
    const buf = new ArrayBuffer(2);
    new Uint8Array(buf).set([7, 8]);
    expect(Array.from(toUint8Array(buf))).toEqual([7, 8]);
  });

  it('handles a typed array view (e.g. DataView)', () => {
    const view = new DataView(new ArrayBuffer(4), 1, 2);
    new Uint8Array(view.buffer).set([1, 2, 3, 4]);
    expect(Array.from(toUint8Array(view))).toEqual([2, 3]);
  });
});

describe('byteLength', () => {
  it.each([
    [null, 0],
    [undefined, 0],
    [new Uint8Array([1, 2, 3]), 3],
    [new ArrayBuffer(5), 5],
    [[1, 2], 2],
  ])('byteLength(%j) = %i', (input, expected) => {
    expect(byteLength(input)).toBe(expected);
  });
});

describe('uint16be / readUint16 / readUint24', () => {
  it('encodes and decodes uint16 big-endian', () => {
    const encoded = uint16be(0x1234);
    expect(encoded).toEqual([0x12, 0x34]);
    expect(readUint16(new Uint8Array(encoded), 0)).toBe(0x1234);
  });

  it('reads uint24 big-endian', () => {
    expect(readUint24(new Uint8Array([0x12, 0x34, 0x56]), 0)).toBe(0x123456);
  });

  it('reads from offset', () => {
    const buf = new Uint8Array([0xff, 0xff, 0x12, 0x34]);
    expect(readUint16(buf, 2)).toBe(0x1234);
  });
});

describe('tlsBytes', () => {
  it('flattens numbers, arrays, and Uint8Arrays', () => {
    const result = tlsBytes(0x01, [0x02, 0x03], new Uint8Array([0x04]));
    expect(Array.from(result)).toEqual([0x01, 0x02, 0x03, 0x04]);
  });

  it('handles nested arrays', () => {
    const result = tlsBytes([0x01, [0x02, [0x03]]]);
    expect(Array.from(result)).toEqual([0x01, 0x02, 0x03]);
  });
});

describe('constantTimeEqual', () => {
  it('returns true for equal arrays', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it('returns false for differing arrays', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });

  it('returns false for different lengths', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });

  it('returns false for null inputs', () => {
    expect(constantTimeEqual(null as any, new Uint8Array([1]))).toBe(false);
  });
});

describe('randomBytes', () => {
  it('returns the requested length', () => {
    expect(randomBytes(16).byteLength).toBe(16);
  });

  it('returns different bytes each call (extremely high probability)', () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    expect(constantTimeEqual(a, b)).toBe(false);
  });
});
