import { describe, it, expect } from 'vitest';
import { formatUuid } from '../../src/crypto/md5.js';

describe('formatUuid', () => {
  it('formats 16 bytes as a standard UUID string', () => {
    const bytes = new Uint8Array([
      0x55, 0x0e, 0x84, 0x00,
      0xe2, 0x9b,
      0x41, 0xd4,
      0xa7, 0x16,
      0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
    ]);
    expect(formatUuid(bytes)).toBe('550e8400-e29b-41d4-a716-446655440000');
  });

  it('handles all-zero UUID', () => {
    expect(formatUuid(new Uint8Array(16))).toBe('00000000-0000-0000-0000-000000000000');
  });

  it('handles all-FF UUID', () => {
    const bytes = new Uint8Array(16).fill(0xff);
    expect(formatUuid(bytes)).toBe('ffffffff-ffff-ffff-ffff-ffffffffffff');
  });

  it('reads from offset', () => {
    const bytes = new Uint8Array([
      0x99, 0x99, // ignored
      0x55, 0x0e, 0x84, 0x00,
      0xe2, 0x9b, 0x41, 0xd4,
      0xa7, 0x16,
      0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
    ]);
    expect(formatUuid(bytes, 2)).toBe('550e8400-e29b-41d4-a716-446655440000');
  });

  it('produces lowercase hex', () => {
    const bytes = new Uint8Array(16).fill(0xab);
    expect(formatUuid(bytes)).toMatch(/^[0-9a-f-]+$/);
  });
});

// Note: md5x2 is async and uses crypto.subtle.digest('MD5', ...) — that
// extension isn't available in Node test environments, so we don't test it
// here. Integration testing happens during real Worker runs.
