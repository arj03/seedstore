// Small byte helpers shared across the storage host. No dependencies.

const HEX_CHARS = "0123456789abcdef";
const HEX_BYTES = Array.from({ length: 256 }, (_, b) => HEX_CHARS[b >> 4] + HEX_CHARS[b & 15]);
export function toHex(b: Uint8Array): string {
  let out = "", i = 0;
  // A table lookup per byte, four bytes per append. Cheaper than formatting an unsigned
  // word with toString(16) and padStart, and the unroll is what carries it — QuickJS pays
  // per append, not per lookup, so the same table one byte at a time is slower than either.
  for (; i + 4 <= b.length; i += 4)
    out += HEX_BYTES[b[i]] + HEX_BYTES[b[i + 1]] + HEX_BYTES[b[i + 2]] + HEX_BYTES[b[i + 3]];
  for (; i < b.length; i++) out += HEX_BYTES[b[i]];
  return out;
}

/** Nibble value PLUS ONE per ASCII code, so both 0 and the `undefined` an out-of-range
 *  character reads back as mean "not a hex digit". A table rather than `parseInt` over a
 *  two-character slice, which allocated a string per byte to decode every block id and
 *  key the store handles. */
const NIBBLE = (() => {
  const t = new Uint8Array(128), upper = HEX_CHARS.toUpperCase();
  for (let i = 0; i < 16; i++) {
    t[HEX_CHARS.charCodeAt(i)] = i + 1;
    t[upper.charCodeAt(i)] = i + 1;
  }
  return t;
})();

export function fromHex(hex: string): Uint8Array {
  const n = hex.length >> 1, out = new Uint8Array(n);
  // Carry a cursor rather than multiplying the index by two per byte: this runs in the
  // guest, and QuickJS charges enough per arithmetic op for that to be worth ~15%.
  for (let i = 0, j = 0; i < n; i++, j += 2) {
    const hi = NIBBLE[hex.charCodeAt(j)], lo = NIBBLE[hex.charCodeAt(j + 1)];
    out[i] = hi && lo ? ((hi - 1) << 4) | (lo - 1) : 0;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function writeU32BE(out: Uint8Array, offset: number, value: number): void {
  out[offset] = (value >>> 24) & 0xff;
  out[offset + 1] = (value >>> 16) & 0xff;
  out[offset + 2] = (value >>> 8) & 0xff;
  out[offset + 3] = value & 0xff;
}

export function readU32BE(buf: Uint8Array, offset: number): number {
  return ((buf[offset] << 24) | (buf[offset + 1] << 16) |
          (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
}

// 64-bit big-endian as a hi·2³² + lo pair of u32s — exact for values ≤ Number.MAX_SAFE_INTEGER
// (file sizes / offsets never approach 2⁵³). The windowed PUT/GET host seam frames its
// length-prefixed offsets with these.
export function writeU64BE(out: Uint8Array, offset: number, value: number): void {
  writeU32BE(out, offset, Math.floor(value / 0x100000000));
  writeU32BE(out, offset + 4, value >>> 0);
}

export function readU64BE(buf: Uint8Array, offset: number): number {
  return readU32BE(buf, offset) * 0x100000000 + readU32BE(buf, offset + 4);
}
