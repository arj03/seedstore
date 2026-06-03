// GF(2^8) arithmetic for Reed–Solomon (README §4.1).
//
// The construction is pinned deployment-wide: field polynomial 0x11D, the
// generator (primitive element) α = 2. §9's keyless repair only holds when
// every peer's encoder emits byte-identical parity, which means every peer
// must agree on these tables — so they are fixed constants, never a knob.
//
// Addition in GF(2^8) is XOR. Multiplication is served from a precomputed
// 256×256 table MUL (64 KB): MUL[a*256 + b] = a·b. This turns the hot
// encode/decode inner loop from "two log lookups + an add + an exp lookup + a
// zero branch" into a single indexed byte load, which is the bulk of the
// speedup. EXP/LOG are still kept for inverse (matrix solve) and to build MUL.
// This is the only cryptographic-grade arithmetic that ships in storage WASM —
// libsodium has no erasure coding (§2, §16).

export const GF_POLY: i32 = 0x11d;

export const EXP = new Uint8Array(512);
export const LOG = new Uint8Array(256);
// Full multiply table, row-major: MUL[(a << 8) | b] = a · b in GF(2^8).
export const MUL = new Uint8Array(256 * 256);

function mulSlow(a: i32, b: i32): u8 {
  if (a == 0 || b == 0) return 0;
  return EXP[(LOG[a] as i32) + (LOG[b] as i32)];
}

function initTables(): void {
  let x: i32 = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x as u8;
    LOG[x] = i as u8;
    x <<= 1;
    if (x & 0x100) x ^= GF_POLY;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  // Build the multiply table from exp/log (one-time, ~64 K cheap ops).
  for (let a = 0; a < 256; a++) {
    const row = a << 8;
    for (let b = 0; b < 256; b++) MUL[row | b] = mulSlow(a, b);
  }
}
initTables();

// Single-lookup multiply (the table already encodes the 0-absorbing rule).
@inline
export function gfMul(a: u8, b: u8): u8 {
  return MUL[((a as i32) << 8) | (b as i32)];
}

// Multiplicative inverse. Caller guarantees a != 0 (Cauchy denominators and
// pivots never pass 0 here).
@inline
export function gfInv(a: u8): u8 {
  return EXP[255 - (LOG[a] as i32)];
}

/** Base pointer of the MUL table, for raw-load access in the RS inner loops.
 *  Row for coefficient c starts at mulBase() + (c << 8). */
@inline
export function mulBase(): i32 {
  return MUL.dataStart as i32;
}
