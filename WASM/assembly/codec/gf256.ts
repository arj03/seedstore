// GF(2^8) arithmetic for Reed–Solomon (README §4.1).
//
// The construction is pinned deployment-wide: field polynomial 0x11D, the
// generator (primitive element) α = 2. §9's keyless repair only holds when
// every peer's encoder emits byte-identical parity, which means every peer
// must agree on these tables — so they are fixed constants, never a knob.
//
// Addition in GF(2^8) is XOR; multiplication uses exp/log tables. EXP is
// doubled to 512 entries so a sum of two logs (each ≤ 254) never needs a
// modulo. This is the only cryptographic-grade arithmetic that ships in
// storage WASM — libsodium has no erasure coding (§2, §16).

export const GF_POLY: i32 = 0x11d;

export const EXP = new Uint8Array(512);
export const LOG = new Uint8Array(256);

function initTables(): void {
  let x: i32 = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x as u8;
    LOG[x] = i as u8;
    x <<= 1;
    if (x & 0x100) x ^= GF_POLY;
  }
  // α has order 255; EXP[255] == EXP[0] == 1. Extend the table so log sums
  // up to 508 index without wrapping.
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  // LOG[0] is undefined and never read (multiply/inverse special-case 0).
}
initTables();

// Multiply two field elements. 0 is absorbing.
@inline
export function gfMul(a: u8, b: u8): u8 {
  if (a == 0 || b == 0) return 0;
  return EXP[(LOG[a] as i32) + (LOG[b] as i32)];
}

// Multiplicative inverse. Caller guarantees a != 0 (the only nonzero-free
// path — Cauchy denominators and pivots — never passes 0 here).
@inline
export function gfInv(a: u8): u8 {
  return EXP[255 - (LOG[a] as i32)];
}
