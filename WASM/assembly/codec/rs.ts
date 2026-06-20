// Systematic Reed–Solomon RS(k, m) over GF(2^8) (README §4.1, §4.2, §9).
//
// The generator is [ I_k ; C ] where the top k rows are the identity (so the
// data blocks pass through verbatim — *systematic*: when all k data blocks are
// present a read just concatenates them and never decodes, §4.1) and the
// bottom m rows are a Cauchy matrix C. Because every square submatrix of a
// Cauchy matrix is non-singular, *any* k of the n = k + m rows form an
// invertible matrix, which is exactly the MDS "any k of n reconstruct"
// property the durability invariant (§10) rests on.
//
// The hot multiply-and-accumulate loops use WASM SIMD: for a fixed coefficient
// c, c·x is split into two 4-bit table lookups — c·(x & 0x0F) and c·(x & 0xF0)
// — each a 16-entry table, so a single i8x16.swizzle multiplies 16 bytes at
// once (the GF(2^8) "PSHUFB" trick).
//
// The key to throughput is *output register-blocking*: the coefficient and its
// two 16-byte multiply tables depend only on the input row, not on which output
// column we are filling, so the inner loop computes a whole STRIP of 8 output
// vectors (128 bytes) per coefficient-table load. That amortizes the table
// loads, the coefficient fetch and the zero-skip branch over 8 columns, and
// gives the core 8 independent accumulator chains to overlap (the XOR-accumulate
// across the k inputs is otherwise a latency-bound dependency). A 16-byte SIMD
// step and then a scalar tail (the same MUL table, one indexed load per byte)
// finish a block whose size is not a multiple of 128. Encoding stays fully
// deterministic — same (k, m, bytes) → byte-identical parity — which is what
// lets a repairer regenerate a block keylessly (§9).

import { gfMul, gfInv, mulBase, mulHiBase } from "./gf256";

// Scratch for the per-row coefficient vector (k ≤ 32 in the codec).
const COEF = new Uint8Array(64);

// Cauchy coefficient for parity row p (0..m) and data column j (0..k):
//   C[p][j] = 1 / (x_p XOR y_j),  x_p = k + p,  y_j = j.
@inline
function cauchy(k: i32, p: i32, j: i32): u8 {
  return gfInv((((k + p) ^ j) & 0xff) as u8);
}

// SIMD GF multiply of 16 bytes `d` by a constant, given that constant's 16-byte
// low/high split tables: c·d = lowT[d & 0x0F] ⊕ highT[d >> 4].
// @ts-ignore: v128 is a builtin when the simd feature is enabled
@inline
function gfMulSimd(d: v128, lowT: v128, highT: v128, mask: v128): v128 {
  const lo = v128.and(d, mask);
  const hi = v128.and(i16x8.shr_u(d, 4), mask);
  return v128.xor(v128.swizzle(lowT, lo), v128.swizzle(highT, hi));
}

const STRIDE: i32 = 128; // 8 v128 lanes per register-blocked step

// One output block = Σ_j coef[j] · src[j·bs ..] over GF(2^8). `srcPtr` holds k
// contiguous blocks of `bs` bytes; `coefPtr` holds the k coefficients. Shared by
// encode (parity rows) and decode (recovered data rows): both are the same MDS
// linear combination, only the source blocks and coefficients differ.
@inline
function gfMacBlock(
  k: i32, bs: i32, srcPtr: i32, coefPtr: i32, outPtr: i32,
  mbase: i32, mhbase: i32, mask: v128,
): void {
  const blocked = bs & ~(STRIDE - 1);
  let p = 0;

  // Register-blocked body: 8 output vectors per coefficient-table load. The 8
  // multiplies within a j are independent (same tables, different data) and the
  // 8 accumulator chains across j are independent, so the core keeps many ops in
  // flight instead of stalling on the XOR-accumulate latency.
  for (; p < blocked; p += STRIDE) {
    let a0 = i8x16.splat(0); let a1 = i8x16.splat(0);
    let a2 = i8x16.splat(0); let a3 = i8x16.splat(0);
    let a4 = i8x16.splat(0); let a5 = i8x16.splat(0);
    let a6 = i8x16.splat(0); let a7 = i8x16.splat(0);
    for (let j = 0; j < k; j++) {
      const c = load<u8>(coefPtr + j) as i32;
      if (c == 0) continue;
      const lowT = v128.load(mbase + (c << 8));
      const highT = v128.load(mhbase + (c << 4));
      const b = srcPtr + j * bs + p;
      a0 = v128.xor(a0, gfMulSimd(v128.load(b),       lowT, highT, mask));
      a1 = v128.xor(a1, gfMulSimd(v128.load(b, 16),   lowT, highT, mask));
      a2 = v128.xor(a2, gfMulSimd(v128.load(b, 32),   lowT, highT, mask));
      a3 = v128.xor(a3, gfMulSimd(v128.load(b, 48),   lowT, highT, mask));
      a4 = v128.xor(a4, gfMulSimd(v128.load(b, 64),   lowT, highT, mask));
      a5 = v128.xor(a5, gfMulSimd(v128.load(b, 80),   lowT, highT, mask));
      a6 = v128.xor(a6, gfMulSimd(v128.load(b, 96),   lowT, highT, mask));
      a7 = v128.xor(a7, gfMulSimd(v128.load(b, 112),  lowT, highT, mask));
    }
    const o = outPtr + p;
    v128.store(o, a0);      v128.store(o, a1, 16);
    v128.store(o, a2, 32);  v128.store(o, a3, 48);
    v128.store(o, a4, 64);  v128.store(o, a5, 80);
    v128.store(o, a6, 96);  v128.store(o, a7, 112);
  }
  // 16-byte SIMD remainder.
  const simdLen = bs & ~15;
  for (; p < simdLen; p += 16) {
    let acc = i8x16.splat(0);
    for (let j = 0; j < k; j++) {
      const c = load<u8>(coefPtr + j) as i32;
      if (c == 0) continue;
      const lowT = v128.load(mbase + (c << 8));
      const highT = v128.load(mhbase + (c << 4));
      acc = v128.xor(acc, gfMulSimd(v128.load(srcPtr + j * bs + p), lowT, highT, mask));
    }
    v128.store(outPtr + p, acc);
  }
  // Scalar tail.
  for (; p < bs; p++) {
    let acc: i32 = 0;
    for (let j = 0; j < k; j++) {
      const c = load<u8>(coefPtr + j) as i32;
      if (c == 0) continue;
      acc ^= load<u8>(mbase + (c << 8) + (load<u8>(srcPtr + j * bs + p) as i32)) as i32;
    }
    store<u8>(outPtr + p, acc as u8);
  }
}

/** Encode: read k data blocks at dataPtr, write m parity blocks at outPtr. */
export function rsEncode(k: i32, m: i32, bs: i32, dataPtr: i32, outPtr: i32): void {
  const mbase = mulBase();
  const mhbase = mulHiBase();
  const coefPtr = COEF.dataStart as i32;
  const mask = i8x16.splat(0x0f);

  for (let i = 0; i < m; i++) {
    for (let j = 0; j < k; j++) store<u8>(coefPtr + j, cauchy(k, i, j));
    gfMacBlock(k, bs, dataPtr, coefPtr, outPtr + i * bs, mbase, mhbase, mask);
  }
}

/** Invert an n×n GF(2^8) matrix at mPtr into invPtr, using augPtr (n*2n bytes)
 *  as the [M | I] Gauss–Jordan scratch. Returns false if M is singular. The
 *  matrix is tiny (n ≤ 32), so it stays scalar. */
export function gfInvertMatrix(n: i32, mPtr: i32, invPtr: i32, augPtr: i32): bool {
  const w = 2 * n;
  for (let r = 0; r < n; r++) {
    const rowM = mPtr + r * n;
    const rowA = augPtr + r * w;
    for (let c = 0; c < n; c++) store<u8>(rowA + c, load<u8>(rowM + c));
    for (let c = 0; c < n; c++) store<u8>(rowA + n + c, (r == c ? 1 : 0) as u8);
  }
  for (let col = 0; col < n; col++) {
    let pr = -1;
    for (let r = col; r < n; r++) {
      if (load<u8>(augPtr + r * w + col) != 0) { pr = r; break; }
    }
    if (pr < 0) return false;
    if (pr != col) {
      const a = augPtr + pr * w;
      const b = augPtr + col * w;
      for (let c = 0; c < w; c++) {
        const t = load<u8>(a + c);
        store<u8>(a + c, load<u8>(b + c));
        store<u8>(b + c, t);
      }
    }
    const piv = augPtr + col * w;
    const pivInv = gfInv(load<u8>(piv + col));
    for (let c = 0; c < w; c++) store<u8>(piv + c, gfMul(load<u8>(piv + c), pivInv));
    for (let r = 0; r < n; r++) {
      if (r == col) continue;
      const rowA = augPtr + r * w;
      const factor = load<u8>(rowA + col);
      if (factor == 0) continue;
      for (let c = 0; c < w; c++) {
        store<u8>(rowA + c, load<u8>(rowA + c) ^ gfMul(factor, load<u8>(piv + c)));
      }
    }
  }
  for (let r = 0; r < n; r++) {
    const rowI = invPtr + r * n;
    const rowA = augPtr + r * w + n;
    for (let c = 0; c < n; c++) store<u8>(rowI + c, load<u8>(rowA + c));
  }
  return true;
}

/** Decode: reconstruct the k data blocks from any k present blocks.
 *  rowIdx[r] (at rowIdxPtr) is the generator-row index (0..n) of the present
 *  block r (bytes at blocksPtr + r*bs). Writes k data blocks at outPtr. */
export function rsDecode(
  k: i32, bs: i32,
  rowIdxPtr: i32, blocksPtr: i32, outPtr: i32,
  mPtr: i32, invPtr: i32, augPtr: i32,
): bool {
  // Build the k×k matrix from the generator rows of the chosen present blocks.
  for (let r = 0; r < k; r++) {
    const idx = load<u8>(rowIdxPtr + r) as i32;
    const mrow = mPtr + r * k;
    if (idx < k) {
      memory.fill(mrow, 0, k);
      store<u8>(mrow + idx, 1);
    } else {
      const p = idx - k;
      for (let j = 0; j < k; j++) store<u8>(mrow + j, cauchy(k, p, j));
    }
  }
  if (!gfInvertMatrix(k, mPtr, invPtr, augPtr)) return false;

  // data[j] = Σ_r inv[j][r] · present[r] — same SIMD multiply-accumulate as
  // encode. When all k present blocks are data rows the inverse is a permutation
  // (each row has a single 1), so the zero-skip leaves one swizzle per output —
  // the common single-loss read stays cheap (§4.1, §21).
  const mbase = mulBase();
  const mhbase = mulHiBase();
  const coefPtr = COEF.dataStart as i32;
  const mask = i8x16.splat(0x0f);

  for (let j = 0; j < k; j++) {
    for (let r = 0; r < k; r++) store<u8>(coefPtr + r, load<u8>(invPtr + j * k + r));
    gfMacBlock(k, bs, blocksPtr, coefPtr, outPtr + j * bs, mbase, mhbase, mask);
  }
  return true;
}
