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
// once (the GF(2^8) "PSHUFB" trick). Output accumulators stay in v128 registers
// across the k inputs (register blocking). A scalar tail (the same MUL table,
// one indexed load per byte) handles a block whose size is not a multiple of
// 16. Encoding stays fully deterministic — same (k, m, bytes) → byte-identical
// parity — which is what lets a repairer regenerate a block keylessly (§9).

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

/** Encode: read k data blocks at dataPtr, write m parity blocks at outPtr. */
export function rsEncode(k: i32, m: i32, bs: i32, dataPtr: i32, outPtr: i32): void {
  const mbase = mulBase();
  const mhbase = mulHiBase();
  const coefPtr = COEF.dataStart as i32;
  const mask = i8x16.splat(0x0f);
  const simdLen = bs & ~15;

  for (let i = 0; i < m; i++) {
    for (let j = 0; j < k; j++) store<u8>(coefPtr + j, cauchy(k, i, j));
    const optr = outPtr + i * bs;

    // SIMD body: 16 bytes per step, accumulating all k contributions in `acc`.
    for (let p = 0; p < simdLen; p += 16) {
      let acc = i8x16.splat(0);
      for (let j = 0; j < k; j++) {
        const c = load<u8>(coefPtr + j) as i32;
        if (c == 0) continue;
        const lowT = v128.load(mbase + (c << 8));
        const highT = v128.load(mhbase + (c << 4));
        const d = v128.load(dataPtr + j * bs + p);
        acc = v128.xor(acc, gfMulSimd(d, lowT, highT, mask));
      }
      v128.store(optr + p, acc);
    }
    // Scalar tail.
    for (let p = simdLen; p < bs; p++) {
      let acc: i32 = 0;
      for (let j = 0; j < k; j++) {
        const c = load<u8>(coefPtr + j) as i32;
        if (c == 0) continue;
        acc ^= load<u8>(mbase + (c << 8) + (load<u8>(dataPtr + j * bs + p) as i32)) as i32;
      }
      store<u8>(optr + p, acc as u8);
    }
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

  // data[j] = Σ_r inv[j][r] · present[r] — same SIMD multiply-accumulate.
  const mbase = mulBase();
  const mhbase = mulHiBase();
  const coefPtr = COEF.dataStart as i32;
  const mask = i8x16.splat(0x0f);
  const simdLen = bs & ~15;

  for (let j = 0; j < k; j++) {
    for (let r = 0; r < k; r++) store<u8>(coefPtr + r, load<u8>(invPtr + j * k + r));
    const optr = outPtr + j * bs;

    for (let p = 0; p < simdLen; p += 16) {
      let acc = i8x16.splat(0);
      for (let r = 0; r < k; r++) {
        const c = load<u8>(coefPtr + r) as i32;
        if (c == 0) continue;
        const lowT = v128.load(mbase + (c << 8));
        const highT = v128.load(mhbase + (c << 4));
        const d = v128.load(blocksPtr + r * bs + p);
        acc = v128.xor(acc, gfMulSimd(d, lowT, highT, mask));
      }
      v128.store(optr + p, acc);
    }
    for (let p = simdLen; p < bs; p++) {
      let acc: i32 = 0;
      for (let r = 0; r < k; r++) {
        const c = load<u8>(coefPtr + r) as i32;
        if (c == 0) continue;
        acc ^= load<u8>(mbase + (c << 8) + (load<u8>(blocksPtr + r * bs + p) as i32)) as i32;
      }
      store<u8>(optr + p, acc as u8);
    }
  }
  return true;
}
