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
// All routines operate on raw linear-memory pointers: a "block" is bs
// contiguous bytes, blocks are laid out back-to-back. Encoding is fully
// deterministic — same (k, m, bytes) → byte-identical parity — which is what
// lets a repairer regenerate a block and check it against the already-signed
// block_id without the file key (§9, keyless repair).

import { gfMul, gfInv } from "./gf256";

// Cauchy coefficient for parity row p (0..m) and data column j (0..k):
//   C[p][j] = 1 / (x_p XOR y_j),  x_p = k + p,  y_j = j.
// {y_j} = {0..k-1} and {x_p} = {k..k+m-1} are disjoint and each distinct, so
// every denominator is non-zero and every square submatrix is invertible.
@inline
function cauchy(k: i32, p: i32, j: i32): u8 {
  return gfInv((((k + p) ^ j) & 0xff) as u8);
}

/** Encode: read k data blocks at dataPtr, write m parity blocks at outPtr. */
export function rsEncode(k: i32, m: i32, bs: i32, dataPtr: i32, outPtr: i32): void {
  for (let i = 0; i < m; i++) {
    const optr = outPtr + i * bs;
    memory.fill(optr, 0, bs);
    for (let j = 0; j < k; j++) {
      const coef = cauchy(k, i, j);
      if (coef == 0) continue;
      const dptr = dataPtr + j * bs;
      for (let p = 0; p < bs; p++) {
        store<u8>(optr + p, load<u8>(optr + p) ^ gfMul(coef, load<u8>(dptr + p)));
      }
    }
  }
}

/** Invert an n×n GF(2^8) matrix at mPtr into invPtr, using augPtr (n*2n bytes)
 *  as the [M | I] Gauss–Jordan scratch. Returns false if M is singular. */
export function gfInvertMatrix(n: i32, mPtr: i32, invPtr: i32, augPtr: i32): bool {
  const w = 2 * n;
  for (let r = 0; r < n; r++) {
    const rowM = mPtr + r * n;
    const rowA = augPtr + r * w;
    for (let c = 0; c < n; c++) store<u8>(rowA + c, load<u8>(rowM + c));
    for (let c = 0; c < n; c++) store<u8>(rowA + n + c, (r == c ? 1 : 0) as u8);
  }
  for (let col = 0; col < n; col++) {
    // Find a non-zero pivot at or below the diagonal.
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
 *  block r (bytes at blocksPtr + r*bs). Writes k data blocks at outPtr. The
 *  caller supplies mPtr/invPtr/augPtr scratch (each large enough for k). */
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
  // data[j] = Σ_r inv[j][r] · present[r]
  for (let j = 0; j < k; j++) {
    const optr = outPtr + j * bs;
    memory.fill(optr, 0, bs);
    for (let r = 0; r < k; r++) {
      const coef = load<u8>(invPtr + j * k + r);
      if (coef == 0) continue;
      const bptr = blocksPtr + r * bs;
      for (let p = 0; p < bs; p++) {
        store<u8>(optr + p, load<u8>(optr + p) ^ gfMul(coef, load<u8>(bptr + p)));
      }
    }
  }
  return true;
}
