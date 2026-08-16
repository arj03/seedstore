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
// loads and the coefficient fetch over 8 columns, and gives the core 8
// independent accumulator chains to overlap (the XOR-accumulate across the k
// inputs is otherwise a latency-bound dependency). A 16-byte SIMD step and then
// a scalar tail (the same MUL table, one indexed load per byte) finish a block
// whose size is not a multiple of 128. Encoding stays fully deterministic —
// same (k, m, bytes) → byte-identical parity — which is what lets a repairer
// regenerate a block keylessly (§9).
//
// A DECODE row's zero coefficients are dropped once, into a compacted term list,
// rather than skipped by a branch on every strip. Arithmetically the two are the
// same — a zero coefficient contributes nothing to an XOR accumulation, so the
// sum is byte-identical either way and §9's keyless repair still holds — but not
// in cost: a skipped term still costs a loop iteration, and the rows this codec
// decodes are mostly zeros (see rsDecode). Dropping them also cuts what the
// loader's module-call bound charges, since its termination check is billed per
// loop back-edge (seedkernel SECURITY §14.1).
//
// Encode rows are dense, so they get none of that and must not pay for it. The
// inner loop below is on a codegen cliff — measured on the loader's wazero, a
// 64 KiB RS(10,6) encode costs ~8% MORE if the zero test is removed from it, and
// another ~8% if the source address is loaded rather than computed, even though
// both changes only ever remove work. Neither shape is worth defending on its
// merits; what is worth defending is that the encode path compiles to what it
// compiled to before. Hence `dense` below, and hence the zero test staying in a
// loop whose terms are all non-zero. Re-measure before touching either.

import { gfMul, gfInv, mulBase, mulHiBase } from "./gf256";

// Scratch for one output row's compacted term list (k ≤ 32 in the codec): the
// non-zero coefficients, and the source block each one multiplies.
const COEF = new Uint8Array(64);
const SRC = new Int32Array(64);

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

// Drop the zero coefficients of one generator/inverse row into the term list:
// COEF[t] is a non-zero coefficient and SRC[t] the base of the block it
// multiplies. Returns the term count. Called once per output block, outside the
// strip loop, so the zeros cost one pass over k rather than one iteration of the
// inner loop per strip.
@inline
function compactRow(
  k: i32, bs: i32, rowPtr: i32, srcPtr: i32, coefPtr: i32, srcOffPtr: i32,
): i32 {
  let nz = 0;
  for (let j = 0; j < k; j++) {
    const c = load<u8>(rowPtr + j) as i32;
    if (c == 0) continue;
    store<u8>(coefPtr + nz, c as u8);
    store<i32>(srcOffPtr + (nz << 2), srcPtr + j * bs);
    nz++;
  }
  return nz;
}

// One output block = Σ_t COEF[t] · src(t) over GF(2^8), for the `nz` terms of a
// row. Shared by encode (parity rows) and decode (recovered data rows): both are
// the same MDS linear combination, only the source blocks and coefficients
// differ. nz == 0 is a legal row and writes zeros.
//
// `dense` picks how src(t) is found. It is a compile-time argument — this is
// @inline, so each caller compiles its own copy and the branch folds away:
//
//   dense  — term t reads block t, at srcPtr + t·bs: encode's k terms are its k
//            data blocks in order, so the address is arithmetic on the loop
//            counter and nothing waits on memory for it.
//   sparse — term t reads the block at SRC[t], wherever compactRow found it.
//
// The zero test is dead in both (compactRow already removed the zeros, and encode
// has none) but stays for the codegen reason in the header comment.
@inline
function gfMacBlock(
  nz: i32, bs: i32, coefPtr: i32, srcOffPtr: i32, outPtr: i32,
  mbase: i32, mhbase: i32, mask: v128, dense: bool, srcPtr: i32,
): void {
  const blocked = bs & ~(STRIDE - 1);
  let p = 0;

  // Register-blocked body: 8 output vectors per coefficient-table load. The 8
  // multiplies within a term are independent (same tables, different data) and
  // the 8 accumulator chains across terms are independent, so the core keeps
  // many ops in flight instead of stalling on the XOR-accumulate latency.
  for (; p < blocked; p += STRIDE) {
    let a0 = i8x16.splat(0); let a1 = i8x16.splat(0);
    let a2 = i8x16.splat(0); let a3 = i8x16.splat(0);
    let a4 = i8x16.splat(0); let a5 = i8x16.splat(0);
    let a6 = i8x16.splat(0); let a7 = i8x16.splat(0);
    for (let t = 0; t < nz; t++) {
      const c = load<u8>(coefPtr + t) as i32;
      if (c == 0) continue;
      const lowT = v128.load(mbase + (c << 8));
      const highT = v128.load(mhbase + (c << 4));
      const b = (dense ? srcPtr + t * bs : load<i32>(srcOffPtr + (t << 2))) + p;
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
    for (let t = 0; t < nz; t++) {
      const c = load<u8>(coefPtr + t) as i32;
      const lowT = v128.load(mbase + (c << 8));
      const highT = v128.load(mhbase + (c << 4));
      const b = (dense ? srcPtr + t * bs : load<i32>(srcOffPtr + (t << 2))) + p;
      acc = v128.xor(acc, gfMulSimd(v128.load(b), lowT, highT, mask));
    }
    v128.store(outPtr + p, acc);
  }
  // Scalar tail.
  for (; p < bs; p++) {
    let acc: i32 = 0;
    for (let t = 0; t < nz; t++) {
      const c = load<u8>(coefPtr + t) as i32;
      const b = dense ? srcPtr + t * bs : load<i32>(srcOffPtr + (t << 2));
      acc ^= load<u8>(mbase + (c << 8) + (load<u8>(b + p) as i32)) as i32;
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

  // Every term is present on an encode: a Cauchy coefficient is 1/(x_p ⊕ y_j)
  // with x_p = k + p ≥ k > j = y_j, so the operand is never zero and neither is
  // its inverse. There is nothing for compactRow to drop, and the k source blocks
  // are the k data blocks in order — the dense form.
  for (let i = 0; i < m; i++) {
    for (let j = 0; j < k; j++) store<u8>(coefPtr + j, cauchy(k, i, j));
    gfMacBlock(k, bs, coefPtr, 0, outPtr + i * bs, mbase, mhbase, mask, true, dataPtr);
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
  // encode, over the terms that are actually there.
  const mbase = mulBase();
  const mhbase = mulHiBase();
  const coefPtr = COEF.dataStart as i32;
  const srcOffPtr = SRC.dataStart as i32;
  const mask = i8x16.splat(0x0f);

  for (let j = 0; j < k; j++) {
    const nz = compactRow(k, bs, invPtr + j * k, blocksPtr, coefPtr, srcOffPtr);
    // A row that is a single 1 says this data block is one we still hold. That
    // is the ordinary case rather than a corner: the matrix inverted above has
    // an identity row for every surviving data block, and so does its inverse,
    // so a read that lost one block reconstructs one block and copies k-1 of
    // them (§4.1, §21). Copying is not an approximation — the linear
    // combination it replaces would reproduce those bytes exactly.
    if (nz == 1 && (load<u8>(coefPtr) as i32) == 1) {
      memory.copy(outPtr + j * bs, load<i32>(srcOffPtr), bs);
      continue;
    }
    gfMacBlock(nz, bs, coefPtr, srcOffPtr, outPtr + j * bs, mbase, mhbase, mask, false, 0);
  }
  return true;
}
