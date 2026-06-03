// codec — the storage layer's pure-compute handler (README §17, "no caps").
//
// It owns the one algorithm libsodium cannot provide: systematic Reed–Solomon
// erasure coding over GF(2^8) (§4.1). Confidentiality and hashing are *not*
// here — they are no-cap host crypto services reached via kernel.call (§16),
// so the structural sandbox can guarantee this module touches neither disk nor
// network even if compromised (§2, §17). The only host interaction is the
// block-id op, which calls the `crypto.hash` (genesis SHA-3-256) bridge — the
// same one the kernel already exposes — to demonstrate that composition.
//
// ABI: the host stages a request at the exported `scratch` offset, calls
// handle(input_len), and reads the response back from `scratch`.
//
//   request  = [op u8] [args ...]
//   response = [bytes ...]   (length is handle()'s return value; 0 = no output)
//
// Ops:
//   OP_INFO   (0) → [version u8][poly_lo u8][poly_hi u8][max_k u8][max_m u8]
//   OP_ENCODE (1)  args [k u8][m u8][bs u32 BE][data k*bs]      → parity m*bs
//   OP_DECODE (2)  args [k u8][m u8][bs u32 BE][cnt u8]
//                       [rowIdx cnt][blocks cnt*bs]             → data k*bs
//   OP_BLOCKID(3)  args [bytes ...]                             → id 32

import { rsEncode, rsDecode } from "./rs";

@external("kernel", "call")
declare function kernelCall(
  schemaPtr: i32, schemaLen: i32,
  payloadPtr: i32, payloadLen: i32,
): i32;

export const VERSION: i32 = 1;
const GF_POLY_LO: i32 = 0x1d;
const GF_POLY_HI: i32 = 0x01;

const OP_INFO: i32 = 0;
const OP_ENCODE: i32 = 1;
const OP_DECODE: i32 = 2;
const OP_BLOCKID: i32 = 3;

// Bounds chosen so the GF matrices fit MATRIX_SIZE (n ≤ 64 → augmented n*2n =
// 8192 bytes). Defaults are RS(10,6); the cold-archive extension is RS(20,20)
// → n = 40 (§4.1), comfortably inside these caps.
const MAX_K: i32 = 32;
const MAX_M: i32 = 32;

const SCRATCH_SIZE: i32 = 2 << 20; // 2 MB — one chunk's worth of blocks + headroom
const PRIV_SIZE: i32 = 2 << 20;

// ── private memory layout ────────────────────────────────────────────────
const PRIV_NAME_OFF: i32 = 0;             // crypto.hash schema name (configure)
const NAME_MAX: i32 = 64;
const PRIV_MATRIX_OFF: i32 = 64;          // GF matrices
const M_OFF: i32 = PRIV_MATRIX_OFF;       // k×k        (≤ 4096)
const INV_OFF: i32 = PRIV_MATRIX_OFF + 4096;
const AUG_OFF: i32 = PRIV_MATRIX_OFF + 8192; // k×2k    (≤ 8192)
const MATRIX_SIZE: i32 = 24576;
const PRIV_WORK_OFF: i32 = PRIV_MATRIX_OFF + MATRIX_SIZE; // big output buffer

export let scratch: i32 = 0;
let priv: i32 = 0;
let hashNameLen: i32 = 0;

scratch = heap.alloc(SCRATCH_SIZE) as i32;
priv = heap.alloc(PRIV_SIZE) as i32;

@inline
function readU32BE(p: i32): i32 {
  return ((load<u8>(p) as i32) << 24) | ((load<u8>(p + 1) as i32) << 16) |
         ((load<u8>(p + 2) as i32) << 8) | (load<u8>(p + 3) as i32);
}

/** Plant the genesis-hash bridge's schema name so OP_BLOCKID can call it.
 *  Payload: [name_len u8][name ..]. The host bakes this in once at install
 *  because WASM cannot compute the SHA-3 derived name itself (§16, the same
 *  reason seedkernel handlers receive their route/signer names). */
export function configure(input_len: i32): void {
  if (input_len < 1) return;
  const nLen = load<u8>(scratch) as i32;
  if (nLen <= 0 || nLen > NAME_MAX || 1 + nLen > input_len) return;
  memory.copy(priv + PRIV_NAME_OFF, scratch + 1, nLen);
  hashNameLen = nLen;
}

export function handle(input_len: i32): i32 {
  if (input_len < 1) return 0;
  const op = load<u8>(scratch) as i32;

  if (op == OP_INFO) {
    store<u8>(scratch, VERSION as u8);
    store<u8>(scratch + 1, GF_POLY_LO as u8);
    store<u8>(scratch + 2, GF_POLY_HI as u8);
    store<u8>(scratch + 3, MAX_K as u8);
    store<u8>(scratch + 4, MAX_M as u8);
    return 5;
  }

  if (op == OP_ENCODE) {
    if (input_len < 7) return 0;
    const k = load<u8>(scratch + 1) as i32;
    const m = load<u8>(scratch + 2) as i32;
    const bs = readU32BE(scratch + 3);
    if (k < 1 || k > MAX_K || m < 0 || m > MAX_M || bs < 1) return 0;
    if (input_len != 7 + k * bs) return 0;
    const outLen = m * bs;
    if (outLen > PRIV_SIZE - PRIV_WORK_OFF || outLen > SCRATCH_SIZE) return 0;
    if (m == 0) return 0; // nothing to encode (replication path is host-side)
    const work = priv + PRIV_WORK_OFF;
    rsEncode(k, m, bs, scratch + 7, work);
    memory.copy(scratch, work, outLen);
    return outLen;
  }

  if (op == OP_DECODE) {
    if (input_len < 8) return 0;
    const k = load<u8>(scratch + 1) as i32;
    const m = load<u8>(scratch + 2) as i32;
    const bs = readU32BE(scratch + 3);
    const cnt = load<u8>(scratch + 7) as i32;
    if (k < 1 || k > MAX_K || m < 0 || m > MAX_M || bs < 1) return 0;
    if (cnt < k) return 0;
    const n = k + m;
    const rowIdxPtr = scratch + 8;
    const blocksPtr = rowIdxPtr + cnt;
    if (input_len != 8 + cnt + cnt * bs) return 0;
    // Validate row indices are in range and distinct enough to be a basis.
    for (let r = 0; r < k; r++) {
      if ((load<u8>(rowIdxPtr + r) as i32) >= n) return 0;
    }
    const outLen = k * bs;
    if (outLen > PRIV_SIZE - PRIV_WORK_OFF || outLen > SCRATCH_SIZE) return 0;
    const work = priv + PRIV_WORK_OFF;
    const ok = rsDecode(
      k, bs, rowIdxPtr, blocksPtr, work,
      priv + M_OFF, priv + INV_OFF, priv + AUG_OFF,
    );
    if (!ok) return 0;
    memory.copy(scratch, work, outLen);
    return outLen;
  }

  if (op == OP_BLOCKID) {
    if (hashNameLen == 0) return 0;
    const dataLen = input_len - 1;
    // Stage the bytes in private memory: kernel.call clobbers scratch with the
    // hash response (§4, the staging discipline every handler follows).
    const staged = priv + PRIV_WORK_OFF;
    if (dataLen > PRIV_SIZE - PRIV_WORK_OFF) return 0;
    memory.copy(staged, scratch + 1, dataLen);
    const r = kernelCall(priv + PRIV_NAME_OFF, hashNameLen, staged, dataLen);
    if (r <= 0) return 0;
    return r; // hash already written to scratch by the host
  }

  return 0;
}
