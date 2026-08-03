// The PURE, cap-free core of the file descriptor (README §4.3): the fixed binary
// codecs and structural validation, with NO crypto/capability dependency. This is
// the *one definition* of the descriptor wire format, shared two ways: the host
// imports it (manifest.ts re-exports it and adds the sodium-backed sign/verify),
// and the build stitches it verbatim into the zero-authority guest bundle
// (scripts/build-guest.mjs) so the confined orchestration never re-implements the
// format. Every function here is synchronous and QuickJS-safe (Uint8Array only —
// no TextEncoder/Buffer).
//
// There is no manifest *object* here, and no manifest codec: a file's index is an
// ordered list of these same descriptors, chunked and placed exactly like the file
// body (§4.3), so the only list format is the self-delimiting one at the bottom of
// this file.
//
// Signing/verifying lives in manifest.ts (host) and the guest's CAP_SIGN/CAP_VERIFY
// seam, NOT here — the author signature is checked from the author's *public* key
// alone, never the read key, which is what preserves keyless repair (§9).

import { bytesEqual, toHex, writeU32BE, readU32BE, concatBytes } from "./util.js";

export const BLOCK_ID_LEN = 32;

// ── signed-format tags (README §16) ──────────────────────────────────────────
// Every *signed* storage object opens with a distinct leading byte, so an object of
// one type can never be replayed as another (the kernel's sub-separation rule applied
// to storage's own vocabulary). The tag sits inside the signed `core`, so it is already
// under the signature and inside the scoped preimage with no extra framing. Descriptor
// is 0x01; the Part II signed formats reserve their own before they exist.
export const TAG_DESCRIPTOR = 0x01;
export const TAG_TOMBSTONE = 0x02; // reserved: the §25 block.tombstone (not yet implemented)
export const TAG_HEAD = 0x03;      // reserved: the §27.3 mutable file head (not yet implemented)

// ── chunk descriptor ───────────────────────────────────────────────────────

// ONE chunk shape, not two. `n = k + m` always, and `m` always means **this chunk
// survives m losses** (§4.1). Where the code degenerates — `k = 1`, where RS(1, m)
// parity is byte-identical to the lone data block — the descriptor simply LISTS that
// block `m + 1` times: multiplicity carries the replica count, so a coded chunk and a
// replicated one are the same object read the same way. There is no id count to branch
// on, no replica target to compute, and no second row in a table anywhere.
//
// `level` places the chunk in the file's index tree (§4.3) and doubles as the nonce
// domain (§4.4): level 0 is the file's own ciphertext, level ℓ > 0 an index chunk whose
// plaintext is the ordered descriptor list of level ℓ−1. `tailBytes` is how many of the
// chunk's `k × blockSize` plaintext bytes are real, which is what replaces the manifest's
// old `file_size` field — a reader trims each chunk by its own signed number.
export interface Descriptor {
  level: number;        // 0 = file body, ℓ > 0 = index over level ℓ−1 (also the nonce domain)
  k: number;            // data blocks (0..k are data rows)
  m: number;            // losses this chunk survives: m parity blocks, or m extra replicas
  blockSize: number;
  tailBytes: number;    // real plaintext bytes in this chunk; the rest is zero padding
  blockIds: Uint8Array[]; // k + m ids by generator-row index; a k=1 chunk repeats its one id
}

const CORE_HEAD = 13; // tag,level,k,m (4) + blockSize (4) + tailBytes (4) + n (1)

/** The descriptor's signed core — the bytes the author signs over (§4.3). Leads with
 *  the descriptor format tag (§16). */
export function encodeDescriptorCore(d: Descriptor): Uint8Array {
  const n = d.blockIds.length;
  if (n !== d.k + d.m) throw new Error("descriptor: blockIds.length must be k+m");
  if (d.tailBytes > d.k * d.blockSize) throw new Error("descriptor: tailBytes exceeds the chunk");
  const head = new Uint8Array(CORE_HEAD);
  head[0] = TAG_DESCRIPTOR; // leading format tag (§16)
  head[1] = d.level;
  head[2] = d.k;
  head[3] = d.m;
  writeU32BE(head, 4, d.blockSize);
  writeU32BE(head, 8, d.tailBytes);
  head[12] = n;
  return concatBytes([head, ...d.blockIds]);
}

export function decodeDescriptorCore(core: Uint8Array): Descriptor {
  if (core.length < CORE_HEAD || core[0] !== TAG_DESCRIPTOR) throw new Error("descriptor: bad core");
  const level = core[1], k = core[2], m = core[3];
  const blockSize = readU32BE(core, 4);
  const tailBytes = readU32BE(core, 8);
  if (k < 1) throw new Error("descriptor: k must be >= 1");
  if (blockSize < 1) throw new Error("descriptor: blockSize must be >= 1");
  if (tailBytes > k * blockSize) throw new Error("descriptor: tailBytes exceeds the chunk");
  const n = core[12];
  if (n !== k + m) throw new Error("descriptor: n must be k+m");
  if (core.length !== CORE_HEAD + n * BLOCK_ID_LEN) throw new Error("descriptor: truncated");
  const blockIds: Uint8Array[] = [];
  for (let i = 0; i < n; i++) blockIds.push(core.slice(CORE_HEAD + i * BLOCK_ID_LEN, CORE_HEAD + (i + 1) * BLOCK_ID_LEN));
  return { level, k, m, blockSize, tailBytes, blockIds };
}

export interface SignedDescriptor {
  authorPk: Uint8Array;
  sig: Uint8Array;
  core: Uint8Array;
  descriptor: Descriptor;
}

export function parseSignedDescriptor(env: Uint8Array): SignedDescriptor {
  if (env.length < 32 + 64 + CORE_HEAD) throw new Error("signed descriptor: too short");
  const authorPk = env.slice(0, 32);
  const sig = env.slice(32, 96);
  const core = env.slice(96);
  return { authorPk, sig, core, descriptor: decodeDescriptorCore(core) };
}

/** Does this chunk's descriptor list the given block_id? Every peer that
 *  accepts a block checks block_id ∈ block_ids (§4.3). */
export function descriptorContains(d: Descriptor, blockId: Uint8Array): boolean {
  return d.blockIds.some((id) => bytesEqual(id, blockId));
}

// ── descriptor-derived geometry (§4.1, §8, §9) ───────────────────────────────
// Everything a reader or a repairer needs beyond the ids themselves is computed from
// the signed (k, m, id list) here, so it can never be a deployment knob that drifts
// out of step with the chunk it describes. A cohort running mixed geometry (§4.1) is
// therefore repaired correctly chunk by chunk, from each chunk's own bytes.

/** How many copies of each DISTINCT listed block a healthy chunk wants, on distinct
 *  peers (§4.1, §10). A coded chunk lists each of its k + m blocks once, so each wants
 *  one holder and the parity is its redundancy; a k = 1 chunk lists its lone block
 *  m + 1 times, so multiplicity *is* the replica count. Keyed by id hex. */
export function copyTargets(d: Descriptor): Map<string, number> {
  const want = new Map<string, number>();
  for (const id of d.blockIds) {
    const h = toHex(id);
    want.set(h, (want.get(h) ?? 0) + 1);
  }
  return want;
}

/** The chunk's **loss margin**: how many further losses it survives right now, given
 *  the live-holder count of each listed block (in blockIds order — repeats of one id
 *  repeat its count). Each distinct block contributes at most the copies the descriptor
 *  asked for, so an over-replicated block can never inflate the margin, and the sum
 *  minus k is the spare: `live_blocks − k` for a coded chunk, `min(copies, m+1) − 1` for
 *  a k = 1 one. Both are m on a fully-healthy chunk and 0 one loss from death — one
 *  health number, one formula (§8). */
export function lossMargin(d: Descriptor, copies: number[]): number {
  const live = new Map<string, number>();
  for (let i = 0; i < d.blockIds.length; i++) live.set(toHex(d.blockIds[i]), copies[i] ?? 0);
  let usable = 0;
  for (const [h, want] of copyTargets(d)) usable += Math.min(live.get(h) ?? 0, want);
  return usable - d.k;
}

/** The low-water mark, in loss margin: repair fires while the margin is below ⌈m/2⌉ —
 *  half the redundancy spent — never waiting until the chunk is one loss from death
 *  (§8, §9). For a coded chunk that is the familiar `live_blocks < k + ⌈m/2⌉`. */
export function lowWaterMargin(d: Descriptor): number {
  return Math.ceil(d.m / 2);
}

// ── the index list (§4.3) ────────────────────────────────────────────────────
// A file's index level is nothing but its ordered signed descriptors, length-prefixed
// so the list is self-delimiting. It carries no header: there is no version (the
// descriptor's own tag covers it), no file_size (each descriptor signs its tailBytes),
// and no enc alg (the format version fixes it). This byte stream is then encrypted and
// chunked by the SAME window/chunk path the file body takes, so it has no size ceiling
// of its own and no object type of its own.

export function encodeDescriptorList(envelopes: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const env of envelopes) {
    const len = new Uint8Array(4);
    writeU32BE(len, 0, env.length);
    parts.push(len, env);
  }
  return concatBytes(parts);
}

export function decodeDescriptorList(buf: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  let o = 0;
  while (o < buf.length) {
    if (o + 4 > buf.length) throw new Error("descriptor list: truncated length");
    const len = readU32BE(buf, o); o += 4;
    if (len === 0 || o + len > buf.length) throw new Error("descriptor list: truncated entry");
    out.push(buf.slice(o, o + len)); o += len;
  }
  if (out.length === 0) throw new Error("descriptor list: empty");
  return out;
}
