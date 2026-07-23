// The PURE, cap-free core of the file descriptor + manifest (README §4.3): the
// fixed binary codecs and structural validation, with NO crypto/capability
// dependency. This is the *one definition* of the descriptor/manifest wire format,
// shared two ways: the host imports it (manifest.ts re-exports it and adds the
// sodium-backed sign/verify), and the build stitches it verbatim into the
// zero-authority guest bundle (scripts/build-guest.mjs) so the confined
// orchestration never re-implements the format. Every function here is synchronous
// and QuickJS-safe (Uint8Array only — no TextEncoder/Buffer).
//
// Signing/verifying lives in manifest.ts (host) and the guest's CAP_SIGN/CAP_VERIFY
// seam, NOT here — the author signature is checked from the author's *public* key
// alone, never the read key, which is what preserves keyless repair (§9).

import { bytesEqual, writeU32BE, readU32BE, concatBytes } from "./util.js";

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

// `m` means the same thing for both kinds of chunk: **this chunk survives m losses**
// (§4.1). How it buys that survival is the id count, and nothing else:
//
//   coded       blockIds.length === k + m   the k data + m parity blocks, one per peer
//   replicated  blockIds.length === k       the k data blocks, each on r = m + 1 peers
//
// So a descriptor stays self-describing all the way to the durability target: a
// repairer reads k, m, and the id count off the signed bytes and needs no deployment
// config to know the shape, the replica count, or the low-water mark (§9).
export interface Descriptor {
  k: number;            // data blocks (0..k are data rows)
  m: number;            // losses this chunk survives: m parity blocks, or m extra replicas
  blockSize: number;
  blockIds: Uint8Array[]; // k + m ids by generator-row index (coded), or k ids (replicated)
}

/** The descriptor's signed core — the bytes the author signs over (§4.3). Leads with
 *  the descriptor format tag (§16). */
export function encodeDescriptorCore(d: Descriptor): Uint8Array {
  const n = d.blockIds.length;
  if (n !== d.k && n !== d.k + d.m) {
    throw new Error("descriptor: blockIds.length must be k (replicated) or k+m (coded)");
  }
  const head = new Uint8Array(1 + 1 + 1 + 4 + 1);
  head[0] = TAG_DESCRIPTOR; // leading format tag (§16)
  head[1] = d.k;
  head[2] = d.m;
  writeU32BE(head, 3, d.blockSize);
  head[7] = n;
  return concatBytes([head, ...d.blockIds]);
}

export function decodeDescriptorCore(core: Uint8Array): Descriptor {
  if (core.length < 8 || core[0] !== TAG_DESCRIPTOR) throw new Error("descriptor: bad core");
  const k = core[1], m = core[2];
  const blockSize = readU32BE(core, 3);
  if (k < 1) throw new Error("descriptor: k must be >= 1");
  if (blockSize < 1) throw new Error("descriptor: blockSize must be >= 1");
  const n = core[7];
  if (n !== k && n !== k + m) throw new Error("descriptor: n must be k (replicated) or k+m (coded)");
  if (core.length !== 8 + n * BLOCK_ID_LEN) throw new Error("descriptor: truncated");
  const blockIds: Uint8Array[] = [];
  for (let i = 0; i < n; i++) blockIds.push(core.slice(8 + i * BLOCK_ID_LEN, 8 + (i + 1) * BLOCK_ID_LEN));
  return { k, m, blockSize, blockIds };
}

export interface SignedDescriptor {
  authorPk: Uint8Array;
  sig: Uint8Array;
  core: Uint8Array;
  descriptor: Descriptor;
}

export function parseSignedDescriptor(env: Uint8Array): SignedDescriptor {
  if (env.length < 32 + 64 + 8) throw new Error("signed descriptor: too short");
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
// the signed (k, m, id-count) here, so it can never be a deployment knob that drifts
// out of step with the chunk it describes. A cohort running mixed geometry (§4.1) is
// therefore repaired correctly chunk by chunk, from each chunk's own bytes.

/** Replicated ⇔ the descriptor lists only its k data blocks, each destined for
 *  r = m + 1 peers; coded ⇔ it lists all k + m blocks, one per peer (§4.1). (At m = 0
 *  the two coincide — no parity and no second copy is the same zero-redundancy chunk.) */
export function isReplicated(d: Descriptor): boolean {
  return d.blockIds.length === d.k;
}

/** Copies of each *listed* block a healthy chunk wants on distinct peers: r = m + 1
 *  replicas, or the single copy of each of a coded chunk's k + m blocks, whose
 *  redundancy is the parity instead (§4.1, §10). */
export function replicaTarget(d: Descriptor): number {
  return isReplicated(d) ? d.m + 1 : 1;
}

/** The placement slots a chunk wants — one (block, distinct peer) target apiece, as
 *  indices into blockIds (§6, §10). Coded: one slot per block. Replicated: r slots per
 *  block, replica-major, so the first k slots are one whole copy and a thin cohort
 *  fills a complete copy before starting a second. */
export function slotIndices(d: Descriptor): number[] {
  const out: number[] = [];
  const r = replicaTarget(d);
  for (let c = 0; c < r; c++) for (let i = 0; i < d.blockIds.length; i++) out.push(i);
  return out;
}

/** The chunk's **loss margin**: how many further losses it survives right now, given
 *  the live-holder count of each listed block (in blockIds order). Coded: any k of the
 *  k + m blocks reconstruct, so the spare is live-blocks − k. Replicated: every listed
 *  block is needed and each carries copies, so the spare is the fewest copies − 1.
 *  Both are m on a fully-healthy chunk and 0 one loss from death — one health number
 *  for both kinds of chunk (§8). */
export function lossMargin(d: Descriptor, copies: number[]): number {
  if (isReplicated(d)) {
    let min = copies.length > 0 ? copies[0] : 0;
    for (let i = 1; i < copies.length; i++) if (copies[i] < min) min = copies[i];
    return min - 1;
  }
  let live = 0;
  for (let i = 0; i < copies.length; i++) if (copies[i] > 0) live++;
  return live - d.k;
}

/** The low-water mark, in loss margin: repair fires while the margin is below ⌈m/2⌉ —
 *  half the redundancy spent — never waiting until the chunk is one loss from death
 *  (§8, §9). For a coded chunk that is the familiar `live_blocks < k + ⌈m/2⌉`. */
export function lowWaterMargin(d: Descriptor): number {
  return Math.ceil(d.m / 2);
}

// ── manifest ─────────────────────────────────────────────────────────────

export const ENC_XCHACHA20 = 1;

export interface Manifest {
  fileSize: number;
  encAlg: number;            // §4.4
  chunks: Uint8Array[];      // signed descriptor envelopes, in file order
}

// The manifest header does NOT carry (k, m, blockSize): the geometry is the chunk
// descriptor's, which is self-describing (§4.1/§4.3) — GET and repair read k/m/blockSize
// from each signed descriptor, never from a manifest field or deployment config that
// could disagree. The manifest holds only what is genuinely per-file: the size, the
// encryption algorithm, and the ordered list of chunk descriptors.

/** The manifest plaintext (§4.3). It is then encrypted under K and replicated
 *  across cohort peers; manifest_id = content_hash(ciphertext). */
export function encodeManifest(man: Manifest): Uint8Array {
  const head = new Uint8Array(1 + 8 + 1 + 4);
  let o = 0;
  head[o++] = 1; // version
  // file_size as u64 BE
  const hi = Math.floor(man.fileSize / 0x100000000);
  writeU32BE(head, o, hi); o += 4;
  writeU32BE(head, o, man.fileSize >>> 0); o += 4;
  head[o++] = man.encAlg;
  writeU32BE(head, o, man.chunks.length); o += 4;
  const parts: Uint8Array[] = [head];
  for (const env of man.chunks) {
    const len = new Uint8Array(4);
    writeU32BE(len, 0, env.length);
    parts.push(len, env);
  }
  return concatBytes(parts);
}

export function decodeManifest(buf: Uint8Array): Manifest {
  if (buf.length < 14 || buf[0] !== 1) throw new Error("manifest: bad header");
  let o = 1;
  const hi = readU32BE(buf, o); o += 4;
  const lo = readU32BE(buf, o); o += 4;
  const fileSize = hi * 0x100000000 + lo;
  const encAlg = buf[o++];
  const chunkCount = readU32BE(buf, o); o += 4;
  if (fileSize > 0x10000000000) throw new Error("manifest: fileSize out of bounds"); // 2^40 ≈ 1 TiB sanity cap
  if (chunkCount === 0) throw new Error("manifest: chunkCount must be >= 1");
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < chunkCount; i++) {
    if (o + 4 > buf.length) throw new Error("manifest: truncated chunk length");
    const len = readU32BE(buf, o); o += 4;
    if (o + len > buf.length) throw new Error("manifest: truncated chunk");
    chunks.push(buf.slice(o, o + len)); o += len;
  }
  return { fileSize, encAlg, chunks };
}
