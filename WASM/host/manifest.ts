// The two small objects that describe a file (README §4.3): the per-chunk
// *signed* descriptor and the file *manifest*.
//
// Both are hand-rolled fixed binary layouts — small enough to need no
// serialization library (§4.3). The descriptor is signed by the file's author
// (the §2 identity) so a holder cannot forge it to misdirect repair; crucially
// the signature is checked from the author's *public* key alone, never the read
// key, which is what preserves keyless repair (§9). The manifest names *what*
// blocks a file is made of, never *which* peers hold them — placement is
// discovered live via have/want (§5), so it never goes stale under churn.

import type { Sodium } from "./sodium.js";
import { bytesEqual, writeU32BE, readU32BE, concatBytes } from "./util.js";

export const BLOCK_ID_LEN = 32;

// ── chunk descriptor ───────────────────────────────────────────────────────

export interface Descriptor {
  k: number;            // data blocks (0..k are data rows)
  m: number;            // parity blocks (k..n are parity rows); 0 for a replicated chunk
  blockSize: number;
  blockIds: Uint8Array[]; // n = k + m ids, by generator-row index
}

/** The descriptor's signed core — the bytes the author signs over (§4.3). */
export function encodeDescriptorCore(d: Descriptor): Uint8Array {
  const n = d.blockIds.length;
  if (n !== d.k + d.m) throw new Error("descriptor: blockIds.length must equal k+m");
  const head = new Uint8Array(1 + 1 + 1 + 4 + 1);
  head[0] = 1;             // version
  head[1] = d.k;
  head[2] = d.m;
  writeU32BE(head, 3, d.blockSize);
  head[7] = n;
  return concatBytes([head, ...d.blockIds]);
}

export function decodeDescriptorCore(core: Uint8Array): Descriptor {
  if (core.length < 8 || core[0] !== 1) throw new Error("descriptor: bad core");
  const k = core[1], m = core[2];
  const blockSize = readU32BE(core, 3);
  const n = core[7];
  if (n !== k + m) throw new Error("descriptor: n != k+m");
  if (core.length !== 8 + n * BLOCK_ID_LEN) throw new Error("descriptor: truncated");
  const blockIds: Uint8Array[] = [];
  for (let i = 0; i < n; i++) blockIds.push(core.slice(8 + i * BLOCK_ID_LEN, 8 + (i + 1) * BLOCK_ID_LEN));
  return { k, m, blockSize, blockIds };
}

/** A signed chunk descriptor as stored alongside every block and listed in the
 *  manifest (§4.3): [authorPk 32][sig 64][core ...]. Signing stays sender-side
 *  in the host (§16) — this mirrors what the kernel's signature wrapper does
 *  (Ed25519 over the inner bytes), invoked directly so repair can verify a
 *  descriptor out-of-band from the author's public key. */
export function signDescriptor(sodium: Sodium, d: Descriptor, authorPk: Uint8Array, authorSk: Uint8Array): Uint8Array {
  const core = encodeDescriptorCore(d);
  const sig = sodium.crypto_sign_detached(core, authorSk);
  return concatBytes([authorPk, sig, core]);
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

/** Verify the author signature over the descriptor (§4.3). Returns the parsed
 *  descriptor if valid, else null. Needs only the author's public key. */
export function verifyDescriptor(sodium: Sodium, env: Uint8Array): SignedDescriptor | null {
  let sd: SignedDescriptor;
  try { sd = parseSignedDescriptor(env); } catch { return null; }
  try {
    if (!sodium.crypto_sign_verify_detached(sd.sig, sd.core, sd.authorPk)) return null;
  } catch { return null; }
  return sd;
}

/** Does this chunk's descriptor list the given block_id? Every peer that
 *  accepts a block checks block_id ∈ block_ids (§4.3). */
export function descriptorContains(d: Descriptor, blockId: Uint8Array): boolean {
  return d.blockIds.some((id) => bytesEqual(id, blockId));
}

// ── manifest ─────────────────────────────────────────────────────────────

export const ENC_NONE = 0;
export const ENC_XCHACHA20 = 1;

export interface Manifest {
  fileSize: number;
  blockSize: number;
  k: number;
  m: number;
  encAlg: number;            // §4.4
  chunks: Uint8Array[];      // signed descriptor envelopes, in file order
}

/** The manifest plaintext (§4.3). It is then encrypted under K and replicated
 *  across cohort peers; manifest_id = genesis_hash(ciphertext). */
export function encodeManifest(man: Manifest): Uint8Array {
  const head = new Uint8Array(1 + 8 + 4 + 1 + 1 + 1 + 4);
  let o = 0;
  head[o++] = 1; // version
  // file_size as u64 BE
  const hi = Math.floor(man.fileSize / 0x100000000);
  writeU32BE(head, o, hi); o += 4;
  writeU32BE(head, o, man.fileSize >>> 0); o += 4;
  writeU32BE(head, o, man.blockSize); o += 4;
  head[o++] = man.k;
  head[o++] = man.m;
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
  if (buf.length < 19 || buf[0] !== 1) throw new Error("manifest: bad header");
  let o = 1;
  const hi = readU32BE(buf, o); o += 4;
  const lo = readU32BE(buf, o); o += 4;
  const fileSize = hi * 0x100000000 + lo;
  const blockSize = readU32BE(buf, o); o += 4;
  const k = buf[o++], m = buf[o++], encAlg = buf[o++];
  const chunkCount = readU32BE(buf, o); o += 4;
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < chunkCount; i++) {
    if (o + 4 > buf.length) throw new Error("manifest: truncated chunk length");
    const len = readU32BE(buf, o); o += 4;
    if (o + len > buf.length) throw new Error("manifest: truncated chunk");
    chunks.push(buf.slice(o, o + len)); o += len;
  }
  return { fileSize, blockSize, k, m, encAlg, chunks };
}
