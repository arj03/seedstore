// store.coordinator — orchestrates PUT and GET (README §6, §7, §17; caps
// store, net, clock, rand). It is the cap-richest Part I handler (§15), holding
// the whole write/read path: content-key generation, chunk + encrypt, erasure
// code, placement negotiation, manifest build + replication, and on read,
// locate + fetch + decode + decrypt.

import type { Node, PeerId } from "./core.js";
import type { Cohort } from "./cohort.js";
import { DOMAIN_BODY, DOMAIN_MANIFEST } from "./crypto.js";
import {
  signDescriptor, parseSignedDescriptor,
  encodeManifest, decodeManifest, ENC_XCHACHA20, type Descriptor,
} from "./manifest.js";
import { MsgType, encodeOffer, encodeStore } from "./protocol.js";
import { toHex, fromHex, concatBytes } from "./util.js";

export interface PutResult {
  manifestId: Uint8Array;
  /** The per-file content key K. The owner keeps it and seals it to readers. */
  key: Uint8Array;
  chunkCount: number;
  /** True if the file was replicated rather than RS-coded (§4.1). */
  replicated: boolean;
  /** Every block id placed for this file (all chunks' blocks + the manifest), in
   *  placement order. Lets a caller probe where the file landed (HAVE), e.g. the
   *  browser demo showing per-holder counts — the manifest names ids, not holders
   *  (§4.3), so this is the only handle on the concrete block set. */
  blockIds: Uint8Array[];
}

export class Coordinator {
  constructor(private readonly node: Node, private readonly cohort: Cohort) {}

  // ── PUT (§6) ──────────────────────────────────────────────────────────
  async put(plaintext: Uint8Array): Promise<PutResult> {
    const { k, m, blockSize } = this.node.config;
    const fileSize = plaintext.length;
    const K = this.node.crypto.randomKey();
    const totalBlocks = Math.max(1, Math.ceil(fileSize / blockSize));
    const descriptors: Uint8Array[] = [];
    const placedIds: Uint8Array[] = [];
    const replicated = totalBlocks <= this.node.config.smallMaxBlocks;

    if (replicated) {
      // A file too small to fill a chunk is replicated r = m+1 times, not coded
      // (§4.1). One chunk of d data blocks, no parity.
      const d = totalBlocks;
      const ct = this.node.crypto.encrypt(K, DOMAIN_BODY, 0, padTo(plaintext, d * blockSize));
      const dataBlocks = splitBlocks(ct, blockSize);
      const blockIds = dataBlocks.map((b) => this.node.crypto.hash(b));
      const env = this.signChunk({ k: d, m: 0, blockSize, blockIds });
      for (let i = 0; i < d; i++) {
        const placed = await this.placeBlock(blockIds[i], dataBlocks[i], env, new Set(), this.node.config.replicas);
        if (placed.length === 0) throw new Error("put: no peer accepted a replica");
        placedIds.push(blockIds[i]);
      }
      descriptors.push(env);
    } else {
      // RS path (§4.1): chunk the ciphertext into k data blocks, add m parity.
      const numChunks = Math.ceil(totalBlocks / k);
      for (let c = 0; c < numChunks; c++) {
        const start = c * k * blockSize;
        const chunkPlain = plaintext.slice(start, start + k * blockSize);
        const ct = this.node.crypto.encrypt(K, DOMAIN_BODY, c, padTo(chunkPlain, k * blockSize));
        const dataBlocks = splitBlocks(ct, blockSize);
        const parityBlocks = this.node.codec.rsEncode(k, m, blockSize, dataBlocks);
        const all = [...dataBlocks, ...parityBlocks];
        const blockIds = all.map((b) => this.node.crypto.hash(b));
        const env = this.signChunk({ k, m, blockSize, blockIds });
        // The n blocks of a chunk go on DISTINCT peers (§6) so losing one peer
        // costs at most one block of the chunk (the §10 invariant). With fewer
        // than n reachable peers we place as many as the cohort holds rather than
        // failing the whole PUT — recoverable as long as ≥ k distinct ids landed,
        // and repair (§9) restores the rest once more peers join. Once no untried
        // peer takes a block, none will take a later one either, so we stop there.
        // A degenerate RS(1,·) code repeats an id (a parity block byte-identical
        // to the lone data block); the repeat still gets its own peer above — that
        // is the chunk's replication when k = 1 — but we record each distinct id
        // once so the returned block set and the holder probe stay accurate.
        const used = new Set<PeerId>();
        const placedHex = new Set<string>();
        for (let i = 0; i < all.length; i++) {
          const placed = await this.placeBlock(blockIds[i], all[i], env, used, 1);
          if (placed.length === 0) break;
          for (const p of placed) used.add(p);
          const idHex = toHex(blockIds[i]);
          if (!placedHex.has(idHex)) { placedHex.add(idHex); placedIds.push(blockIds[i]); }
        }
        if (placedHex.size < k) {
          throw new Error(`put: chunk ${c} landed ${placedHex.size}/${k} distinct blocks needed to read it back — connect more holders`);
        }
        descriptors.push(env);
      }
    }

    // Build, encrypt, and replicate the manifest (§4.3). It names block_ids,
    // never holders, so placement can shift under repair without it going stale.
    const manPlain = encodeManifest({
      fileSize, blockSize, k, m, encAlg: ENC_XCHACHA20, chunks: descriptors,
    });
    const manCt = this.node.crypto.encrypt(K, DOMAIN_MANIFEST, 0, manPlain);
    const manifestId = this.node.crypto.hash(manCt);
    const placed = await this.placeBlock(manifestId, manCt, null, new Set(), this.node.config.replicas);
    if (placed.length === 0) throw new Error("put: no peer accepted the manifest");
    placedIds.push(manifestId);

    return { manifestId, key: K, chunkCount: descriptors.length, replicated, blockIds: placedIds };
  }

  // ── GET (§7) ──────────────────────────────────────────────────────────
  async get(manifestId: Uint8Array, K: Uint8Array): Promise<Uint8Array> {
    const manCt = await this.fetchBlock(manifestId);
    if (!manCt) throw new Error("get: manifest not found in cohort");
    const man = decodeManifest(this.node.crypto.decrypt(K, DOMAIN_MANIFEST, 0, manCt));

    const out = new Uint8Array(man.fileSize);
    let written = 0;
    for (let c = 0; c < man.chunks.length; c++) {
      const sd = parseSignedDescriptor(man.chunks[c]);
      const d = sd.descriptor;
      const chunkCipher = d.m === 0
        ? await this.fetchReplicatedChunk(d)
        : await this.fetchCodedChunk(d, c);
      const domainIndex = d.m === 0 ? 0 : c;
      const chunkPlain = this.node.crypto.decrypt(K, DOMAIN_BODY, domainIndex, chunkCipher);
      const take = Math.min(chunkPlain.length, man.fileSize - written);
      out.set(chunkPlain.subarray(0, take), written);
      written += take;
    }
    return out;
  }

  /** Replicated chunk (§4.1): fetch each data block from any live holder. */
  private async fetchReplicatedChunk(d: Descriptor): Promise<Uint8Array> {
    const blocks: Uint8Array[] = [];
    for (const id of d.blockIds) {
      const b = await this.fetchBlock(id);
      if (!b) throw new Error("get: a replica is unavailable");
      blocks.push(b);
    }
    return concatBytes(blocks);
  }

  /** Coded chunk (§7): locate via have/want, fetch any k of n, decode. When all
   *  k data blocks are present, systematic RS means we just concatenate them
   *  and never decode (§4.1). */
  private async fetchCodedChunk(d: Descriptor, _chunkIdx: number): Promise<Uint8Array> {
    const k = d.k;
    const holders = await this.cohort.haveWant(d.blockIds);
    const present: { index: number; bytes: Uint8Array }[] = [];
    // Prefer the k data blocks first (indices 0..k) for the no-decode fast path.
    for (let idx = 0; idx < d.blockIds.length && present.length < k; idx++) {
      const set = holders.get(toHex(d.blockIds[idx]));
      if (!set || set.size === 0) continue;
      const peer = this.bestHolder(set);
      const b = await this.cohort.verificationFetch(peer, d.blockIds[idx]);
      if (b) present.push({ index: idx, bytes: b });
    }
    if (present.length < k) throw new Error("get: fewer than k blocks retrievable — chunk unavailable");

    const allData = present.length >= k && present.slice(0, k).every((p) => p.index < k);
    if (allData) {
      const ordered = present.filter((p) => p.index < k).sort((a, b) => a.index - b.index).slice(0, k);
      if (ordered.length === k && ordered.every((p, i) => p.index === i)) {
        return concatBytes(ordered.map((p) => p.bytes)); // systematic — no decode
      }
    }
    const data = this.node.codec.rsDecode(k, d.m, d.blockSize, present);
    return concatBytes(data);
  }

  // ── placement (§6 step 3–4) ────────────────────────────────────────────
  /** Offer a block to candidate peers ordered by reciprocity standing (§13) and
   *  reachability; on accept, push it. Places onto up to `count` distinct peers
   *  not in `exclude`. Returns the peers that stored it. */
  async placeBlock(
    blockId: Uint8Array, bytes: Uint8Array, descriptor: Uint8Array | null,
    exclude: Set<PeerId>, count: number,
  ): Promise<PeerId[]> {
    const placed: PeerId[] = [];
    for (const peer of this.rankedPeers(exclude)) {
      if (placed.length >= count) break;
      if (placed.includes(peer)) continue;
      const accepted = await this.offer(peer, blockId, bytes.length, descriptor);
      if (!accepted) continue;
      const stored = await this.storePush(peer, blockId, descriptor, bytes);
      if (stored) { placed.push(peer); this.node.markSeen(peer); }
    }
    return placed;
  }

  private async offer(peer: PeerId, blockId: Uint8Array, size: number, descriptor: Uint8Array | null): Promise<boolean> {
    try {
      const res = await this.node.transport.request(peer, MsgType.OFFER, encodeOffer({ blockId, size, descriptor }));
      return res.length >= 1 && res[0] === 1;
    } catch { return false; }
  }

  private async storePush(peer: PeerId, blockId: Uint8Array, descriptor: Uint8Array | null, bytes: Uint8Array): Promise<boolean> {
    try {
      const res = await this.node.transport.request(peer, MsgType.STORE, encodeStore({ blockId, descriptor, bytes }));
      return res.length >= 1 && res[0] === 1;
    } catch { return false; }
  }

  /** Fetch a block from whichever cohort peer holds it, verifying by hash. */
  async fetchBlock(id: Uint8Array): Promise<Uint8Array | null> {
    const holders = (await this.cohort.haveWant([id])).get(toHex(id)) ?? new Set<PeerId>();
    for (const peer of this.rankBy([...holders])) {
      const b = await this.cohort.verificationFetch(peer, id);
      if (b) return b;
    }
    return null;
  }

  // Candidate peers ordered by reciprocity score, highest first (§6, §13).
  private rankedPeers(exclude: Set<PeerId>): PeerId[] {
    return this.rankBy(this.node.cohortPeers().filter((p) => !exclude.has(p)));
  }
  private rankBy(peers: PeerId[]): PeerId[] {
    const now = this.node.now();
    return peers
      .map((p) => ({ p, s: this.node.reputation.score(fromHex(p), now) }))
      .sort((a, b) => b.s - a.s)
      .map((x) => x.p);
  }
  private bestHolder(set: Set<PeerId>): PeerId {
    return this.rankBy([...set])[0];
  }

  private signChunk(d: Descriptor): Uint8Array {
    return signDescriptor(this.node.sodium, d, this.node.identity.publicKey, this.node.identity.privateKey);
  }
}

function padTo(buf: Uint8Array, len: number): Uint8Array {
  if (buf.length === len) return buf;
  const out = new Uint8Array(len);
  out.set(buf.subarray(0, Math.min(buf.length, len)));
  return out;
}
function splitBlocks(buf: Uint8Array, blockSize: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let o = 0; o < buf.length; o += blockSize) out.push(buf.slice(o, o + blockSize));
  return out;
}
