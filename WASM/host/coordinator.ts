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
import { toHex, fromHex, concatBytes, mapPool } from "./util.js";

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
      // Each chunk is self-contained, so we run them through a bounded window
      // instead of one-at-a-time: this overlaps one chunk's CPU (encrypt/RS/sign)
      // and its placement round trips with another's, so PUT wall-clock stops
      // scaling with the *serial* round-trip count over the whole file. Results
      // are gathered by chunk index, so file order and the manifest are
      // unaffected by the order chunks happen to finish in.
      const numChunks = Math.ceil(totalBlocks / k);
      const indices = Array.from({ length: numChunks }, (_, c) => c);
      const results = await mapPool(indices, this.node.config.putConcurrency,
        (c) => this.placeChunk(plaintext, c, K));
      for (const r of results) {
        descriptors.push(r.descriptor);
        for (const id of r.placedIds) placedIds.push(id);
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

  /** Encode, sign, and place one RS chunk (§6). Self-contained — its own ≥ k
   *  check — so chunks placed concurrently never interfere (the chunk window).
   *
   *  Within the chunk the n blocks are placed CONCURRENTLY too: the cohort is
   *  ranked once (§13), then block i takes the disjoint candidate slice ranked[i],
   *  ranked[i+n], ranked[i+2n], … (stride n). Disjoint slices put the n blocks on
   *  n DISTINCT peers (§6, so losing one peer costs at most one block of the chunk
   *  — the §10 invariant) WITHOUT a shared mutable "used" set, which is what used
   *  to force the blocks to be placed one after another; a declined primary falls
   *  back within its own slice, so fallbacks never collide either. The top n peers
   *  by standing each take one block. Different chunks may still share a peer for
   *  different blocks — the holder's sibling rule (§6) only forbids two blocks of
   *  the SAME chunk on one holder, and disjoint slices already guarantee that.
   *  With fewer than n reachable peers a chunk places as many as the cohort holds
   *  rather than failing the PUT — recoverable as long as ≥ k distinct ids landed,
   *  and repair (§9) restores the rest once more peers join. A degenerate RS(1,·)
   *  code repeats an id (a parity block byte-identical to the lone data block); the
   *  repeat still gets its own peer — the chunk's replication when k = 1 — but each
   *  distinct id is recorded once so the returned block set and the holder probe
   *  stay accurate. */
  private async placeChunk(
    plaintext: Uint8Array, c: number, K: Uint8Array,
  ): Promise<{ descriptor: Uint8Array; placedIds: Uint8Array[] }> {
    const { k, m, blockSize } = this.node.config;
    const start = c * k * blockSize;
    const chunkPlain = plaintext.slice(start, start + k * blockSize);
    const ct = this.node.crypto.encrypt(K, DOMAIN_BODY, c, padTo(chunkPlain, k * blockSize));
    const dataBlocks = splitBlocks(ct, blockSize);
    const parityBlocks = this.node.codec.rsEncode(k, m, blockSize, dataBlocks);
    const all = [...dataBlocks, ...parityBlocks];
    const n = all.length;
    const blockIds = all.map((b) => this.node.crypto.hash(b));
    const env = this.signChunk({ k, m, blockSize, blockIds });

    // Rank once, hand each block a disjoint stride-n slice, place all n in parallel.
    const ranked = this.rankedPeers(new Set());
    const landed = await Promise.all(all.map((bytes, i) => {
      const candidates: PeerId[] = [];
      for (let j = i; j < ranked.length; j += n) candidates.push(ranked[j]);
      return this.placeBlockOn(blockIds[i], bytes, env, candidates);
    }));

    const placedHex = new Set<string>();
    const placedIds: Uint8Array[] = [];
    for (let i = 0; i < n; i++) {
      if (!landed[i]) continue;
      const idHex = toHex(blockIds[i]);
      if (!placedHex.has(idHex)) { placedHex.add(idHex); placedIds.push(blockIds[i]); }
    }
    if (placedHex.size < k) {
      throw new Error(`put: chunk ${c} landed ${placedHex.size}/${k} distinct blocks needed to read it back — connect more holders`);
    }
    return { descriptor: env, placedIds };
  }

  // ── GET (§7) ──────────────────────────────────────────────────────────
  async get(manifestId: Uint8Array, K: Uint8Array): Promise<Uint8Array> {
    const manCt = await this.fetchBlock(manifestId);
    if (!manCt) throw new Error("get: manifest not found in cohort");
    const man = decodeManifest(this.node.crypto.decrypt(K, DOMAIN_MANIFEST, 0, manCt));

    const out = new Uint8Array(man.fileSize);
    const sds = man.chunks.map((env) => parseSignedDescriptor(env));

    // One discovery fan-out for the whole file, not one have/want per chunk:
    // union every chunk's block_ids into a single have/want, then fetch the
    // chunks concurrently through a bounded window. Each chunk's output offset is
    // fixed by the descriptors up front — every chunk's plaintext is k·blockSize,
    // the final one truncated to fileSize — so chunks write into `out`
    // independently and in any order.
    const allIds: Uint8Array[] = [];
    for (const sd of sds) for (const id of sd.descriptor.blockIds) allIds.push(id);
    const holders = await this.cohort.haveWant(allIds);

    let acc = 0;
    const offsets = sds.map((sd) => {
      const at = acc;
      const d = sd.descriptor;
      acc += (d.m === 0 ? d.blockIds.length : d.k) * d.blockSize;
      return at;
    });

    await mapPool(sds, this.node.config.getConcurrency, async (sd, c) => {
      const d = sd.descriptor;
      const chunkCipher = d.m === 0
        ? await this.fetchReplicatedChunk(d, holders)
        : await this.fetchCodedChunk(d, holders);
      const chunkPlain = this.node.crypto.decrypt(K, DOMAIN_BODY, d.m === 0 ? 0 : c, chunkCipher);
      const take = Math.min(chunkPlain.length, man.fileSize - offsets[c]);
      if (take > 0) out.set(chunkPlain.subarray(0, take), offsets[c]);
    });
    return out;
  }

  /** Replicated chunk (§4.1): fetch each data block from any live holder, using
   *  the file-wide have/want already gathered by `get`. */
  private async fetchReplicatedChunk(d: Descriptor, holders: Map<string, Set<PeerId>>): Promise<Uint8Array> {
    const blocks: Uint8Array[] = [];
    for (const id of d.blockIds) {
      const b = await this.fetchVerified(id, holders.get(toHex(id)));
      if (!b) throw new Error("get: a replica is unavailable");
      blocks.push(b);
    }
    return concatBytes(blocks);
  }

  /** Coded chunk (§7): from the file-wide have/want, fetch any k of n and decode.
   *  When all k data blocks are present, systematic RS means we just concatenate
   *  them and never decode (§4.1). */
  private async fetchCodedChunk(d: Descriptor, holders: Map<string, Set<PeerId>>): Promise<Uint8Array> {
    const k = d.k;
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
   *  not in `exclude`. Returns the peers that stored it. Used for replicas (a
   *  small file, the manifest) and repair; the RS-coded chunk path uses the
   *  per-block `placeBlockOn` so its n blocks can be placed in parallel. */
  async placeBlock(
    blockId: Uint8Array, bytes: Uint8Array, descriptor: Uint8Array | null,
    exclude: Set<PeerId>, count: number,
  ): Promise<PeerId[]> {
    const placed: PeerId[] = [];
    for (const peer of this.rankedPeers(exclude)) {
      if (placed.length >= count) break;
      if (placed.includes(peer)) continue;
      if (await this.tryStore(peer, blockId, bytes, descriptor)) placed.push(peer);
    }
    return placed;
  }

  /** Place one block on the first of `candidates` that accepts it, returning that
   *  peer or null. The candidate list is explicit so the concurrent blocks of a
   *  chunk can take disjoint slices and never compete for the same peer. */
  private async placeBlockOn(
    blockId: Uint8Array, bytes: Uint8Array, descriptor: Uint8Array | null, candidates: PeerId[],
  ): Promise<PeerId | null> {
    for (const peer of candidates) {
      if (await this.tryStore(peer, blockId, bytes, descriptor)) return peer;
    }
    return null;
  }

  /** OFFER a block to one peer and, if accepted, STORE it (§6 step 3–4). Returns
   *  whether the peer now holds it; marks it seen on success (§8). */
  private async tryStore(
    peer: PeerId, blockId: Uint8Array, bytes: Uint8Array, descriptor: Uint8Array | null,
  ): Promise<boolean> {
    if (!(await this.offer(peer, blockId, bytes.length, descriptor))) return false;
    if (!(await this.storePush(peer, blockId, descriptor, bytes))) return false;
    this.node.markSeen(peer);
    return true;
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

  /** Fetch a block from whichever cohort peer holds it, verifying by hash. Does
   *  its own have/want — used for the manifest and by repair (§9), where there is
   *  no file-wide discovery to share. */
  async fetchBlock(id: Uint8Array): Promise<Uint8Array | null> {
    const holders = (await this.cohort.haveWant([id])).get(toHex(id));
    return this.fetchVerified(id, holders);
  }

  /** Pull `id` from its holders, highest reciprocity standing first (§13),
   *  returning the first bytes that verify by hash, or null if none serve it. */
  private async fetchVerified(id: Uint8Array, holders: Set<PeerId> | undefined): Promise<Uint8Array | null> {
    for (const peer of this.rankBy([...(holders ?? [])])) {
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
