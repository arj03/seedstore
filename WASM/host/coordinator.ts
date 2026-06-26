// store.coordinator — orchestrates PUT and GET (README §6, §7, §17; caps
// store, net, clock, rand). It is the cap-richest Part I handler (§15), holding
// the whole write/read path: content-key generation, chunk + encrypt, erasure
// code, placement negotiation, manifest build + replication, and on read,
// locate + fetch + decode + decrypt.

import type { Node, PeerId } from "./core.js";
import type { Cohort } from "./cohort.js";
import { DOMAIN_BODY, DOMAIN_MANIFEST } from "./crypto.js";
import {
  signDescriptor, verifyDescriptor,
  encodeManifest, decodeManifest, ENC_XCHACHA20, type Descriptor,
} from "./manifest.js";
import {
  MsgType, type Offer, type StoreReq, encodeOfferBatch, decodeOfferMask,
  encodeStoreBatch, decodeStoreMask, encodeFetchBatchReq, decodeFetchBatchRes,
} from "./protocol.js";
import { toHex, fromHex, concatBytes, mapPool, bytesEqual } from "./util.js";

// A batched OFFER / STORE / FETCH is split to stay under config.maxMessageBytes —
// the per-transport cap that keeps one message inside the frame cap AND the request
// timeout (§27 + core.ts). OFFERs carry fixed-size descriptor entries, so a count
// cap bounds them; STORE/FETCH carry whole blocks, so a bytes/blockSize cap does.
// Larger files just split into more sub-batches (still far fewer round trips than
// per block).

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

/** One RS chunk mid-placement: its n encoded blocks + signed descriptor, the peer
 *  each block landed on (null until placed), and the distinct ids that landed
 *  (filled once placement finishes). */
interface ChunkPlacement {
  blockIds: Uint8Array[];
  blocks: Uint8Array[];
  descriptor: Uint8Array;
  placedPeer: (PeerId | null)[];
  placedIds: Uint8Array[];
}

export class Coordinator {
  constructor(private readonly node: Node, private readonly cohort: Cohort) {}

  /** Last transport-level OFFER/STORE failure during placement, surfaced in the
   *  PUT error so a failed placement can be localized (decline vs unreachable). */
  private lastTransportError: string | null = null;

  /** Why a placement most likely failed, for the PUT error. If a holder was
   *  unreachable we say so; otherwise the holders answered and DECLINED — and on a
   *  fresh PUT (valid descriptors, no siblings placed yet) the only thing a holder
   *  declines on is the §14 quota, i.e. it is OUT OF STORAGE. This is the silent
   *  failure that reads as "GET works, PUT fails": serving a FETCH never checks the
   *  quota, admitting an OFFER does. */
  private declineHint(): string {
    return this.lastTransportError
      ? ` last transport error: ${this.lastTransportError};`
      : " holders answered but declined every offer — most likely OUT OF STORAGE (their quota/disk is full): clear the holders' data dirs or raise their quota;";
  }

  // ── PUT (§6) ──────────────────────────────────────────────────────────
  async put(plaintext: Uint8Array): Promise<PutResult> {
    this.lastTransportError = null; // fresh for this PUT (placement failure reporting)
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
        if (placed.length === 0) throw new Error(`put: no peer accepted a replica.${this.declineHint()} connect more holders`);
        placedIds.push(blockIds[i]);
      }
      descriptors.push(env);
    } else {
      // RS path (§4.1): chunk the ciphertext into k data blocks, add m parity,
      // sign each chunk, then place the whole file through batched per-peer
      // OFFERs. Encoding (encrypt/RS/sign) is done up front; placement collapses
      // the OFFER handshake to one round trip per peer (placeChunksBatched), with
      // the bulky STOREs still windowed. Chunk/file order is fixed here, so the
      // manifest is unaffected by the order STOREs happen to land in.
      const numChunks = Math.ceil(totalBlocks / k);
      const chunks = Array.from({ length: numChunks }, (_, c) => this.encodeChunk(plaintext, c, K));
      await this.placeChunksBatched(chunks);
      for (const ch of chunks) {
        descriptors.push(ch.descriptor);
        for (const id of ch.placedIds) placedIds.push(id);
      }
    }

    // Build, encrypt, and replicate the manifest (§4.3). It names block_ids,
    // never holders, so placement can shift under repair without it going stale.
    const manPlain = encodeManifest({
      fileSize, blockSize, k, m, encAlg: ENC_XCHACHA20, chunks: descriptors,
    });
    const manCt = this.node.crypto.encrypt(K, DOMAIN_MANIFEST, 0, manPlain);
    const manifestId = this.node.crypto.hash(manCt);
    // Carry the manifest as a one-block replicated chunk (m = 0) with a signed
    // descriptor, so a holder can self-heal it the same way it heals any replica
    // (§9): without a descriptor repair would skip it and the file's root could
    // decay below redundancy and be lost while its body stays healthy.
    const manEnv = this.signChunk({ k: 1, m: 0, blockSize: manCt.length, blockIds: [manifestId] });
    const placed = await this.placeBlock(manifestId, manCt, manEnv, new Set(), this.node.config.replicas);
    if (placed.length === 0) throw new Error(`put: no peer accepted the manifest.${this.declineHint()} connect more holders`);
    placedIds.push(manifestId);

    return { manifestId, key: K, chunkCount: descriptors.length, replicated, blockIds: placedIds };
  }

  /** Encode + sign one RS chunk (§6): encrypt the k data blocks, add m parity,
   *  hash to block_ids, sign the descriptor. Placement is separate
   *  (placeChunksBatched) so every chunk's blocks can be offered to a peer in one
   *  batch. `placedPeer[i]` is filled in as block i lands. */
  private encodeChunk(plaintext: Uint8Array, c: number, K: Uint8Array): ChunkPlacement {
    const { k, m, blockSize } = this.node.config;
    const start = c * k * blockSize;
    const chunkPlain = plaintext.slice(start, start + k * blockSize);
    const ct = this.node.crypto.encrypt(K, DOMAIN_BODY, c, padTo(chunkPlain, k * blockSize));
    const dataBlocks = splitBlocks(ct, blockSize);
    const parityBlocks = this.node.codec.rsEncode(k, m, blockSize, dataBlocks);
    const blocks = [...dataBlocks, ...parityBlocks];
    const blockIds = blocks.map((b) => this.node.crypto.hash(b));
    const descriptor = this.signChunk({ k, m, blockSize, blockIds });
    return { blockIds, blocks, descriptor, placedPeer: new Array(blocks.length).fill(null), placedIds: [] };
  }

  /** Place every chunk's n blocks across the cohort with one batched OFFER per
   *  peer per round, then windowed STOREs (§6 step 3–4).
   *
   *  The cohort is ranked once (§13). Block index i (0..n-1) targets the residue
   *  class ranked[i], ranked[i+n], ranked[i+2n], … — disjoint across i, so a
   *  chunk's n blocks always land on n DISTINCT peers (§6, losing one peer costs
   *  at most one block of the chunk — the §10 invariant), fallback rounds
   *  included. In round r, every still-unplaced block i across ALL chunks whose
   *  target is ranked[i+r·n] is gathered per peer into a single OFFER (so peer
   *  ranked[i] sees block i of every chunk at once); the accepted blocks STORE
   *  through the put window. A declined or unreachable block falls to the next
   *  peer in its residue class next round. With fewer than n reachable peers a
   *  chunk places as many as the cohort holds rather than failing — recoverable
   *  while ≥ k distinct ids landed, repair (§9) tops up the rest. A degenerate
   *  RS(1,·) repeats an id (parity byte-identical to the lone data block); the
   *  repeat still gets its own peer (k = 1 replication) but each distinct id is
   *  counted once for the ≥ k check and the returned block set. */
  private async placeChunksBatched(chunks: ChunkPlacement[]): Promise<void> {
    const { k, m } = this.node.config;
    // Guard the batch cap: a missing/invalid value (e.g. a stale config that
    // predates maxMessageBytes) must NOT collapse to NaN — that would make every
    // sub-batch empty and silently place nothing. Fall back to a sane 1 MiB.
    const maxBytes = this.node.config.maxMessageBytes > 0 ? this.node.config.maxMessageBytes : (1 << 20);
    const n = k + m;
    const ranked = this.rankedPeers(new Set());
    // Outcome tally, so a failed PUT says WHERE it broke (decline vs store vs
    // unreachable) instead of just "0 landed".
    let offered = 0, accepted = 0, stored = 0;
    this.lastTransportError = null;

    for (let r = 0; ; r++) {
      // Gather, per target peer, the (chunk, blockIndex) pairs still unplaced and
      // whose residue-class candidate exists this round.
      const byPeer = new Map<PeerId, { ch: ChunkPlacement; i: number }[]>();
      for (const ch of chunks) {
        for (let i = 0; i < n; i++) {
          if (ch.placedPeer[i]) continue;       // already landed on a peer
          const peer = ranked[i + r * n];
          if (!peer) continue;                   // residue class exhausted
          let list = byPeer.get(peer);
          if (!list) byPeer.set(peer, (list = []));
          list.push({ ch, i });
        }
      }
      if (byPeer.size === 0) break;              // nothing left to try

      // Each holder runs its OWN OFFER→STORE pipeline, all peers in parallel: a
      // peer's STOREs begin the moment its OFFER returns (no cross-peer barrier
      // idling the uplink), so both sockets stay saturated instead of one starving
      // behind the other. The OFFER is one batched message per peer (split by a
      // count cap: a file's descriptors are all one size, so maxMessageBytes /
      // entryBytes bounds it).
      const entryBytes = 40 + (chunks[0]?.descriptor.length ?? 0);
      const maxOffers = Math.max(1, Math.floor(maxBytes / entryBytes));
      await Promise.all([...byPeer].map(async ([peer, items]) => {
        for (const slice of chunkArray(items, maxOffers)) {
          const offers: Offer[] = slice.map(({ ch, i }) => ({
            blockId: ch.blockIds[i], size: ch.blocks[i].length, descriptor: ch.descriptor,
          }));
          offered += offers.length;
          const mask = await this.offerBatch(peer, offers);
          const ok = slice.filter((_, j) => mask[j]);
          accepted += ok.length;
          // STORE the accepted blocks in byte-bounded batches — one streamed message
          // per batch (the upload twin of the batched FETCH), each capped at maxBytes
          // so it fits the transport frame and the request timeout. The batches to one
          // peer are WINDOWED by putConcurrency (the upload twin of getConcurrency in
          // gatherBlocks), not issued one-at-a-time-serially: when the transport cap
          // forces ~one block per message (WebRTC's ~64 KB channel), a big file is many
          // single-block STOREs, and a serial loop would pay one round trip per block —
          // exactly the latency the window hides, restoring PUT's pipeline so it keeps
          // pace with GET on a low-latency link. On WS each peer has only a few large
          // batches, so the window is a no-op. Peers still run in parallel (outer
          // Promise.all), so this windows each peer's link independently.
          const groups = batchByBytes(ok, ({ ch, i }) => 40 + ch.descriptor.length + ch.blocks[i].length, maxBytes);
          await mapPool(groups, this.node.config.putConcurrency, async (group) => {
            const stored0 = await this.storeBatch(peer, group.map(({ ch, i }) => ({
              blockId: ch.blockIds[i], descriptor: ch.descriptor, bytes: ch.blocks[i],
            })));
            for (let j = 0; j < group.length; j++) if (stored0[j]) {
              group[j].ch.placedPeer[group[j].i] = peer;
              this.node.markSeen(peer);
              stored++;
            }
          });
        }
      }));
    }

    // Each chunk needs ≥ k DISTINCT block ids landed to be readable (§4.1). On
    // failure, report the breakdown: did holders DECLINE the offers (accepted 0),
    // accept but fail to STORE (stored 0), or was the transport unreachable?
    for (const ch of chunks) {
      const distinct = new Set<string>();
      for (let i = 0; i < ch.blockIds.length; i++) if (ch.placedPeer[i]) distinct.add(toHex(ch.blockIds[i]));
      if (distinct.size < k) {
        const why = accepted === 0 ? this.declineHint() :
          stored === 0 ? " holders accepted but STORE landed nothing (message too large? store full?);" :
          this.declineHint();
        throw new Error(`put: chunk landed ${distinct.size}/${k} distinct blocks — of ${offered} offered across ${ranked.length} peer(s), ${accepted} accepted, ${stored} stored.${why} connect more holders`);
      }
      ch.placedIds = [...distinct].map((h) => fromHex(h));
    }
  }

  // ── GET (§7) ──────────────────────────────────────────────────────────
  async get(manifestId: Uint8Array, K: Uint8Array): Promise<Uint8Array> {
    const manCt = await this.fetchBlock(manifestId);
    if (!manCt) throw new Error("get: manifest not found in cohort");
    const man = decodeManifest(this.node.crypto.decrypt(K, DOMAIN_MANIFEST, 0, manCt));

    // Verify every chunk descriptor's signature before using it (§4.3). A
    // tampered descriptor would carry forged block-ids that redirect repair
    // and make GET read out of thin air; the manifest is encrypted, not signed,
    // so a wrong K gives noise — but a correct K with a tampered manifest is
    // stopped by the per-chunk signature check.
    const sds: { descriptor: Descriptor }[] = [];
    for (const env of man.chunks) {
      const sd = verifyDescriptor(this.node.sodium, env);
      if (!sd) throw new Error("get: chunk descriptor signature invalid");
      sds.push(sd);
    }

    const out = new Uint8Array(man.fileSize);

    // One discovery fan-out for the whole file (union every chunk's block_ids into
    // a single have/want), then one batched FETCH per holder pulling all the
    // blocks that holder serves — instead of a fetch per block. Each chunk's
    // output offset is fixed by the descriptors up front (every chunk's plaintext
    // is k·blockSize, the final one truncated to fileSize), so chunks assemble
    // independently once their blocks are in hand.
    const allIds: Uint8Array[] = [];
    for (const sd of sds) for (const id of sd.descriptor.blockIds) allIds.push(id);
    const holders = await this.cohort.haveWant(allIds);
    const got = await this.gatherBlocks(sds, holders);

    let acc = 0;
    const offsets = sds.map((sd) => {
      const at = acc;
      const d = sd.descriptor;
      acc += (d.m === 0 ? d.blockIds.length : d.k) * d.blockSize;
      return at;
    });
    for (let c = 0; c < sds.length; c++) {
      const d = sds[c].descriptor;
      const chunkCipher = this.assembleChunk(d, got);
      const chunkPlain = this.node.crypto.decrypt(K, DOMAIN_BODY, d.m === 0 ? 0 : c, chunkCipher);
      const take = Math.min(chunkPlain.length, man.fileSize - offsets[c]);
      if (take > 0) out.set(chunkPlain.subarray(0, take), offsets[c]);
    }
    return out;
  }

  /** Fetch every block the file's chunks need, batched per holder (§7/§8). After
   *  the file-wide have/want, each still-missing block is requested from its best
   *  untried holder, grouped into one FETCH per peer per round (split into
   *  sub-batches so a response stays under the frame cap, and windowed by
   *  getConcurrency). A coded chunk stops once k of its blocks are in hand,
   *  preferring the systematic data blocks; a declined/missing/corrupt block
   *  falls to the next-best holder next round. Every returned block is
   *  hash-verified (§4.2) and scores its holder (§8). Returns the verified blocks
   *  keyed by id hex (shared across chunks, so a block named by more than one
   *  descriptor is fetched once). Self-held blocks read locally — no round trip. */
  private async gatherBlocks(
    sds: { descriptor: Descriptor }[], holders: Map<string, Set<PeerId>>,
  ): Promise<Map<string, Uint8Array>> {
    const got = new Map<string, Uint8Array>();
    const tried = new Map<string, Set<PeerId>>();
    const triedOf = (h: string): Set<PeerId> => { let s = tried.get(h); if (!s) tried.set(h, (s = new Set())); return s; };
    const maxBytes = this.node.config.maxMessageBytes > 0 ? this.node.config.maxMessageBytes : (1 << 20);
    const maxIds = Math.max(1, Math.floor(maxBytes / this.node.config.blockSize));

    // How many MORE distinct blocks a chunk still needs (0 once it can be read).
    const stillNeeds = (d: Descriptor): number => {
      const distinct = new Set<string>();
      for (const id of d.blockIds) if (got.has(toHex(id))) distinct.add(toHex(id));
      const need = d.m === 0 ? d.blockIds.length : d.k; // replica: all; coded: any k
      return Math.max(0, need - distinct.size);
    };

    for (;;) {
      // Per peer, the id hexes to request this round: each still-needed block from
      // its best untried holder. Descriptor order lists data blocks first, so a
      // coded chunk prefers them (systematic, no decode).
      const byPeer = new Map<PeerId, string[]>();
      const queued = new Set<string>();
      for (const { descriptor: d } of sds) {
        let need = stillNeeds(d);
        if (need === 0) continue;
        for (const id of d.blockIds) {
          if (need === 0) break;
          const h = toHex(id);
          if (got.has(h) || queued.has(h)) continue;
          const cands = this.rankBy([...(holders.get(h) ?? [])].filter((p) => !triedOf(h).has(p)));
          if (cands.length === 0) continue;
          let list = byPeer.get(cands[0]); if (!list) byPeer.set(cands[0], (list = []));
          list.push(h);
          queued.add(h);
          need--;
        }
      }
      if (byPeer.size === 0) break;

      // Split each peer's request into frame-sized sub-batches, window them all.
      const tasks: { peer: PeerId; hexes: string[] }[] = [];
      for (const [peer, hexes] of byPeer) for (const slice of chunkArray(hexes, maxIds)) tasks.push({ peer, hexes: slice });

      await mapPool(tasks, this.node.config.getConcurrency, async ({ peer, hexes }) => {
        const ids = hexes.map((h) => fromHex(h));
        const blocks = await this.fetchBatch(peer, ids);
        const pk = peer === this.node.peerId ? null : fromHex(peer); // null = self (don't score)
        const now = this.node.now();
        for (let i = 0; i < hexes.length; i++) {
          triedOf(hexes[i]).add(peer);                // tried this holder, fall to the next one next round
          if (blocks === null) continue;              // unreachable — not a §8 miss to score
          const b = blocks[i];
          if (b && bytesEqual(this.node.crypto.hash(b), ids[i])) {
            if (!got.has(hexes[i])) got.set(hexes[i], b);
            if (pk) { this.node.markSeen(peer); this.node.reputation.observe(pk, now, true); }
          } else if (pk) {
            this.node.reputation.observe(pk, now, false); // advertised but not served/corrupt (§8)
          }
        }
      });
    }
    return got;
  }

  /** Assemble one chunk's ciphertext from the gathered blocks (§4.1/§7). A
   *  replicated chunk concatenates its data blocks; a coded chunk concatenates the
   *  k data blocks when all present (systematic — no decode), else RS-decodes any
   *  k it has. */
  private assembleChunk(d: Descriptor, got: Map<string, Uint8Array>): Uint8Array {
    if (d.m === 0) {
      const blocks: Uint8Array[] = [];
      for (const id of d.blockIds) {
        const b = got.get(toHex(id));
        if (!b) throw new Error("get: a replica is unavailable");
        blocks.push(b);
      }
      return concatBytes(blocks);
    }
    const k = d.k;
    const present: { index: number; bytes: Uint8Array }[] = [];
    for (let i = 0; i < d.blockIds.length && present.length < k; i++) {
      const b = got.get(toHex(d.blockIds[i]));
      if (b) present.push({ index: i, bytes: b });
    }
    if (present.length < k) throw new Error("get: fewer than k blocks retrievable — chunk unavailable");

    const allData = present.slice(0, k).every((p) => p.index < k);
    if (allData) {
      const ordered = present.filter((p) => p.index < k).sort((a, b) => a.index - b.index).slice(0, k);
      if (ordered.length === k && ordered.every((p, i) => p.index === i)) {
        return concatBytes(ordered.map((p) => p.bytes)); // systematic — no decode
      }
    }
    return concatBytes(this.node.codec.rsDecode(k, d.m, d.blockSize, present));
  }

  /** Fetch a batch of blocks from one peer in a single round trip; returns one
   *  entry per id (the bytes, or null if the holder didn't serve that one), or
   *  `null` for the whole batch if the peer was unreachable — the caller scores a
   *  reachable-but-didn't-serve as a §8 miss, but an unreachable peer not at all.
   *  Self reads the local store directly (no network). The caller hash-verifies
   *  every block (§4.2) — the holder is never trusted to have served right. */
  private async fetchBatch(peer: PeerId, ids: Uint8Array[]): Promise<(Uint8Array | null)[] | null> {
    if (peer === this.node.peerId) {
      return ids.map((id) => { const sb = this.node.store.get(id); return sb ? sb.bytes : null; });
    }
    try {
      const res = await this.node.transport.request(peer, MsgType.FETCH, encodeFetchBatchReq(ids));
      const blocks = decodeFetchBatchRes(res);
      return ids.map((_, i) => blocks[i] ?? null);
    } catch { return null; } // unreachable within the request window
  }

  // ── placement (§6 step 3–4) ────────────────────────────────────────────
  /** Offer a block to candidate peers ordered by reciprocity standing (§13) and
   *  reachability; on accept, push it. Places onto up to `count` distinct peers
   *  not in `exclude`. Returns the peers that stored it. Used for replicas (a
   *  small file, the manifest) and repair; the RS-coded chunk path uses the
   *  batched `placeChunksBatched` so a peer's blocks are offered in one round. */
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

  /** OFFER a block to one peer and, if accepted, STORE it (§6 step 3–4). Returns
   *  whether the peer now holds it; marks it seen on success (§8). */
  private async tryStore(
    peer: PeerId, blockId: Uint8Array, bytes: Uint8Array, descriptor: Uint8Array | null,
  ): Promise<boolean> {
    if (!(await this.offerBatch(peer, [{ blockId, size: bytes.length, descriptor }]))[0]) return false;
    if (!(await this.storePush(peer, blockId, descriptor, bytes))) return false;
    this.node.markSeen(peer);
    return true;
  }

  /** Offer a batch of blocks to one peer in a single round trip; returns the
   *  holder's per-block accept mask (§6). An unreachable peer / malformed reply is
   *  all-declines. The holder re-checks every block at STORE time, so this is the
   *  advisory pre-check that lets a peer pre-decline what won't fit. */
  private async offerBatch(peer: PeerId, offers: Offer[]): Promise<boolean[]> {
    try {
      const res = await this.node.transport.request(peer, MsgType.OFFER, encodeOfferBatch(offers));
      const mask = decodeOfferMask(res);
      return offers.map((_, i) => mask[i] === true);
    } catch (e) { this.lastTransportError = `OFFER→${peer.slice(0, 8)} (${offers.length} blk): ${(e as Error)?.message ?? e}`; return offers.map(() => false); }
  }

  /** STORE a batch of blocks on one peer in a single streamed message; returns the
   *  holder's per-block stored/failed mask (§6 step 4). The holder hash-verifies +
   *  admits every block (acceptStore) — batching changes only the framing. An
   *  unreachable peer / malformed reply is all-failed. */
  private async storeBatch(peer: PeerId, stores: StoreReq[]): Promise<boolean[]> {
    try {
      const res = await this.node.transport.request(peer, MsgType.STORE, encodeStoreBatch(stores));
      const mask = decodeStoreMask(res);
      return stores.map((_, i) => mask[i] === true);
    } catch (e) { this.lastTransportError = `STORE→${peer.slice(0, 8)} (${stores.length} blk, ${stores.reduce((s, x) => s + x.bytes.length, 0)} B): ${(e as Error)?.message ?? e}`; return stores.map(() => false); }
  }

  /** Single-block STORE (the replica + manifest + repair paths) over the batched wire. */
  private async storePush(peer: PeerId, blockId: Uint8Array, descriptor: Uint8Array | null, bytes: Uint8Array): Promise<boolean> {
    return (await this.storeBatch(peer, [{ blockId, descriptor, bytes }]))[0];
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
function chunkArray<T>(arr: T[], size: number): T[][] {
  if (arr.length <= size) return [arr];
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}
/** Group items so each group's summed `sizeOf` stays under `maxBytes` (a single
 *  over-cap item still gets its own group, so progress is always made). */
function batchByBytes<T>(items: T[], sizeOf: (item: T) => number, maxBytes: number): T[][] {
  const out: T[][] = [];
  let group: T[] = [];
  let acc = 0;
  for (const it of items) {
    const sz = sizeOf(it);
    if (group.length > 0 && acc + sz > maxBytes) { out.push(group); group = []; acc = 0; }
    group.push(it);
    acc += sz;
  }
  if (group.length > 0) out.push(group);
  return out;
}
