// cohort — the discovery handler (README §5, §17; caps net, clock). Maintains
// nothing global: discovery, liveness, and the verification-fetch sampling that
// backs them all happen inside the bounded peer set (§5.1). have/want is the
// whole discovery layer (§5.2) — one round trip, no crypto protocol, and it
// only ever names ids the asker already holds, so files cannot be enumerated.

import type { Node, PeerId } from "./core.js";
import { MsgType, encodeHaveReq, decodeHaveRes, encodeFetchReq, decodeFetchRes } from "./protocol.js";
import { toHex, fromHex, bytesEqual } from "./util.js";

export class Cohort {
  constructor(private readonly node: Node) {}

  /** disc.have/want for a set of block_ids (§5.2). Returns, per id (hex), the
   *  set of cohort peers that answered "have". Responders are marked live (§8).
   *  Have/want is advertisement only — §8 backs it with verificationFetch. */
  async haveWant(ids: Uint8Array[], peers = this.node.cohortPeers()): Promise<Map<string, Set<PeerId>>> {
    const holders = new Map<string, Set<PeerId>>();
    for (const id of ids) holders.set(toHex(id), new Set());
    // A node is itself a holder of whatever its own store keeps — the repair
    // loop (§9) is run *by* a chunk's block-holders, so its own blocks must
    // count and be usable for reconstruction.
    for (const id of ids) if (this.node.store.has(id)) holders.get(toHex(id))!.add(this.node.peerId);
    const req = encodeHaveReq(ids);
    await Promise.all(
      peers.map(async (peer) => {
        try {
          const res = await this.node.transport.request(peer, MsgType.HAVE, req);
          const held = decodeHaveRes(res);
          this.node.markSeen(peer);
          for (let i = 0; i < ids.length && i < held.length; i++) {
            if (held[i]) holders.get(toHex(ids[i]))!.add(peer);
          }
        } catch {
          /* unreachable within the request window — leaves the peer un-seen,
             which tips it toward Suspected/Lost on the next liveness pass (§8). */
        }
      }),
    );
    return holders;
  }

  /** A verification-fetch (§8): pull a block from a holder and confirm it
   *  hashes to its block_id. A pass proves retrievability and raises the
   *  holder's reciprocity standing; a miss decays it (§13.1). Returns the
   *  verified bytes, or null if the holder could not serve them. */
  async verificationFetch(peer: PeerId, id: Uint8Array): Promise<Uint8Array | null> {
    // Self-fetch reads the local store directly (no network round trip).
    if (peer === this.node.peerId) {
      const sb = this.node.store.get(id);
      return sb && bytesEqual(this.node.crypto.hash(sb.bytes), id) ? sb.bytes : null;
    }
    const peerPk = fromHex(peer);
    try {
      const res = await this.node.transport.request(peer, MsgType.FETCH, encodeFetchReq(id));
      const bytes = decodeFetchRes(res);
      if (bytes && bytesEqual(this.node.crypto.hash(bytes), id)) {
        this.node.markSeen(peer);
        this.node.reputation.observe(peerPk, this.node.now(), true);
        return bytes;
      }
      // Advertised but could not serve (or served corrupt bytes) — counts as a
      // miss and is treated as not holding the block (§8, §10).
      this.node.reputation.observe(peerPk, this.node.now(), false);
      return null;
    } catch {
      return null;
    }
  }

  /** For each block_id, the set of holders that are *live* — recently reachable
   *  and, when `verify` is set, recently served a verification-fetch for it
   *  (§8). `live_blocks` is the count of ids with at least one live holder. */
  async liveHolders(ids: Uint8Array[], verify = true): Promise<Map<string, Set<PeerId>>> {
    const advertised = await this.haveWant(ids);
    if (!verify) return advertised;
    const verified = new Map<string, Set<PeerId>>();
    for (const id of ids) {
      const key = toHex(id);
      const live = new Set<PeerId>();
      // Confirm retrievability for each advertised holder (latency-bounded by
      // the transport timeout, §8). We keep the full set — repair needs the
      // real holder count (replicas) and the occupied-peer set, not just "≥1".
      for (const peer of advertised.get(key) ?? []) {
        if (await this.verificationFetch(peer, id)) live.add(peer);
      }
      verified.set(key, live);
    }
    return verified;
  }

  /** live_blocks for a chunk: how many of its block_ids have a live holder. */
  async liveBlockCount(ids: Uint8Array[], verify = true): Promise<number> {
    const live = await this.liveHolders(ids, verify);
    let count = 0;
    for (const set of live.values()) if (set.size > 0) count++;
    return count;
  }
}
