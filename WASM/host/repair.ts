// repair — self-healing, per chunk, performed by the chunk's own block-holders
// (README §9, §17; caps store, net, clock). Anyone holding a block also holds
// that chunk's signed descriptor (§4.3) — the sibling block-ids — which, with
// the deployment's (k, m), is all you need to audit and rebuild it. No peer is
// special and no one is appointed: the work gets done by whoever notices first.
//
// Repair is idempotent: the deterministic re-encode (§4.1) regenerates the same
// content-addressed block-ids, so two peers healing at once converge on
// identical blocks and the surplus is reclaimed as ordinary over-replication.
// A repairer re-certifies every regenerated block against its already-signed
// block_id before trusting it, so a poisoned descriptor can never make repair
// mint or propagate garbage (§9).

import type { Node, PeerId } from "./core.js";
import type { Cohort } from "./cohort.js";
import type { Coordinator } from "./coordinator.js";
import { verifyDescriptor, type Descriptor } from "./manifest.js";
import { toHex, bytesEqual } from "./util.js";

export class Repair {
  constructor(
    private readonly node: Node,
    private readonly cohort: Cohort,
    private readonly coordinator: Coordinator,
  ) {}

  /** Run the repair loop over every chunk this node holds a block of (§9). A
   *  holder enumerates its blocks' descriptors and audits each chunk. Returns
   *  the number of blocks (re-)placed. */
  async repairHeldChunks(): Promise<number> {
    const seen = new Set<string>();
    let replaced = 0;
    for (const id of this.node.store.list()) {
      const sb = this.node.store.get(id);
      if (!sb || !sb.descriptor) continue;
      const key = toHex(this.node.crypto.hash(sb.descriptor));
      if (seen.has(key)) continue;
      seen.add(key);
      replaced += await this.repairChunk(sb.descriptor);
    }
    return replaced;
  }

  /** Audit and, if under-replicated, heal one chunk from its signed descriptor.
   *  Returns the number of blocks re-placed (0 if healthy or unrepairable). */
  async repairChunk(descEnv: Uint8Array): Promise<number> {
    // The descriptor must verify from the author's public key alone (§4.3) —
    // keyless, so any block-holder can repair without the read key (§9).
    const sd = verifyDescriptor(this.node.sodium, descEnv);
    if (!sd) return 0;
    const d = sd.descriptor;

    const holders = await this.cohort.liveHolders(d.blockIds, true);
    let liveCount = 0;
    for (const set of holders.values()) if (set.size > 0) liveCount++;
    // Repair triggers on a low-water mark strictly above k (§8, §9), never
    // waiting until the chunk is one loss from death.
    if (liveCount >= this.node.config.lowWater) return 0;

    return d.m === 0
      ? this.healReplicated(d, descEnv, holders)
      : this.healCoded(d, descEnv, holders);
  }

  /** Replicated chunk (§4.1): repair is a single block copy from any live
   *  holder, with no reconstruction at all. */
  private async healReplicated(
    d: Descriptor, descEnv: Uint8Array, holders: Map<string, Set<PeerId>>,
  ): Promise<number> {
    let replaced = 0;
    for (const id of d.blockIds) {
      const set = holders.get(toHex(id)) ?? new Set<PeerId>();
      if (set.size >= this.node.config.replicas) continue;
      const bytes = await this.coordinator.fetchBlock(id);
      if (!bytes) continue;
      const need = this.node.config.replicas - set.size;
      const placed = await this.coordinator.placeBlock(id, bytes, descEnv, set, need);
      replaced += placed.length;
    }
    return replaced;
  }

  /** Coded chunk (§9): fetch any k retrievable blocks, reconstruct the chunk
   *  ciphertext, re-encode only the missing blocks, and place them on fresh
   *  peers — each re-certified against its signed block_id first. */
  private async healCoded(
    d: Descriptor, descEnv: Uint8Array, holders: Map<string, Set<PeerId>>,
  ): Promise<number> {
    const present: { index: number; bytes: Uint8Array }[] = [];
    for (let idx = 0; idx < d.blockIds.length && present.length < d.k; idx++) {
      const set = holders.get(toHex(d.blockIds[idx]));
      if (!set || set.size === 0) continue;
      const peer = [...set][0];
      const b = await this.cohort.verificationFetch(peer, d.blockIds[idx]);
      if (b) present.push({ index: idx, bytes: b });
    }
    if (present.length < d.k) return 0; // cannot heal — fewer than k retrievable

    const data = this.node.codec.rsDecode(d.k, d.m, d.blockSize, present);
    const parity = this.node.codec.rsEncode(d.k, d.m, d.blockSize, data);
    const all = [...data, ...parity];

    // Spread regenerated blocks onto peers not already holding part of this
    // chunk, preserving the distinct-holder invariant (§6, §10).
    const occupied = new Set<PeerId>();
    for (const set of holders.values()) for (const p of set) occupied.add(p);

    let replaced = 0;
    for (let i = 0; i < all.length; i++) {
      const id = d.blockIds[i];
      if ((holders.get(toHex(id))?.size ?? 0) > 0) continue; // already live
      // Re-certify the regenerated block against the already-signed id (§9):
      // deterministic encode guarantees a match, so a mismatch means a bad
      // input/decode and the block is dropped rather than propagated.
      if (!bytesEqual(this.node.crypto.hash(all[i]), id)) continue;
      const placed = await this.coordinator.placeBlock(id, all[i], descEnv, occupied, 1);
      for (const p of placed) occupied.add(p);
      replaced += placed.length;
    }
    return replaced;
  }
}
