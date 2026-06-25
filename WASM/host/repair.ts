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
    const distinct = distinctBlocks(d.blockIds);
    // Effective redundancy: distinct live holders per block, each capped by how
    // many slots that block fills. A degenerate code (e.g. RS(1,1), whose parity
    // is byte-identical to its data) repeats one id across slots, so that id must
    // live on as many distinct holders as it has slots (§6/§10); for ordinary RS
    // every id is unique and this is exactly the old `live_blocks` count (§8).
    let redundancy = 0;
    for (const [h, b] of distinct) redundancy += Math.min(holders.get(h)?.size ?? 0, b.count);
    // Repair triggers on a low-water mark strictly above k (§8, §9), never
    // waiting until the chunk is one loss from death.
    if (redundancy >= this.node.config.lowWater) return 0;

    return d.m === 0
      ? this.healReplicated(d, descEnv, holders)
      : this.healCoded(d, descEnv, holders, distinct);
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

  /** Coded chunk (§9): bring every block back to full redundancy. A block some
   *  holder still serves but too few hold — a degenerate code's repeated id, or a
   *  lost extra replica — is simply copied to fresh peers; a block no live holder
   *  serves is reconstructed from any k present blocks, re-certified against its
   *  signed block_id, then placed. Each id lands on as many distinct holders as it
   *  has slots, preserving the one-block-per-holder invariant (§6, §10). */
  private async healCoded(
    d: Descriptor, descEnv: Uint8Array,
    holders: Map<string, Set<PeerId>>,
    distinct: Map<string, { id: Uint8Array; count: number }>,
  ): Promise<number> {
    // Reconstruct any *entirely missing* id once, up front, from k present blocks.
    // (A block that still has a live holder is copied below, not decoded — cheaper.)
    const regenerated = new Map<string, Uint8Array>();
    if ([...distinct.keys()].some((h) => (holders.get(h)?.size ?? 0) === 0)) {
      const present: { index: number; bytes: Uint8Array }[] = [];
      for (let idx = 0; idx < d.blockIds.length && present.length < d.k; idx++) {
        const set = holders.get(toHex(d.blockIds[idx]));
        if (!set || set.size === 0) continue;
        const b = await this.cohort.verificationFetch([...set][0], d.blockIds[idx]);
        if (b) present.push({ index: idx, bytes: b });
      }
      if (present.length >= d.k) {
        const data = this.node.codec.rsDecode(d.k, d.m, d.blockSize, present);
        const all = [...data, ...this.node.codec.rsEncode(d.k, d.m, d.blockSize, data)];
        for (let i = 0; i < all.length; i++) {
          const h = toHex(d.blockIds[i]);
          if (regenerated.has(h)) continue;
          // Re-certify against the already-signed id (§9): deterministic encode
          // must reproduce it, so a mismatch means a bad input/decode — drop it,
          // never propagate, so a poisoned descriptor can't mint garbage.
          if (bytesEqual(this.node.crypto.hash(all[i]), d.blockIds[i])) regenerated.set(h, all[i]);
        }
      }
    }

    // Spread copies onto peers not already holding part of this chunk (§6, §10).
    const occupied = new Set<PeerId>();
    for (const set of holders.values()) for (const p of set) occupied.add(p);

    let replaced = 0;
    for (const [h, { id, count }] of distinct) {
      const live = holders.get(h)?.size ?? 0;
      const need = count - live;
      if (need <= 0) continue;
      // A live copy is the cheapest source; otherwise the reconstructed block.
      const bytes = live > 0 ? await this.coordinator.fetchBlock(id) : regenerated.get(h);
      if (!bytes) continue; // missing and not reconstructable this pass
      const placed = await this.coordinator.placeBlock(id, bytes, descEnv, occupied, need);
      for (const p of placed) occupied.add(p);
      replaced += placed.length;
    }
    return replaced;
  }
}

/** A chunk's distinct block-ids → their bytes and multiplicity (how many slots
 *  each fills). Ordinary RS gives every id multiplicity 1; a degenerate k=1 code,
 *  whose parity equals its data, collapses several slots onto one id (§9). */
function distinctBlocks(blockIds: Uint8Array[]): Map<string, { id: Uint8Array; count: number }> {
  const out = new Map<string, { id: Uint8Array; count: number }>();
  for (const id of blockIds) {
    const h = toHex(id);
    const e = out.get(h);
    if (e) e.count++; else out.set(h, { id, count: 1 });
  }
  return out;
}
