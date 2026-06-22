// Shared types + deployment configuration for the storage orchestration
// (README §17). The three orchestration "handlers" — cohort, coordinator,
// repair — are host-side classes (the cap-holding logic above the bridges,
// §2 composition) that all operate against this Node surface.

import type { PeerId, Transport } from "seedkernel-wasm/net";
import type { BlobStore } from "./store-local.js";
import type { CodecClient } from "./codec-client.js";
import type { Crypto } from "./crypto.js";
import type { ReputationClient } from "./reputation-client.js";
import type { Sodium } from "./sodium.js";

export interface Identity {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** The durability/overhead dial, set once per deployment (§4.1, §27). */
export interface StorageConfig {
  k: number;
  m: number;
  blockSize: number;
  /** r = m + 1 replicas for a file too small to fill a chunk (§4.1). */
  replicas: number;
  /** Repair fires when live_blocks < lowWater; default k + ceil(m/2) (§8, §9). */
  lowWater: number;
  /** Files of at most this many blocks are replicated, not RS-coded (§4.1). */
  smallMaxBlocks: number;
  /** Grace window G: an unreachable holder is Suspected, not Lost (§8). */
  graceMs: number;
  /** How many chunks a PUT places / a GET fetches concurrently — the §6/§7
   *  windows. Chunks are independent, so a bounded worker pool overlaps one
   *  chunk's CPU (encrypt/RS/sign) and network with another's; without it PUT/GET
   *  wall-clock scales with the *serial* round-trip count across the whole file,
   *  which is fine on the zero-latency loopback but cripples a real high-latency
   *  cohort. Kept well under net-link's MAX_QUEUE (256) so a peer's send queue
   *  never overflows; the chunk window stacks with the n-way within-chunk fan-out,
   *  so peak in-flight is bounded by putConcurrency × n. W = 1 = one chunk at a
   *  time (its n blocks still place in parallel). */
  putConcurrency: number;
  getConcurrency: number;
}

export function defaultConfig(k = 2, m = 2, blockSize = 256): StorageConfig {
  // Replication beats padding a tiny file while d < (k+m)/(m+1) (§4.1) — e.g.
  // 2 blocks at the default RS(10,6). The largest such d is ceil((k+m)/(m+1))-1.
  const smallMaxBlocks = Math.max(1, Math.ceil((k + m) / (m + 1)) - 1);
  return {
    k,
    m,
    blockSize,
    replicas: m + 1,
    lowWater: k + Math.ceil(m / 2),
    smallMaxBlocks,
    graceMs: 24 * 3600 * 1000,
    putConcurrency: 16,
    getConcurrency: 16,
  };
}

/** Liveness state of a holder for a block (§8). */
export type Liveness = "live" | "suspected" | "lost";

/** The surface the orchestration modules share. StorageNode implements it. */
export interface Node {
  readonly peerId: PeerId;
  readonly identity: Identity;
  readonly transport: Transport;
  readonly store: BlobStore;
  readonly codec: CodecClient;
  readonly crypto: Crypto;
  readonly reputation: ReputationClient;
  /** libsodium — descriptor signing stays sender-side in the host (§16). */
  readonly sodium: Sodium;
  readonly config: StorageConfig;
  now(): number;
  /** Cohort peers, excluding self (§5.1). */
  cohortPeers(): PeerId[];
  /** Note that a peer answered/served just now (feeds liveness, §8). */
  markSeen(peer: PeerId): void;
  lastSeen(peer: PeerId): number;
}

/** peer_id is the hex of a peer's kernel public key (§2). */
export { type PeerId } from "seedkernel-wasm/net";
