// StorageNode — a single storage peer running *on* the seedkernel (README §19
// bootstrap). It is now a THIN host: the entire storage protocol lives in the
// confined guest (host/tier2-guest.js), run inside ONE seedkernel safe-js realm
// over the generic capability bridge. StorageNode only:
//
//   - stands up the handler table and wires the loader's admission policy (§12.5). There is
//     no module registry and no signature wrapper any more — authenticity is the
//     transport's job (the AKE channel attributes every frame), so the kernel
//     carries no per-message signing (seedkernel "Drop the whole envelope +
//     signing", "Move admission policy to bundle loading")
//   - installs the pure codec + reputation handlers (RS coding + reciprocity
//     scoring); everything else the guest reaches through the generic cap-bridge
//     (crypto/net/fs/clock/module), so there are no storage-specific host bridges
//   - runs the guest's *initiator* entrypoints (put / get / repair) via the
//     realm's async `call()` (they fan out over net and park mid-await, §2.1)
//   - serves the guest's *holder* entrypoint (handle: HAVE / OFFER / STORE /
//     FETCH) via the same realm's synchronous `callSync()`, so it can answer a
//     peer's request while this node's own initiator is parked mid-await in that
//     realm — the runtime split (a suspended async guest is just heap state, §2.1)
//
// There is no host-side copy of the protocol any more: placement, k-of-n,
// admission, the wire format, repair triggers — all of it is the guest. The same
// class runs in Node and the browser; only the BlobStore backend and the Network
// implementation differ (§1, §12).

// Import the kernel host from seedkernel's *browser* subpath: it is the same
// platform-neutral KernelHost, but without the node:fs shims node.js pulls in,
// so this module loads unchanged in both Node and the browser (§1, §20). For the
// same reason StorageNode never reads the guest text from disk — the caller
// supplies it (`guestSource`): node.js reads it off disk, browser.js fetches it.
import { KernelHost } from "seedkernel-wasm/browser";
import { createCapBridge, capPreamble, bundlePreamble } from "seedkernel-wasm/cap-bridge";
// The generic zero-authority sandbox lives in the kernel as `safe-js`: ONE realm
// runs both roles over the genuinely-async seam — `call()` for the initiator
// (put/get/repair, which awaits net) and `callSync()` for the holder (handle),
// which answers synchronously from local fs + crypto and so can serve re-entrantly
// while an initiator is parked mid-await in the same realm (§2.1).
import {
  createSafeRealm,
  type SafeRealm, type SafeRealmBridge,
} from "seedkernel-wasm/safe-js";

import type { Sodium } from "./sodium.js";
import type { Network, PeerId } from "seedkernel-wasm/net";
import { Transport } from "seedkernel-wasm/net";
import { MemoryFs, type Fs } from "seedkernel-wasm/fs";
import { DEFAULT_QUOTA_BYTES, type BlobStore } from "./store-local.js";
import { FsBlobStore } from "./store-fs.js";
import { Crypto } from "./crypto.js";
import { storageNames, type StorageNames } from "./names.js";
import { type Identity, type StorageConfig, defaultConfig } from "./core.js";
import { STORAGE_APP, ZERO_AUTHOR, storageSignScope } from "./manifest.js";
import { encodeScoreReq } from "./reputation-core.js";
import { toHex, readU32BE, writeU64BE, readU64BE, concatBytes } from "./util.js";

const NO_ARG = new Uint8Array(0);
/** The one scalar the host frames for the guest: the file size that opens a PUT stream.
 *  Everything else about a stream lives in the guest's own realm state, so there is no
 *  other length-prefixed argument to build here. */
function u64be(n: number): Uint8Array { const b = new Uint8Array(8); writeU64BE(b, 0, n); return b; }

/** Decode the guest's PUT result — the single result format every driver reads
 *  (`encodePutResult` in tier2-guest.orchestration.js):
 *  [manifestId 32][replicated u8][chunkCount u32][K 32][placed u32][intended u32]
 *  [idCount u32]{id 32}. */
function decodePutResult(r: Uint8Array): PutResult {
  const blockIds: Uint8Array[] = [];
  const idCount = readU32BE(r, 77);
  for (let i = 0; i < idCount; i++) blockIds.push(r.slice(81 + i * 32, 81 + (i + 1) * 32));
  return {
    manifestId: r.slice(0, 32),
    replicated: r[32] === 1,
    chunkCount: readU32BE(r, 33),
    key: r.slice(37, 69),
    replicasLanded: readU32BE(r, 69),
    replicasIntended: readU32BE(r, 73),
    blockIds,
  };
}

/** PUT result: the manifest root, the per-file content key K, and where the
 *  file landed (every distinct block id placed + the manifest, in placement
 *  order — the manifest names ids, not holders, so this is the only handle on
 *  the concrete block set, e.g. for the browser demo's per-holder counts). */
export interface PutResult {
  manifestId: Uint8Array;
  /** The per-file content key K. The owner keeps it and seals it to readers. */
  key: Uint8Array;
  chunkCount: number;
  /** True if the file was replicated rather than RS-coded (§4.1). */
  replicated: boolean;
  blockIds: Uint8Array[];
  /** Replicas that actually landed across all chunks, and how many were intended
   *  (min(k+m, reachable cohort) per chunk). When landed < intended the PUT is
   *  durable enough to satisfy the ≥ k floor but UNDER-replicated — a holder was
   *  reachable yet declined (full/quota) or the cohort is short — so a caller should
   *  warn rather than report a clean success. */
  replicasLanded: number;
  replicasIntended: number;
}

export interface StorageNodeOptions {
  network: Network;
  sodium: Sodium;
  codecBytes: Uint8Array;
  reputationBytes: Uint8Array;
  /** The stitched guest program text (build/host/tier2-guest.js). The whole
   *  protocol — node.js reads it off disk, browser.js fetches it, so this module
   *  stays node:fs-free. */
  guestSource: string;
  identity?: Identity;
  config?: Partial<StorageConfig>;
  /** Raw-byte `fs.*` backend (§12; seedkernel's Fs). Defaults to an in-RAM
   *  MemoryFs; a server node passes a NodeFs, the browser an OPFS-backed one. The
   *  default store is an FsBlobStore over this, and BOTH guest realms serve `fs.*`
   *  from it — so the holder's writes and the host-side store view share a backend.
   *  Do NOT write blocks into this `fs` out-of-band on a live node: the guest holder
   *  caches its committed-tier byte total (bytesUsed) and only rebuilds it lazily, so
   *  writes it didn't make leave its §14 quota accounting stale until the realm is
   *  rebuilt (over/under-admitting in the meantime). */
  fs?: Fs;
  /** Donated blob store (§12) — a *read view* over `fs` for inspection (the guest
   *  holder writes the `<hex>.blk`/`.dsc` layout itself, via `fs.*`). Defaults to
   *  an FsBlobStore over `fs` with a `quota`-byte budget; a custom store must layer
   *  over the same `fs` the node serves, or the two would diverge. Its put/delete are
   *  for callers that drive the store directly (e.g. tests): calling them on a live
   *  node bypasses the guest holder, whose cached quota budget then goes stale until
   *  the guest realm is rebuilt — FsBlobStore itself reads used-bytes live for the
   *  mirror-image reason (it can't see the guest's `fs.*` writes). */
  store?: BlobStore;
  quota?: number;
  clock?: () => number;
  /** net.send timeout — how long before a peer is treated as unreachable (§8). */
  timeoutMs?: number;
  /** The bundle author this node signs and verifies descriptors under (README §16).
   *  The scope is `guestSignScope(signAuthor, "seedstore")` and descriptors are
   *  signed/verified over `DOMAIN_guest ‖ scope ‖ core`, so every node in one cohort
   *  must agree on it (a descriptor one signs verifies on another). Defaults to the
   *  zero key — the in-process posture for a host-side node with no bundle behind it;
   *  a cohort joining shell-run holders (the cross-path tests, p2p.html) passes that
   *  bundle's author so its StorageNodes verify what the shell signs.
   *
   *  Deliberately the AUTHOR and not a pre-derived scope: the scope and the guest's
   *  injected signing prefix are then derived from it in one place, exactly as the
   *  seedkernel shell derives them from an admitted manifest (§12.4). */
  signAuthor?: Uint8Array;
}

export class StorageNode {
  readonly peerId: PeerId;
  readonly identity: Identity;
  readonly transport: Transport;
  readonly fs: Fs;
  readonly store: BlobStore;
  readonly crypto: Crypto;
  readonly sodium: Sodium;
  readonly config: StorageConfig;
  readonly host: KernelHost;
  readonly names: StorageNames;

  private readonly peers = new Set<PeerId>();
  private readonly clockFn: () => number;
  private readonly guestSource: string;
  /** The bundle author this node's signing scope is derived from (§16). */
  private readonly signAuthor: Uint8Array;
  private readonly signScope: Uint8Array;
  private repairLoopOn = false;
  private repairTimer: ReturnType<typeof setTimeout> | null = null;
  // The tail of the initiator operation chain (put/get/repair/warm). runExclusive chains
  // each whole operation onto it, so they run strictly one at a time (see there) and
  // close() can await the chain — not just the most recent window call — before disposing
  // the realm. `closed` short-circuits any operation raised after close() with a clean
  // rejection instead of a mid-flight "realm disposed" error.
  private inFlight: Promise<unknown> = Promise.resolve();
  private closed = false;

  // ONE realm runs the whole guest: the async initiator (put/get/repair, via call())
  // and the synchronous holder (handle, via callSync()). Created eagerly at boot so a
  // node serves the moment it is connected. callSync runs the holder re-entrantly —
  // straight through to its bytes without pumping the job queue — so it answers a peer
  // while this realm's own initiator is parked mid-await, without disturbing it (§2.1).
  private realm!: SafeRealm;

  private constructor(opts: StorageNodeOptions, host: KernelHost, identity: Identity) {
    this.sodium = opts.sodium;
    this.host = host;
    this.identity = identity;
    this.peerId = toHex(identity.publicKey);
    this.guestSource = opts.guestSource;
    // One derivation from the author: the bridge's SIGN scope and the guest's injected
    // verify prefix both come from it, so the two can never disagree (§16).
    this.signAuthor = opts.signAuthor ?? ZERO_AUTHOR;
    this.signScope = storageSignScope(this.signAuthor);
    // Defaults under the caller's own (k, m, blockSize), with any explicit field
    // overriding. Nothing here is *derived* from k/m: the replica count, the low-water
    // mark, and smallMaxBlocks are all §4.1 math computed where they are used (from the
    // signed descriptor, or from k/m in the guest), so overriding the geometry cannot
    // leave a stale durability knob behind for them to disagree with.
    const c = opts.config;
    this.config = { ...defaultConfig(c?.k, c?.m, c?.blockSize), ...c };
    this.clockFn = opts.clock ?? (() => Date.now());
    this.crypto = new Crypto(opts.sodium);
    this.fs = opts.fs ?? new MemoryFs();
    this.store = opts.store ?? new FsBlobStore(this.fs, opts.quota ?? DEFAULT_QUOTA_BYTES);
    this.names = storageNames(host);
    this.transport = new Transport(this.peerId, opts.network, opts.timeoutMs ?? 200);
  }

  /** Boot a storage node: stand up the handler table, wire the admission policy, install the
   *  codec + reputation handlers, then build the sync holder realm and route
   *  incoming requests to the guest's `handle` (§19, §2.1). */
  static async create(opts: StorageNodeOptions): Promise<StorageNode> {
    await opts.sodium.ready;
    const host = new KernelHost(opts.sodium as never);
    // Single-deployment reference posture: admit audited handler bytes from any
    // author. A real deployment narrows this to a content-hash allowlist + closed
    // author set — that is exactly `buildAdmit(policy)` on the shell's boot path
    // (§12.5, §19). Capabilities are no longer install-declared — the JS sandbox is
    // the confinement, so the policy governs WHO may bind a name only. Admission is
    // deny-all until this runs, so it is what lets installHandlers land anything.
    host.setAdmitPolicy(() => true);

    const identity = opts.identity ?? (() => {
      const kp = opts.sodium.crypto_sign_keypair();
      return { publicKey: kp.publicKey, privateKey: kp.privateKey };
    })();

    const node = new StorageNode(opts, host, identity);
    node.installHandlers(opts.codecBytes, opts.reputationBytes);

    // The one guest realm, created eagerly so the node serves the moment it is
    // connected. The holder side routes every incoming request to the guest's `handle`
    // via callSync — it answers from local fs + crypto without yielding (no net round
    // trip) and without pumping the job queue, so it responds re-entrantly while this
    // same realm's initiator is parked mid-await, without advancing it (§2.1).
    node.realm = await createSafeRealm({
      source: node.guestFullSource(), bridge: node.buildBridge(), memoryLimitBytes: node.config.realmMemoryBytes,
    });
    node.transport.onRequest((_from, type, payload) => {
      const arg = new Uint8Array(1 + payload.length);
      arg[0] = type & 0xff;
      arg.set(payload, 1);
      return node.realm.callSync("handle", arg);
    });
    return node;
  }

  // ── the guest runtime (the one realm + bridge + injected config) ────────────
  /** The generic cap-bridge: kernel primitives only, no storage vocabulary.
   *  codec/reputation are reached as installed handlers via host.callHandler; net
   *  via the Transport; fs over the node's raw backend. One bridge serves the one
   *  realm — the initiator awaits the net op (a real Promise); the holder path
   *  touches only the synchronous ops. */
  private buildBridge(): SafeRealmBridge {
    return createCapBridge({
      sodium: this.sodium,
      identity: this.identity,
      callHandler: (name, payload) => this.host.callHandler(name, payload),
      transport: this.transport,
      peers: () => this.cohortPeers(),
      fs: this.fs,
      now: () => this.now(),
      // Scope the guest's SIGN op to this deployment (README §16): the kernel signs
      // `DOMAIN_guest ‖ scope ‖ msg`, never the raw node key over guest bytes.
      signScope: this.signScope,
    });
  }

  /** The `const APP = {…};` block the guest reads its config from — storage's
   *  app-specific constants, injected the same way the CAP op preamble is. The
   *  seedkernel shell builds the byte-identical block from a bundle manifest's
   *  `guest.config` (with operator config merged over it).
   *
   *  What is NOT here: the module kernel names and the signing prefix. Those are facts
   *  a runtime derives, and they arrive as `BUNDLE` (below) — where operator config,
   *  which merges over APP, cannot reach them. */
  private appPreamble(): string {
    const c = this.config;
    // The APP injection is TOTAL: every value the guest reads is here and concrete —
    // the guest reads APP and never falls back to a guessed default. The §4.1 durability
    // math is absent because it is derived, not injected: smallMaxBlocks from k/m in the
    // guest, and the replica count + low-water mark from each chunk's signed descriptor.
    const app = {
      k: c.k, m: c.m, blockSize: c.blockSize,
      // The holder side's byte budget (§14) — the same quota FsBlobStore enforces,
      // surfaced so the confined `handle` path admits exactly as the host store does.
      quota: this.store.stat().quota,
      // Transport/operator policy (like quota, not author-signed): the per-message
      // batch cap and the fan-out windows the guest splits/pipelines OFFER/STORE/
      // FETCH under, so it batches byte-for-byte as the spec intends.
      maxMessageBytes: c.maxMessageBytes,
      putWindow: c.putWindow, getWindow: c.getWindow,
      // Streamed PUT/GET window (§3), always concrete (core.ts homes the 4 MiB default).
      // Bigger windows amortise the per-window OFFER→STORE→ack barrier on a fat/low-loss link.
      windowTargetBytes: c.windowTargetBytes,
    };
    return `const APP = ${JSON.stringify(app)};\n`;
  }

  /** The `const BUNDLE = {…};` block (seedkernel §12.4): the facts a runtime derives
   *  about the app it is running — here from this node's own author + names rather than
   *  from an admitted manifest, since a host-side StorageNode has no bundle behind it.
   *  Built by the SHARED `bundlePreamble`, so the signing prefix it injects is the same
   *  bytes, from the same derivation, that a shell running the seedstore bundle injects
   *  — which is what makes a descriptor signed on one verify on the other. */
  private bundleFacts(): string {
    return bundlePreamble({
      app: STORAGE_APP,
      author: this.signAuthor,
      modules: { codec: this.names.codec, reputation: this.names.reputation },
    });
  }

  /** The full guest source: the generic CAP op catalog + the bundle facts + the
   *  injected APP config + the orchestration program. */
  private guestFullSource(): string {
    return capPreamble() + this.bundleFacts() + this.appPreamble() + this.guestSource;
  }

  // ── Node surface ───────────────────────────────────────────────────────
  now(): number { return this.clockFn(); }
  cohortPeers(): PeerId[] { return [...this.peers]; }

  // ── cohort membership (§5.1) ───────────────────────────────────────────
  /** Add a peer to this node's cohort. Reciprocal — call on both nodes, or use
   *  connect() for a symmetric link. */
  addPeer(peerId: PeerId): void {
    if (peerId !== this.peerId) this.peers.add(peerId);
  }
  removePeer(peerId: PeerId): void { this.peers.delete(peerId); }

  /** Make a symmetric cohort link between two nodes. */
  static connect(a: StorageNode, b: StorageNode): void {
    a.addPeer(b.peerId);
    b.addPeer(a.peerId);
  }

  // ── PUT / GET / repair / share (§6, §7, §9, §4.4) — all run in the guest ──
  /** Run one initiator OPERATION — a whole streamed PUT or GET, not a single realm call —
   *  with exclusive use of the realm, recording it as in-flight so close() can await it
   *  before disposing (disposing while a call is parked mid-await — a repair pass caught
   *  by close, waiting out an unreachable peer's timeout — would resume into a freed
   *  realm: a QuickJS UseAfterFree abort).
   *
   *  Exclusive for the whole operation, not per call, because the guest keeps a stream's
   *  protocol state (K, the running offset, the descriptors placed so far) in realm state
   *  rather than round-tripping it through the host: two overlapping streams in one realm
   *  would clobber each other. Chaining whole operations is what makes that single
   *  implicit session safe by construction — and, as before, it keeps a PUT and a repair
   *  pass from competing for the link. */
  private runExclusive<T>(body: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(new Error("storage node closed"));
    const p = this.inFlight.then(body);
    this.inFlight = p.then(() => {}, () => {});
    return p;
  }

  /** PUT a file (§6), orchestrated in the guest, STREAMED so the confined guest heap never
   *  holds the whole file (README §3): putStart opens the stream and reports the plaintext
   *  window size, putWindow feeds each slice in file order — its ciphertext placed and
   *  dropped before the next crosses — and putFinish seals the manifest and reports the
   *  result. K, the chunk descriptors and the replica accounting stay in the guest, so the
   *  host ships plaintext in and reads one result out, and re-encodes no protocol format. */
  async put(plaintext: Uint8Array): Promise<PutResult> {
    return this.runExclusive(async () => {
      const meta = await this.realm.call("putStart", u64be(plaintext.length));
      const windowBytes = readU32BE(meta, 0);
      // ── THE WINDOW BARRIER IS REAL, AND REMOVING IT DOES NOT MAKE PUT FASTER ────
      // This `await` is a full BARRIER: a window's every OFFER → STORE → ack settles before
      // the next window's first byte is encoded, so the wire goes idle for the encode+place
      // of window n+1, once per window. That much is measurable (50 MB to two WS holders
      // over a ~100 Mbit up link, RS(1,1), 24 MiB window, conns 2) in p2p-cli's four
      // CUMULATIVE timestamps: `drain` ~7–8.3 s lands BEFORE `queue` ~12–13.5 s — buffers
      // ran dry ~60% through the send — with `peak buffered` pinned at exactly 42.0 MB,
      // ~one window's ciphertext, i.e. in-flight bytes bounded by the WINDOW, not the link.
      //
      // It is still not the ceiling. TRIED AND REVERTED 2026-07-21: a pipelined guest, in
      // which putFeed started its window's encode+placement and awaited the PREVIOUS one,
      // so two windows were open and one was always queued behind the one draining. It
      // demonstrably worked — `drain` moved after `queue` (13.3 s vs 12.4 s) and `peak
      // buffered` went 42.0 → 67.5 MB, so the wire really did stop idling — and PUT came
      // out at 7.2 MB/s wire, dead centre of the 6.8–7.6 MB/s the barrier version gives.
      // Deeper queue, same drain rate: the bytes moved from "not yet encoded" into kernel
      // socket buffers, not onto the link. So the idle wire is a SYMPTOM of the receiver
      // not draining rather than a cause of lost throughput, and the iperf3 headroom
      // (106 Mbit on 4 flows) is not ours to claim by keeping the sender busy. The cost
      // was guest pipeline/ordering/latch complexity and ~2× window in guest heap, for a
      // measured zero. Don't re-implement it.
      //
      // Nor is the holder, as far as we can measure. `tests/bench-holder.mjs` prices the
      // ingest path (hash + descriptor verify + sibling check + 2 fs writes per block) with
      // the network taken out: at the live geometry on real disk it runs ~96 MB/s per
      // holder, ~48 MB/s for two co-resident holders on one cpu — about 7× the 7.2 MB/s the
      // live PUT actually demanded of that box. So the ~6 s settle tail seen on some runs is
      // not the holder chewing; a holder box would have to be ~7× slower than a dev machine
      // for ingest to bind. Untimed there: the WS receive path (unmasking, reassembly) on
      // the holder, the honest remaining unknown — run that bench ON a holder to close it.
      //
      // Which leaves the path/transport itself as the live suspect, and the sender-side
      // levers spent. Widening the window (`windowTargetBytes`) is the wrong lever twice
      // over: it only makes the idle gaps fewer, not shorter, and costs guest heap (peak
      // ≈ 3× window at RS(1,1)).
      //
      // Do NOT read p2p-cli's printed "MB/s upload" as evidence the link is saturated: it
      // divides ALL bulk bytes by (drain − encode), a span that by definition did not
      // carry them all whenever drain < queue, so it over-reports (15.1 MB/s printed vs
      // ≈7.8 actual).
      // ───────────────────────────────────────────────────────────────────────────
      // At least one window always goes in, so a zero-length file is still a PUT.
      for (let off = 0; ; off += windowBytes) {
        await this.realm.call("putWindow", plaintext.subarray(off, Math.min(off + windowBytes, plaintext.length)));
        if (off + windowBytes >= plaintext.length) break;
      }
      return decodePutResult(await this.realm.call("putFinish", NO_ARG));
    });
  }

  /** GET a file (§7), orchestrated in the guest, STREAMED so the guest reconstructs only
   *  one window of chunks at a time; the file is assembled here. getStart fetches the
   *  manifest and verifies every chunk descriptor once, keeping them in realm state;
   *  getNext then drains the file one window of plaintext at a time. */
  async get(manifestId: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    return this.runExclusive(async () => {
      const fileSize = readU64BE(await this.realm.call("getStart", concatBytes([manifestId, key])), 0);
      const out = new Uint8Array(fileSize);
      let written = 0;
      while (written < fileSize) {
        const part = await this.realm.call("getNext", NO_ARG);
        if (part.length === 0) throw new Error(`get: stream ended ${written}/${fileSize} bytes in`);
        out.set(part, written); written += part.length;
      }
      return out;
    });
  }

  /** Pre-warm the realm's codec + crypto caps with a throwaway encode/decode (no
   *  network, no store), so the first PUT/GET doesn't pay V8's cold-JIT tax on the
   *  latency-sensitive path — a cold first PUT otherwise encodes the whole file before
   *  the first byte hits the wire. Idempotent and optional: a client that will PUT/GET
   *  calls it once after connecting; a pure holder (which only ever serves via callSync)
   *  need not. */
  async warm(): Promise<void> {
    await this.runExclusive(() => this.realm.call("warm", NO_ARG));
  }

  /** Run one repair pass over every chunk this node holds a block of (§9),
   *  orchestrated in the guest via the realm's async `call()`. Returns the number of blocks
   *  (re-)placed. */
  async runRepair(): Promise<number> {
    return readU32BE(await this.runExclusive(() => this.realm.call("repair", NO_ARG)), 0);
  }

  /** Decayed reciprocity score this node holds for a peer (§13), read from the
   *  installed reputation handler — the same state the guest's verification-fetch
   *  observations write (the guest reaches it the same way, via MODULE_CALL). */
  score(peerPk: Uint8Array): number {
    const res = this.host.callHandler(this.names.reputation, encodeScoreReq(peerPk, this.now()));
    if (!res || res.length < 8) return 0;
    return new DataView(res.buffer, res.byteOffset, 8).getFloat64(0, true);
  }

  /** Share a file: seal K to a recipient's kernel key (§4.4). */
  shareKey(K: Uint8Array, recipientPk: Uint8Array): Uint8Array { return this.crypto.seal(K, recipientPk); }
  /** Open a sealed K addressed to this node. */
  openKey(sealed: Uint8Array): Uint8Array | null {
    return this.crypto.sealOpen(sealed, this.identity.publicKey, this.identity.privateKey);
  }

  /** Start the §9 self-healing loop: on a jittered interval, run one repair pass
   *  over every chunk this node holds a block of, re-placing any that have fallen
   *  below the low-water mark onto fresh cohort peers. This makes redundancy the
   *  node's own job — no button, no operator — as the spec intends.
   *
   *  Self-arming and overlap-free: the next tick is scheduled only after a pass
   *  finishes. Per-tick jitter (default ±50%) staggers holders so they don't all
   *  repair at once — the first timer to fire heals, the rest see the freshly
   *  placed blocks on their next have/want and stand down (repair is idempotent,
   *  §9). Long-lived holders are where the durable `m` leans (§8), so this is the
   *  loop to run on a server/console node; a low-uptime browser tab may skip it.
   *  Calling it twice is a no-op; stopRepairLoop()/close() stop it. */
  startRepairLoop(opts: { intervalMs?: number; jitter?: number; onPass?: (replaced: number) => void } = {}): void {
    if (this.repairLoopOn) return;
    this.repairLoopOn = true;
    const intervalMs = opts.intervalMs ?? 30_000;
    const jitter = opts.jitter ?? 0.5;
    const arm = () => {
      this.repairTimer = setTimeout(tick, intervalMs * (1 + Math.random() * jitter));
      (this.repairTimer as { unref?: () => void }).unref?.(); // never hold the process open
    };
    const tick = async () => {
      let replaced = 0;
      try { replaced = await this.runRepair(); }
      catch { /* a transient pass failure is fine — the next tick retries */ }
      if (!this.repairLoopOn) return;                          // stopped during the await
      opts.onPass?.(replaced);
      arm();
    };
    arm(); // first tick jittered too, so a cohort booted together doesn't sync up
  }

  /** Stop the §9 repair loop started by startRepairLoop(). */
  stopRepairLoop(): void {
    this.repairLoopOn = false;
    if (this.repairTimer) { clearTimeout(this.repairTimer); this.repairTimer = null; }
  }

  /** Tear down the guest realm + the transport, stopping the repair loop if
   *  running (test cleanup). */
  close(): void {
    this.closed = true; // reject any initiator operation raised after this cleanly, rather
                        // than letting it hit the freed realm — a diagnosable "storage node
                        // closed", not a crash. An operation already under way keeps its
                        // window calls (its stream is mid-flight); disposal waits for it.
    this.stopRepairLoop();
    // Close the transport first so any parked initiator round trip settles (times out as
    // unreachable) rather than hanging, and no new holder request arrives (so no callSync
    // fires after this — the holder path never suspends, so nothing of it is in flight).
    this.transport.close();
    // The realm may be parked mid-await on an initiator call (a repair pass caught by
    // close, waiting out a peer timeout); disposing it now would resume that computation
    // into a freed realm (QuickJS UseAfterFree). Defer disposal until the in-flight chain
    // settles. The realm is created eagerly at boot, so it always exists here.
    const disposeRealm = () => this.realm.dispose();
    this.inFlight.then(disposeRealm, disposeRealm);
  }

  // ── bootstrap wiring (§19) ──────────────────────────────────────────────
  private installHandlers(codecBytes: Uint8Array, reputationBytes: Uint8Array): void {
    // The two pure handlers import nothing and cannot call back into the host
    // (there is no kernel.call any more), so the structural sandbox guarantees
    // they reach neither disk nor network even if buggy (§17). The guest calls
    // them as installed handlers via MODULE_CALL, and computes block-ids itself
    // via the cap-bridge hash (CAP_HASH) — the codec no longer hashes, so there
    // is no crypto.hash service to plant on it any more.
    this.installOne(this.names.codec, codecBytes);
    this.installOne(this.names.reputation, reputationBytes);
  }

  private installOne(name: string, wasm: Uint8Array): void {
    // The node authors its own handlers, so it admits the bytes directly under the
    // same policy the bundle loader uses (§12.4) — installBundleModule → records.admit
    // runs the accept-all policy wired in create(). This replaces the old ceremony of
    // signing an install envelope to itself; there is no wire install path.
    this.host.installBundleModule(name, wasm, this.identity.publicKey);
  }

  /** True if both pure handlers are installed on the kernel (§19). */
  handlersInstalled(): boolean {
    return this.host.isRegistered(this.names.codec) && this.host.isRegistered(this.names.reputation);
  }
}
