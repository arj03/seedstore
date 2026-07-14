// StorageNode — a single storage peer running *on* the seedkernel (README §19
// bootstrap). It is now a THIN host: the entire storage protocol lives in the
// confined guest (host/tier2-guest.js), run inside seedkernel's safe-js realms
// over the generic capability bridge. StorageNode only:
//
//   - loads kernel.wasm + bootstrap.wasm and wires signature + installer
//   - registers the storage bridges (crypto.* no-cap; store/net/clock/rand
//     cap-gated) and installs the pure codec + reputation handlers
//   - runs the guest's *initiator* entrypoints (put / get / repair) in an async
//     realm (it fans out over net and parks mid-await, §2.1)
//   - serves the guest's *holder* entrypoint (handle: HAVE / OFFER / STORE /
//     FETCH) from a SYNC realm, so it can answer a peer's request while its own
//     initiator realm is parked mid-await — the runtime split (§2.1)
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
import { KernelHost, referencePolicy, CURRENT_VERSION } from "seedkernel-wasm/browser";
import { createCapBridge, capPreamble } from "seedkernel-wasm/cap-bridge";
// The generic zero-authority sandbox lives in the kernel as `safe-js`: an async
// realm for the initiator (put/get/repair) and a sync realm for the holder
// (handle), so the holder can serve while the initiator is parked mid-await.
import {
  createSafeRealm, createSyncSafeRealm,
  type SafeRealm, type SyncSafeRealm, type SafeRealmBridge,
} from "seedkernel-wasm/safe-js";

import type { Sodium } from "./sodium.js";
import type { Network, PeerId } from "seedkernel-wasm/net";
import { Transport } from "seedkernel-wasm/net";
import { MemoryFs, type Fs } from "seedkernel-wasm/fs";
import { DEFAULT_QUOTA_BYTES, type BlobStore } from "./store-local.js";
import { FsBlobStore } from "./store-fs.js";
import { Crypto } from "./crypto.js";
import { storageNames, type StorageNames } from "./names.js";
import { registerStorageBridges } from "./bridges.js";
import { type Identity, type StorageConfig, defaultConfig } from "./core.js";
import { STORAGE_SIGN_SCOPE, guestSignPrefix } from "./manifest.js";
import { toHex, fromHex, readU32BE, writeU32BE, concatBytes } from "./util.js";

// Small big-endian encoders for the windowed PUT/GET host seam (util.ts has the u32
// primitives; these frame the length-prefixed arguments the streaming entries read).
function u32be(n: number): Uint8Array { const b = new Uint8Array(4); writeU32BE(b, 0, n); return b; }
function u64be(n: number): Uint8Array { const b = new Uint8Array(8); writeU32BE(b, 0, Math.floor(n / 0x100000000)); writeU32BE(b, 4, n >>> 0); return b; }
function readU64BE(b: Uint8Array, o: number): number { return readU32BE(b, o) * 0x100000000 + readU32BE(b, o + 4); }

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
  kernelBytes: Uint8Array;
  bootstrapBytes: Uint8Array;
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
   *  the holder realm is rebuilt — FsBlobStore itself reads used-bytes live for the
   *  mirror-image reason (it can't see the guest's `fs.*` writes). */
  store?: BlobStore;
  quota?: number;
  clock?: () => number;
  /** net.send timeout — how long before a peer is treated as unreachable (§8). */
  timeoutMs?: number;
  /** The guest signing scope (README §16). Descriptors are signed/verified over
   *  `DOMAIN_guest ‖ scope ‖ core`, so every node in one cohort must share it (a
   *  descriptor one signs verifies on another). Defaults to the in-process
   *  `STORAGE_SIGN_SCOPE` (zero author); a cohort that shares a bundle author — the
   *  shell-run / holder-guest cross-path tests — passes `storageSignScope(author)` so
   *  its StorageNodes verify what a shell running that bundle signs. */
  signScope?: Uint8Array;
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
  private readonly signScope: Uint8Array;
  private installSeq = 0;
  private repairLoopOn = false;
  private repairTimer: ReturnType<typeof setTimeout> | null = null;
  // The last initiator-realm call (put/get/repair), so close() can await an in-flight one
  // before disposing the realm. The initiator serializes calls — the Asyncify bridge is
  // module-global, so two never overlap — so one handle is enough.
  private inFlight: Promise<unknown> = Promise.resolve();

  // Two realms run the one guest: an async initiator (put/get/repair) created
  // lazily on first use, and a sync holder (handle) created eagerly at boot so a
  // node serves the moment it is connected. Caching the initiator's creation
  // *promise* (not the settled realm) means two concurrent first calls await one
  // realm — a second async realm would leak and the two would overlap host calls,
  // the §2.1 Asyncify module-global hard-abort.
  private initiator: Promise<SafeRealm> | null = null;
  private holder!: SyncSafeRealm;

  private constructor(opts: StorageNodeOptions, host: KernelHost, identity: Identity) {
    this.sodium = opts.sodium;
    this.host = host;
    this.identity = identity;
    this.peerId = toHex(identity.publicKey);
    this.guestSource = opts.guestSource;
    this.signScope = opts.signScope ?? STORAGE_SIGN_SCOPE;
    // Derive replicas / lowWater / smallMaxBlocks from the *caller's* k & m, then
    // let any explicit field in opts.config override — otherwise overriding k/m
    // alone would leave those derived from the (2,2) default (e.g. an unreachable
    // lowWater > n on the demo's RS(1,1)).
    const c = opts.config;
    this.config = { ...defaultConfig(c?.k, c?.m, c?.blockSize), ...c };
    this.clockFn = opts.clock ?? (() => Date.now());
    this.crypto = new Crypto(opts.sodium);
    this.fs = opts.fs ?? new MemoryFs();
    this.store = opts.store ?? new FsBlobStore(this.fs, opts.quota ?? DEFAULT_QUOTA_BYTES);
    this.names = storageNames(host);
    this.transport = new Transport(this.peerId, opts.network, opts.timeoutMs ?? 200);
  }

  /** Boot a storage node: load the kernel, wire signature + installer, register
   *  bridges, install the codec + reputation handlers, then build the sync holder
   *  realm and route incoming requests to the guest's `handle` (§19, §2.1). */
  static async create(opts: StorageNodeOptions): Promise<StorageNode> {
    await opts.sodium.ready;
    const host = await KernelHost.load(
      opts.kernelBytes as BufferSource, opts.bootstrapBytes as BufferSource, opts.sodium as never,
    );
    host.registerSignature(host.deriveBootstrapName("signature"));
    host.registerInstaller(
      host.deriveBootstrapName("install"),
      host.deriveBootstrapName("installer.lookup"),
      host.deriveBootstrapName("installer.caps_of"),
    );
    // Single-deployment reference posture: accept audited handler bytes and
    // acknowledge their declared caps. A real deployment narrows this to a
    // content-hash allowlist + closed author set (§19).
    host.setApproveInstall(referencePolicy(host, () => true, () => true));

    const identity = opts.identity ?? (() => {
      const kp = opts.sodium.crypto_sign_keypair();
      return { publicKey: kp.publicKey, privateKey: kp.privateKey };
    })();

    const node = new StorageNode(opts, host, identity);
    node.registerBridges();
    node.installHandlers(opts.codecBytes, opts.reputationBytes);

    // The holder side, confined in a SYNC realm: every incoming request is routed
    // to the guest's `handle`, which answers from local fs + crypto without
    // yielding (no net round trip), so it can respond while this node's own async
    // initiator realm is parked mid-await (the runtime split, §2.1).
    node.holder = await createSyncSafeRealm({ source: node.guestFullSource(), bridge: node.buildBridge() });
    node.transport.onRequest((_from, type, payload) => {
      const arg = new Uint8Array(1 + payload.length);
      arg[0] = type & 0xff;
      arg.set(payload, 1);
      return node.holder.call("handle", arg);
    });
    return node;
  }

  // ── the guest runtime (initiator realm + bridge + injected config) ──────────
  /** The generic cap-bridge: kernel primitives only, no storage vocabulary.
   *  codec/reputation are reached as installed handlers via host.callHandler; net
   *  via the Transport; fs over the node's raw backend. Both realms share one
   *  bridge — the holder never calls net ops, so the DUAL bridge's sync arms
   *  suffice for the sync realm. */
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

  /** The `const APP = {…};` block the guest reads its config + module names from —
   *  storage's app-specific constants, injected the same way the CAP op preamble
   *  is. The seedkernel shell builds the byte-identical block from a bundle
   *  manifest's `config` field. */
  private appPreamble(): string {
    const c = this.config;
    const app = {
      k: c.k, m: c.m, blockSize: c.blockSize,
      replicas: c.replicas, lowWater: c.lowWater, smallMaxBlocks: c.smallMaxBlocks,
      // The holder side's byte budget (§14) — the same quota FsBlobStore enforces,
      // surfaced so the confined `handle` path admits exactly as the host store does.
      quota: this.store.stat().quota,
      // Transport/operator policy (like quota, not author-signed): the per-message
      // batch cap and the fan-out windows the guest splits/pipelines OFFER/STORE/
      // FETCH under, so it batches byte-for-byte as the spec intends.
      maxMessageBytes: c.maxMessageBytes,
      putConcurrency: c.putConcurrency, getConcurrency: c.getConcurrency,
      // Streamed PUT/GET window (§3): undefined ⇒ the guest's 4 MiB default. Bigger
      // windows amortise the per-window OFFER→STORE→ack barrier on a fat/low-loss link.
      windowTargetBytes: c.windowTargetBytes,
      codecName: toHex(this.names.codec), repName: toHex(this.names.reputation),
      // The scoped-signature prefix `DOMAIN_guest ‖ scope` the guest prepends before
      // CAP_VERIFY (README §16) — the same bytes the bridge's SIGN op prepends, so the
      // two paths agree. The seedkernel shell injects the byte-identical value from the
      // admitted bundle's (author, app); here it comes from this node's scope.
      signPrefix: toHex(guestSignPrefix(this.signScope)),
    };
    return `const APP = ${JSON.stringify(app)};\n`;
  }

  /** The full guest source: the generic CAP op catalog + the injected APP config +
   *  the orchestration program. */
  private guestFullSource(): string {
    return capPreamble() + this.appPreamble() + this.guestSource;
  }

  /** The async initiator realm (put/get/repair), created lazily on first use. */
  private initiatorRealm(): Promise<SafeRealm> {
    if (!this.initiator) {
      this.initiator = createSafeRealm({ source: this.guestFullSource(), bridge: this.buildBridge(), memoryLimitBytes: this.config.realmMemoryBytes });
    }
    return this.initiator;
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
  /** Run one initiator entrypoint in the async realm, recording it as in-flight so
   *  close() can await it before disposing the realm (disposing while a call is parked
   *  mid-await — a repair pass caught by close, waiting out an unreachable peer's timeout
   *  — would resume into a freed realm: a QuickJS UseAfterFree abort). */
  private async runInitiator(entry: string, payload: Uint8Array): Promise<Uint8Array> {
    const realm = await this.initiatorRealm();
    const p = realm.call(entry, payload);
    this.inFlight = p.then(() => {}, () => {});
    return p;
  }

  /** PUT a file (§6), orchestrated inside the initiator realm, STREAMED so the
   *  confined guest heap never holds the whole file (README §3): the plaintext is
   *  fed one chunk-aligned window at a time and each window's ciphertext is placed
   *  and dropped before the next is sent. putStart mints K and reports the window
   *  size; putWindow/putSmall place each window and return its chunk descriptors;
   *  putManifest seals the manifest over them. The result is assembled here. */
  async put(plaintext: Uint8Array): Promise<PutResult> {
    const fileSize = plaintext.length;
    const meta = await this.runInitiator("putStart", u64be(fileSize));
    const key = meta.slice(0, 32);
    const replicated = meta[32] === 1;
    const windowBytes = readU32BE(meta, 33);

    const descriptors: Uint8Array[] = [];
    const blockIds: Uint8Array[] = [];
    let replicasLanded = 0, replicasIntended = 0;
    // Decode one window's result:
    //   [descCount u32]{[len u32][descriptor]}[idCount u32]{id 32}[placed u32][intended u32]
    const collect = (w: Uint8Array) => {
      let o = 0;
      const dc = readU32BE(w, o); o += 4;
      for (let i = 0; i < dc; i++) { const l = readU32BE(w, o); o += 4; descriptors.push(w.slice(o, o + l)); o += l; }
      const ic = readU32BE(w, o); o += 4;
      for (let i = 0; i < ic; i++) { blockIds.push(w.slice(o, o + 32)); o += 32; }
      replicasLanded += readU32BE(w, o); o += 4;
      replicasIntended += readU32BE(w, o); o += 4;
    };

    if (replicated) {
      collect(await this.runInitiator("putSmall", concatBytes([key, plaintext])));
    } else {
      for (let off = 0; off < fileSize; off += windowBytes) {
        const slice = plaintext.subarray(off, Math.min(off + windowBytes, fileSize));
        collect(await this.runInitiator("putWindow", concatBytes([key, u64be(off), slice])));
      }
    }

    const manParts: Uint8Array[] = [key, u64be(fileSize), u32be(descriptors.length)];
    for (const d of descriptors) manParts.push(u32be(d.length), d);
    const manifestId = await this.runInitiator("putManifest", concatBytes(manParts));
    blockIds.push(manifestId);
    return { manifestId, replicated, chunkCount: descriptors.length, key, blockIds, replicasLanded, replicasIntended };
  }

  /** GET a file (§7), orchestrated inside the initiator realm, STREAMED so the guest
   *  reconstructs only one window of chunks at a time; the file is assembled here.
   *  getStart fetches + verifies the manifest and returns the file size, a window
   *  granularity, and every chunk descriptor; getChunk reconstructs each window. */
  async get(manifestId: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    const start = await this.runInitiator("getStart", concatBytes([manifestId, key]));
    const fileSize = readU64BE(start, 0);
    const windowChunks = readU32BE(start, 8);
    const chunkCount = readU32BE(start, 12);
    let o = 16;
    const envs: Uint8Array[] = [];
    for (let i = 0; i < chunkCount; i++) { const l = readU32BE(start, o); o += 4; envs.push(start.slice(o, o + l)); o += l; }

    const out = new Uint8Array(fileSize);
    let written = 0;
    for (let cs = 0; cs < chunkCount; cs += windowChunks) {
      const windowEnvs = envs.slice(cs, cs + windowChunks);
      const parts: Uint8Array[] = [key, u32be(cs), u64be(fileSize), u32be(windowEnvs.length)];
      for (const e of windowEnvs) parts.push(u32be(e.length), e);
      const chunk = await this.runInitiator("getChunk", concatBytes(parts));
      out.set(chunk, written); written += chunk.length;
    }
    return out;
  }

  /** Pre-warm the initiator realm's codec + crypto caps with a throwaway
   *  encode/decode (no network, no store), so the first PUT/GET doesn't pay V8's
   *  cold-JIT tax on the latency-sensitive path — a cold first PUT otherwise encodes
   *  the whole file before the first byte hits the wire. Also boots the lazily-created
   *  initiator realm now. Idempotent and optional: a client that will PUT/GET calls it
   *  once after connecting; a pure holder (which serves from the sync realm) need not. */
  async warm(): Promise<void> {
    await this.runInitiator("warm", new Uint8Array(0));
  }

  /** Run one repair pass over every chunk this node holds a block of (§9),
   *  orchestrated inside the initiator realm. Returns the number of blocks
   *  (re-)placed. */
  async runRepair(): Promise<number> {
    return readU32BE(await this.runInitiator("repair", new Uint8Array(0)), 0);
  }

  /** Decayed reciprocity score this node holds for a peer (§13), read from the
   *  installed reputation handler — the same state the guest's verification-fetch
   *  observations write (the guest reaches it the same way, via MODULE_CALL). */
  score(peerPk: Uint8Array): number {
    const now = this.now();
    const req = new Uint8Array(41);
    req[0] = 2; // OP_SCORE (reputation handler ABI, assembly/reputation/index.ts)
    req.set(peerPk, 1);
    writeU32BE(req, 33, Math.floor(now / 0x100000000));
    writeU32BE(req, 37, now >>> 0);
    const res = this.host.callHandler(this.names.reputation, req);
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

  /** Tear down both guest realms + the transport, stopping the repair loop if
   *  running (test cleanup). */
  close(): void {
    this.stopRepairLoop();
    // Close the transport first so any parked initiator round trip settles (times out as
    // unreachable) rather than hanging, and no new holder request arrives.
    this.transport.close();
    // The sync holder realm never suspends (local fs + crypto only), so it is safe to
    // free at once. The async initiator realm may be parked mid-await (a repair pass
    // caught by close, waiting out a peer timeout); disposing it now would resume that
    // computation into a freed realm (QuickJS UseAfterFree). Defer its disposal until the
    // in-flight call settles.
    this.holder?.dispose();
    const disposeInitiator = () => { void this.initiator?.then((r) => r.dispose(), () => { /* creation failed — nothing to free */ }); };
    this.inFlight.then(disposeInitiator, disposeInitiator);
  }

  // ── bootstrap wiring (§19) ──────────────────────────────────────────────
  private registerBridges(): void {
    // The only storage-named host service: the no-cap crypto.hash the installed
    // codec WASM calls for block-ids (§16). The guest reaches net/fs/clock/rand
    // through the generic cap-bridge (buildBridge), not through storage bridges.
    registerStorageBridges(this.host, this.names, { crypto: this.crypto });
  }

  private installHandlers(codecBytes: Uint8Array, reputationBytes: Uint8Array): void {
    // The two pure handlers declare no capabilities, so the structural sandbox
    // guarantees they reach neither disk nor network even if buggy (§17). The
    // guest calls them as installed handlers via MODULE_CALL.
    this.installOne(this.names.codec, codecBytes);
    this.installOne(this.names.reputation, reputationBytes);
    // Plant the crypto.hash name on the installed codec so its block-id op can
    // call the bridge (the same configure the host bakes in at install, §16).
    const cfg = new Uint8Array(1 + this.names.cryptoHash.length);
    cfg[0] = this.names.cryptoHash.length; cfg.set(this.names.cryptoHash, 1);
    this.host.callDynamicExport(this.names.codec, "configure", cfg);
  }

  private installOne(name: Uint8Array, wasm: Uint8Array): void {
    const seq = ++this.installSeq;
    const payload = this.host.encodeInstallPayload(seq, name, [], wasm);
    this.host.dispatch(this.host.wrapAndEncode(
      this.identity.privateKey, this.identity.publicKey, CURRENT_VERSION, this.host.deriveBootstrapName("install"), payload,
    ));
  }

  /** True if both pure handlers are installed on the kernel (§19). */
  handlersInstalled(): boolean {
    return this.host.isRegistered(this.names.codec) && this.host.isRegistered(this.names.reputation);
  }

  pubkeyOf(peerId: PeerId): Uint8Array { return fromHex(peerId); }
}
