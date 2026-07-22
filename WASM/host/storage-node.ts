// StorageNode — a single storage peer running *on* the seedkernel (README §19
// bootstrap). It is now a THIN host: the entire storage protocol lives in the
// confined guest (host/tier2-guest.js), run inside ONE seedkernel safe-js realm
// over the generic capability bridge. StorageNode stands up the shared
// platform-neutral `createShell()` from seedkernel (the §12.9 move) and loads the
// seedstore signed bundle — the ONE install path (§12.4).
//
// The raw-bind `host.installWasmHandler` path is gone: handlers arrive via the
// verified bundle loader, under the admission policy, and the kernel names are
// derived from the manifest author — exactly as a shell-run node does it. The
// `ZERO_AUTHOR` default is gone: the signing scope comes from the bundle's
// verified author.
//
// StorageNode only:
//   - creates the platform seam (fs, network, freshnessStore, identity, sodium)
//   - calls createShell() + loadBundleBlob() to wire the shared shell
//   - runs the guest's *initiator* entrypoints (put / get / repair) via
//     shell.runGuest()
//   - serves the guest's *holder* entrypoint via shell.serve()

import type { Network, PeerId, Transport as ITransport } from "seedkernel-wasm/net";
import type { Fs } from "seedkernel-wasm/fs";
import { MemoryFs } from "seedkernel-wasm/fs";
import { FsBlobView, type BlobView } from "./store-view.js";
import { Crypto } from "./crypto.js";
import {
  type Identity, type StorageConfig, defaultConfig, assertStorageConfig, DEFAULT_QUOTA_BYTES,
} from "./core.js";
import { STORAGE_APP, storageSignScope } from "./manifest.js";
import { encodeScoreReq } from "./reputation-core.js";
import { toHex, readU32BE, readU64BE, writeU64BE, concatBytes } from "./util.js";
import {
  createShell, openPolicy, type Shell, type KernelTable,
} from "seedkernel-wasm/shell-core";
import { FreshnessMarks, kernelNameFor, type LoadedBundle } from "seedkernel-wasm/bundle";
import type { Sodium } from "./sodium.js";

const NO_ARG = new Uint8Array(0);

function u64be(n: number): Uint8Array { const b = new Uint8Array(8); writeU64BE(b, 0, n); return b; }

/** Decode the guest's PUT result — the single result format every driver reads
 *  (`encodePutResult` in tier2-guest.orchestration.js). */
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

export interface PutResult {
  manifestId: Uint8Array;
  key: Uint8Array;
  chunkCount: number;
  replicated: boolean;
  blockIds: Uint8Array[];
  replicasLanded: number;
  replicasIntended: number;
}

export interface StorageNodeOptions {
  network: Network;
  sodium: Sodium;
  /** The signed seedstore bundle blob (seedstore.skb). The ONE install path:
   *   the shared shell loads it through the §12.4 bundle loader — verify
   *   manifest, govern policy, integrity-check modules, install handlers —
   *   exactly as a shell-run node does. Handlers are NOT raw-bound. */
  bundleBlob: Uint8Array;
  identity?: Identity;
  config?: Partial<StorageConfig>;
  fs?: Fs;
  store?: BlobView;
  quota?: number;
  clock?: () => number;
  timeoutMs?: number;
}

export class StorageNode {
  readonly peerId: PeerId;
  readonly identity: Identity;
  readonly transport: ITransport;
  readonly fs: Fs;
  readonly store: BlobView;
  readonly quota: number;
  readonly crypto: Crypto;
  readonly sodium: Sodium;
  readonly config: StorageConfig;
  /** The handler table, exposed through KernelTable (callHandler + isBound)
   *   without installWasmHandler — the bind is solely the bundle loader's job. */
  readonly host: KernelTable;

  private readonly shell: Shell;
  private readonly clockFn: () => number;
  private readonly signAuthor: Uint8Array;
  /** The cohort's signing scope (§16), derived from the verified bundle author.
   *   Exposed so host-side callers can produce descriptors that the guest's
   *   holder path will verify — signDescriptor() with this scope as the 5th
   *   argument matches what the guest's verifyPrefix checks. */
  readonly signScope: Uint8Array;
  private readonly modules: { codec: string; reputation: string };
  private repairLoopOn = false;
  private repairTimer: ReturnType<typeof setTimeout> | null = null;
  private inFlight: Promise<unknown> = Promise.resolve();
  private closed = false;

  private constructor(
    opts: StorageNodeOptions,
    shell: Shell,
    identity: Identity,
    loaded: LoadedBundle,
  ) {
    this.sodium = opts.sodium;
    this.shell = shell;
    this.host = shell.host;
    this.identity = identity;
    this.peerId = toHex(identity.publicKey);
    this.fs = opts.fs ?? new MemoryFs();
    this.quota = opts.quota ?? DEFAULT_QUOTA_BYTES;
    this.store = opts.store ?? new FsBlobView(this.fs);
    this.clockFn = opts.clock ?? (() => Date.now());
    this.crypto = new Crypto(opts.sodium);
    this.transport = shell.transport;

    // Derive signing scope and kernel names from the verified bundle author —
    // the same derivation a shell-run node uses.
    this.signAuthor = loaded.author;
    this.signScope = storageSignScope(this.signAuthor);
    this.modules = {
      codec: kernelNameFor(this.signAuthor, STORAGE_APP, "codec"),
      reputation: kernelNameFor(this.signAuthor, STORAGE_APP, "reputation"),
    };

    // `this.config` is the geometry a caller can inspect (p2p-cli reads config.k/.m for
    // its wire estimate), so it must equal what the guest ACTUALLY runs: the bundle's
    // signed guest.config with the operator override merged OVER it — the same precedence
    // shell-core applies when it builds the guest APP. Reconstructing from defaultConfig()
    // alone would only agree when the override happened to name every field. guest.config
    // is untyped JSON (Record<string,string|number>), so coerce it to the config shape at
    // this boundary — the bundle producer writes the numeric geometry.
    const override = opts.config;
    assertStorageConfig(override);
    const signed = (loaded.manifest.guest?.config ?? {}) as unknown as Partial<StorageConfig>;
    const merged: Partial<StorageConfig> = { ...signed, ...override };
    this.config = { ...defaultConfig(merged.k, merged.m, merged.blockSize), ...merged };
  }

  /** Boot a storage node: stand up the shared shell, load the signed seedstore
   *   bundle, and wire the holder realm. The raw-bind install path is gone —
   *   handlers arrive solely via the §12.4 bundle loader. */
  static async create(opts: StorageNodeOptions): Promise<StorageNode> {
    await opts.sodium.ready;

    const identity = opts.identity ?? (() => {
      const kp = opts.sodium.crypto_sign_keypair();
      return { publicKey: kp.publicKey, privateKey: kp.privateKey };
    })();

    const fs = opts.fs ?? new MemoryFs();
    const network = opts.network;

    // realmMemoryBytes is host-only (the QuickJS heap bound) — split it out of the
    // config that becomes the guest's APP, and pass it to the shell as the realm limit.
    // The rest of opts.config is the operator override merged OVER the bundle's signed
    // guest.config; quota is operator policy (§14), never author-signed, added here.
    const { realmMemoryBytes, ...guestOverride } = opts.config ?? {};

    opts = { ...opts, fs }; // share the one fs instance with the constructor below

    const shell = createShell({
      platform: {
        sodium: opts.sodium,
        identity,
        fs,
        freshnessStore: new FreshnessMarks(),
        network,
        now: opts.clock,
      },
      // Open admission: a storage node loads exactly the one signed bundle its operator
      // handed it (opts.bundleBlob) — the choice of bundle is the trust decision, so
      // there is no author allow-list to clear (the manifest signature + module hashes
      // are still verified by loadBundleBlob). See seedkernel policy.openPolicy.
      policy: openPolicy(),
      timeoutMs: opts.timeoutMs,
      config: { ...guestOverride, quota: opts.quota ?? DEFAULT_QUOTA_BYTES },
      realmMemoryBytes,
    });

    const loaded = await shell.loadBundleBlob(opts.bundleBlob);
    await shell.serve();

    return new StorageNode(opts, shell, identity, loaded);
  }

  // ── cohort membership (§5.1) ───────────────────────────────────────────
  now(): number { return this.clockFn(); }
  cohortPeers(): PeerId[] { return [...this.shell.peers]; }

  addPeer(peerId: PeerId): void {
    this.shell.addPeer(peerId);
  }
  removePeer(peerId: PeerId): void {
    this.shell.removePeer(peerId);
  }

  static connect(a: StorageNode, b: StorageNode): void {
    a.addPeer(b.peerId);
    b.addPeer(a.peerId);
  }

  // ── PUT / GET / repair / share — all run through shell.runGuest() ──────
  private runExclusive<T>(body: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(new Error("storage node closed"));
    const p = this.inFlight.then(body);
    this.inFlight = p.then(() => {}, () => {});
    return p;
  }

  /** PUT a file (§6), orchestrated in the guest, STREAMED. */
  async put(plaintext: Uint8Array): Promise<PutResult> {
    return this.runExclusive(async () => {
      const meta = await this.shell.runGuest("putStart", u64be(plaintext.length));
      const windowBytes = readU32BE(meta, 0);
      for (let off = 0; ; off += windowBytes) {
        await this.shell.runGuest("putWindow", plaintext.subarray(off, Math.min(off + windowBytes, plaintext.length)));
        if (off + windowBytes >= plaintext.length) break;
      }
      return decodePutResult(await this.shell.runGuest("putFinish", NO_ARG));
    });
  }

  /** GET a file (§7), orchestrated in the guest, STREAMED. */
  async get(manifestId: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    return this.runExclusive(async () => {
      const fileSize = readU64BE(await this.shell.runGuest("getStart", concatBytes([manifestId, key])), 0);
      const out = new Uint8Array(fileSize);
      let written = 0;
      while (written < fileSize) {
        const part = await this.shell.runGuest("getNext", NO_ARG);
        if (part.length === 0) throw new Error(`get: stream ended ${written}/${fileSize} bytes in`);
        out.set(part, written); written += part.length;
      }
      return out;
    });
  }

  /** Pre-warm the realm's codec + crypto caps. */
  async warm(): Promise<void> {
    await this.runExclusive(() => this.shell.runGuest("warm", NO_ARG));
  }

  /** Run one repair pass over every chunk this node holds a block of (§9). */
  async runRepair(): Promise<number> {
    return readU32BE(await this.runExclusive(() => this.shell.runGuest("repair", NO_ARG)), 0);
  }

  /** Decayed reciprocity score this node holds for a peer (§13). */
  score(peerPk: Uint8Array): number {
    const res = this.host.callHandler(this.modules.reputation, encodeScoreReq(peerPk, this.now()));
    if (!res || res.length < 8) return 0;
    return new DataView(res.buffer, res.byteOffset, 8).getFloat64(0, true);
  }

  /** Share a file: seal K to a recipient's kernel key (§4.4). */
  shareKey(K: Uint8Array, recipientPk: Uint8Array): Uint8Array { return this.crypto.seal(K, recipientPk); }
  /** Open a sealed K addressed to this node. */
  openKey(sealed: Uint8Array): Uint8Array | null {
    return this.crypto.sealOpen(sealed, this.identity.publicKey, this.identity.privateKey);
  }

  // ── repair loop (§9) ──────────────────────────────────────────────────
  startRepairLoop(opts: { intervalMs?: number; jitter?: number; onPass?: (replaced: number) => void } = {}): void {
    if (this.repairLoopOn) return;
    this.repairLoopOn = true;
    const intervalMs = opts.intervalMs ?? 30_000;
    const jitter = opts.jitter ?? 0.5;
    const arm = () => {
      this.repairTimer = setTimeout(tick, intervalMs * (1 + Math.random() * jitter));
      (this.repairTimer as { unref?: () => void }).unref?.();
    };
    const tick = async () => {
      let replaced = 0;
      try { replaced = await this.runRepair(); }
      catch { /* transient pass failure — next tick retries */ }
      if (!this.repairLoopOn) return;
      opts.onPass?.(replaced);
      arm();
    };
    arm();
  }

  stopRepairLoop(): void {
    this.repairLoopOn = false;
    if (this.repairTimer) { clearTimeout(this.repairTimer); this.repairTimer = null; }
  }

  close(): void {
    // Reject any initiator operation raised after this cleanly (runExclusive checks
    // `closed`) rather than letting it reach a torn-down realm. shell.close() closes the
    // transport so any parked round trip settles, then defers realm disposal until its
    // in-flight chain drains — so a repair pass caught mid-await here is never resumed
    // into a freed realm (a QuickJS use-after-free). An in-flight stream keeps running.
    this.closed = true;
    this.stopRepairLoop();
    this.shell.close();
  }

  /** True if both pure handlers are installed on the kernel (§19). */
  handlersInstalled(): boolean {
    return this.host.isBound(this.modules.codec) && this.host.isBound(this.modules.reputation);
  }
}
