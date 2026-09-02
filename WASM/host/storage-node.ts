// StorageNode — a single storage peer running *on* the seedkernel (README §19
// bootstrap). A THIN host: the entire storage protocol lives in the confined
// guest (host/tier2-guest.js), run in one seedkernel safe-js realm over the
// generic guest seam. Boots the shared `bootShell()` and loads the signed
// bundles (§12.4) — first the transport bundle (§12.6), then the seedstore one.
// Modules arrive only via the verified bundle loader, never raw-bound.
//
// A caller that already stands a shell up (a WebRTC/WS node) passes the whole
// `runtime` in; StorageNode then loads only the seedstore bundle on it.

import type { Fs } from "seedkernel-wasm/fs";
import { writeOp, OpArgs } from "seedkernel-wasm/op-frame";
import { TRANSPORT_SERVICE } from "seedkernel-wasm/transport-bundle";
import { MemoryFs } from "seedkernel-wasm/fs-memory";
import { FsBlobView, type BlobView } from "./store-view.js";
import { Crypto } from "./crypto.js";
import {
  type Identity, type PeerId, type StorageConfig, defaultConfig, assertStorageConfig, normaliseConfig, DEFAULT_QUOTA_BYTES,
  TEST_BLOCK_SIZE,
} from "./core.js";
import { Op, decodeStats, type RequestStats } from "./protocol.js";
import { toHex, fromHex, readU32BE, readU64BE, concatBytes } from "./util.js";
import type { ChannelFactoryLike } from "./loopback.js";
import type { Sodium } from "./sodium.js";
import {
  bootShell, type AppHandle, type BootResult, type RealmFactory, type Shell,
} from "seedkernel-wasm/shell-core";

const NO_ARG = new Uint8Array(0);
/** "no contact secret" on the wire: the transport reads all-zero as an open peer. */
const ZERO32 = new Uint8Array(32);
type Transport = NonNullable<BootResult["transport"]>;

// ── the host's door into the transport bundle (seedkernel §12.10) ────────────
//
// Peers and cohort readiness are the transport GUEST's — its address book dies with
// its realm — so they are claim calls on the id that bundle claims, through the same
// door a co-resident guest reaches with `host.call`. `OpArgs` is that bundle's own
// framing, which the shell passes through and never reads.

/** One op to the transport, with the shell's caller-id prefix. Throws when nothing
 *  claims the id — a node with no transport bundle, which is a legitimate
 *  configuration and so has to be an answer rather than a promise that never settles. */
function transportOp(shell: Pick<Shell, "call">, args: OpArgs): Promise<Uint8Array> {
  const answer = shell.call(TRANSPORT_SERVICE, args.build());
  if (!answer) throw new Error(`transport: no bundle claims ${TRANSPORT_SERVICE}`);
  return answer;
}

/** Teach this node's transport one peer: where to reach it, and the contact secret
 *  THAT peer gates its door with (absent ⇒ an open peer). Straight into the guest's
 *  own address book — nothing is retained host-side — so a node whose transport is
 *  replaced must be taught its peers again. */
export function netAddr(
  shell: Pick<Shell, "call">, peerId: PeerId, dest: string, contactSecret?: Uint8Array,
): Promise<Uint8Array> {
  return transportOp(shell, new OpArgs("addr")
    .blob(fromHex(peerId))
    .blob(contactSecret ?? ZERO32)
    .text(dest));
}

/** Rotate this node's inbound contact secret without replacing the transport. Omit it
 *  to make the node open — all-zero, spelled the same way `netAddr` spells an open
 *  peer. Contact policy belongs to the signed transport guest, so this is an ordinary
 *  local-service call rather than a driver option. */
export function netContact(
  shell: Pick<Shell, "call">, contactSecret?: Uint8Array,
): Promise<Uint8Array> {
  return transportOp(shell, new OpArgs("contact").blob(contactSecret ?? ZERO32));
}

/** Dial every peer the transport knows of and resolve once each authenticated, or the
 *  deadline passes. Best-effort by construction: the op settles either way, so it
 *  bounds a boot rather than deciding anything — read `netPeers` for what landed. */
export function netReady(shell: Pick<Shell, "call">, timeoutMs = 5000): Promise<Uint8Array> {
  return transportOp(shell, new OpArgs("ready").u32(timeoutMs));
}

/** The peers this node holds at least one authenticated link to. A fact about links,
 *  and links are the guest's, so it is a question rather than a field. */
export async function netPeers(shell: Pick<Shell, "call">): Promise<PeerId[]> {
  const bytes = await transportOp(shell, new OpArgs("peers"));
  const out: PeerId[] = [];
  for (let off = 0; off + 32 <= bytes.length; off += 32) out.push(toHex(bytes.slice(off, off + 32)));
  return out;
}

/** Decode the guest's PUT result — the single result format every driver reads
 *  (`encodePutResult` in tier2-guest.orchestration.js):
 *    [K 32][chunkCount u32][placed u32][intended u32][rootLen u32][root ...][idCount u32]{id 32} */
function decodePutResult(r: Uint8Array): PutResult {
  const rootLen = readU32BE(r, 44);
  const tail = 48 + rootLen;
  const blockIds: Uint8Array[] = [];
  const idCount = readU32BE(r, tail);
  for (let i = 0; i < idCount; i++) blockIds.push(r.slice(tail + 4 + i * 32, tail + 4 + (i + 1) * 32));
  return {
    key: r.slice(0, 32),
    root: r.slice(48, tail),
    chunkCount: readU32BE(r, 32),
    replicasLanded: readU32BE(r, 36),
    replicasIntended: readU32BE(r, 40),
    blockIds,
  };
}

export interface PutResult {
  /** The file's ROOT DESCRIPTOR (§4.3) — the signed envelope a reader is handed, which
   *  replaced the old 32-byte manifest_id when the manifest stopped being an object. It
   *  is variable-length: a one-chunk file's root is that chunk's own descriptor. */
  root: Uint8Array;
  key: Uint8Array;
  chunkCount: number;
  blockIds: Uint8Array[];
  replicasLanded: number;
  replicasIntended: number;
}

/** A prebuilt runtime: the shell, the channel adapter it was built on, and the
 *  identity it registered under. One value, from `bootTransportShell()`. */
export interface StorageRuntime {
  shell: Shell;
  transport: Transport;
  identity: Identity;
}

export interface StorageNodeOptions {
  /** A prebuilt runtime with the transport bundle already admitted and its
   *  listeners started (a WebRTC/WS node), from `bootTransportShell()`. Present,
   *  its `identity` is this node's and `opts.identity` is not read. Absent,
   *  StorageNode builds its own from `channels`/`listen` below. */
  runtime?: StorageRuntime;
  sodium: Sodium;
  /** The signed seedstore bundle blob (seedstore.skb), loaded through the §12.4
   *  bundle loader (verify manifest, govern policy, install modules). */
  bundleBlob: Uint8Array;
  /** This node's signing identity. Only read when StorageNode builds its own
   *  runtime; minted if absent. With `runtime`, `runtime.identity` is the one. */
  identity?: Identity;
  config?: Partial<StorageConfig>;
  fs?: Fs;
  store?: BlobView;
  quota?: number;
  clock?: () => number;
  timeoutMs?: number;
  /** The socket seam the transport driver dials/listens through (seedkernel
   *  §12.6): an in-process fabric for tests, a NodeChannelFactory for TCP, or a
   *  browser WebSocket/WebRTC factory. A WebRTC factory has no `connect`; its
   *  links arrive through signaling and the factory's `listen` sink. */
  channels?: ChannelFactoryLike;
  listen?: { host: string; port: number };
  wsListen?: { host: string; port: number };
  /** Optional deployment secret — the gate a caller must produce before this
   *  node's inbound side opens (seedkernel §12.6.3). It is installation-local
   *  transport guest config; call `setContactSecret` to rotate it after boot. */
  contactSecret?: Uint8Array;
  /** Optional network key — which network this node belongs to (an isolation
   *  boundary, not a gate; §12.6). Absent ⇒ the public network. */
  networkKey?: Uint8Array;
  /** Optional peer whitelist — 32-byte channel keys this node will talk to,
   *  supplied to the transport in LOCAL (seedkernel §12.6.3). A lint, not a gate.
   *  Absent ⇒ admit every peer that completes the handshake. */
  admitPeers?: Uint8Array[];
  /** Parallel connections per dialed peer (default 1) — the transport's dial
   *  fan-out. */
  connsPerPeer?: number;
  /** The signed transport bundle blob. Defaults to the one shipped in the
   *  seedkernel artifact; an operator who pins a different transport author
   *  builds their own. Only read when StorageNode builds its own runtime. */
  transportBlob?: Uint8Array;
  /** Override the cohort's signing scope author: sign descriptors under this
   *  author instead of the loaded bundle's (used when joining a cohort whose
   *  holders run a DIFFERENT bundle's author — the browser demo's override). */
  signAuthor?: Uint8Array;
}

export class StorageNode {
  readonly peerId: PeerId;
  readonly identity: Identity;
  /** The channel adapter — sockets and listeners, and nothing else. The transport
   *  itself is a signed bundle; this is the host side that hands it descriptors. Neither
   *  the address book nor the request face is here: peers are the guest's (`netAddr`,
   *  `netReady`, `netPeers` above) and a send is the guest's call to the id the transport
   *  claims (see `netSend` in host/tier2-guest.orchestration.js). */
  readonly net: Transport;
  readonly fs: Fs;
  readonly store: BlobView;
  readonly quota: number;
  readonly crypto: Crypto;
  readonly sodium: Sodium;
  readonly config: StorageConfig;
  /** The logical names of the modules this deployment's bundle installs — read off the
   *  verified manifest, which is the whole of what a host may know about them now: a
   *  slot's modules are private to its guest, so there is no table to ask. */
  readonly moduleNames: ReadonlySet<string>;

  /** The shell this node runs on. Public because some drivers (the latency
   *  harness) reach the runtime directly, and a caller-passed shell is already theirs. */
  readonly shell: Shell;
  private readonly clockFn: () => number;
  /** The cohort's signing-scope author (§16), derived from the verified bundle
   *  author. Pass as signDescriptor()'s 5th arg to match the guest's node/verify. */
  readonly signAuthor: Uint8Array;
  /** This app's fs keyspace prefix (seedkernel §12.2): every key the holder
   *  writes is `appScope + key` on the raw backend. Tooling opening a node's
   *  directory cold must wrap it in `scopedFs(raw, appScope)` to see the same blocks. */
  readonly appScope: string;
  /** The load's returned handle: app key + scoped fs view + the slot-bound loopback
   *  `invoke`. Invocation needs no shell-level identity lookup. */
  private readonly handle: AppHandle;
  private repairLoopOn = false;
  private repairTimer: ReturnType<typeof setTimeout> | null = null;
  private inFlight: Promise<unknown> = Promise.resolve();
  private closed = false;
  private readonly ownsShell: boolean;

  private constructor(
    opts: StorageNodeOptions,
    shell: Shell,
    net: Transport,
    identity: Identity,
    loaded: AppHandle,
    ownsShell: boolean,
  ) {
    this.sodium = opts.sodium;
    this.shell = shell;
    this.moduleNames = new Set(loaded.manifest.modules.map((m) => m.name));
    this.identity = identity;
    this.peerId = toHex(identity.publicKey);
    // Defaults to the shell's scoped view (`loaded.fs`) so the host read view
    // shares the same backend the guest writes to. A caller's own fs wins.
    this.fs = opts.fs ?? new MemoryFs();
    this.quota = opts.quota ?? DEFAULT_QUOTA_BYTES;
    this.store = opts.store ?? new FsBlobView(this.fs);
    this.clockFn = opts.clock ?? (() => Date.now());
    this.crypto = new Crypto(opts.sodium);
    this.net = net;
    this.ownsShell = ownsShell;
    this.handle = loaded;

    // `signAuthor` overrides the derived scope (§16) so a caller can join a cohort
    // whose holders run a different bundle's author; fs keyspace/app key stay the
    // loaded bundle's regardless.
    this.signAuthor = opts.signAuthor ?? loaded.author;
    this.appScope = loaded.appScope;

    // Mirrors the guest's own CFG precedence rule (tier2-guest CFG) — must not
    // drift from it. guest.config is untyped JSON, so coerce it here.
    const override = normaliseConfig(opts.config ?? {});
    assertStorageConfig(override);
    const signed = (loaded.manifest.guest?.config ?? {}) as unknown as Partial<StorageConfig>;
    const merged: Partial<StorageConfig> = { ...signed, ...override };
    // A deployed bundle always signs its geometry into guest.config, so the fallback
    // is reachable only from a synthetic bundle that declared none — a test. Spelled
    // out rather than defaulted, so the one site that can still land on test geometry
    // says so.
    this.config = { ...defaultConfig(merged.blockSize ?? TEST_BLOCK_SIZE, merged.k, merged.m), ...merged };
  }

  /** Boot a storage node: take the caller's prebuilt runtime, or stand one up here
   *  (shell + transport bundle), then load the seedstore bundle onto it. Handlers
   *  arrive solely via the §12.4 bundle loader. */
  static async create(opts: StorageNodeOptions): Promise<StorageNode> {
    await opts.sodium.ready;

    // The runtime to load onto: the caller's, or one built here — and its identity
    // is this node's, so peerId can never drift from what the transport registered
    // under. Either way the fs backend comes back on the load's handle, so host
    // reads and guest writes share it.
    const ownsShell = opts.runtime === undefined;
    const runtime = opts.runtime ?? await bootTransportShell({
      sodium: opts.sodium,
      identity: opts.identity ?? (() => {
        const kp = opts.sodium.crypto_sign_keypair();
        return { publicKey: kp.publicKey, privateKey: kp.privateKey };
      })(),
      fs: opts.fs, channels: opts.channels,
      listen: opts.listen, wsListen: opts.wsListen, networkKey: opts.networkKey,
      contactSecret: opts.contactSecret, admitPeers: opts.admitPeers,
      connsPerPeer: opts.connsPerPeer, timeoutMs: opts.timeoutMs,
      transportBlob: opts.transportBlob,
      now: opts.clock,
    });
    const { shell, transport: net, identity } = runtime;

    // Anything past this point can throw (blob verify, config check), and must not
    // leave a shell we stood up running with nothing to close it. A caller's own
    // shell is the caller's to close.
    try {
      // Admitting the bundle is what routes inbound storage frames to it (the
      // manifest claims STORAGE_PROTO, §12.10) — nothing else arms it. `localConfig`
      // and `realmMemoryBytes` ride with THIS load (§12.4/§12.3), not the shell,
      // so they reach a caller-supplied shell too and don't leak into the transport's budget.
      const loaded = await shell.loadBundleBlob(opts.bundleBlob, {
        localConfig: localConfigFor(opts),
        realmMemoryBytes: normaliseConfig(opts.config ?? {}).realmMemoryBytes,
      });

      // The guest writes through `loaded.fs` (a scopedFs view, seedkernel §12.2);
      // the host read view reuses the same handle rather than re-deriving the scope.
      return new StorageNode({ ...opts, fs: loaded.fs }, shell, net, identity, loaded, ownsShell);
    } catch (err) {
      if (ownsShell) shell.close();
      throw err;
    }
  }

  // ── cohort membership (§5.1) ───────────────────────────────────────────
  now(): number { return this.clockFn(); }

  /** The transport's authenticated peers right now. Link state belongs to the
   *  signed transport guest, so this is an async question rather than callbacks
   *  maintained by the WebSocket/WebRTC channel factory. */
  linkedPeers(): Promise<PeerId[]> { return netPeers(this.shell); }

  /** Rotate the inbound contact gate without reloading the transport or dropping
   *  existing links. Omit the secret to make this node open. */
  setContactSecret(contactSecret?: Uint8Array): Promise<Uint8Array> {
    return netContact(this.shell, contactSecret);
  }

  /** Connect two nodes into one cohort: teach each transport the other's destination,
   *  then dial (the transport's `ready` fires the handshake and resolves once every known
   *  peer authenticated or its deadline passed). Async — links must be up before
   *  PUT/GET reach the peer. The address book lives in the transport guest and dies with
   *  its realm (seedkernel §12.10), so a node whose transport is replaced must be
   *  connected again. */
  static async connect(a: StorageNode, b: StorageNode): Promise<void> {
    await Promise.all([
      netAddr(a.shell, b.peerId, `tcp://127.0.0.1:${b.net.port}`),
      netAddr(b.shell, a.peerId, `tcp://127.0.0.1:${a.net.port}`),
    ]);
    await Promise.all([netReady(a.shell), netReady(b.shell)]);
  }

  // ── PUT / GET / repair / share — all local ops through the load's handle ─────

  /** Serialize initiator ops: each call to this app's one entrypoint (`handle`,
   *  seedkernel §12.2) awaits the previous before running through `this.handle`. */
  private runExclusive<T>(body: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(new Error("storage node closed"));
    const p = this.inFlight.then(body);
    this.inFlight = p.then(() => {}, () => {});
    return p;
  }

  /** One local op into the guest: the op-frame composition is kernel-shipped content
   *  (seedkernel-wasm/op-frame `writeOp`) - the shell passes bytes and never reads them. */
  private invoke(op: string, args: Uint8Array): Promise<Uint8Array> {
    return this.handle.invoke(writeOp(op, args));
  }

  /** PUT a file (§6), orchestrated in the guest, STREAMED. */
  async put(plaintext: Uint8Array): Promise<PutResult> {
    return this.runExclusive(async () => {
      const meta = await this.invoke(Op.PUT_START, NO_ARG);
      const windowBytes = readU32BE(meta, 0);
      for (let off = 0; ; off += windowBytes) {
        await this.invoke(Op.PUT_WINDOW, plaintext.subarray(off, Math.min(off + windowBytes, plaintext.length)));
        if (off + windowBytes >= plaintext.length) break;
      }
      return decodePutResult(await this.invoke(Op.PUT_FINISH, NO_ARG));
    });
  }

  /** GET a file (§7), orchestrated in the guest, STREAMED. `root` is the signed root
   *  descriptor from the PUT (or shared alongside `key`); K leads the argument so the
   *  variable-length root can be its tail. */
  async get(root: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    return this.runExclusive(async () => {
      const fileSize = readU64BE(await this.invoke(Op.GET_START, concatBytes([key, root])), 0);
      const out = new Uint8Array(fileSize);
      let written = 0;
      while (written < fileSize) {
        const part = await this.invoke(Op.GET_NEXT, NO_ARG);
        if (part.length === 0) throw new Error(`get: stream ended ${written}/${fileSize} bytes in`);
        out.set(part, written); written += part.length;
      }
      return out;
    });
  }

  /** Issue ONE control-plane message to a peer and answer with its reply (§18).
   *  `body` is `[type u8][payload]` — the same bytes a holder's `handle` decodes.
   *  Runs through this node's own guest, so the frame on the wire is exactly what
   *  the placement engine would send. Throws if the peer was unreachable within
   *  the request window; a decline still comes back as response bytes. */
  async request(peer: PeerId, body: Uint8Array): Promise<Uint8Array> {
    const r = await this.runExclusive(() => this.invoke(Op.REQUEST, concatBytes([fromHex(peer), body])));
    if (r[0] !== 1) throw new Error(`request: peer ${peer.slice(0, 8)}… unreachable within the request window`);
    return r.slice(1);
  }

  /** Pre-warm the realm's codec module + crypto primitives. */
  async warm(): Promise<void> {
    await this.runExclusive(() => this.invoke(Op.WARM, NO_ARG));
  }

  /** Run one repair pass over every chunk this node holds a block of (§9). */
  async runRepair(): Promise<number> {
    return readU32BE(await this.runExclusive(() => this.invoke(Op.REPAIR, NO_ARG)), 0);
  }

  /** Decayed reciprocity score this node holds for a peer (§13), read from the
   *  guest — the same module instance the placement ranker scores against. */
  async score(peerPk: Uint8Array): Promise<number> {
    const res = await this.invoke(Op.SCORE, peerPk);
    if (!res || res.length < 8) return 0;
    return new DataView(res.buffer, res.byteOffset, 8).getFloat64(0, true);
  }

  /** This node's request statistics since the last read, keyed by MsgType (host/
   *  protocol.ts `RequestStats`): SENT count + peak in-flight, and RECEIVED count/
   *  bytes/processing-ms as a holder. Read-and-clear — call once before and once
   *  after the measured phase. */
  async stats(): Promise<Map<number, RequestStats>> {
    return decodeStats(await this.invoke(Op.STATS, NO_ARG));
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
    // `closed` makes runExclusive reject any op raised after this; shell.close()
    // defers realm disposal until the in-flight chain drains, so a pass caught
    // mid-await is never resumed into a freed realm (a QuickJS use-after-free).
    this.closed = true;
    this.stopRepairLoop();
    this.shell.close();
  }

  /** True if both pure modules are installed with the bundle (§19). A bundle load
   *  builds every module or none (seedkernel §12.4), so the manifest's declared
   *  names ARE the modules the guest holds. */
  handlersInstalled(): boolean {
    return this.moduleNames.has("codec") && this.moduleNames.has("reputation");
  }
}

/** Build the runtime a StorageNode loads its bundles onto: the platform seam (fs,
 *  channel factory, realm factory) plus the transport bundle admitted first, with
 *  listeners started. Wraps the kernel's `bootShell`; returns the `StorageRuntime`
 *  StorageNode takes as `runtime` — the shell, the `TransportHost` (the shell
 *  itself doesn't expose it), and the identity both registered under. */
export async function bootTransportShell(
  opts: {
    sodium: Sodium; identity: Identity;
    fs?: Fs; channels?: ChannelFactoryLike;
    listen?: { host: string; port: number };
    wsListen?: { host: string; port: number };
    networkKey?: Uint8Array; contactSecret?: Uint8Array;
    admitPeers?: Uint8Array[]; connsPerPeer?: number;
    timeoutMs?: number; transportBlob?: Uint8Array;
    createRealm?: RealmFactory;
    now?: () => number;
  },
): Promise<StorageRuntime> {
  const fs = opts.fs ?? new MemoryFs();
  const { shell, transport } = await bootShell({
    sodium: opts.sodium, identity: opts.identity, fs,
    // Top-level (not under `transport`) since it must reach both the adapter and
    // the shell's link signing scope (seedkernel §12.6).
    networkKey: opts.networkKey,
    createRealm: opts.createRealm, now: opts.now,
    // This node's network, whole (seedkernel §12.6): the sockets AND the signed
    // program that drives them, one object because they are one decision — the blob
    // whose author is PINNED is the blob that gets loaded.
    transport: {
      channels: opts.channels,
      listen: opts.listen,
      wsListen: opts.wsListen,
      // Also PINS the transport slot to this blob's own author — no other
      // transport-role bundle may claim the slot on this node. Defaults to the
      // kernel-shipped artifact.
      bundle: opts.transportBlob,
      // Policies of the signed transport program, not socket-driver facts, so they
      // ride the LOAD as its LOCAL config. JSON, so omit absent values and spell peer
      // ids as hex strings.
      config: {
        ...(opts.contactSecret === undefined
          ? {}
          : { contactSecret: toHex(opts.contactSecret) }),
        ...(opts.timeoutMs === undefined
          ? {}
          : { requestTimeoutMs: opts.timeoutMs }),
        ...(opts.connsPerPeer === undefined
          ? {}
          : { connsPerPeer: opts.connsPerPeer }),
        ...(opts.admitPeers === undefined
          ? {}
          : { admitPeers: opts.admitPeers.map(toHex) }),
      },
    },
    // The one admission branch that's ours: the operator handing us a bundle IS
    // the trust decision (manifest sig + module hashes are still verified);
    // the transport author pin and revocation/downgrade guard are bootShell's/the shell's.
    admit: () => true,
  });
  return { shell, transport: transport!, identity: opts.identity };
}

/** This installation's settings for the storage bundle, as the `LOCAL` the guest
 *  reads (seedkernel §12.4). `realmMemoryBytes` is split back out (the realm's
 *  bound, not the guest's); `quota` can never be signed, so this is its only door. */
function localConfigFor(opts: StorageNodeOptions): Record<string, string | number> {
  const { realmMemoryBytes, ...guestOverride } = normaliseConfig(opts.config ?? {});
  return {
    ...(guestOverride as Record<string, string | number>),
    quota: opts.quota ?? DEFAULT_QUOTA_BYTES,
  };
}
