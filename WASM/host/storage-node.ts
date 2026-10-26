// StorageNode — a single storage peer running *on* the seedkernel (SPEC §19
// bootstrap). A THIN client: the entire storage protocol lives in the confined
// guest (host/tier2-guest.orchestration.js), run in one seedkernel realm over the
// generic guest seam, and the node it runs on is the host's own (runtime.ts stands one
// up). This loads the signed seedstore bundle (seedkernel §12.4) onto that node and
// calls its guest's ops.
// Modules arrive only via verified `install`, never raw-bound.

import type { Fs } from "seedkernel-wasm/fs";
import { writeOp, OpArgs } from "seedkernel-wasm/op-frame";
import { FsBlobView, type BlobView } from "./store-view.js";
import { Crypto } from "./crypto.js";
import {
  type Identity, type PeerId, type StorageConfig, defaultConfig, assertStorageConfig, normaliseConfig, DEFAULT_QUOTA_BYTES,
  TEST_BLOCK_SIZE, NET_SERVICE,
} from "./core.js";
import { Op, decodeStats, decodePutResult, encodeGroups, type Groups, type PutResult, type RequestStats } from "./protocol.js";
import { groupBytes, validGroupName } from "./descriptor-core.js";
import { toHex, fromHex, readU32BE, readU64BE, concatBytes } from "./util.js";
import { parseDest } from "seedkernel-wasm/peer-addr";
import type { Sodium } from "./sodium.js";
import type { AppHandle, BootResult, Shell } from "seedkernel-wasm/shell-core";

const NO_ARG = new Uint8Array(0);
/** "no contact secret" on the wire: the transport reads all-zero as an open peer. */
const ZERO32 = new Uint8Array(32);
type Transport = NonNullable<BootResult["transport"]>;

// ── the host's door into the transport bundle (seedkernel §12.10) ────────────
//
// Peers and cohort readiness are the transport GUEST's — its address book dies with
// its realm — so they are claim calls on the id that bundle claims, through the same
// door a co-resident guest reaches with `host.call`. `OpArgs` also encodes the host's
// link events; these service ops use it as optional application framing, which the
// shell passes through and never reads.

/** One op to the transport, with the shell's caller-id prefix. Throws when nothing
 *  claims the id — a node with no transport bundle, which is a legitimate
 *  configuration and so has to be an answer rather than a promise that never settles. */
function transportOp(shell: Pick<Shell, "call">, args: OpArgs): Promise<Uint8Array> {
  const answer = shell.call(NET_SERVICE, args.build());
  if (!answer) throw new Error(`transport: no bundle claims ${NET_SERVICE}`);
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

/** Teach the transport one peer from an operator's reference, `pk[.secret]@[scheme://]host:port[/path]`
 *  — the shipped transport's own spelling, the one its `peers` config takes — with
 *  `defaultScheme` filling a bare `host:port`. `.secret` is THAT peer's contact secret.
 *  Checked here, so a typo fails where it was typed rather than reading as a peer that
 *  never answers. Resolves with the peer id once it is taught. */
export async function netPeer(
  shell: Pick<Shell, "call">, spec: string, defaultScheme = "ws",
): Promise<PeerId> {
  const at = spec.indexOf("@");
  if (at < 0) throw new Error(`bad peer (want pk[.secret]@dest): ${spec}`);
  const [pk, secret, ...extra] = spec.slice(0, at).trim().toLowerCase().split(".");
  const hex32 = (v: string | undefined) => v !== undefined && /^[0-9a-f]{64}$/.test(v);
  if (!hex32(pk) || extra.length > 0) throw new Error(`bad peer key (want 64 hex characters): ${spec}`);
  if (secret !== undefined && !hex32(secret)) throw new Error(`bad peer contact secret (want 64 hex characters): ${spec}`);
  const where = spec.slice(at + 1).trim();
  const dest = where.includes("://") ? where : `${defaultScheme}://${where}`;
  // A `relay+` destination reaches the peer through that relay (seedkernel §12.7).
  const relayed = dest.startsWith("relay+") ? dest.slice("relay+".length) : dest;
  if (!parseDest(relayed)) throw new Error(`bad peer destination (want [relay+][scheme://]host:port[/path]): ${spec}`);
  await netAddr(shell, pk, dest, secret === undefined ? undefined : fromHex(secret));
  return pk;
}

/** The relay's state: "none", registered and "up", or "redialing". */
export type RelayState = "none" | "up" | "redialing";
/** The state byte the transport's `relay` and `relayState` ops both answer. */
const relayStateOf = (b: Uint8Array): RelayState => (b[0] === 1 ? "up" : b[0] === 2 ? "redialing" : "none");

/** Register on a relay, so peers can reach this node through it: a `ws://`/`wss://` URL
 *  with no path, "" to leave. Resolves to the relay's state once registered, or once that
 *  attempt has failed and the transport is redialing. Which peers to reach is the app's to
 *  say, as `relay+` addresses (`netAddr`); the transport moves each relayed link to WebRTC
 *  when the node's channels also reach `rtc:` destinations (seedkernel §12.7). A private
 *  relay (seedrelay's `--secret`) also wants its `secret`, which the transport proves and
 *  never sends. */
export async function netRelay(shell: Pick<Shell, "call">, url: string, secret?: string): Promise<RelayState> {
  const op = new OpArgs("relay").text(url);
  if (secret) op.text(secret);
  return relayStateOf(await transportOp(shell, op));
}

/** The relay's state now. */
export async function netRelayState(shell: Pick<Shell, "call">): Promise<RelayState> {
  return relayStateOf(await transportOp(shell, new OpArgs("relayState")));
}

/** The peers this node holds at least one authenticated link to. A fact about links,
 *  and links are the guest's, so it is a question rather than a field. */
export async function netPeers(shell: Pick<Shell, "call">): Promise<PeerId[]> {
  const bytes = await transportOp(shell, new OpArgs("peers"));
  const out: PeerId[] = [];
  for (let off = 0; off + 32 <= bytes.length; off += 32) out.push(toHex(bytes.slice(off, off + 32)));
  return out;
}

/** Each linked peer, and whether this node reaches it over a direct path (seedkernel
 *  §12.7) rather than through a relay: the transport's `routes`, `[key 32][direct u8]` apiece. */
export async function netRoutes(shell: Pick<Shell, "call">): Promise<Map<PeerId, boolean>> {
  const bytes = await transportOp(shell, new OpArgs("routes"));
  const out = new Map<PeerId, boolean>();
  for (let off = 0; off + 33 <= bytes.length; off += 33) out.set(toHex(bytes.subarray(off, off + 32)), bytes[off + 32] !== 0);
  return out;
}

export type { PutResult };

/** The signed seedstore bundle (seedstore.skb), as a driver's `loadWasmBytes` reads it. One
 *  blob carries everything: manifest + codec.wasm + reputation.wasm + the guest. */
export interface WasmBytes {
  bundleBlob: Uint8Array;
}

/** A node to install onto: the shell, the channel adapter it was built on, and the
 *  identity it registered under. One value, from `storageRuntime()` (runtime.ts). */
export interface StorageRuntime {
  shell: Shell;
  transport: Transport;
  identity: Identity;
}

export interface StorageNodeOptions {
  /** The node to install onto, with the transport bundle already admitted and its
   *  listeners started (`storageRuntime()`, runtime.ts). Its `identity` is this node's. */
  runtime: StorageRuntime;
  /** This node's own libsodium, for what storage computes host-side (key sharing). */
  sodium: Sodium;
  /** The signed seedstore bundle blob (seedstore.skb), loaded through the seedkernel §12.4
   *  `install` (verify manifest, govern policy, install modules). */
  bundleBlob: Uint8Array;
  config?: Partial<StorageConfig>;
  store?: BlobView;
  quota?: number;
  /** This node's groups (§5.1): name → member keys as hex. Every member of every group is
   *  its cohort, and a chunk is stored only among its own group. Operator policy, like
   *  `quota`, so it is never signed. Omitted ⇒ no groups: the node stores for nobody and
   *  answers nobody until `setGroups`. */
  groups?: Groups;
  /** The realm's invocation budget (seedkernel §12.3): queue wait + guest execution +
   *  a deferred answer. A DIFFERENT clock from the transport's `timeoutMs`, the
   *  per-request stall window a silent peer is given — that one is deliberately short (a
   *  cohort wants an offline peer written off fast), and the same number as a realm
   *  budget starves a large-block encode before it can finish. Omitted ⇒ the host
   *  default. */
  guestDeadlineMs?: number;
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
  /** The roster the guest holds, as last set. */
  groups: Groups;
  readonly crypto: Crypto;
  readonly sodium: Sodium;
  readonly config: StorageConfig;
  /** The logical names of the modules this deployment's bundle installs — read off the
   *  verified manifest, which is the whole of what a host may know about them: a
   *  slot's modules are private to its guest, so there is no table to ask. */
  readonly moduleNames: ReadonlySet<string>;

  /** The shell this node runs on. Public because some drivers (the latency
   *  harness) reach the runtime directly, and a caller-passed shell is already theirs. */
  readonly shell: Shell;
  /** This app's fs keyspace prefix (seedkernel §12.2): every key the holder
   *  writes is `appScope + key` on the raw backend. Tooling opening a node's
   *  directory cold must wrap it in `scopedFs(raw, appScope)` to see the same blocks. */
  readonly appScope: string;
  /** The load's returned handle: app label + scoped fs view + the slot-bound loopback
   *  `invoke`. Invocation needs no shell-level identity lookup. */
  private readonly handle: AppHandle;
  private repairLoopOn = false;
  private repairTimer: ReturnType<typeof setTimeout> | null = null;
  private inFlight: Promise<unknown> = Promise.resolve();
  private closed = false;

  private constructor(opts: StorageNodeOptions, loaded: AppHandle, local: LocalConfig) {
    const { shell, transport: net, identity } = opts.runtime;
    this.sodium = opts.sodium;
    this.shell = shell;
    this.moduleNames = new Set(loaded.manifest.modules.map((m) => m.name));
    this.identity = identity;
    this.peerId = toHex(identity.publicKey);
    // The load's scoped view (`loaded.fs`), so the host read view shares the backend the
    // guest writes to.
    this.fs = loaded.fs!;
    this.quota = local.guest.quota;
    this.groups = local.guest.groups;
    this.store = opts.store ?? new FsBlobView(this.fs);
    this.crypto = new Crypto(opts.sodium);
    this.net = net;
    this.handle = loaded;
    this.appScope = loaded.appScope;

    // The guest's CFG (signed APP, then LOCAL over it), merged from the very LOCAL the
    // guest was handed, so the two cannot disagree. guest.config is untyped JSON.
    const { quota: _quota, groups: _groups, ...override } = local.guest;
    const signed = (loaded.manifest.guest?.config ?? {}) as unknown as Partial<StorageConfig>;
    const merged: Partial<StorageConfig> = { ...signed, ...override, realmMemoryBytes: local.realmMemoryBytes };
    // A deployed bundle always signs its geometry into guest.config, so the fallback
    // is reachable only from a synthetic bundle that declared none — a test. Spelled
    // out rather than defaulted, so the one site that can still land on test geometry
    // says so.
    this.config = { ...defaultConfig(merged.blockSize ?? TEST_BLOCK_SIZE, merged.k, merged.m), ...merged };
  }

  /** Load the seedstore bundle onto a node (`opts.runtime`), whose identity is this
   *  node's, so peerId can never drift from what the transport registered under.
   *  Handlers arrive solely via `install` (seedkernel §12.4). A failed load leaves the node to its
   *  owner. */
  static async create(opts: StorageNodeOptions): Promise<StorageNode> {
    await opts.sodium.ready;
    const local = localConfigFor(opts);
    // Admitting the bundle is what routes inbound storage frames to it (the manifest
    // claims STORAGE_PROTO, seedkernel §12.10) — nothing else arms it. `localConfig` and
    // `realmMemoryBytes` ride with THIS load (seedkernel §12.4/§12.3), not the shell, so they don't
    // leak into the transport's budget. The guest writes through `loaded.fs` (a scoped
    // view, seedkernel §12.2), which the host read view reuses.
    const loaded = await opts.runtime.shell.install(opts.bundleBlob, {
      localConfig: local.guest,
      realmMemoryBytes: local.realmMemoryBytes,
      guestDeadlineMs: opts.guestDeadlineMs,
    });
    return new StorageNode(opts, loaded, local);
  }

  // ── cohort membership (§5.1) ───────────────────────────────────────────
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
      netAddr(a.shell, b.peerId, `tcp://127.0.0.1:${b.net.portOf("tcp")}`),
      netAddr(b.shell, a.peerId, `tcp://127.0.0.1:${a.net.portOf("tcp")}`),
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

  /** One local op into the guest: the op-frame composition is seedkernel-shipped content
   *  (seedkernel-wasm/op-frame `writeOp`) - the shell passes bytes and never reads them. */
  private invoke(op: string, args: Uint8Array): Promise<Uint8Array> {
    return this.handle.invoke(writeOp(op, args));
  }

  /** Replace this node's groups (§5.1), whole, at any time: the next request, admission
   *  and placement read the new roster. Whatever keeps the roster (an operator, or a
   *  groups app) drives it through here. */
  async setGroups(groups: Groups): Promise<void> {
    const checked = checkGroups(groups);
    await this.runExclusive(() => this.invoke(Op.GROUPS, encodeGroups(checked)));
    this.groups = checked;
  }

  /** PUT a file (§6) into one of this node's groups, orchestrated in the guest, STREAMED.
   *  The group may be left out when the node has exactly one. */
  async put(plaintext: Uint8Array, opts: { group?: string } = {}): Promise<PutResult> {
    const group = opts.group ?? soleGroup(this.groups);
    return this.runExclusive(async () => {
      const meta = await this.invoke(Op.PUT_START, groupBytes(group));
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

  /** Decayed reciprocity score this node holds for a peer in one group (§13), read from
   *  the guest — the same module instance the placement ranker scores against. Goodwill is
   *  per group: serving one group's chunks earns nothing in another. */
  async score(peerPk: Uint8Array, group: string = soleGroup(this.groups)): Promise<number> {
    const res = await this.invoke(Op.SCORE, concatBytes([peerPk, groupBytes(group)]));
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

  /** Share a file: seal K to a recipient's node key (§4.4). */
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

/** This installation's settings for the storage bundle: `guest` is the `LOCAL` the guest
 *  reads (seedkernel §12.4), and `realmMemoryBytes` is split back out of it (the realm's
 *  bound, not the guest's). `quota` can never be signed, so LOCAL is its only door. */
interface LocalConfig {
  guest: Omit<Partial<StorageConfig>, "realmMemoryBytes"> & { quota: number; groups: Groups };
  realmMemoryBytes?: number;
}
/** Normalised and checked once, before the bundle loads. */
function localConfigFor(opts: StorageNodeOptions): LocalConfig {
  const config = normaliseConfig(opts.config ?? {});
  assertStorageConfig(config);
  const { realmMemoryBytes, ...guest } = config;
  return { guest: { ...guest, quota: opts.quota ?? DEFAULT_QUOTA_BYTES, groups: checkGroups(opts.groups ?? {}) }, realmMemoryBytes };
}

/** A roster with valid names and lowercase 64-hex keys, each listed once. */
export function checkGroups(groups: Groups): Groups {
  const out: Groups = {};
  for (const [name, members] of Object.entries(groups)) {
    if (!validGroupName(name)) throw new Error(`groups: "${name}" is not a group name (1-32 of A-Z a-z 0-9 . _ -)`);
    const keys = new Set<string>();
    for (const m of members) {
      const key = String(m).toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(key)) throw new Error(`groups: "${m}" in ${name} is not a 64-hex-character key`);
      keys.add(key);
    }
    out[name] = [...keys];
  }
  return out;
}

function soleGroup(groups: Groups): string {
  const names = Object.keys(groups);
  if (names.length !== 1) throw new Error(`storage: name a group — this node has ${names.length === 0 ? "none (pass groups, or call setGroups)" : names.join(", ")}`);
  return names[0];
}
