// A seedkernel node for storage to install onto (SPEC §19 bootstrap). The host assembles
// it, through its own `standUp` (seedkernel §12.8, §12.9); this file only says what
// storage wants of the node: an identity, admission of the bundle its operator hands it,
// and its transport's sockets and settings. A page passes the host it runs
// (seedkernel-wasm/platform-web `browserHost`), Node its own (`bootNodeShell`, or an
// in-memory host per node for in-process cohorts, node.ts).

import type { PlatformHost } from "seedkernel-wasm/platform";
import type { ChannelFactory, ListenAddress } from "seedkernel-wasm/socket-seam";
import type { TransportOptions } from "seedkernel-wasm/shell-core";
import type { Identity } from "./core.js";
import { StorageNode, type StorageNodeOptions, type StorageRuntime } from "./storage-node.js";
import { toHex } from "./util.js";

/** What stands a node up: a seedkernel host's `standUp`, or `bootNodeShell`. */
export type StandUp = PlatformHost["standUp"];

export interface StorageRuntimeOptions {
  identity: Identity;
  /** Where the node keeps its files, under the host's store. Default "seedstore". */
  dir?: string;
  /** The socket seam the transport driver dials/listens through (seedkernel §12.6): an
   *  in-process fabric for tests, or a page's WebSocket/WebRTC factories. Omitted, the
   *  host's own sockets (TCP on Node). A WebRTC factory has no `connect`; its links arrive
   *  through signaling and the factory's `listen` sink. */
  channels?: ChannelFactory;
  /** The listeners to bind, each labelled for the transport: the shipped one reads `ws`
   *  as RFC 6455 and any other label as length framing. */
  listen?: ListenAddress[];
  /** Silence the host transport driver's link-down diagnostic (seedkernel
   *  `TransportHostOptions.suppressLinkLog`). Left OFF in production on purpose: a
   *  cohort that cannot reach its peers should say so on stderr, which is the only
   *  thing a `p2p-cli` run reporting "only 0/N peers linked" otherwise leaves
   *  unexplained. Tests set it, because tearing cohorts down is what they DO and the
   *  `truncated` line per peer per shutdown buries the assertions. */
  suppressLinkLog?: boolean;
  /** This machine's datagram sockets (seedkernel-wasm/shell-node `nodeDatagrams`): with
   *  them the transport moves a linked console peer to a direct UDP path (seedkernel
   *  §12.7). */
  datagrams?: TransportOptions["datagrams"];
  /** Optional deployment secret — the gate a caller must produce before this
   *  node's inbound side opens (seedkernel §12.6.3). It is installation-local
   *  transport guest config; call `setContactSecret` to rotate it after boot. */
  contactSecret?: Uint8Array;
  /** Optional network key — which network this node belongs to (an isolation
   *  boundary, not a gate; seedkernel §12.6.3). It is installation-local transport
   *  guest config, like the contact secret. Absent ⇒ the public network. */
  networkKey?: Uint8Array;
  /** Optional peer whitelist — 32-byte channel keys this node will talk to,
   *  supplied to the transport in LOCAL (seedkernel §12.6.3). A lint, not a gate.
   *  Absent ⇒ admit every peer that completes the handshake. */
  admitPeers?: Uint8Array[];
  /** Parallel connections per dialed peer (default 1) — the transport's dial
   *  fan-out. */
  connsPerPeer?: number;
  /** The per-request stall window a silent peer is given (the transport's
   *  `requestTimeoutMs`). */
  timeoutMs?: number;
  /** STUN/TURN servers for WebRTC peers, as `RTCConfiguration.iceServers` takes them. */
  iceServers?: { urls: string | string[]; username?: string; credential?: string }[];
  /** The signed transport bundle blob. Defaults to the one shipped in the
   *  seedkernel artifact; an operator selecting a different transport passes
   *  its blob here. */
  transportBlob?: Uint8Array;
}

/** Stand a node up for storage through the host: its transport bundle installed at boot
 *  and its listeners started, ready for `StorageNode.create`. */
export async function storageRuntime(standUp: StandUp, opts: StorageRuntimeOptions): Promise<StorageRuntime> {
  const { shell, transport } = await standUp({
    dir: opts.dir ?? "seedstore",
    identity: opts.identity,
    // The one admission branch that's ours: the operator handing the node our bundle IS
    // the trust decision (the bundle's signature is still verified); transport selection
    // and the revocation/downgrade guard are the host's.
    admit: () => true,
    // This node's network, whole (seedkernel §12.6): the sockets AND the signed program
    // that drives them, one object because they are one decision.
    transport: {
      channels: opts.channels,
      listen: opts.listen,
      suppressLinkLog: opts.suppressLinkLog,
      datagrams: opts.datagrams,
      // Selecting these bytes authorizes them as the transport; a later change must
      // replace this slot explicitly. Defaults to the seedkernel-shipped artifact.
      bundle: opts.transportBlob,
      // Policies of the signed transport program, not socket-driver facts, so they ride
      // the LOAD as its LOCAL config. JSON, so omit absent values and spell peer ids as
      // hex strings.
      config: {
        ...(opts.networkKey === undefined ? {} : { networkKey: toHex(opts.networkKey) }),
        ...(opts.contactSecret === undefined ? {} : { contactSecret: toHex(opts.contactSecret) }),
        ...(opts.timeoutMs === undefined ? {} : { requestTimeoutMs: opts.timeoutMs }),
        ...(opts.connsPerPeer === undefined ? {} : { connsPerPeer: opts.connsPerPeer }),
        ...(opts.admitPeers === undefined ? {} : { admitPeers: opts.admitPeers.map(toHex) }),
        ...(opts.iceServers === undefined ? {} : { iceServers: opts.iceServers }),
      },
    },
  });
  return { shell, transport: transport!, identity: opts.identity };
}

/** A node stood up for storage and the seedstore bundle installed on it, in one call. A
 *  node whose install fails is closed again. */
export async function bootStorageNode(
  standUp: StandUp, opts: StorageRuntimeOptions & Omit<StorageNodeOptions, "runtime">,
): Promise<StorageNode> {
  const runtime = await storageRuntime(standUp, opts);
  try {
    return await StorageNode.create({ ...opts, runtime });
  } catch (err) {
    runtime.shell.close();
    throw err;
  }
}
