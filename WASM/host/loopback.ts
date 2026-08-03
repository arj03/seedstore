// LoopbackNetwork — the in-process network fabric for tests and single-process
// demos (the successor of the old seedkernel LoopbackNetwork, which sat under a
// hand-rolled Transport). The transport is now a signed bundle driven by the
// shared TransportHost over the ChannelFactory seam (seedkernel §12.6): this file
// is that seam — a LoopbackChannels fabric, one `view()` per node — plus the
// online/offline control the storage tests and the in-page demo need.
//
// The old LoopbackNetwork had `setOnline(peerId, bool)`/`isOnline(peerId)` and
// dropped frames to/from an offline peer. Here a node going offline is made real:
// every link it holds (dialed or accepted) is killed, so its side of each
// authenticated channel closes and the transport forgets it, and a later dial to
// its port draws a dead channel (the ECONNREFUSED of the fabric's own dead-port
// dial). Requests to an offline peer then fail within the transport's stall
// window, exactly as a real offline peer would.
//
// There is no re-online in the tests (a node that returns boots a fresh
// transport), so going back online is only a bookkeeping toggle here.

import { LoopbackChannels } from "seedkernel-wasm/transport-host";

/** The structural RawChannel shape this file needs (socket-seam.ts is not an
 *  exported entry, so the shape is stated here rather than imported). */
export interface RawChannelLike {
  send(bytes: Uint8Array): void;
  onMessage(cb: (bytes: Uint8Array) => void): void;
  onClose(cb: () => void): void;
  close(graceful: boolean): void;
  allowLargeFrames?(): void;
  readonly remoteAddr?: string;
}

/** The structural ChannelFactory shape (socket-seam.ts `ChannelFactory`). */
export interface ChannelFactoryLike {
  connect(addr: { host: string; port: number; transport: "tcp" | "ws"; contactSecret?: Uint8Array }): RawChannelLike;
  listen(
    tcp: { host: string; port: number } | undefined,
    ws: { host: string; port: number } | undefined,
    onAccept: (channel: RawChannelLike) => void,
  ): Promise<{ port: number; wsPort: number }>;
  close(): void;
}

/** A channel that dies immediately — what a dial to an offline peer's port draws,
 *  mirroring the fabric's own dead-port dial (the dial side's onClose fires and
 *  the transport forgets the link before it ever authenticates). */
function deadChannel(): RawChannelLike {
  const cbHolder: { cb?: () => void } = {};
  queueMicrotask(() => cbHolder.cb?.());
  return {
    send: () => {},
    onMessage: () => {},
    onClose: (cb) => { cbHolder.cb = cb; },
    close: () => {},
    allowLargeFrames: () => {},
    remoteAddr: "offline",
  };
}

export class LoopbackNetwork {
  private readonly fabric = new LoopbackChannels();
  /** Bound port → the peer that owns it (for offline dial refusal). */
  private readonly portOf = new Map<number, string>();
  private readonly offline = new Set<string>();
  /** Every live channel of a peer (dialed and accepted) — killed on offline. */
  private readonly links = new Map<string, RawChannelLike[]>();

  /** The peers' bound ports, for dial wiring. A node binds at most one tcp and
   *  one ws port on the fabric. */
  portOfPeer(peerId: string): { port: number; wsPort: number } | null {
    let found: { port: number; wsPort: number } | null = null;
    for (const [port, owner] of this.portOf) {
      if (owner !== peerId) continue;
      if (!found) { found = { port, wsPort: 0 }; }
      else if (found.port !== port) { found.wsPort = port; }
    }
    return found;
  }

  /** A per-node view of the fabric — hand it to a node as its `channels`. */
  view(peerId: string): ChannelFactoryLike {
    const inner = this.fabric.view();
    const net = this;
    return {
      connect: (addr) => {
        if (addr.transport === "tcp" && net.isOfflinePort(addr.port)) return deadChannel();
        const ch = inner.connect(addr);
        net.track(peerId, ch);
        return ch;
      },
      listen: async (tcp, ws, onAccept) => {
        const r = await inner.listen(tcp, ws, (ch) => {
          net.track(peerId, ch);
          onAccept(ch);
        });
        if (r.port) net.portOf.set(r.port, peerId);
        if (r.wsPort) net.portOf.set(r.wsPort, peerId);
        return r;
      },
      close: () => inner.close(),
    };
  }

  /** Take a peer offline (its links die; dials to it draw nothing) or back online. */
  setOnline(peerId: string, online: boolean): void {
    if (online) {
      this.offline.delete(peerId);
      return;
    }
    this.offline.add(peerId);
    const links = this.links.get(peerId);
    if (links) {
      this.links.delete(peerId);
      for (const ch of links) {
        try { (ch as { kill?: () => void }).kill?.(); } catch { /* already gone */ }
      }
    }
  }

  isOnline(peerId: string): boolean { return !this.offline.has(peerId); }

  /** The shared fabric, for teardown. */
  close(): void { this.fabric.close(); }

  private isOfflinePort(port: number): boolean {
    const owner = this.portOf.get(port);
    return owner !== undefined && this.offline.has(owner);
  }

  private track(peerId: string, ch: RawChannelLike): void {
    let list = this.links.get(peerId);
    if (!list) this.links.set(peerId, (list = []));
    list.push(ch);
  }
}
