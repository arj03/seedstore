// LoopbackNetwork — the in-process network fabric for tests and single-process
// demos. The transport is a signed bundle driven by the shared TransportHost over
// the ChannelFactory seam (seedkernel §12.6); this file is that seam (a loopback
// fabric, one `view()` per node) plus offline control. Vendored here
// because seedkernel moved this test/demo infra out of its own runtime.
//
// Going offline kills every link a node holds (dialed or accepted), so the
// transport forgets it and a later dial draws a dead channel (ECONNREFUSED-like) —
// requests then fail within the transport's stall window like a real offline peer.
// Nothing brings a peer back online.

// A destination is opaque to everything above the factory (seedkernel §12.10), so the
// seedkernel's own parser takes one apart here rather than a second copy of the grammar:
// this fabric routes `tcp://` and `ws://` by port, and nothing else (`wss://` asks
// for a TLS stack no in-process pair has).
import { parseDest } from "seedkernel-wasm/peer-addr";
import type { ChannelFactory, RawLink } from "seedkernel-wasm/socket-seam";

/** One end of an in-process socket pair. Delivery is asynchronous (a microtask, or a
 *  `setTimeout(delayMs)` when the fabric models a latency-bearing link), mirroring a
 *  real socket; closing one end fires the other's onClose — the close semantics of
 *  MessageChannel's fail() path, which is how a real channel reports the far side
 *  going away. */
class LoopbackChannel implements RawLink {
  /** A socket pair with `send` as the boundary. In byte-stream mode a send is
   *  split into `chunkBytes`-sized deliveries for the guest to reassemble. */
  readonly stream: boolean;
  peer: LoopbackChannel | null = null;
  msg: ((bytes: Uint8Array) => void) | null = null;
  cls: (() => void) | null = null;
  dead = false;
  readonly remoteAddr: string;
  /** Wire latency per delivered message (ms). 0 = the zero-latency fabric. */
  readonly delayMs: number;
  readonly chunkBytes: number;

  constructor(remoteAddr: string, delayMs = 0, chunkBytes = 0) {
    this.remoteAddr = remoteAddr;
    this.delayMs = delayMs;
    this.chunkBytes = chunkBytes;
    this.stream = chunkBytes > 0;
  }

  static pair(remoteAddr: string, delayMs = 0, chunkBytes = 0): [LoopbackChannel, LoopbackChannel] {
    const a = new LoopbackChannel(remoteAddr, delayMs, chunkBytes);
    const b = new LoopbackChannel(remoteAddr, delayMs, chunkBytes);
    a.peer = b;
    b.peer = a;
    return [a, b];
  }

  send(bytes: Uint8Array): void {
    if (this.dead) return;
    const p = this.peer;
    const step = this.chunkBytes > 0 ? this.chunkBytes : Math.max(1, bytes.length);
    const deliver = (chunk: Uint8Array) => {
      if (this.delayMs > 0) {
        setTimeout(() => { if (p && !p.dead) p.msg?.(chunk); }, this.delayMs);
      } else {
        queueMicrotask(() => { if (p && !p.dead) p.msg?.(chunk); });
      }
    };
    if (bytes.length === 0) {
      deliver(bytes);
      return;
    }
    for (let off = 0; off < bytes.length; off += step) {
      deliver(bytes.subarray(off, Math.min(bytes.length, off + step)));
    }
  }
  onData(cb: (bytes: Uint8Array) => void): void { this.msg = cb; }
  onClose(cb: () => void): void { this.cls = cb; }
  close(): void {
    if (this.dead) return;
    this.dead = true;
    const p = this.peer;
    queueMicrotask(() => { if (p && !p.dead) p.cls?.(); });
  }
  /** The far end went away / this end failed: notify our own onClose (the
   *  MessageChannel.fail() path — how a socket reports being cut). */
  kill(): void {
    if (this.dead) return;
    this.dead = true;
    this.cls?.();
  }
}

/** The in-process network: one socket fabric SHARED by every node in a process (like a
 *  real network), plus offline control. `view()` is one node's door into it. */
export class LoopbackNetwork {
  private readonly listeners = new Map<number, (channel: RawLink) => void>();
  private nextPort = 10000;
  /** Bound port → the peer that owns it (for offline dial refusal). */
  private readonly portOf = new Map<number, string>();
  private readonly offline = new Set<string>();
  /** Every live channel of a peer (dialed and accepted) — killed on offline. */
  private readonly links = new Map<string, LoopbackChannel[]>();

  /** `delayMs` > 0 makes every delivered message take `delayMs` ms to arrive — a
   *  wire-level round-trip latency (one request/response costs 2×delayMs), the model
   *  the latency/concurrency harnesses use now that the host's shell has no host
   *  side inbound seam to time against. */
  constructor(private readonly delayMs = 0, private readonly chunkBytes = 0) {}

  /** A per-node view of the fabric — hand it to a node as its `channels`. `listen` binds
   *  one port per address; framing selection belongs to the transport guest, so the
   *  factory says only which listener accepted, by its label. `close` unbinds only the
   *  ports this view bound: an in-place transport upgrade closing its driver must not
   *  unbind every other node sharing this fabric. */
  view(peerId: string): ChannelFactory {
    const mine: number[] = [];
    return {
      connect: (dest) => this.connect(peerId, dest),
      listen: async (addrs, onAccept) => addrs.map((a) => {
        const port = a.port > 0 ? a.port : this.nextPort++;
        if (this.listeners.has(port)) throw new Error("LoopbackNetwork: port already bound");
        this.listeners.set(port, (ch) => {
          this.track(peerId, ch as LoopbackChannel);
          onAccept(ch, { listener: a.label });
        });
        this.portOf.set(port, peerId);
        mine.push(port);
        return port;
      }),
      close: () => { for (const p of mine.splice(0)) this.listeners.delete(p); },
    };
  }

  /** Dial an opaque destination, as a real `ChannelFactory` does: this fabric speaks
   *  `tcp://host:port` and `ws://host:port`, and anything else it cannot route. The
   *  scheme is the DIALER's half of the framing decision (the acceptor's is the
   *  listener label `listen` hands out), so a ws dial has to name the ws port — the
   *  two ends would otherwise pick different codecs for the same pipe. */
  private connect(peerId: string, dest: string): RawLink | null {
    const d = parseDest(dest);
    if (!d || (d.scheme !== "tcp" && d.scheme !== "ws")) return null;
    // The destination's host is the "far end" both sides see — it is what the
    // half-open limiter buckets accepts by (the per-source cap; §12.6.2).
    const [dial, accepted] = LoopbackChannel.pair(d.host, this.delayMs, this.chunkBytes);
    const onAccept = this.listeners.get(d.port);
    const owner = this.portOf.get(d.port);
    if (!onAccept || (owner !== undefined && this.offline.has(owner))) {
      // A dead port, or an offline peer's: the channel fails at once on the DIAL side
      // (mirroring ECONNREFUSED → the socket's error/close events), so the transport
      // forgets the link instead of holding it until the deadline.
      queueMicrotask(() => dial.kill());
      return dial;
    }
    this.track(peerId, dial);
    queueMicrotask(() => onAccept(accepted));
    return dial;
  }

  /** Take a peer offline: its links die, and dials to it draw a dead channel. */
  setOffline(peerId: string): void {
    this.offline.add(peerId);
    for (const ch of this.links.get(peerId) ?? []) {
      try { ch.kill(); } catch { /* already gone */ }
    }
    this.links.delete(peerId);
  }

  isOnline(peerId: string): boolean { return !this.offline.has(peerId); }

  /** The shared fabric, for teardown. */
  close(): void { this.listeners.clear(); }

  private track(peerId: string, ch: LoopbackChannel): void {
    let list = this.links.get(peerId);
    if (!list) this.links.set(peerId, (list = []));
    list.push(ch);
  }
}
