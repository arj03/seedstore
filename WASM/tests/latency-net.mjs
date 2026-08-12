// A LoopbackNetwork (host/loopback.ts) that injects a fixed per-request delay
// into the transport driver, plus instrumentation of how many requests are in
// flight at once. This is the piece every benchmark in the repo was missing.
//
// Why it matters: the LoopbackNetwork delivers channel pairs on a queueMicrotask —
// it models a link with *zero* latency. bench.mjs / bench-wasm.mjs measure only the
// RS codec + crypto compute, and the integration tests run on that same loopback,
// so a PUT that issues ~1,280 *serial* round trips completes in ~0 ms in every
// test. The cost that actually bit us on a real cross-machine cohort — wall-clock
// = round-trip-count × RTT — was therefore invisible to the whole suite. Give the
// link a real RTT and it shows up.
//
// WHERE it stands has moved twice, and the current place is the last one available.
// It began at the wire-frame level of the old net-link transport (req/res frames with a
// corr header), then moved to the driver's `request()` seam. Both are gone: the wire
// below is the transport bundle's record layer, so a frame is ciphertext, and the driver
// has no request face at all — an app's send is a call to the id the transport claims and
// leaves from inside the guest's realm (seedkernel §12.10).
//
// What is left, and what this uses, is the RECEIVING shell's own inbound seam:
// `createShell({ answer })`, consulted on each arriving frame before the routing table.
// There the request is plaintext and attributed — `payload[0]` is the app's MsgType
// (§18) — so it counts exactly the requests the frame-level version did, and it sees
// them settle, because it dispatches them itself and hands the same promise back.
//
// The delay is applied on arrival rather than on the caller's outbound side. That models
// the same per-request RTT for the round-trip economy these tests pin (a request costs
// `delayMs` before its answer can begin), and it is now the only side an app request is
// visible from. The transport's own stall clock runs on the wire, unaffected.

import { LoopbackNetwork } from "../build/host/loopback.js";

const TYPE_HAVE = 1; // MsgType.HAVE — discovery fan-out, excluded from the "work" signal
const EMPTY = new Uint8Array(0);

export class LatencyNetwork {
  constructor(delayMs = 2) {
    this.delayMs = delayMs;
    this.fabric = new LoopbackNetwork();
    /** peerId → the shell whose inbound frames this harness times. */
    this.shells = new Map();
    this.reset();
  }

  // ── LoopbackNetwork passthrough (createConnectedCohort + offline control) ──
  view(peerId) { return this.fabric.view(peerId); }
  setOnline(peerId, online) { this.fabric.setOnline(peerId, online); }
  isOnline(peerId) { return this.fabric.isOnline(peerId); }
  close() { this.fabric.close(); }

  /** The `answer` hook for one node, handed to its shell at construction
   *  (host/cluster.ts) because that is when a shell's inbound seam is fixed.
   *
   *  It cannot dispatch until `wrapAll` has told it which shell it belongs to — the node
   *  does not exist yet at this point — so until then it answers `null` and the frame
   *  takes the ordinary route, untimed. That window covers the cohort's own wiring
   *  (the handshakes), which is not app traffic and was never counted. */
  answerFor(peerId) {
    const net = this;
    return (from, proto, payload) => {
      const shell = net.shells.get(peerId);
      if (!shell) return null;
      const type = payload?.[0];
      net.track(type);
      net.begin(type);
      return new Promise((resolve) => setTimeout(resolve, net.delayMs))
        .then(() => shell.dispatch(from, proto, payload) ?? EMPTY)
        .then(
          (r) => { net.end(type); return r; },
          (e) => { net.end(type); throw e; },
        );
    };
  }

  /** Start timing: register each node's shell, which is what its `answer` hook
   *  dispatches through. Called after the cohort is connected, so the handshake traffic
   *  that built it is not counted as app requests. */
  wrapAll(nodes) { for (const n of nodes) this.shells.set(n.peerId, n.shell); }

  /** Zero the concurrency counters between measured runs. */
  reset() {
    this.inflight = 0;          // control requests sent but not yet answered
    this.maxInflight = 0;       // peak of the above (all request types)
    this.inflightWork = 0;      // ditto, excluding the have/want fan-out
    this.maxInflightWork = 0;   // the concurrency the put/get window drove
    this.requests = 0;          // total control requests issued
    this.byType = {};           // count per MsgType — OFFER/FETCH batching shows up here
    this.inflightByType = {};   // current in-flight per MsgType
    this.maxInflightByType = {}; // peak in-flight per MsgType — isolates one path's pipeline (e.g. STORE)
  }

  track(type) {
    if (type === undefined) return;
    this.requests++;
    this.byType[type] = (this.byType[type] ?? 0) + 1;
  }
  begin(type) {
    if (type === undefined) return;
    if (++this.inflight > this.maxInflight) this.maxInflight = this.inflight;
    if (type !== TYPE_HAVE && ++this.inflightWork > this.maxInflightWork) this.maxInflightWork = this.inflightWork;
    const cur = this.inflightByType[type] = (this.inflightByType[type] ?? 0) + 1;
    if (cur > (this.maxInflightByType[type] ?? 0)) this.maxInflightByType[type] = cur;
  }
  end(type) {
    if (type === undefined) return;
    this.inflight--;
    if (type !== TYPE_HAVE) this.inflightWork--;
    this.inflightByType[type]--;
  }
}
