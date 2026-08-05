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
// The old LatencyNetwork sat at the wire-frame level of the old net-link transport
// (req/res frames with a corr header). The transport is now a signed bundle running
// in its own confined realm, so the app-level request structure is no longer
// visible at the frame boundary — but it IS visible at the driver's request seam:
// the storage guest's net/send resolves to the TransportHost's `request()`, and
// the payload's first byte is the app's MsgType (HAVE/OFFER/FETCH/STORE). So this
// wrapper stands on the driver and counts/delays exactly the app requests the old
// frame-level one did: every request an initiator issues crosses ITS driver, so
// wrapping the nodes (or just the owner) captures the OFFER/STORE/FETCH batching.
//
// One request direction is delayed (the caller's outbound), which models a
// per-request RTT well enough for the round-trip economy the tests pin; the
// transport's own stall clock runs on the wire, unaffected.

import { LoopbackNetwork } from "../build/host/loopback.js";

const TYPE_HAVE = 1; // MsgType.HAVE — discovery fan-out, excluded from the "work" signal

export class LatencyNetwork {
  constructor(delayMs = 2) {
    this.delayMs = delayMs;
    this.fabric = new LoopbackNetwork();
    this.reset();
  }

  // ── LoopbackNetwork passthrough (createConnectedCohort + offline control) ──
  view(peerId) { return this.fabric.view(peerId); }
  setOnline(peerId, online) { this.fabric.setOnline(peerId, online); }
  isOnline(peerId) { return this.fabric.isOnline(peerId); }
  close() { this.fabric.close(); }

  /** Wrap ONE node's transport driver (StorageNode.net) so its outbound
   *  requests are delayed and counted by MsgType. `payload[0]` is the app's
   *  message type (§18); the driver's request() is where the guest's NET_SEND
   *  resolves. */
  wrap(driver) {
    const net = this;
    const origRequest = driver.request.bind(driver);
    driver.request = (to, proto, payload) => {
      const type = payload?.[0];
      net.track(type);
      net.begin(type);
      return new Promise((resolve, reject) => {
        setTimeout(() => {
          origRequest(to, proto, payload).then(
            (r) => { net.end(type); resolve(r); },
            (e) => { net.end(type); reject(e); },
          );
        }, this.delayMs);
      });
    };
  }

  /** Wrap every node's driver. */
  wrapAll(nodes) { for (const n of nodes) this.wrap(n.net); }

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
