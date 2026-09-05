// reputation WASM tests (§13): decayed per-peer reciprocity counters.

import { readFileSync } from "node:fs";

import { ReputationClient } from "./reputation-client.mjs";
import { ensureSodium, newKey, paths } from "./helpers.mjs";
import { encodeObserveReq, decodeObserveResp } from "../build/host/reputation-core.js";

const DAY = 24 * 3600 * 1000;

export async function run(t) {
  await ensureSodium();
  const rep = await ReputationClient.load(new Uint8Array(readFileSync(paths.reputation)));

  t.group("reputation: batched outcomes equal sequential observations, including decay");
  {
    const peer = newKey().publicKey;
    const start = 1_000_000_000_000;
    for (const [passes, misses, elapsed] of [[7, 3, 0], [300, 5, 7 * DAY], [0, 9, 28 * DAY]]) {
      rep.reset();
      for (let i = 0; i < 8; i++) rep.observe(peer, start, true);
      for (let i = 0; i < 2; i++) rep.observe(peer, start, false);
      const now = start + elapsed;
      for (let i = 0; i < passes; i++) rep.observe(peer, now, true);
      for (let i = 0; i < misses; i++) rep.observe(peer, now, false);
      const expected = rep.peers.get(rep.peerHex(peer));
      const req = encodeObserveReq(8, 2, start, now, passes, misses);
      t.eq(rep.exports.handle(rep.write(req)), 32, "batched observation returns the full state");
      const actual = decodeObserveResp(new Uint8Array(rep.exports.memory.buffer, rep.scratch, 32));
      t.ok(Math.abs(actual.serve - expected.serve) < 1e-10 && Math.abs(actual.miss - expected.miss) < 1e-10,
        `${passes} passes and ${misses} misses retain every observation after decay`);
      t.eq(actual.last, now, "batch records its observation time");
      t.ok(Math.abs(actual.score - rep.score(peer, now)) < 1e-10, "batch and sequential scores agree");
      t.eq(rep.exports.handle(rep.write(req.subarray(0, 40))), 0, "a truncated batch is rejected");
    }
  }

  t.group("reputation: passes raise, misses penalize (§13.1)");
  {
    rep.reset();
    const good = newKey().publicKey;
    const bad = newKey().publicKey;
    const t0 = 1_000_000_000_000;
    for (let i = 0; i < 5; i++) rep.observe(good, t0, true);
    rep.observe(bad, t0, true);
    rep.observe(bad, t0, false);
    rep.observe(bad, t0, false);
    const sGood = rep.score(good, t0);
    const sBad = rep.score(bad, t0);
    t.ok(sGood > sBad, `good citizen outranks unreliable holder (${sGood.toFixed(2)} > ${sBad.toFixed(2)})`);
    t.ok(sBad < 0, "two misses against one pass yields a negative score");
    t.eq(rep.count(), 2, "two peers tracked");
  }

  t.group("reputation: score decays with time toward zero (§13.1 recency)");
  {
    rep.reset();
    const peer = newKey().publicKey;
    const t0 = 1_000_000_000_000;
    for (let i = 0; i < 8; i++) rep.observe(peer, t0, true);
    const fresh = rep.score(peer, t0);
    const afterWeek = rep.score(peer, t0 + 7 * DAY);   // one half-life
    const afterMonth = rep.score(peer, t0 + 28 * DAY); // four half-lives
    t.ok(Math.abs(afterWeek - fresh / 2) < 0.01, `~halves after one half-life (${afterWeek.toFixed(2)} ≈ ${(fresh / 2).toFixed(2)})`);
    t.ok(afterMonth < afterWeek && afterMonth < fresh / 8 + 0.01, "keeps decaying — a peer that stops serving fades");
  }

  t.group("reputation: unknown peer scores zero");
  {
    rep.reset();
    const stranger = newKey().publicKey;
    t.eq(rep.score(stranger, 1_000_000_000_000), 0, "never-seen peer has zero standing");
    t.eq(rep.count(), 0, "scoring a stranger is read-only — it never enters the peer set");
  }

  t.group("reputation: stale peers are pruned when the set grows (bounded state)");
  {
    rep.reset();
    const stale = newKey().publicKey;
    const t0 = 1_000_000_000_000;
    rep.observe(stale, t0, true); // single observation → mass 1.0
    t.eq(rep.count(), 1, "one peer tracked after first observe");
    const fresh = newKey().publicKey;
    const tLater = t0 + 120 * DAY; // > 16 half-lives (112 days) past t0 — mass has decayed below 2^-16
    rep.observe(fresh, tLater, true); // appending a NEW peer triggers a prune pass
    t.eq(rep.count(), 1, "the decayed-away stale peer was evicted when a new peer arrived");
    t.eq(rep.score(stale, tLater), 0, "the pruned peer is scored as never seen");
  }

  t.group("reputation: independent per-peer state (Sybil-local, §13)");
  {
    rep.reset();
    const a = newKey().publicKey, b = newKey().publicKey;
    const t0 = 1_000_000_000_000;
    rep.observe(a, t0, true); rep.observe(a, t0, true);
    rep.observe(b, t0, true);
    t.ok(rep.score(a, t0) > rep.score(b, t0), "scores are per-peer, only from witnessed events");
  }
}
