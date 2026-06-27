// reputation WASM tests (§13): decayed per-peer reciprocity counters.

import { readFileSync } from "node:fs";

import { ReputationClient } from "./reputation-client.mjs";
import { ensureSodium, newKey, paths } from "./helpers.mjs";

const DAY = 24 * 3600 * 1000;

export async function run(t) {
  await ensureSodium();
  const rep = await ReputationClient.load(new Uint8Array(readFileSync(paths.reputation)));

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
