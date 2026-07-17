// The batched OFFER / FETCH wire (host/protocol.ts) and the holder's batched
// admission (StorageNode.admitBatch). Two halves:
//   - pure encode/decode round trips, including the self-delimiting offer entries,
//     the per-block accept mask, and FETCH responses with present/absent blocks;
//   - the holder evaluating a whole OFFER batch at once: the §6 sibling rule
//     declines the second of a sibling PAIR offered together, and the §14 quota
//     declines the tail once the cumulative budget is spent. STORE re-checks each
//     block, so this batched pre-check never has to be the only gate — but it must
//     still be correct.

import {
  encodeOfferBatch, decodeOfferBatch, encodeOfferMask, decodeOfferMask,
  encodeStoreBatch, decodeStoreBatch, encodeStoreMask, decodeStoreMask,
  encodeFetchBatchReq, decodeFetchBatchReq, encodeFetchBatchRes, decodeFetchBatchRes,
  FETCH_UNANSWERED, MsgType,
} from "../build/host/protocol.js";
import { signDescriptor } from "../build/host/manifest.js";
import {
  loadSodium, loadWasmBytes, LoopbackNetwork, createConnectedCohort,
} from "../build/host/node.js";
import { bytesEqual, toHex } from "../build/host/util.js";

const TIMEOUT = 200;

function id(seed) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (i * 7 + seed * 13) & 255;
  return out;
}
function bytes(n, seed) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed * 7) & 255;
  return out;
}

export async function run(t) {
  t.group("OFFER batch + accept-mask round-trip the wire");
  {
    const offers = [
      { blockId: id(1), size: 1000, descriptor: bytes(168, 9) },
      { blockId: id(2), size: 0, descriptor: null },              // bare replica (manifest)
      { blockId: id(3), size: 0xfffff, descriptor: bytes(40, 3) },
    ];
    const back = decodeOfferBatch(encodeOfferBatch(offers));
    t.eq(back.length, offers.length, "every offer survives the batch");
    let same = true;
    for (let i = 0; i < offers.length; i++) {
      same &&= bytesEqual(back[i].blockId, offers[i].blockId) && back[i].size === offers[i].size
        && (offers[i].descriptor === null ? back[i].descriptor === null : bytesEqual(back[i].descriptor, offers[i].descriptor));
    }
    t.ok(same, "blockId, size, and (variable-length, possibly null) descriptor all round-trip");

    const mask = [true, false, true];
    t.ok(decodeOfferMask(encodeOfferMask(mask)).every((v, i) => v === mask[i]), "accept-mask round-trips");
  }

  t.group("STORE batch + stored-mask round-trip the wire");
  {
    const stores = [
      { blockId: id(40), descriptor: bytes(168, 2), bytes: bytes(1000, 1) },
      { blockId: id(41), descriptor: null, bytes: bytes(7, 5) },          // bare replica, tiny
      { blockId: id(42), descriptor: bytes(40, 4), bytes: bytes(50000, 3) },
    ];
    const back = decodeStoreBatch(encodeStoreBatch(stores));
    t.eq(back.length, stores.length, "every store survives the batch");
    let same = true;
    for (let i = 0; i < stores.length; i++) {
      same &&= bytesEqual(back[i].blockId, stores[i].blockId) && bytesEqual(back[i].bytes, stores[i].bytes)
        && (stores[i].descriptor === null ? back[i].descriptor === null : bytesEqual(back[i].descriptor, stores[i].descriptor));
    }
    t.ok(same, "blockId, (possibly null) descriptor, and variable-length bytes all round-trip");
    const mask = [true, true, false];
    t.ok(decodeStoreMask(encodeStoreMask(mask)).every((v, i) => v === mask[i]), "stored-mask round-trips");
  }

  t.group("FETCH batch req + res round-trip, present / absent / unanswered blocks");
  {
    const ids = [id(10), id(11), id(12), id(13)];
    t.ok(decodeFetchBatchReq(encodeFetchBatchReq(ids)).every((x, i) => bytesEqual(x, ids[i])), "id list round-trips");

    // A genuine miss (null → ABSENT), a held-but-capped block (FETCH_UNANSWERED, re-ask),
    // and two present blocks — every found-byte state on one wire.
    const blocks = [bytes(500, 1), null, FETCH_UNANSWERED, bytes(32 * 1024, 2)];
    const back = decodeFetchBatchRes(encodeFetchBatchRes(blocks));
    t.eq(back.length, 4, "one entry per requested id");
    t.ok(back[0] && bytesEqual(back[0], blocks[0]), "present block round-trips");
    t.eq(back[1], null, "absent block decodes as null");
    t.eq(back[2], FETCH_UNANSWERED, "unanswered block decodes as the re-ask marker");
    t.ok(back[3] && bytesEqual(back[3], blocks[3]), "second present (large) block round-trips");
  }

  // ── holder-side batched admission (StorageNode.admitBatch over the transport) ──
  const sodium = await loadSodium();
  const wasm = await loadWasmBytes();

  t.group("a holder evaluates the sibling rule over the whole OFFER batch");
  {
    const net = new LoopbackNetwork();
    const [a, b] = await createConnectedCohort({ count: 2, network: net, sodium, wasm, timeoutMs: TIMEOUT });
    try {
      // Two blocks of ONE chunk (siblings, §6), signed so the holder admits them.
      const sib0 = id(20), sib1 = id(21);
      const env = signDescriptor(sodium, { k: 1, m: 1, blockSize: 100, blockIds: [sib0, sib1] }, a.identity.publicKey, a.identity.privateKey);
      const offers = [
        { blockId: sib0, size: 100, descriptor: env },
        { blockId: sib1, size: 100, descriptor: env }, // sibling of sib0 — must not both pass
      ];
      const mask = decodeOfferMask(await a.transport.request(b.peerId, MsgType.OFFER, encodeOfferBatch(offers)));
      t.eq(mask[0], true, "the holder accepts the first block of the chunk");
      t.eq(mask[1], false, "it declines the second — a sibling provisionally accepted in the same batch (§6)");
    } finally { a.close(); b.close(); }
  }

  t.group("a holder spends its quota cumulatively across the batch");
  {
    const net = new LoopbackNetwork();
    // Room for two 100-byte blocks, not three (the manifest path: no descriptor,
    // so this is a pure §14 quota decision).
    const [a, b] = await createConnectedCohort({ count: 2, network: net, sodium, wasm, quota: 250, timeoutMs: TIMEOUT });
    try {
      const offers = [
        { blockId: id(30), size: 100, descriptor: null },
        { blockId: id(31), size: 100, descriptor: null },
        { blockId: id(32), size: 100, descriptor: null }, // would overrun the 250-byte budget
      ];
      const mask = decodeOfferMask(await a.transport.request(b.peerId, MsgType.OFFER, encodeOfferBatch(offers)));
      t.eq(mask[0], true, "first block fits the quota");
      t.eq(mask[1], true, "second still fits (cumulative 200 ≤ 250)");
      t.eq(mask[2], false, "third declined — the running budget is spent (§14)");
    } finally { a.close(); b.close(); }
  }

  t.group("a holder commits a batched STORE block-by-block (quota + sibling)");
  {
    const net = new LoopbackNetwork();
    // Room for one 1000-byte block, not two.
    const [a, b] = await createConnectedCohort({ count: 2, network: net, sodium, wasm, quota: 1500, timeoutMs: TIMEOUT });
    try {
      const b0 = bytes(1000, 1), b1 = bytes(1000, 2);
      const i0 = b.crypto.hash(b0), i1 = b.crypto.hash(b1); // content-addressed (acceptStore hashes)
      const stored = decodeStoreMask(await a.transport.request(b.peerId, MsgType.STORE, encodeStoreBatch([
        { blockId: i0, descriptor: null, bytes: b0 },
        { blockId: i1, descriptor: null, bytes: b1 }, // would overrun the 1500-byte budget
      ])));
      t.eq(stored[0], true, "first block stored");
      t.eq(stored[1], false, "second rejected — its predecessor in the batch already spent the quota (§14)");
      t.ok(b.store.has(i0) && !b.store.has(i1), "only the first block actually committed to the store");
    } finally { a.close(); b.close(); }
  }

  t.group("a holder serves a batched FETCH, present and absent together");
  {
    const net = new LoopbackNetwork();
    const [a, b] = await createConnectedCohort({ count: 2, network: net, sodium, wasm, timeoutMs: TIMEOUT });
    try {
      const held = bytes(777, 4);
      const heldId = b.crypto.hash(held);
      b.store.put(heldId, held, null); // plant a block directly on the holder
      const absentId = id(99);

      const res = decodeFetchBatchRes(await a.transport.request(b.peerId, MsgType.FETCH, encodeFetchBatchReq([heldId, absentId])));
      t.eq(res.length, 2, "one entry per requested id");
      t.ok(res[0] && bytesEqual(res[0], held), "the held block comes back in the batch");
      t.eq(res[1], null, "the absent block comes back null — the reader falls to another holder");
      t.ok(toHex(b.crypto.hash(res[0])) === toHex(heldId), "served bytes are content-addressed to their id (§4.2)");
    } finally { a.close(); b.close(); }
  }
}
