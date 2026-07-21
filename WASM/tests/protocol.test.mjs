// The batched OFFER / FETCH wire (host/protocol.ts) and the holder's batched
// admission (the confined guest's admitBatch). Two halves:
//   - pure encode/decode round trips, including the self-delimiting offer entries,
//     the per-block accept mask, and FETCH responses with present/absent blocks;
//   - the holder evaluating a whole OFFER batch at once: the §6 sibling rule
//     declines the second of a sibling PAIR offered together, and the §14 quota
//     declines the tail once the cumulative budget is spent. STORE re-checks each
//     block, so this batched pre-check never has to be the only gate — but it must
//     still be correct.
//
// Every offered or stored block carries its author-signed chunk descriptor (§4.3) —
// there is no descriptor-less entry to admit, on the wire or in the holder, and the
// tests below cover both refusals.

import {
  encodeOfferBatch, decodeOfferBatch, encodeMask, decodeMask,
  encodeStoreBatch, decodeStoreBatch,
  encodeFetchBatchReq, decodeFetchBatchReq, encodeFetchBatchRes, decodeFetchBatchRes,
  FETCH_UNANSWERED, MsgType,
} from "../build/host/protocol.js";
import { signDescriptor } from "../build/host/manifest.js";
import {
  loadSodium, loadWasmBytes, LoopbackNetwork, createConnectedCohort,
} from "../build/host/node.js";
import { bytesEqual, toHex } from "../build/host/util.js";
import { plantBlock } from "./helpers.mjs";

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
      { blockId: id(1), descriptor: bytes(168, 9) },
      { blockId: id(2), descriptor: bytes(136, 5) },
      { blockId: id(3), descriptor: bytes(40, 3) },
    ];
    const back = decodeOfferBatch(encodeOfferBatch(offers));
    t.eq(back.length, offers.length, "every offer survives the batch");
    let same = true;
    for (let i = 0; i < offers.length; i++) {
      same &&= bytesEqual(back[i].blockId, offers[i].blockId) && bytesEqual(back[i].descriptor, offers[i].descriptor);
    }
    t.ok(same, "blockId and the variable-length descriptor round-trip — an entry carries no size, the descriptor's signed blockSize is the geometry");

    const mask = [true, false, true];
    t.ok(decodeMask(encodeMask(mask)).every((v, i) => v === mask[i]), "accept-mask round-trips");
  }

  t.group("STORE batch + stored-mask round-trip the wire");
  {
    const stores = [
      { blockId: id(40), descriptor: bytes(168, 2), bytes: bytes(1000, 1) },
      { blockId: id(41), descriptor: bytes(136, 5), bytes: bytes(7, 5) },
      { blockId: id(42), descriptor: bytes(40, 4), bytes: bytes(50000, 3) },
    ];
    const back = decodeStoreBatch(encodeStoreBatch(stores));
    t.eq(back.length, stores.length, "every store survives the batch");
    let same = true;
    for (let i = 0; i < stores.length; i++) {
      same &&= bytesEqual(back[i].blockId, stores[i].blockId) && bytesEqual(back[i].bytes, stores[i].bytes)
        && bytesEqual(back[i].descriptor, stores[i].descriptor);
    }
    t.ok(same, "blockId, descriptor, and variable-length bytes all round-trip");
    const mask = [true, true, false];
    t.ok(decodeMask(encodeMask(mask)).every((v, i) => v === mask[i]), "stored-mask round-trips");
  }

  // The descriptor is mandatory on the wire, not merely expected: §4.3 says every peer
  // that accepts a block first verifies its descriptor, which only holds if a
  // descriptor-less entry cannot be expressed. Both decoders reject one as malformed —
  // hand-framed here, since the encoders can no longer produce it.
  t.group("the wire refuses a descriptor-less entry outright (§4.3)");
  {
    const offerEntry = new Uint8Array(4 + 32 + 4); // [count 1][blockId][dlen 0]
    offerEntry[3] = 1;
    offerEntry.set(id(7), 4);
    let threw = false;
    try { decodeOfferBatch(offerEntry); } catch { threw = true; }
    t.ok(threw, "an OFFER entry with a zero-length descriptor is a decode error");

    const storeEntry = new Uint8Array(4 + 32 + 4 + 4); // [count 1][blockId][dlen 0][blen 0]
    storeEntry[3] = 1;
    storeEntry.set(id(7), 4);
    threw = false;
    try { decodeStoreBatch(storeEntry); } catch { threw = true; }
    t.ok(threw, "a STORE entry with a zero-length descriptor is a decode error");
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
        { blockId: sib0, descriptor: env },
        { blockId: sib1, descriptor: env }, // sibling of sib0 — must not both pass
      ];
      const mask = decodeMask(await a.transport.request(b.peerId, MsgType.OFFER, encodeOfferBatch(offers)));
      t.eq(mask[0], true, "the holder accepts the first block of the chunk");
      t.eq(mask[1], false, "it declines the second — a sibling provisionally accepted in the same batch (§6)");
    } finally { a.close(); b.close(); }
  }

  // Quota reaches the holder as a sibling option, not through the typed StorageConfig —
  // but a seedkernel shell spells the same operator knob INSIDE its boot config, and
  // both drivers appear in one file (holder-guest.test.mjs). Getting it wrong here used
  // to be silent: the node would run on the 64 MiB default while the caller believed it
  // had set a budget, so a quota test could "pass" without testing a quota at all.
  t.group("a StorageConfig rejects unknown keys instead of ignoring them");
  {
    const net = new LoopbackNetwork();
    let quotaErr = null, typoErr = null;
    try {
      await createConnectedCohort({ count: 1, network: net, sodium, wasm, config: { quota: 500 }, timeoutMs: TIMEOUT });
    } catch (e) { quotaErr = e; }
    t.ok(quotaErr !== null, "config: { quota } is refused — quota is the sibling option (or a shell's boot config)");
    t.ok(quotaErr && /sibling option/.test(quotaErr.message), "the error says where quota actually goes");
    try {
      await createConnectedCohort({ count: 1, network: net, sodium, wasm, config: { windowTarget: 1 }, timeoutMs: TIMEOUT });
    } catch (e) { typoErr = e; }
    t.ok(typoErr !== null, "a misspelled knob (windowTarget) is refused, not silently defaulted");
    t.ok(typoErr && /windowTargetBytes/.test(typoErr.message), "the error lists the real key names");
  }

  t.group("a holder spends its quota cumulatively across the batch");
  {
    const net = new LoopbackNetwork();
    // Three unrelated one-block chunks (k=1, m=0), so the sibling rule never fires and
    // this is a pure §14 quota decision. The holder charges what it will commit — the
    // 100-byte block plus its 136-byte descriptor sidecar = 236 each — reading the size
    // from the signed geometry, never from the offer. Room for two, not three.
    const [a, b] = await createConnectedCohort({ count: 2, network: net, sodium, wasm, quota: 500, timeoutMs: TIMEOUT });
    try {
      const solo = (blockId) => signDescriptor(
        sodium, { k: 1, m: 0, blockSize: 100, blockIds: [blockId] }, a.identity.publicKey, a.identity.privateKey,
      );
      const offers = [id(30), id(31), id(32)].map((blockId) => ({ blockId, descriptor: solo(blockId) }));
      t.eq(offers[0].descriptor.length, 136, "a one-block descriptor envelope is [pk 32][sig 64][core 40]");
      const mask = decodeMask(await a.transport.request(b.peerId, MsgType.OFFER, encodeOfferBatch(offers)));
      t.eq(mask[0], true, "first block fits the quota (236 ≤ 500)");
      t.eq(mask[1], true, "second still fits (cumulative 472 ≤ 500)");
      t.eq(mask[2], false, "third declined — the running budget is spent (§14)");
    } finally { a.close(); b.close(); }
  }

  t.group("a holder commits a batched STORE block-by-block (quota + sibling)");
  {
    const net = new LoopbackNetwork();
    // Room for one 1000-byte block + its 136-byte descriptor, not two.
    const [a, b] = await createConnectedCohort({ count: 2, network: net, sodium, wasm, quota: 1500, timeoutMs: TIMEOUT });
    try {
      const b0 = bytes(1000, 1), b1 = bytes(1000, 2);
      const i0 = b.crypto.hash(b0), i1 = b.crypto.hash(b1); // content-addressed (acceptStore hashes)
      const solo = (blockId) => signDescriptor(
        sodium, { k: 1, m: 0, blockSize: 1000, blockIds: [blockId] }, a.identity.publicKey, a.identity.privateKey,
      );
      const stored = decodeMask(await a.transport.request(b.peerId, MsgType.STORE, encodeStoreBatch([
        { blockId: i0, descriptor: solo(i0), bytes: b0 },
        { blockId: i1, descriptor: solo(i1), bytes: b1 }, // would overrun the 1500-byte budget
      ])));
      t.eq(stored[0], true, "first block stored");
      t.eq(stored[1], false, "second rejected — its predecessor in the batch already spent the quota (§14)");
      t.ok(b.store.has(i0) && !b.store.has(i1), "only the first block actually committed to the store");
    } finally { a.close(); b.close(); }
  }

  // The regression this whole invariant exists for: the descriptor is what binds a
  // block to an author-signed chunk, so without a real one a cohort peer could push
  // arbitrary bytes into a holder's store with only the §14 quota in the way — past
  // the §6 sibling rule and past §4.3 entirely.
  t.group("a holder refuses bytes whose descriptor doesn't verify (§4.3 admission)");
  {
    const net = new LoopbackNetwork();
    const [a, b] = await createConnectedCohort({ count: 2, network: net, sodium, wasm, timeoutMs: TIMEOUT });
    try {
      const junk = bytes(100, 8);
      const jid = b.crypto.hash(junk); // correctly content-addressed — only the descriptor is bad
      const stored = decodeMask(await a.transport.request(b.peerId, MsgType.STORE, encodeStoreBatch([
        { blockId: jid, descriptor: bytes(136, 1), bytes: junk }, // unsigned garbage of descriptor shape
      ])));
      t.eq(stored[0], false, "STORE declined — the descriptor carries no valid author signature");
      t.ok(!b.store.has(jid), "nothing committed to the store");

      // Signed, but for a DIFFERENT chunk: the signature verifies and yet this block is
      // not one of its block_ids (§4.3's block_id ∈ block_ids check).
      const other = signDescriptor(
        sodium, { k: 1, m: 0, blockSize: 100, blockIds: [id(77)] }, a.identity.publicKey, a.identity.privateKey,
      );
      const stored2 = decodeMask(await a.transport.request(b.peerId, MsgType.STORE, encodeStoreBatch([
        { blockId: jid, descriptor: other, bytes: junk },
      ])));
      t.eq(stored2[0], false, "STORE declined — validly signed, but the block is not of that chunk");
      t.ok(!b.store.has(jid), "still nothing committed");

      // Signed, of this chunk, but the bytes disagree with the signed blockSize: the
      // geometry is the descriptor's, so bytes that aren't blockSize long are not the
      // block that was admitted (this is what makes OFFER's old size field redundant).
      const wrongSize = signDescriptor(
        sodium, { k: 1, m: 0, blockSize: 99, blockIds: [jid] }, a.identity.publicKey, a.identity.privateKey,
      );
      const stored3 = decodeMask(await a.transport.request(b.peerId, MsgType.STORE, encodeStoreBatch([
        { blockId: jid, descriptor: wrongSize, bytes: junk }, // 100 bytes vs a signed blockSize of 99
      ])));
      t.eq(stored3[0], false, "STORE declined — the bytes in hand aren't the descriptor's blockSize");
      t.ok(!b.store.has(jid), "still nothing committed");
    } finally { a.close(); b.close(); }
  }

  t.group("a holder serves a batched FETCH, present and absent together");
  {
    const net = new LoopbackNetwork();
    const [a, b] = await createConnectedCohort({ count: 2, network: net, sodium, wasm, timeoutMs: TIMEOUT });
    try {
      const held = bytes(777, 4);
      const heldId = b.crypto.hash(held);
      plantBlock(b.fs, toHex(heldId), held); // seed the holder directly, bypassing the protocol
      const absentId = id(99);

      const res = decodeFetchBatchRes(await a.transport.request(b.peerId, MsgType.FETCH, encodeFetchBatchReq([heldId, absentId])));
      t.eq(res.length, 2, "one entry per requested id");
      t.ok(res[0] && bytesEqual(res[0], held), "the held block comes back in the batch");
      t.eq(res[1], null, "the absent block comes back null — the reader falls to another holder");
      t.ok(toHex(b.crypto.hash(res[0])) === toHex(heldId), "served bytes are content-addressed to their id (§4.2)");
    } finally { a.close(); b.close(); }
  }
}
