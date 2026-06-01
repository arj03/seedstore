# Seed store: a peer-to-peer storage layer for seedkernel

## 1. Introduction

Seed store is a peer-to-peer storage layer for [seedkernel](https://github.com/arj03/seedkernel). It lets any node donate whatever storage it has and store files across a set of peers, so that no single peer can make a file unavailable, peers can be offline for stretches without data loss, the system heals itself by moving data when redundancy drops, large files are sharded so size is bounded only by the swarm, and good citizens earn a verifiable reputation rather than a coin.

Seedkernel routes small signed messages and puts a hard size cap on each one, so bulk data lives outside the kernel and is referenced by a content hash. Seed store is that outside store: the kernel keeps routing names to handlers, the bytes never touch its dispatch path, and everything here is built from the pieces seedkernel already provides — a name to dispatch on, bytes that are a WASM handler, and an author who signed the install.

This design assumes a **closed, social network**: you store with and among peers you have a relationship with (friends, friends-of-friends, or an explicit storage group), not an open market of strangers. That assumption is what keeps the whole thing small — privacy and Sybil resistance come from the *shape* of the network rather than from added cryptographic machinery. The whole system is four ideas: **a social cohort, client-side encryption, content addressing, and a have/want exchange.**

**Design principles (inherited from the kernel, applied to storage):**

- The storage layer adds **no new kernel concepts**. It is bridges + app handlers + message names, gated by the existing capability and signature machinery.
- **Integrity comes from content addressing, not from signatures.** A block is named by its hash; a block either hashes to its name or it is discarded. This is what lets bulk transfer skip the per-message verify (§4).
- **Identity comes from the signature module.** A peer *is* its kernel pubkey. Reputation and storage receipts key on that one identity.
- **Redundancy is erasure coding, not replication.** Any *k* of *n* fragments reconstruct a chunk, so up to *n − k* holders can vanish with no data loss, at a fraction of replication's overhead.
- **Placement is by relationship, not by global address.** Fragments live on peers in your cohort, chosen by negotiation. Who holds what is discovered live from the cohort rather than pinned anywhere, and there is no global index — the absence of that index is a feature, not a gap (§5).
- **Confidentiality is structural.** The wire is encrypted; stored data is encrypted so holders only ever see ciphertext; and there is no public directory mapping content to holders.
- **Browser nodes and long-running peers run the same protocol**, differing only in their `store.local` backend and default quota.

The reference composition stacks: storage app handlers → cohort + repair + proof handlers → storage bridges (`store.local`, `net.send`, `clock.now`, `rand`) → installer → signature → kernel.

---

## 1.1 Concepts at a glance

- **Block** — the unit that moves on the wire: a content-addressed slice of bytes, ≤ 48 KB so it fits an envelope with room for framing (§4). `block_id = genesis_hash(ciphertext_bytes)`.
- **Chunk** — a logical slice of a file (e.g. 4 MB) that is erasure-coded into *n* **fragments**, of which any *k* reconstruct it. Fragments are stored as blocks.
- **Manifest** — the small root object that lists a file's chunks, their RS parameters, fragment block-ids, and the wrapped content key. The only thing you need to *read* a whole file. It does *not* name holders; which peer holds a block is discovered live from the cohort.
- **Repair header** — a few bytes stored alongside each fragment, naming its chunk's sibling block-ids and `(k, m)`, so any fragment-holder can rebuild the chunk without the read key (§3.6).
- **Cohort** — the bounded set of peers you have a storage relationship with. Discovery, placement, and repair all happen inside it. There is no global overlay.
- **Have/want** — the discovery primitive: peers tell each other which block-ids they hold or want. One round trip, no crypto protocol.
- **Receipt** — a *signed* attestation that a holder answered a storage challenge correctly (§13). A peer's reputation is the verifiable pile of receipts others signed about it.
- **`store.local`** — the I/O bridge (capability `store`) that reads/writes the node's donated blob store: filesystem on a server, OPFS/IndexedDB in a browser.

```
file ──chunk──► chunk[i] ──erasure-code──► fragment[i][0..n)
                                              │  each fragment = one content-addressed block of ciphertext
                                              ▼
                     placement: negotiate with cohort peers (frag.offer / accept)
                                              ▼
              push block + repair header ──► cohort peers     locate later via have/want
```

---

## 2. How it composes with the kernel

Nothing here changes the envelope, the dispatch rule, or `SetHandler`. Storage shows up as four kinds of seedkernel object:

**Identity.** Every operation that needs "who" reads `signature.signer`. The author of a manifest, the signer of a storage receipt, the owner whose reputation moves — all are the top signer. There is no separate account system.

**Names.** All storage messages are envelopes with storage names. App handlers install under author-scoped names so two deployments' storage apps never collide.

**Capabilities.** Each storage bridge is bound to exactly one capability, declared by the handlers that use it at install time and acknowledged by the installer policy. A pure-compute handler (the chunker, the erasure coder, the manifest builder) declares **no** caps — it is computation, and the structural sandbox guarantees it can touch no I/O even if compromised.

**Transport.** Seed store needs an authenticated channel between peers that carries kernel envelopes, with each frame's signer pinned to the channel identity; any such transport works (the chat demo's WebRTC data channel is one example). It adds one capability-gated `net.send` for *addressed unicast* to a specific cohort peer, and bulk blocks ride either the same channel as unsigned, hash-verified frames or a dedicated bulk data channel (§4).

**The 64 KB cap is the whole reason this layer exists**, so §4 treats it first.

---

## 3. Data model: files → manifests → chunks → fragments

### 3.1 Chunking

A file is cut into fixed-size **chunks** (default 4 MB; a deployment knob). Fixed-size chunking is simplest; a deployment that wants cross-file dedup can swap in content-defined chunking (a rolling-hash cut) without touching anything else, because everything downstream addresses chunks by id, not by offset.

### 3.2 Erasure coding (the redundancy primitive)

Each chunk is encoded with **Reed–Solomon `RS(k, m)`** into `n = k + m` fragments, where any *k* fragments reconstruct the chunk. Defaults: `k = 10, m = 6` → `n = 16`, 1.6× storage overhead, survives the loss of any 6 holders. Compare naïve 3× replication, which survives only 2 losses at nearly double the cost. Reed–Solomon encode/decode is simple, self-contained byte arithmetic and compiles to a small WASM handler that needs no capabilities. It operates on whatever bytes it is given — here, ciphertext (§3.5) — so reconstructing a missing fragment never requires the file's key.

The choice of `(k, m)` is per-chunk and recorded in the manifest, so a deployment can dial durability per file (cold archives might use `RS(20, 20)`; hot ephemeral data `RS(4, 2)`).

### 3.3 Fragments are blocks

Each fragment is sliced into **blocks** of ≤ 48 KB (§4) and each block is content-addressed: `block_id = genesis_hash(block_bytes)`. A fragment that is one block long is the common case; large fragments are a short block list. Content addressing makes every block **self-verifying**: a receiver recomputes the hash and rejects anything that doesn't match, so a malicious holder cannot return corrupt bytes undetected, and no signature is needed on bulk data. Because the bytes are ciphertext (§3.5), a `block_id` is the hash of an encrypted blob — opaque and unguessable to anyone who has not handled that exact file.

### 3.4 The manifest

The manifest is the file's root object — small, and the only thing a reader needs to bootstrap a download:

```
manifest (CBOR or fixed binary; itself chunked into blocks if > 48 KB):
  version
  file_size, chunk_size
  enc:   { alg, nonce_base }            // §3.5; absent if stored in clear
  key:   wrapped_content_key            // sealed to the sharing group; §3.5
  chunks: [
    {
      chunk_index,
      k, m,                              // RS parameters for this chunk
      chunk_id,                          // = genesis_hash(ciphertext chunk)
      descriptor_id,                     // = genesis_hash(signed repair descriptor), §3.6
      fragments: [
        { frag_index, block_ids: [...] } // the blocks that make up this fragment
      ]
    }, ...
  ]
  manifest_id = genesis_hash(manifest_bytes)
```

The manifest is stored exactly like file data — chunked, **erasure-coded, and spread across cohort peers** — and is shared with the file's sharing group, so it has no single point of failure and there is no index server. A file is referenced by `manifest_id`; that one hash, under a signature, is what travels in a 64 KB kernel envelope. Crucially, the manifest says *what* blocks a file is made of, never *which* peers hold them — that is discovered live via have/want (§5), so the holder map stays current under churn and repair instead of going stale in a fixed file.

### 3.5 Encryption (the load-bearing privacy mechanism)

Kernel envelopes are signed, not encrypted, and at-rest storage has no confidentiality of its own. In this design, **encryption is what makes the closed network safe** — it lets you store on cohort peers who can read nothing, and it makes block-ids opaque. Seed store encrypts **client-side before erasure coding**:

- Generate a random per-file content key; AEAD-encrypt each chunk (key + per-chunk nonce) before erasure coding. Holders store ciphertext fragments and learn nothing about content.
- The content key is wrapped to the file's sharing group and carried in the manifest; sharing a file means sharing or re-wrapping the key, not moving bytes.
- Random per-file keys mean two different files never produce colliding ciphertext, so a `block_id` is meaningful only to someone who has handled that exact file. Convergent encryption (key = hash(plaintext)) is an opt-in for deployments that want cross-user dedup and accept its equality-leak.

### 3.6 The repair descriptor (signed; travels with each block)

*Reading* a file needs the whole manifest and the content key, and is gated to the sharing group. *Repair* needs much less — only a chunk's *shape* — and we want it possible for far more peers, so each stored block carries a tiny **repair descriptor**. This descriptor is control-plane data and **must be authenticated**: `block_id = genesis_hash(ciphertext_bytes)` covers a block's *bytes* but says nothing about the *relationships between blocks*, so an unsigned descriptor could be altered by a malicious holder to misdirect or suppress repair — point a repairer at fragments that don't exist, lie about `(k, m)`, or hide that a chunk is decaying. Content addressing alone cannot close this gap: a tampered descriptor is still a valid string of bytes, and what's missing is an anchor the attacker cannot forge. So the descriptor is **signed by the file's author** (the §2 manifest signer):

```
descriptor D:
  file_root          // the manifest_id this chunk belongs to
  chunk_index
  k, m               // RS parameters
  chunk_id           // = genesis_hash(ciphertext chunk) — the keyless reconstruction anchor
  frag_ids[0..n)     // block-ids of all n sibling fragments, by frag_index
descriptor_id = genesis_hash(canonical(D))
repair_cert   = sign_author(descriptor_id)
```

It is set at placement time and re-attached whenever a repaired fragment is pushed to a new peer. The manifest also commits to each chunk's `descriptor_id` (§3.4), tying the descriptor into the file's signed root. **Verifying it needs only the author's *public* key — never the read key — so keyless repair (§9) is preserved.**

Every peer that accepts a fragment first verifies its descriptor: it is self-consistent (`genesis_hash(canonical(D)) == descriptor_id`), `repair_cert` is a valid author signature over it, and the fragment's own `block_id ∈ frag_ids`. A fragment whose descriptor fails any check is rejected outright. A holder therefore cannot alter the descriptor it serves — the signature won't re-verify — and cannot substitute its own key, because authority is bound to the file's author, the same trust root that decides whose tombstone is honored (§11). The authenticated `chunk_id` additionally lets a repairer certify its *own* reconstruction before propagating it (§9), so a bad descriptor can never cause garbage to be minted. The descriptor still discloses a chunk's size and shape to anyone storing a piece of it — the same class of disclosure already accepted in §15 — but never its contents, and now never a forgeable instruction. This split — signed shape, keyless verification — is what makes repair redundant rather than owner-bound (§9).

---

## 4. The bulk-data problem (64 KB) and the two planes

The single hardest constraint is that **no envelope may exceed 64 KB**, and it is a fixed protocol constant, not a knob. So a 4 MB chunk cannot be one message. Seed store splits into two planes:

**Control plane — kernel envelopes.** Manifest root hashes, have/want exchanges, placement offers, fetch requests, challenges, receipts, repair coordination. These are small, identity-bearing, and signed where authorization matters. They flow through the normal dispatch pipeline and pay the per-message verify — fine, because they are infrequent relative to bytes moved.

**Bulk plane — content-addressed blocks.** Fragment blocks ≤ 48 KB. These are **self-verifying by hash**, so they need no signature for integrity. Two transport options, chosen per deployment:

1. **In-band, unsigned, hash-verified frames** on the existing data channel. The receiver verifies `genesis_hash(bytes) == requested block_id` and drops on mismatch. This stays entirely inside the seedkernel message model and inherits the channel's encryption and pubkey pinning, but avoids per-block verify cost because there is no signature to check.
2. **A dedicated bulk data channel** alongside the kernel-envelope channel on the same connection. The control plane negotiates a transfer (block-ids, order, window) over signed kernel messages; raw blocks then stream over the bulk channel. This is the most performant for large files.

Either way the rule is the same: **the control plane carries hashes and authorization; the bulk plane carries hash-named bytes that authenticate themselves.** Transfers are flow-controlled with a simple windowed request/ack (`frag.fetch_req` lists wanted block-ids; the holder streams `frag.block`s; the receiver acks ranges) so a browser node doesn't blow its heap on a 4 MB fragment.

---

## 5. Discovery: a social cohort with have/want

We need to answer two questions — *which peers should hold a block?* and *who currently holds it?* — without a public, queryable index that would map content to holders. The closed-network assumption (§1) lets us answer both with almost no machinery.

### 5.1 The cohort

A node keeps connections to a **bounded set of peers it has a relationship with** — direct contacts plus, optionally, a hop or two out. There is no global index or routing table; nothing about who-holds-what exists outside your cohort. New peers join the way Scuttlebutt peers do, by introduction or via a rendezvous point. Cohort size is tens to low hundreds, which is what keeps every operation here cheap.

### 5.2 Have/want is the whole discovery layer

- *Who currently holds fragment F?* — ask the cohort. A have/want carrying the fragment's block-ids turns up whoever has them right now; nothing is pinned in advance, so the answer is always current.
- *Are there extra replicas, and is a given peer still holding its blocks?* — the same one-round exchange: "I want these `block_id`s" / "I have these `block_id`s." No lookup walk, no cryptographic protocol, no rate-limit machinery.

Block-ids are hashes of random-key ciphertext (§3.5), so to a peer outside a file's sharing group they are opaque noise, and on the wire they are encrypted. The only parties who can interpret a have/want entry are those who already hold the file's key — i.e. people you deliberately shared with.

### 5.3 What this is, and is not

This is deliberately **not an open market**: strangers cannot find or serve your data, because there is no global index and nothing to query. That absence is the privacy property we want. The cost is that storage is confined to your cohort — the trade we are choosing.

What leaks, and why it is acceptable here: a peer you exchange have/want with learns which block-ids you hold or want *of files you have already shared with it*, and roughly your inventory size. These are disclosures to people you have already chosen to store with, about files you have already shared with them. The full leak inventory and the optional hardening for less-trusted cohorts are in §15.

---

## 6. Writing a file (PUT)

1. **Chunk & encrypt.** The owner feeds the file to the `chunker` (cap-free) block-by-block (the 64 KB cap applies to messages between handlers too). Each chunk is AEAD-encrypted (§3.5).
2. **Erasure-code.** The `erasure` handler (cap-free) turns each chunk into `n` fragments; the `chunker` slices fragments into ≤ 48 KB blocks, computes block-ids, and forms each chunk's repair descriptor, which the owner signs (§3.6).
3. **Place by negotiation.** For each fragment, the `store.coordinator` picks candidate cohort peers — ordered by reputation (§13) and current reachability — and sends `frag.offer(block_id, size)`. A peer with free quota and willingness replies `frag.accept`; otherwise `frag.decline` and the coordinator moves to the next candidate. There is no global placement function; placement is a short private negotiation within the cohort.
4. **Push.** On accept, the coordinator streams the block over the bulk plane (§4), together with its repair header so the holder can later help heal the chunk.
5. **Share the manifest.** The manifest lists block-ids, not holders; it is shared with the file's sharing group and stored the same erasure-coded way (§3.4). Which peer took which fragment is not pinned anywhere — it is rediscovered live via have/want, so placement can shift under repair without the manifest going stale.
6. **Publish.** `manifest_id` is what the owner keeps and shares, wrapped in a signed 64 KB envelope.

Distinct fragments of the same chunk are placed on **distinct peers** (the coordinator enforces no-two-fragments-same-holder per chunk), so losing one peer costs at most one fragment of any chunk — the core of the §10 invariant.

---

## 7. Reading a file (GET)

1. **Resolve the manifest.** You either hold it (you are in the sharing group) or fetch its blocks from the cohort peers that hold them, then verify and decrypt the wrapped key.
2. **Locate fragments.** Send a have/want to the cohort for the chunk's fragment block-ids. You need any *k* of *n* per chunk, so race requests to the *k* most-reputable reachable peers that answer; if some are offline, the same have/want surfaces any extra replicas repair has created.
3. **Fetch & verify.** Stream blocks over the bulk plane; each is checked against its `block_id` (self-verifying, §3.3).
4. **Decode & decrypt.** Reconstruct each chunk from its *k* fragments, AEAD-decrypt, concatenate.

Because any *k*-of-*n* suffices, a read succeeds even with up to *m* holders offline or unwilling — no peer is on the critical path.

---

## 8. Availability and offline tolerance

Peers are expected to disappear and come back. The protocol distinguishes a transient blip from real loss so it doesn't churn data on every disconnect — and it does so by direct observation within the cohort, not by a global refresh scheme.

**How liveness is observed.** Any fragment-holder (or the owner) periodically sends a have/want for a chunk's sibling block-ids and notes who answers. There is no record to refresh and nothing to expire, so the picture is always current.

**Three states per holder of a fragment:**
- **Live** — recently reachable and confirms it still holds the block.
- **Suspected** — unreachable within a **grace window** `G` (default 24 h). *No repair.* This is precisely "a node may be offline for a period": a laptop closed overnight, a phone in a tunnel, a server rebooting all sit here and recover for free when they reappear.
- **Lost** — unreachable beyond `G`. Eligible to be counted as missing for repair.

**Redundancy measure.** For a chunk, `live_fragments` = number of distinct fragments with at least one Live holder. Data is safe while `live_fragments ≥ k`; the healthy target is `n = k + m`. Repair triggers on a **low-water mark** strictly above `k` (§9), never waiting until the chunk is one loss from death.

**Browser nodes specifically** are treated as low-uptime, often-Suspected holders: they may serve reads and act as extra cache while present, but the durable *m* leans on longer-lived cohort members. A deployment can tag node longevity so placement prefers steady peers for durability and lets browsers absorb read load.

---

## 9. Self-healing / repair

Repair is per-chunk, and it is performed by the chunk's own **fragment-holders**. Anyone holding a fragment also holds that chunk's signed repair descriptor (§3.6) — the sibling block-ids, `(k, m)`, and `chunk_id` — which is all you need to audit and rebuild it, and reconstruction runs on ciphertext, so a repairer never needs the file's key (only the author's public key, to check the descriptor). The sharing group *reads*; any fragment-holder *repairs*. No peer is special and no one is appointed; the work gets done by whoever notices first.

This is what makes repair redundant. The peers able to heal a chunk are exactly the peers storing it — about `n` of them — so repair survives as long as a single fragment-holder is online, and the repair-redundancy automatically scales with the durability `m` you chose. (The alternative, tying repair to whoever can read the manifest, would make a private file's owner the sole possible repairer — a single point of failure for healing even when the bytes themselves are amply redundant.)

**The repair loop (run by any fragment-holder on a jittered interval):**
1. Send a have/want to the cohort for the chunk's sibling block-ids (§5) and count how many distinct fragments are currently retrievable → `live_fragments`.
2. If `live_fragments < low_water` (default `k + ⌈m/2⌉`), repair is needed.
3. **Avoid duplicate work** with a jittered timer: the peer that fires first announces it (`repair.claim`); others hold off and cancel when a freshly placed fragment shows up in have/want. Because the cohort is small and the claim is observable, this needs no election or coordinator.
4. The repairer fetches any *k* retrievable fragments, reconstructs the chunk's ciphertext, and **verifies `genesis_hash(reconstructed) == chunk_id`** from the signed descriptor before trusting the result — this catches a tampered `(k, m)`, a wrong fetched fragment, or any decode error keylessly, so a poisoned descriptor can never make repair mint or propagate garbage. It then re-encodes only the **missing** fragments and places them on fresh cohort peers (§6 steps 3–4) with the signed descriptor, skipping current holders so redundancy spreads to new peers.
5. The new fragments are immediately discoverable via have/want; redundancy returns to `n` with no manifest change, since the manifest never named holders.

**Moving data on availability change** is the same loop run proactively: if a peer sees the cohort thinning (many Suspected/Lost holders, e.g. a correlated outage), it re-spreads fragments toward healthier peers before a chunk crosses low-water.

**The one real cost**: a chunk can only be healed while at least one of its fragment-holders is online within a repair interval. With about `n` holders that is a weak requirement, but it can still fail if a chunk's holders are *all* low-uptime and go dark together (e.g. an all-browser cohort overnight). Placing at least one durable peer among each chunk's holders removes the risk — which is also what §8 recommends for the durable `m`.

**Repair amplification is bounded** by erasure coding: regenerating one lost fragment costs *k* fragment-reads, not a full re-upload, and only the lost fragments are rebuilt.

---

## 10. The redundancy invariant: no peer can make data unavailable

This requirement is met structurally, not by trust:

- **No fragment is unique.** A chunk survives on any *k* of *n* fragments, and distinct fragments live on distinct peers (§6). One peer holds at most one fragment of a given chunk, so its disappearance — or its refusal to serve — costs at most one fragment. You need *more than m* peers to fail or defect simultaneously to lose a chunk.
- **No metadata is unique.** The manifest is stored the same erasure-coded way and shared across the file's group (§3.4); there is no single index server, and the holder map is not stored at all — it is recomputed live.
- **No single repairer is required.** Any of a chunk's ~`n` fragment-holders can heal it (§9), on ciphertext, without the read key; removing any one removes no capability. Repair-redundancy is therefore as high as the data-redundancy *n*, not gated on a small set of readers. And because each chunk's shape travels as an **author-signed descriptor** (§3.6), no holder can misdirect or suppress repair by tampering the header — an altered descriptor fails its signature check and is rejected.
- **Withholding is detected and routed around.** A holder that stops serving fails storage challenges (§13), loses reputation, and gets skipped in future placement; its unreachability tips it to Lost and triggers repair. Active malice degrades to the same path as passive offline-ness.
- **Corruption is impossible to hide.** Content addressing (§3.3) means a tampered block fails its hash check and is discarded; the reader simply fetches another fragment.

The honest assumptions this rests on: *fewer than the redundancy budget of a chunk's holders fail or defect within a repair interval*, and *at least one of a chunk's fragment-holders is online within that interval*. Sizing `(k, m)`, the low-water mark, and the repair cadence against your cohort's real churn is the deployment's durability dial (§20).

---

## 11. Removal

In a store where other people hold your bytes, you cannot force a remote peer to delete on command, so removal is two mechanisms with different guarantees.

**Crypto-shredding — the guarantee.** Because every file has a random per-file key (§3.5), destroying that key makes all of its ciphertext fragments permanent noise to everyone, immediately and irreversibly. The owner and sharing group drop the wrapped key from their manifests and keystores; whatever ciphertext lingers on holders is unreadable forever. This is the only deletion the system can actually promise, and for confidentiality it is enough: a "deleted" file is one whose key no longer exists.

**Tombstones — best-effort space reclamation.** To get the bytes off disk, the owner publishes a **signed tombstone** for the chunk's block-ids, gossiped through the cohort. A holder that receives it verifies the signature, drops the blocks, and stops counting them. Online holders comply at once; offline holders comply when they reconnect and see the tombstone; and the tombstone also tells fragment-holders to **stop repairing** that chunk, so it is allowed to decay below low-water and be reclaimed instead of healed back to life. Anything a tombstone never reaches simply ages out through normal eviction (§14).

**Authority.** A tombstone is honored only when signed by the manifest's author (the §2 identity). For a shared file the simple rule is that only the owner's tombstone removes the data; a member who no longer wants it just drops its own copy and stops repairing — it cannot delete for everyone.

Tombstones are bounded too: a holder keeps one only until the referenced blocks are gone and a short grace period passes, so the tombstone set does not grow without limit.

---

## 12. Donating storage

"Donate whatever storage you have available" is the `store.local` bridge plus a host-configured quota.

**`store.local` (capability `store`)** is a host-native bridge with operations `put(block_id, bytes)`, `get(block_id) → bytes`, `has(block_id)`, `delete(block_id)`, `list(prefix)`, and `stat() → { quota, used, free }`. Like every bridge it runs the caller-capability check before touching disk, so only handlers that declared `store` at install time can reach it. A holder stores opaque `(block_id → ciphertext)` pairs plus the small repair header (§3.6): it needs no file key and learns nothing about what it is holding beyond the chunk's shape.

**Backends differ by host, protocol does not:**
- **Long-running peer:** a directory on disk; quota is a config number; effectively always Live.
- **Browser node:** OPFS or IndexedDB; quota bounded by the browser's storage budget; eviction-aware (treat browser-evicted blocks as Lost and let repair handle them). The browser shell exposes a "donate N GB" control to set the quota.

**Quota honesty is enforced, not assumed.** A node advertises free space, but no peer trusts the number — it trusts the node's track record of *passing storage challenges for data it accepted* (§13). Lying about capacity gets you data you then fail to prove you hold, which costs reputation. `store.local.stat()` is for the owner's own accounting and admission control (refuse `frag.offer` when full), not a network-trusted figure.

---

## 13. Reputation: rewarding good citizens without a coin

The reward is a **verifiable reputation**, and the thing that earns it is *provably holding data and serving it*. No token, no ledger consensus — just signed evidence, which seedkernel's signature module already makes cheap and non-repudiable. In a closed cohort this fits naturally: you mostly score peers you actually interact with.

### 13.1 Proof of storage (the earning event)

A challenger periodically tests a holder it has data with: "send me the bytes at offset *o* of block *B*, plus a Merkle path proving they belong to `block_id`." The holder must produce them on demand; it cannot precompute answers without actually keeping the bytes (offsets are random per challenge). This is a lightweight proof-of-retrievability:

```
proof.challenge:  { block_id, nonce, offset }              // challenger → holder (signed)
proof.response:   { block_id, nonce, sector, merkle_path } // holder → challenger
```

On a correct response the challenger emits a **signed receipt**:

```
proof.receipt = signature-wrapped {
  holder_pubkey, block_id, nonce, timestamp, PASS,
}                                                          // signed by the challenger
```

Receipts are the kernel's signature wrapper doing exactly what it's for: an authenticated, replay-resistant attestation (each carries the challenge `nonce`). A holder accumulates receipts as its **track record**.

### 13.2 What reputation is

A peer's reputation is computed from the receipts *others signed about it*, weighted by:
- **Volume & longevity** — passing challenges for more data, over more time.
- **Challenger diversity** — receipts from many *distinct* peers count more than many from one. This blunts casual inflation, but on the gossip path it is not enough against deliberate collusion (a clique manufactures its own diversity), which is why gossiped receipts are additionally weighted *transitively* (below).
- **Recency, with a hard age bound** — only receipts from the last `X` (a deployment window, e.g. 90 days) count, and receipts older than `X` are discarded rather than kept. This both decays the score of a peer that stops serving and bounds how much reputation state anyone has to store, so it never grows without limit.
- **Retrieval success** — serving real `frag.fetch_req`s, not just challenges.

Two complementary views, and the closed network makes the simple one the default:
- **Subjective / local (default):** every peer scores peers it has directly interacted with. In a cohort you mostly *have* interacted with everyone you store with, so local scoring covers the common case and is inherently Sybil-proof — you only trust what you witnessed, so others' mutual receipts never enter your local view and collusion has nothing to grip.
- **Gossiped / transitive (optional path, mandatory weighting):** to judge a friend-of-a-friend you have never challenged yourself, peers exchange signed receipt summaries (`rep.gossip`). Using this path is optional — but when you do, receipts **must** be weighted transitively, never summed flat. A receipt counts only in proportion to the *challenger's own reputation as you already assess it*, so a vouch from a peer you don't trust is worth almost nothing. This is the one defense that holds against deliberate collusion among real cohort members (Sybil among strangers is already bounded by the closed network, §15): a clique can sign each other glowing receipts all day, but until its members earn standing in *your* trust web those receipts carry ~0 weight.

Concretely this is **EigenTrust-style transitive trust, personalized to the evaluator**. Each peer normalizes its locally-witnessed scores (§13.1) into a trust vector, then propagates trust over the gossiped receipt graph by damped power iteration — a peer's transitive score is the fixpoint of `trust(P) = (1−d)·local_seed(P) + d·Σ_c trust(c)·rating_c(P)` — restarting from its **own** local view rather than any global pre-trusted set. Anchoring on the local seed is what makes it collusion-resistant and keeps it consistent with the subjective default: trust is computed *relative to you*, so a collective with no edge into your local trust set never gains weight, and there is no global reputation object to agree on or attack. A new honest node starts near zero on the gossip path until someone's local trust reaches it — it proves itself locally first — and because the local seed and every edge obey the recency age bound, a peer that stops serving loses both its own score *and* its power to vouch for others. The whole computation is arithmetic over collected signed receipts, so it stays in the pure, cap-free `reputation` handler (§17).

`reputation.score(pubkey) → score` is a read-only query, used by placement (§6), by holders deciding whether to accept a `frag.offer`, and by readers choosing whom to fetch from first.

### 13.3 What reputation buys (the incentive loop)

Reputation is spendable as **priority**, which closes the loop without money:
- **Durability for your own data.** High-reputation owners get their `frag.offer`s accepted readily and placed on the best holders; low or negative-reputation peers are throttled or asked to contribute first.
- **A storage allowance proportional to contribution.** A soft, tit-for-tat budget: roughly, the cohort will durably hold for you about as much as you have reliably held for others. This makes leeching self-limiting and makes donating storage directly valuable to the donor.
- **Preferential read bandwidth and faster repair participation.** Good citizens are chosen first to serve and to repair, and earn more receipts doing so — the loop compounds.

Honest, available, truthful-about-capacity nodes accumulate receipts and climb; nodes that withhold, lie, or churn destructively fail challenges, decay, and get routed around (§10). The reward is that being a good citizen is the *only* way to get good service for your own data.

---

## 14. What to store, and what to evict

A node has finite donated space and will be offered far more than it can hold, so it needs a policy for what to accept and what to drop. This is not a new subsystem — it is the local face of the reputation loop (§13). The one structural idea is **two tiers of storage**:

- **Committed** — fragments a node accepted (`frag.accept`) and now earns reputation by provably keeping (§13.1). These are not dropped casually: shedding one abruptly means failing its next challenge and losing reputation. A node sheds a commitment only by **graceful release** — re-placing the fragment on another peer, or letting repair pick it up — accepting that durability dips until redundancy is restored.
- **Opportunistic cache** — blocks picked up while serving reads, or extra replicas beyond `n`. Free to evict at any time, no commitment, no reputation cost.

**Admission (when a `frag.offer` arrives).** Accept weighted by: reciprocity (prefer peers who store for you), reputation and social closeness, and how under-replicated the chunk is — a repair offer that lifts a chunk off its low-water mark outranks a routine first placement. Reserve a fraction of quota for commitments so cache cannot crowd out durability, and refuse offers outright when the committed tier is full.

**Eviction (under quota pressure).** Drop cache first, favoring blocks that are cold *and* well-replicated elsewhere, while protecting rare or globally under-replicated blocks (the ones repair would struggle to regenerate). Only if still pressed does a node gracefully release its lowest-value commitments — typically those for low-reciprocity peers. Tombstoned and long-unchallenged orphan blocks are first out the door, which is how dead data is reclaimed without an explicit delete.

Concretely, an eviction score like `coldness × redundancy_elsewhere × (1 / reciprocity_with_owner)`, with committed blocks weighted heavily against eviction, captures all of this from signals the node already tracks. The exact weighting is a tuning knob (§20); the property that matters is that a well-behaved node keeps what is scarce and what it owes, and sheds what is abundant and unasked-for.

---

## 15. Threat model and what leaks

Because the network is a closed social cohort, the dominant open-network threats shrink: you only peer with people you've added, so Sybil flooding and eclipse are not the everyday concern they are in an open network, and the installer policy stays restrictive (an open registry would be remote code execution) so untrusted WASM never lands.

**What is protected.** Content — encryption means holders see only ciphertext (§3.5). The wire — an authenticated, encrypted channel with each frame's signer pinned to the channel identity. The content↔holder mapping — there is no global index, and the holder map is never stored, only recomputed live within the cohort. Integrity — content addressing (§3.3) for bulk bytes, and an author signature on the repair descriptor (§3.6) for the chunk-shape metadata that drives repair, so a holder cannot forge it to misdirect healing. Identity — signatures.

**What leaks, accepted by the closed-cohort assumption.** All of these are disclosures *to peers you have chosen to store with, about files you have already shared with them*:
- **Inventory size** — a peer you have/want with learns roughly how much you store and a shared file's fragment count.
- **Per-file holdings** — to a peer in a file's sharing group, which fragments you hold or want.
- **Chunk shape** — a fragment's repair header (§3.6) tells whoever stores it the chunk's sibling block-ids and `(k, m)`, i.e. its size and shape — never its content. Same class of disclosure as the above; the PRF-tag hardening below covers it if a deployment cares.
- **Interest** — asking a key-holder for a file reveals you wanted it (a non-key-holder learns nothing — the id is an opaque hash).
- **Social graph** — who you maintain channels with is visible at the transport level. This is the residual metadata of going social, and it is far smaller than what a global, queryable index would expose.
- **Ex-member probing** — someone who once held a file's ids can probe for those specific blocks until repair rotates them away; for sensitive files, re-encrypt and rotate on a membership change (expensive, usually done only when it matters).

**Optional hardening (documented, deliberately unbuilt).** Add only if a deployment's cohort is less than fully trusted; none of it is needed for a friends-or-devices cohort, and adding it by default would make the system the complicated monster we are avoiding:
- **PRF locator tags.** Address blocks by `tag = PRF_{K_loc}(fragment_id)` (with `K_loc` a per-file locator key separate from the decryption key) instead of by the raw ciphertext hash. This decouples the locator from the content hash, gives holders and observers unlinkability, and lets you rotate locators on a membership change without re-encrypting. Cost: one extra per-file key and a second identifier in the manifest. **If you adopt this, the repair descriptor's `chunk_id` (§3.6) must be tagged the same way** — it is a stable per-chunk identifier held by every fragment-holder, so left in the clear it survives as a cross-file linkage handle that defeats the unlinkability the tags otherwise buy. Tag it as `PRF_{K_loc}(chunk_id)` (the repairer still verifies reconstruction by recomputing the raw `chunk_id` locally and re-applying the PRF), and apply the same to the descriptor's `frag_ids`.
- **Size-hiding have/want.** Pad have-sets to a round number or send them as Bloom filters to blunt the inventory-size leak — cheap, and the right first step for a semi-trusted pool.
- **Size-Hiding PSI.** A malicious-secure, size-hiding private set intersection would hide set size and non-intersection elements even from an authorized-but-curious peer, at the cost of a multi-message protocol, real per-run latency, mandatory rate-limiting, and a substantial implementation burden. It is a possible future layer for genuinely semi-trusted community pools, **not** part of this design.

**Residual kernel-inherited risk.** The protocol does not bound a single handler's CPU or memory, so run the heavy `erasure` and `repair` handlers under a Worker watchdog.

---

## 16. New bridges (host-native, `SetHandler`-installed, one capability each)

| Bridge | Cap | Payload (request) | Host action |
| --- | --- | --- | --- |
| `store.local` | `store` | op-tagged: `put`/`get`/`has`/`delete`/`list`/`stat` (§12) | read/write the donated blob store (FS or OPFS/IndexedDB) |
| `net.send` | `net` | `[peer_id_len][peer_id][bytes...]` | addressed unicast to a cohort peer over its data channel (open/reuse) |
| `clock.now` | `clock` | (empty) | u64 unix ms — grace windows, challenge timing, repair jitter |
| `rand` | `rand` | `[n]` | n cryptographically-random bytes — nonces, content keys, jitter |

`net.send` is the one genuinely new transport primitive (it adds addressed unicast). Async by nature, so it returns a correlation id and the host later delivers the response back to the originating handler. `clock.now` and `rand` are conventional bridges a deployment likely already has.

---

## 17. New app handlers (WASM, installed via signed messages)

| Handler | Caps | Role |
| --- | --- | --- |
| `chunker` | — (pure) | split files into chunks; slice fragments into ≤ 48 KB blocks; compute block-ids and repair headers |
| `erasure` | — (pure) | Reed–Solomon encode/decode (on ciphertext) |
| `manifest` | — (pure) | build/parse manifests; wrap/unwrap content keys |
| `cohort` | `net`, `clock` | maintain the peer set and connections; run have/want exchanges and liveness checks |
| `store.coordinator` | `store`, `net`, `clock` | orchestrate PUT/GET incl. placement negotiation; issue tombstones; windowed transfer; admission & eviction (§14) |
| `repair` | `store`, `net`, `clock` | the repair loop: measure redundancy via have/want, claim, reconstruct on ciphertext (§9) |
| `proof` | `store`, `clock` | answer challenges (holder side) and issue them + sign receipts (challenger side) |
| `reputation` | — (pure) | accumulate signed receipts within the age bound; compute local scores and transitively-weighted (EigenTrust-style, locally-anchored) gossiped scores; `reputation.score` query |

Discovery and placement are deliberately light: a single small `cohort` handler keeps the peer set and runs have/want, and placement is just negotiation folded into `store.coordinator`. The three pure handlers (`chunker`, `erasure`, `manifest`) declare **no** capabilities, so the structural sandbox guarantees they can never reach disk or network even if buggy — the heavy crypto/coding code is exactly where you want that guarantee. Mutating handlers (`store.coordinator`, `repair`, `proof`) that act under a signer's authority consume a per-signer sequence number to reject replays.

---

## 18. Message catalog (control plane; every message ≤ 64 KB)

| Name | Direction | Payload sketch |
| --- | --- | --- |
| `store.put_req` / `store.put_done` | user ↔ coordinator | file blocks in / `manifest_id` out |
| `store.get_req` / `store.get_done` | user ↔ coordinator | `manifest_id` in / file blocks out |
| `frag.offer` / `frag.accept` / `frag.decline` | coordinator ↔ peer | `block_id`, size, **signed repair descriptor** (§3.6) / accept / reason |
| `frag.fetch_req` / `frag.block` / `frag.ack` | reader ↔ holder | wanted block-ids / a block (bulk plane) / window ack |
| `disc.have` / `disc.want` | peer ↔ peer | block-ids held / block-ids wanted (the discovery layer, §5) |
| `proof.challenge` / `proof.response` / `proof.receipt` | challenger ↔ holder | nonce+offset / sector+merkle / **signed** receipt |
| `repair.claim` | peer ↔ cohort | "I'm repairing this chunk" — suppresses duplicate repair (§9) |
| `frag.tombstone` | owner → cohort | **signed** "delete these block-ids and stop repairing" (§11) |
| `rep.gossip` | peer ↔ peer | signed receipt summaries (optional, for friend-of-a-friend scoring) |

Control messages that authorize a state change (the mutators in §17) carry a leading sequence number and are dropped on replay. Bulk `frag.block`s carry no signature; they are validated by `genesis_hash(bytes) == block_id` (§4).

---

## 19. Bootstrap additions

On top of the kernel bootstrap, a storage-capable node additionally:

1. Installs the storage bridges it offers: `store.local` (always, to donate space), `net.send`, `clock.now`, `rand`.
2. Wires an installer policy that admits the storage app handlers — restrictive, *never* open, e.g. a content-hash allowlist of audited storage-handler bytecode plus a closed author set for who may publish upgrades.
3. Receives the storage app handlers as signed install messages (`chunker`, `erasure`, `manifest`, `cohort`, `store.coordinator`, `repair`, `proof`, `reputation`) — each declaring exactly the caps in §17.
4. Joins its cohort: connects to known peers (by introduction or a rendezvous point), exchanges have/want, and starts serving.

A node that only wants to *donate* storage installs the holder-side path (`store.local`, `cohort`, the accept/serve half of `store.coordinator`, the holder half of `proof`) and never needs the writer's chunker/erasure/manifest. A read-only client needs the reverse. The onion composes per-role.

---

## 20. Tuning knobs and open questions

- **`(k, m)` and chunk size** — the durability/overhead dial. Size against measured cohort churn so that the chance of losing more than *m* holders within one repair interval is acceptably small.
- **Erasure code choice: Reed–Solomon vs. Locally Repairable Codes (LRC).** RS (§3.2) is MDS and dead simple — any *k* of *n* reconstruct, repair is a flat `live_fragments ≥ k` count (§8), and the handler is tiny. Its cost is repair amplification: healing one lost fragment reads *k* fragments and reconstructs the whole chunk (§9), and the common failure is exactly one lost fragment per chunk (§6 puts one fragment per peer). An **LRC** adds per-group *local* parities on top of *global* ones, so a single lost fragment rebuilds from just its local group — `r ≪ k` reads, a small linear combination, no full-chunk reconstruct (cheaper bandwidth, CPU, and memory, the last of which matters for browser holders, §4). It preserves everything RS gives seedstore — fixed content-addressed fragments, deterministic re-encode so the signed descriptor (§3.6) still holds, keyless ciphertext repair — unlike a rateless fountain code (RaptorQ), which would break fragment content-addressing outright. The price is that LRCs are **not MDS**: durability becomes loss-pattern-dependent, so the clean §8/§10 "any *k* of *n*" accounting must become per-local-group health plus a global check, and §6 placement gains a "spread each local group across distinct peers" constraint. The win scales with *k* — large for cold archives (`RS(20,20)` → painful 20-read repairs), marginal for small hot chunks — so if adopted it likely belongs as a per-chunk option (the `(k, m)` knob is already per-chunk, §3.2) rather than a blanket default. Revisit if repair bandwidth turns out to dominate operational cost. (Regenerating/MSR codes cut repair bandwidth further still but contact more helpers per repair — worse coordination under churn — so LRC is the pragmatic step.)
- **Grace window `G` and liveness cadence** — set so ordinary offline patterns (overnight, commute, reboot) never trigger repair, but real departures do within a bounded time. Too short → churn storms; too long → slow healing.
- **Low-water mark & repair jitter** — trade healing speed against repair traffic and duplicate-repair avoidance.
- **Cohort uptime** — the load-bearing durability decision (§9): each chunk's holders should include at least one well-connected, long-lived peer so repair can always run.
- **Committed/cache split & eviction weights** — how much quota a node reserves for durable commitments vs. opportunistic cache, and the weighting of the eviction score (§14).
- **Tombstone retention** — how long a holder keeps a tombstone after the referenced blocks are gone (§11).
- **Reputation window `X` and weighting** — the age bound (§13.2), the weighting of volume/diversity/recency, and — on the gossip path — the EigenTrust damping factor `d` and how strongly to anchor on the local seed. Transitive weighting itself is *required* on that path, not a toggle (§13.2); only its parameters are tunable. This lives in the pure, swappable `reputation` handler.
- **Bulk transport choice** — in-band hash-verified frames (simplest) vs. a dedicated bulk channel (fastest). §4 supports either.
- **Convergent vs. random-key encryption** — dedup vs. equality-leak (§3.5).
- **Optional hardening** — PRF locator tags, padded/Bloom have-sets, or full PSI for less-trusted cohorts (§15). Off by default; add only when the cohort's trust assumption no longer holds.

Everything above is expressible as bridges, pure-compute handlers, signed messages, and a restrictive policy callback — i.e. as ordinary seedkernel modules. The kernel never learns what a "file" is; it just keeps routing names to handlers, the bulk bytes never enter its 64 KB world, and the design stays four ideas deep: a social cohort, encryption, content addressing, and have/want.
