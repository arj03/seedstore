# Seed store: a peer-to-peer storage layer for seedkernel

## 1. Introduction

Seed store is a peer-to-peer storage layer for [seedkernel](https://github.com/arj03/seedkernel). It lets any node donate whatever storage it has and store files across a set of peers, so that no single peer can make a file unavailable, peers can be offline for stretches without data loss, the system heals itself by moving data when redundancy drops, large files are sharded so size is bounded only by the swarm, and good citizens earn a verifiable reputation rather than a coin.

Seedkernel routes small signed messages and puts a hard size cap on each one, so bulk data lives outside the kernel and is referenced by a content hash. Seed store is that outside store: the kernel keeps routing names to handlers, the bytes never touch its dispatch path, and everything here is built from the pieces seedkernel already provides — a name to dispatch on, bytes that are a WASM handler, and an author who signed the install.

This design assumes a **closed, social network**: you store with and among peers you have a relationship with (friends, friends-of-friends, or an explicit storage group), not an open market of strangers. That assumption is what keeps the whole thing small — privacy and Sybil resistance come from the *shape* of the network rather than from added cryptographic machinery. The whole system is four ideas: **a social cohort, client-side encryption, content addressing, and a have/want exchange.**

**Design principles (inherited from the kernel, applied to storage):**

- The storage layer adds **no new kernel concepts**. It is bridges + app handlers + message names, gated by the existing capability and signature machinery.
- **Integrity comes from content addressing, not from signatures.** A block is named by its hash; a block either hashes to its name or it is discarded. This is what lets bulk transfer skip the per-message verify that dominates kernel cost (§11).
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
- **Manifest** — the small root object that lists a file's chunks, their RS parameters, fragment block-ids, and the wrapped content key. The only thing you need to retrieve a whole file. It does *not* name holders; which peer holds a block is discovered live from the cohort.
- **Cohort** — the bounded set of peers you have a storage relationship with. Discovery, placement, and repair all happen inside it. There is no global overlay.
- **Have/want** — the discovery primitive: peers tell each other which block-ids they hold or want. One round trip, no crypto protocol.
- **Receipt** — a *signed* attestation that a holder answered a storage challenge correctly (§12). A peer's reputation is the verifiable pile of receipts others signed about it.
- **`store.local`** — the I/O bridge (capability `store`) that reads/writes the node's donated blob store: filesystem on a server, OPFS/IndexedDB in a browser.

```
file ──chunk──► chunk[i] ──erasure-code──► fragment[i][0..n)
                                              │  each fragment = one content-addressed block of ciphertext
                                              ▼
                     placement: negotiate with cohort peers (frag.offer / accept)
                                              ▼
              push blocks ──► cohort peers     locate later via have/want
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

Each chunk is encoded with **Reed–Solomon `RS(k, m)`** into `n = k + m` fragments, where any *k* fragments reconstruct the chunk. Defaults: `k = 10, m = 6` → `n = 16`, 1.6× storage overhead, survives the loss of any 6 holders. Compare naïve 3× replication, which survives only 2 losses at nearly double the cost. Reed–Solomon encode/decode is simple, self-contained byte arithmetic and compiles to a small WASM handler that needs no capabilities.

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

What leaks, and why it is acceptable here: a peer you exchange have/want with learns which block-ids you hold or want *of files you have already shared with it*, and roughly your inventory size. These are disclosures to people you have already chosen to store with, about files you have already shared with them. The full leak inventory and the optional hardening for less-trusted cohorts are in §13.

---

## 6. Writing a file (PUT)

1. **Chunk & encrypt.** The owner feeds the file to the `chunker` (cap-free) block-by-block (the 64 KB cap applies to messages between handlers too). Each chunk is AEAD-encrypted (§3.5).
2. **Erasure-code.** The `erasure` handler (cap-free) turns each chunk into `n` fragments; the `chunker` slices fragments into ≤ 48 KB blocks and computes block-ids.
3. **Place by negotiation.** For each fragment, the `store.coordinator` picks candidate cohort peers — ordered by reputation (§12) and current reachability — and sends `frag.offer(block_id, size)`. A peer with free quota and willingness replies `frag.accept`; otherwise `frag.decline` and the coordinator moves to the next candidate. There is no global placement function; placement is a short private negotiation within the cohort.
4. **Push.** On accept, the coordinator streams the block over the bulk plane (§4).
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

**How liveness is observed.** Any cohort peer that holds a manifest periodically sends a have/want for its block-ids and notes who answers. There is no record to refresh and nothing to expire, so the picture is always current.

**Three states per holder of a fragment:**
- **Live** — recently reachable and confirms it still holds the block.
- **Suspected** — unreachable within a **grace window** `G` (default 24 h). *No repair.* This is precisely "a node may be offline for a period": a laptop closed overnight, a phone in a tunnel, a server rebooting all sit here and recover for free when they reappear.
- **Lost** — unreachable beyond `G`. Eligible to be counted as missing for repair.

**Redundancy measure.** For a chunk, `live_fragments` = number of distinct fragments with at least one Live holder. Data is safe while `live_fragments ≥ k`; the healthy target is `n = k + m`. Repair triggers on a **low-water mark** strictly above `k` (§9), never waiting until the chunk is one loss from death.

**Browser nodes specifically** are treated as low-uptime, often-Suspected holders: they may serve reads and act as extra cache while present, but the durable *m* leans on longer-lived cohort members. A deployment can tag node longevity so placement prefers steady peers for durability and lets browsers absorb read load.

---

## 9. Self-healing / repair

Repair is a shared responsibility of the cohort: any peer that holds a file's manifest can — and should — watch its redundancy and rebuild missing fragments. No peer is special and no one is appointed; the work simply gets done by whoever notices first.

**The repair loop (run by any manifest-holder on a jittered interval):**
1. Send a have/want to the cohort for the file's block-ids (§5) and count, per chunk, how many distinct fragments are currently retrievable → `live_fragments`.
2. If `live_fragments < low_water` (default `k + ⌈m/2⌉`), repair is needed.
3. **Avoid duplicate work** with a jittered timer: the peer that fires first announces it (`repair.claim`); others hold off and cancel when a freshly placed fragment shows up in have/want. Because the cohort is small and the claim is observable, this needs no election or coordinator.
4. The repairer fetches any *k* retrievable fragments, reconstructs the chunk, re-encodes only the **missing** fragments, and places them on fresh cohort peers (§6 steps 3–4), skipping current holders so redundancy spreads to new peers.
5. The new fragments are immediately discoverable via have/want; redundancy returns to `n` with no manifest change, since the manifest never named holders in the first place.

**Moving data on availability change** is the same loop run proactively: if a peer sees the cohort thinning (many Suspected/Lost holders, e.g. a correlated outage), it re-spreads fragments toward healthier peers before a chunk crosses low-water.

**The one real cost** of cohort-bound repair: it requires at least one peer that holds the manifest to be online within a repair interval. As long as a sharing group keeps reasonable aggregate uptime — typically one or two long-running members — this holds. A group that is *entirely* browser nodes with no steady member genuinely risks losing data during a long quiet stretch, so a deployment should make sure each group has at least one well-connected, long-lived peer.

**Repair amplification is bounded** by erasure coding: regenerating one lost fragment costs *k* fragment-reads, not a full re-upload, and only the lost fragments are rebuilt.

---

## 10. The redundancy invariant: no peer can make data unavailable

This requirement is met structurally, not by trust:

- **No fragment is unique.** A chunk survives on any *k* of *n* fragments, and distinct fragments live on distinct peers (§6). One peer holds at most one fragment of a given chunk, so its disappearance — or its refusal to serve — costs at most one fragment. You need *more than m* peers to fail or defect simultaneously to lose a chunk.
- **No metadata is unique.** The manifest is stored the same erasure-coded way and shared across the file's group (§3.4); there is no single index server, and the holder map is not stored at all — it is recomputed live.
- **No single repairer is required.** Any cohort peer that holds the manifest can repair, and they overlap; removing any one peer removes no capability, provided the group keeps aggregate uptime (§9).
- **Withholding is detected and routed around.** A holder that stops serving fails storage challenges (§12), loses reputation, and gets skipped in future placement; its unreachability tips it to Lost and triggers repair. Active malice degrades to the same path as passive offline-ness.
- **Corruption is impossible to hide.** Content addressing (§3.3) means a tampered block fails its hash check and is discarded; the reader simply fetches another fragment.

The honest assumptions this rests on: *fewer than the redundancy budget of a chunk's holders fail or defect within a repair interval*, and *at least one cohort peer holding the manifest is online within that interval*. Sizing `(k, m)`, the low-water mark, and the repair cadence against your cohort's real churn is the deployment's durability dial (§18).

---

## 11. Donating storage

"Donate whatever storage you have available" is the `store.local` bridge plus a host-configured quota.

**`store.local` (capability `store`)** is a host-native bridge with operations `put(block_id, bytes)`, `get(block_id) → bytes`, `has(block_id)`, `delete(block_id)`, `list(prefix)`, and `stat() → { quota, used, free }`. Like every bridge it runs the caller-capability check before touching disk, so only handlers that declared `store` at install time can reach it. A holder stores opaque `(block_id → ciphertext)` pairs: it needs no file key and learns nothing about what it is holding.

**Backends differ by host, protocol does not:**
- **Long-running peer:** a directory on disk; quota is a config number; effectively always Live.
- **Browser node:** OPFS or IndexedDB; quota bounded by the browser's storage budget; eviction-aware (treat browser-evicted blocks as Lost and let repair handle them). The browser shell exposes a "donate N GB" control to set the quota.

**Quota honesty is enforced, not assumed.** A node advertises free space, but no peer trusts the number — it trusts the node's track record of *passing storage challenges for data it accepted* (§12). Lying about capacity gets you data you then fail to prove you hold, which costs reputation. `store.local.stat()` is for the owner's own accounting and admission control (refuse `frag.offer` when full), not a network-trusted figure.

---

## 12. Reputation: rewarding good citizens without a coin

The reward is a **verifiable reputation**, and the thing that earns it is *provably holding data and serving it*. No token, no ledger consensus — just signed evidence, which seedkernel's signature module already makes cheap and non-repudiable. In a closed cohort this fits naturally: you mostly score peers you actually interact with.

### 12.1 Proof of storage (the earning event)

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

### 12.2 What reputation is

A peer's reputation is computed from the receipts *others signed about it*, weighted by:
- **Volume & longevity** — passing challenges for more data, over more time.
- **Challenger diversity** — receipts from many *distinct* peers count more than many from one (collusion resistance).
- **Recency, with a hard age bound** — only receipts from the last `X` (a deployment window, e.g. 90 days) count, and receipts older than `X` are discarded rather than kept. This both decays the score of a peer that stops serving and bounds how much reputation state anyone has to store, so it never grows without limit.
- **Retrieval success** — serving real `frag.fetch_req`s, not just challenges.

Two complementary views, and the closed network makes the simple one the default:
- **Subjective / local (default):** every peer scores peers it has directly interacted with. In a cohort you mostly *have* interacted with everyone you store with, so local scoring covers the common case and is inherently Sybil-proof — you only trust what you witnessed.
- **Gossiped / objective (optional):** peers exchange signed receipt summaries (`rep.gossip`) so you can evaluate a friend-of-a-friend you haven't met, discounting by how much you trust the attesters. Transitive (EigenTrust-style) weighting is a drop-in; the inputs are all signed receipts.

`reputation.score(pubkey) → score` is a read-only query, used by placement (§6), by holders deciding whether to accept a `frag.offer`, and by readers choosing whom to fetch from first.

### 12.3 What reputation buys (the incentive loop)

Reputation is spendable as **priority**, which closes the loop without money:
- **Durability for your own data.** High-reputation owners get their `frag.offer`s accepted readily and placed on the best holders; low or negative-reputation peers are throttled or asked to contribute first.
- **A storage allowance proportional to contribution.** A soft, tit-for-tat budget: roughly, the cohort will durably hold for you about as much as you have reliably held for others. This makes leeching self-limiting and makes donating storage directly valuable to the donor.
- **Preferential read bandwidth and faster repair participation.** Good citizens are chosen first to serve and to repair, and earn more receipts doing so — the loop compounds.

Honest, available, truthful-about-capacity nodes accumulate receipts and climb; nodes that withhold, lie, or churn destructively fail challenges, decay, and get routed around (§10). The reward is that being a good citizen is the *only* way to get good service for your own data.

---

## 13. Threat model and what leaks

Because the network is a closed social cohort, the dominant open-network threats shrink: you only peer with people you've added, so Sybil flooding and eclipse are not the everyday concern they are in an open network, and the installer policy stays restrictive (an open registry would be remote code execution) so untrusted WASM never lands.

**What is protected.** Content — encryption means holders see only ciphertext (§3.5). The wire — an authenticated, encrypted channel with each frame's signer pinned to the channel identity. The content↔holder mapping — there is no global index, and the holder map is never stored, only recomputed live within the cohort. Integrity — content addressing (§3.3). Identity — signatures.

**What leaks, accepted by the closed-cohort assumption.** All of these are disclosures *to peers you have chosen to store with, about files you have already shared with them*:
- **Inventory size** — a peer you have/want with learns roughly how much you store and a shared file's fragment count.
- **Per-file holdings** — to a peer in a file's sharing group, which fragments you hold or want.
- **Interest** — asking a key-holder for a file reveals you wanted it (a non-key-holder learns nothing — the id is an opaque hash).
- **Social graph** — who you maintain channels with is visible at the transport level. This is the residual metadata of going social, and it is far smaller than what a global, queryable index would expose.
- **Ex-member probing** — someone who once held a file's ids can probe for those specific blocks until repair rotates them away; for sensitive files, re-encrypt and rotate on a membership change (expensive, usually done only when it matters).

**Optional hardening (documented, deliberately unbuilt).** Add only if a deployment's cohort is less than fully trusted; none of it is needed for a friends-or-devices cohort, and adding it by default would make the system the complicated monster we are avoiding:
- **PRF locator tags.** Address blocks by `tag = PRF_{K_loc}(fragment_id)` (with `K_loc` a per-file locator key separate from the decryption key) instead of by the raw ciphertext hash. This decouples the locator from the content hash, gives holders and observers unlinkability, and lets you rotate locators on a membership change without re-encrypting. Cost: one extra per-file key and a second identifier in the manifest.
- **Size-hiding have/want.** Pad have-sets to a round number or send them as Bloom filters to blunt the inventory-size leak — cheap, and the right first step for a semi-trusted pool.
- **Size-Hiding PSI.** A malicious-secure, size-hiding private set intersection would hide set size and non-intersection elements even from an authorized-but-curious peer, at the cost of a multi-message protocol, real per-run latency, mandatory rate-limiting, and a substantial implementation burden. It is a possible future layer for genuinely semi-trusted community pools, **not** part of this design.

**Residual kernel-inherited risk.** The protocol does not bound a single handler's CPU or memory, so run the heavy `erasure` and `repair` handlers under a Worker watchdog.

---

## 14. New bridges (host-native, `SetHandler`-installed, one capability each)

| Bridge | Cap | Payload (request) | Host action |
| --- | --- | --- | --- |
| `store.local` | `store` | op-tagged: `put`/`get`/`has`/`delete`/`list`/`stat` (§11) | read/write the donated blob store (FS or OPFS/IndexedDB) |
| `net.send` | `net` | `[peer_id_len][peer_id][bytes...]` | addressed unicast to a cohort peer over its data channel (open/reuse) |
| `clock.now` | `clock` | (empty) | u64 unix ms — grace windows, challenge timing, repair jitter |
| `rand` | `rand` | `[n]` | n cryptographically-random bytes — nonces, content keys, jitter |

`net.send` is the one genuinely new transport primitive (it adds addressed unicast). Async by nature, so it returns a correlation id and the host later delivers the response back to the originating handler. `clock.now` and `rand` are conventional bridges a deployment likely already has.

---

## 15. New app handlers (WASM, installed via signed messages)

| Handler | Caps | Role |
| --- | --- | --- |
| `chunker` | — (pure) | split files into chunks; slice fragments into ≤ 48 KB blocks; compute block-ids |
| `erasure` | — (pure) | Reed–Solomon encode/decode |
| `manifest` | — (pure) | build/parse manifests; wrap/unwrap content keys |
| `cohort` | `net`, `clock` | maintain the peer set and connections; run have/want exchanges and liveness checks |
| `store.coordinator` | `store`, `net`, `clock` | orchestrate PUT/GET, including placement negotiation; windowed transfer |
| `repair` | `store`, `net`, `clock` | the repair loop: measure redundancy via have/want, claim, reconstruct (§9) |
| `proof` | `store`, `clock` | answer challenges (holder side) and issue them + sign receipts (challenger side) |
| `reputation` | — (pure) | accumulate signed receipts within the age bound; compute local + optional gossiped scores; `reputation.score` query |

Discovery and placement are deliberately light: a single small `cohort` handler keeps the peer set and runs have/want, and placement is just negotiation folded into `store.coordinator`. The three pure handlers (`chunker`, `erasure`, `manifest`) declare **no** capabilities, so the structural sandbox guarantees they can never reach disk or network even if buggy — the heavy crypto/coding code is exactly where you want that guarantee. Mutating handlers (`store.coordinator`, `repair`, `proof`) that act under a signer's authority consume a per-signer sequence number to reject replays.

---

## 16. Message catalog (control plane; every message ≤ 64 KB)

| Name | Direction | Payload sketch |
| --- | --- | --- |
| `store.put_req` / `store.put_done` | user ↔ coordinator | file blocks in / `manifest_id` out |
| `store.get_req` / `store.get_done` | user ↔ coordinator | `manifest_id` in / file blocks out |
| `frag.offer` / `frag.accept` / `frag.decline` | coordinator ↔ peer | `block_id`, size / accept / reason |
| `frag.fetch_req` / `frag.block` / `frag.ack` | reader ↔ holder | wanted block-ids / a block (bulk plane) / window ack |
| `disc.have` / `disc.want` | peer ↔ peer | block-ids held / block-ids wanted (the discovery layer, §5) |
| `proof.challenge` / `proof.response` / `proof.receipt` | challenger ↔ holder | nonce+offset / sector+merkle / **signed** receipt |
| `repair.claim` | peer ↔ cohort | "I'm repairing this file" — suppresses duplicate repair (§9) |
| `rep.gossip` | peer ↔ peer | signed receipt summaries (optional, for friend-of-a-friend scoring) |

Control messages that authorize a state change (the mutators in §15) carry a leading sequence number and are dropped on replay. Bulk `frag.block`s carry no signature; they are validated by `genesis_hash(bytes) == block_id` (§4).

---

## 17. Bootstrap additions

On top of the kernel bootstrap, a storage-capable node additionally:

1. Installs the storage bridges it offers: `store.local` (always, to donate space), `net.send`, `clock.now`, `rand`.
2. Wires an installer policy that admits the storage app handlers — restrictive, *never* open, e.g. a content-hash allowlist of audited storage-handler bytecode plus a closed author set for who may publish upgrades.
3. Receives the storage app handlers as signed install messages (`chunker`, `erasure`, `manifest`, `cohort`, `store.coordinator`, `repair`, `proof`, `reputation`) — each declaring exactly the caps in §15.
4. Joins its cohort: connects to known peers (by introduction or a rendezvous point), exchanges have/want, and starts serving.

A node that only wants to *donate* storage installs the holder-side path (`store.local`, `cohort`, the accept/serve half of `store.coordinator`, the holder half of `proof`) and never needs the writer's chunker/erasure/manifest. A read-only client needs the reverse. The onion composes per-role.

---

## 18. Tuning knobs and open questions

- **`(k, m)` and chunk size** — the durability/overhead dial. Size against measured cohort churn so that the chance of losing more than *m* holders within one repair interval is acceptably small.
- **Grace window `G` and liveness cadence** — set so ordinary offline patterns (overnight, commute, reboot) never trigger repair, but real departures do within a bounded time. Too short → churn storms; too long → slow healing.
- **Low-water mark & repair jitter** — trade healing speed against repair traffic and duplicate-repair avoidance.
- **Cohort uptime** — the load-bearing durability decision (§9): each sharing group should include at least one well-connected, long-lived peer so repair can always run.
- **Reputation window `X` and weighting** — the age bound (§12.2), the weighting of volume/diversity/recency, and whether to enable gossiped transitivity. This lives in the pure, swappable `reputation` handler.
- **Bulk transport choice** — in-band hash-verified frames (simplest) vs. a dedicated bulk channel (fastest). §4 supports either.
- **Convergent vs. random-key encryption** — dedup vs. equality-leak (§3.5).
- **Optional hardening** — PRF locator tags, padded/Bloom have-sets, or full PSI for less-trusted cohorts (§13). Off by default; add only when the cohort's trust assumption no longer holds.

Everything above is expressible as bridges, pure-compute handlers, signed messages, and a restrictive policy callback — i.e. as ordinary seedkernel modules. The kernel never learns what a "file" is; it just keeps routing names to handlers, the bulk bytes never enter its 64 KB world, and the design stays four ideas deep: a social cohort, encryption, content addressing, and have/want.
