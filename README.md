# Seed store: a peer-to-peer storage layer for seedkernel

## 1. Introduction

Seed store is a peer-to-peer storage layer for [seedkernel](https://github.com/arj03/seedkernel). It lets any node donate whatever storage it has and store files across a set of peers, so that no single peer can make a file unavailable, peers can be offline for stretches without data loss, the system heals itself by moving data when redundancy drops, large files are sharded so size is bounded only by the swarm, and good citizens earn durability for their own data through direct reciprocity rather than a coin.

Seedkernel routes small signed messages and puts a hard size cap on each one, so bulk data lives outside the kernel and is referenced by a content hash. Seed store is that outside store: the kernel keeps routing names to handlers, the bytes never touch its dispatch path, and everything here is built from the pieces seedkernel already provides — a name to dispatch on, bytes that are a WASM handler, and an author who signed the install.

This design assumes a **closed, social network**: you store with and among peers you have a relationship with (friends, friends-of-friends, or an explicit storage group), not an open market of strangers. That assumption is what keeps the whole thing small — privacy and Sybil resistance come from the *shape* of the network rather than from added cryptographic machinery. The whole system is five ideas: **a social cohort, client-side encryption, content addressing, erasure coding, and a have/want exchange**.

**Design principles (inherited from the kernel, applied to storage):**

- The storage layer adds **no new kernel concepts**. It is bridges + app handlers + message names, gated by the existing capability and signature machinery.
- **Integrity comes from content addressing, not from signatures.** A block is named by its hash; a block either hashes to its name or it is discarded. This is what lets bulk transfer skip the per-message verify (§3).
- **Identity comes from the signature module.** A peer *is* its kernel pubkey. Reciprocity and authority key on that one identity.
- **Redundancy is erasure coding, not replication.** Any *k* of *n* blocks reconstruct a chunk, so up to *n − k* holders can vanish with no data loss, at a fraction of replication's overhead.
- **Placement is by relationship, not by global address.** A chunk's blocks live on peers in your cohort, chosen by negotiation. Who holds what is discovered live from the cohort rather than pinned anywhere, and there is no global index — the absence of that index is a feature, not a gap (§5).
- **Confidentiality is structural.** The wire is encrypted; stored data is encrypted so holders only ever see ciphertext; and there is no public directory mapping content to holders.
- **Trust is local before it is global.** The base system rewards good citizens by direct, pairwise reciprocity you witness yourself (§13); portable, verifiable reputation across peers you have never dealt with is an optional layer (§20), not a baseline requirement.
- **Browser nodes and long-running peers run the same protocol**, differing only in their `store.local` backend and default quota.

The reference composition stacks: storage app handlers → cohort + repair handlers → storage bridges (`store.local`, `net.send`, `clock.now`, `rand`) → installer → signature → kernel.

---

## 1.1 Concepts at a glance

- **Block** — the one unit of stored data: a content-addressed slice of ciphertext, ≤ 48 KB so it fits an envelope with room for framing (§3). `block_id = genesis_hash(block_bytes)`. A block is simultaneously an erasure-coding shard *and* the unit that moves on the wire.
- **Chunk** — a logical slice of a file: `k` data blocks plus `m` Reed–Solomon parity blocks = `n = k + m` blocks, any *k* of which reconstruct it. `chunk_id = genesis_hash(ciphertext chunk)`.
- **Chunk descriptor** — the small *signed* record of a chunk's shape: its `(k, m)`, `chunk_id`, and the `n` block-ids. The only thing a repairer needs; author-signed so a holder cannot forge it; both listed in the manifest and stored alongside every block (§4.3).
- **Manifest** — the file's root object: the list of chunk descriptors plus the wrapped content key. The only thing you need to *read* a whole file. It does *not* name holders; which peer holds a block is discovered live from the cohort.
- **Cohort** — the bounded set of peers you have a storage relationship with. Discovery, placement, and repair all happen inside it. There is no global overlay.
- **Have/want** — the discovery primitive: peers tell each other which block-ids they hold or want. One round trip, no crypto protocol.
- **`store.local`** — the I/O bridge (capability `store`) that reads/writes the node's donated blob store: filesystem on a server, OPFS/IndexedDB in a browser.

```
file ─encrypt─► ciphertext ─slice into k─► data blocks ─RS(k,m)─► n blocks (k data + m parity)
                                                                   │ each block = one content-addressed ≤48 KB ciphertext block
                                                                   ▼
                              placement: negotiate with cohort peers (block.offer / accept)
                                                                   ▼
                    push block + chunk descriptor ──► distinct cohort peers      locate later via have/want
```

---

# Part I — The minimal system

This is the whole system you actually need: a durable, private, self-healing store for a cohort of friends or your own devices. It is complete on its own — every section in Part II is an optional add-on you reach for only when a specific assumption changes.

## 2. How it composes with the kernel

Nothing here changes the envelope, the dispatch rule, or `SetHandler`. Storage shows up as four kinds of seedkernel object:

**Identity.** Every operation that needs "who" reads `signature.signer`. The author of a manifest, the signer of a chunk descriptor, the peer whose reciprocity standing moves — all are the top signer. There is no separate account system.

**Names.** All storage messages are envelopes with storage names. App handlers install under author-scoped names so two deployments' storage apps never collide.

**Capabilities.** Each storage bridge is bound to exactly one capability, declared by the handlers that use it at install time and acknowledged by the installer policy. A pure-compute handler (the chunker, the erasure coder, the manifest builder, the reputation math) declares **no** caps — it is computation, and the structural sandbox guarantees it can touch no I/O even if compromised.

**Transport.** Seed store needs an authenticated channel between peers that carries kernel envelopes, with each frame's signer pinned to the channel identity; any such transport works (the chat demo's WebRTC data channel is one example). It adds one capability-gated `net.send` for *addressed unicast* to a specific cohort peer, and bulk blocks ride the existing data channel as unsigned, hash-verified frames (§3); a dedicated bulk channel is an optional performance upgrade (§22).

**The 64 KB cap is the whole reason this layer exists**, so §3 treats it first.

---

## 3. The bulk-data problem (64 KB) and the two planes

The single hardest constraint is that **no envelope may exceed 64 KB**, and it is a fixed protocol constant, not a knob. So a multi-megabyte file cannot be one message, and even a single chunk is many messages. Seed store splits into two planes:

**Control plane — kernel envelopes.** Manifest root hashes, have/want exchanges, placement offers, fetch requests, receipts, repair coordination. These are small, identity-bearing, and signed where authorization matters. They flow through the normal dispatch pipeline and pay the per-message verify — fine, because they are infrequent relative to bytes moved.

**Bulk plane — content-addressed blocks.** Blocks ≤ 48 KB, **self-verifying by hash**, so they need no signature for integrity. In the base design they ride the existing data channel as **unsigned, hash-verified frames**: the receiver verifies `genesis_hash(bytes) == requested block_id` and drops on mismatch. This stays entirely inside the seedkernel message model, inherits the channel's encryption and pubkey pinning, and avoids per-block verify cost because there is no signature to check. (A dedicated bulk data channel for higher throughput on large files is an optional upgrade — §22.)

The rule is the same either way: **the control plane carries hashes and authorization; the bulk plane carries hash-named bytes that authenticate themselves.** Transfers are flow-controlled with a simple windowed request/ack (`block.fetch_req` lists wanted block-ids; the holder streams `block.data`s; the receiver acks ranges) so a browser node doesn't blow its heap on a large file.

---

## 4. Data model: files → manifests → chunks → blocks

### 4.1 Chunking and erasure coding (the redundancy primitive)

A file is encrypted (§4.4) and the ciphertext is cut into fixed-size **blocks** of `B` bytes (default `B = 48 KB`, sized so one block plus framing fits the 64 KB envelope, §3). Blocks are grouped into **chunks** of `k` blocks, and each chunk is **Reed–Solomon `RS(k, m)`** encoded into `m` additional **parity blocks**, for `n = k + m` blocks per chunk of which any *k* reconstruct it. A chunk is therefore just `k × B` bytes of data plus `m × B` bytes of parity, and every block — data or parity — is the same size and the same kind of object.

Defaults: `k = 10, m = 6` → `n = 16`, 1.6× storage overhead, surviving the loss of any 6 of a chunk's 16 holders. Compare naïve 3× replication, which survives only 2 losses at nearly double the cost. Reed–Solomon is **systematic** — the *k* data blocks are the ciphertext verbatim — so when all *k* data blocks are present a read just concatenates them and never decodes; the GF(2^8) decode runs only to heal around missing blocks. Encode/decode is simple, self-contained byte arithmetic that compiles to a small WASM handler needing no capabilities, and it operates on whatever bytes it is given — here, ciphertext (§4.4) — so reconstructing a missing block never requires the file's key.

The choice of `(k, m)` is per-chunk and recorded in the chunk descriptor (§4.3), so a deployment can dial durability per file (cold archives might use `RS(20, 20)`; hot ephemeral data `RS(4, 2)`).

**This alignment — `chunk = k blocks` — is what collapses the data model.** A block *is* an erasure shard *is* the unit on the wire, so there is no distinct "fragment" object to slice, list, or address; a chunk's descriptor is simply its list of `n` block-ids, and one block per message is always true by construction. (Fixed-size chunking is also the simplest; a deployment that wants cross-file dedup can swap in content-defined chunking, at the cost of variable-length blocks that no longer map one-to-one onto shards.)

### 4.2 Blocks are content-addressed

Each block is content-addressed: `block_id = genesis_hash(block_bytes)`. Content addressing makes every block **self-verifying**: a receiver recomputes the hash and rejects anything that doesn't match, so a malicious holder cannot return corrupt bytes undetected, and no signature is needed on bulk data (§3). Because the bytes are ciphertext (§4.4), a `block_id` is the hash of an encrypted blob — opaque and unguessable to anyone who has not handled that exact file.

### 4.3 The manifest and the signed chunk descriptor

Two small objects describe a file: a per-chunk **descriptor** and the file's **manifest**.

**The chunk descriptor** is a chunk's *shape*, and it is the only thing a *repairer* needs (§9). *Reading* a file needs the whole manifest and the content key and is gated to the sharing group; *repair* needs much less, and we want it possible for far more peers, so each stored block carries its chunk's descriptor. This descriptor is control-plane data and **must be authenticated**: `block_id = genesis_hash(block_bytes)` covers a block's *bytes* but says nothing about the *relationships between blocks*, so an unsigned descriptor could be altered by a malicious holder to misdirect or suppress repair — point a repairer at blocks that don't exist, lie about `(k, m)`, or hide that a chunk is decaying. Content addressing alone cannot close this gap: a tampered descriptor is still a valid string of bytes, and what's missing is an anchor the attacker cannot forge. So the descriptor is **signed by the file's author** (the §2 identity):

```
descriptor D:
  chunk_index
  k, m                 // RS parameters for this chunk
  chunk_id             // = genesis_hash(ciphertext chunk) — the keyless reconstruction anchor
  block_ids[0..n)      // the n blocks of this chunk, by index (0..k data, k..n parity)
descriptor_id = genesis_hash(canonical(D))
repair_cert   = sign_author(descriptor_id)
```

Every peer that accepts a block first verifies its descriptor: it is self-consistent (`genesis_hash(canonical(D)) == descriptor_id`), `repair_cert` is a valid author signature over it, and the block's own `block_id ∈ block_ids`. A block whose descriptor fails any check is rejected outright. A holder therefore cannot alter the descriptor it serves — the signature won't re-verify — and cannot substitute its own key, because authority is bound to the file's author, the same trust root that decides whose tombstone is honored (§11). The authenticated `chunk_id` additionally lets a repairer certify its *own* reconstruction before propagating it (§9), so a bad descriptor can never cause garbage to be minted. **Verifying the descriptor needs only the author's *public* key — never the read key — so keyless repair (§9) is preserved.** The descriptor discloses a chunk's size and shape to anyone storing a piece of it — the disclosure accepted in §15 — but never its contents, and never a forgeable instruction.

**The manifest** is the file's root — small, and the only thing a reader needs to bootstrap a download. It is the list of every chunk descriptor plus the metadata to decrypt:

```
manifest (CBOR or fixed binary; itself stored as blocks, §3):
  version
  file_size, B                          // block size
  enc:    { alg, nonce_base }           // §4.4; absent if stored in clear
  chunks: [ descriptor, ... ]           // the signed chunk descriptors, in order
manifest_id = genesis_hash(manifest_root)
```

The manifest is encrypted under the file's content key and stored exactly like file data — **erasure-coded and spread across cohort peers** — so it has no single point of failure and there is no index server. If it exceeds one block it is chunked like anything else, and `manifest_id` is the hash of a tiny root that lists the manifest's own block-ids (for a manifest that fits one block, the root *is* that block). A file is referenced by `manifest_id`; that one hash, under a signature, is what travels in a 64 KB kernel envelope. Crucially, the manifest says *what* blocks a file is made of, never *which* peers hold them — that is discovered live via have/want (§5), so the holder map stays current under churn and repair instead of going stale in a fixed file.

The same descriptor object thus lives in **two homes**: inside the (encrypted) manifest, so a reader gets every chunk's shape at once; and in the clear alongside each stored block, so a repairer who lacks the manifest still has its chunk's shape and can verify it from the author's public key alone. It is small and signed, so duplicating it is cheap and tamper-evident in both places.

### 4.4 Encryption (the load-bearing privacy mechanism)

Kernel envelopes are signed, not encrypted, and at-rest storage has no confidentiality of its own. In this design, **encryption is what makes the closed network safe** — it lets you store on cohort peers who can read nothing, and it makes block-ids opaque. Seed store encrypts **client-side before erasure coding**:

- Generate a random per-file **content key** `K`; AEAD-encrypt each chunk (key + per-chunk nonce) before slicing into blocks and erasure-coding. Holders store ciphertext blocks and learn nothing about content. The manifest (§4.3) is encrypted under `K` the same way.
- **Sharing a file is sharing the key, not moving bytes.** The owner sends a recipient `{ manifest_id, seal(K → recipient_pubkey) }` over a signed envelope — `K` sealed to the recipient's kernel public key (e.g. an X25519 sealed box). The key is never stored in clear on holders, which is what avoids the circularity of putting `K` inside a manifest that `K` encrypts. Re-sharing is one more sealed copy; revocation that must deny future reads rotates `K` and re-encrypts (§23).
- Random per-file keys mean two different files never produce colliding ciphertext, so a `block_id` is meaningful only to someone who has handled that exact file. Convergent encryption (key = hash(plaintext)) is an opt-in for deployments that want cross-user dedup and accept its equality-leak (§24).

---

## 5. Discovery: a social cohort with have/want

We need to answer two questions — *which peers should hold a block?* and *who currently holds it?* — without a public, queryable index that would map content to holders. The closed-network assumption (§1) lets us answer both with almost no machinery.

### 5.1 The cohort

A node keeps connections to a **bounded set of peers it has a relationship with** — direct contacts plus, optionally, a hop or two out. There is no global index or routing table; nothing about who-holds-what exists outside your cohort. New peers join the way Scuttlebutt peers do, by introduction or via a rendezvous point. Cohort size is tens to low hundreds, which is what keeps every operation here cheap.

### 5.2 Have/want is the whole discovery layer

- *Who currently holds block B?* — ask the cohort. A have/want carrying the block-ids turns up whoever has them right now; nothing is pinned in advance, so the answer is always current.
- *Are there extra replicas, and is a given peer still holding its blocks?* — the same one-round exchange: "I want these `block_id`s" / "I have these `block_id`s." No lookup walk, no cryptographic protocol, no rate-limit machinery.

Block-ids are hashes of random-key ciphertext (§4.4), so to a peer outside a file's sharing group they are opaque noise, and on the wire they are encrypted. The only parties who can interpret a have/want entry are those who already hold the file's key — i.e. people you deliberately shared with.

Note that have/want is **advertisement, not proof**: a peer can answer "have" to a block it cannot actually serve. §8 closes that gap by backing the redundancy count with occasional verification-fetches.

### 5.3 What this is, and is not

This is deliberately **not an open market**: strangers cannot find or serve your data, because there is no global index and nothing to query. That absence is the privacy property we want. The cost is that storage is confined to your cohort — the trade we are choosing.

What leaks, and why it is acceptable here: a peer you exchange have/want with learns which block-ids you hold or want *of files you have already shared with it*, and roughly your inventory size. These are disclosures to people you have already chosen to store with, about files you have already shared with them. The full leak inventory and the optional hardening for less-trusted cohorts are in §15 and §23.

---

## 6. Writing a file (PUT)

1. **Chunk & encrypt.** The owner generates a random content key `K` (via `rand`) and feeds the file to the `chunker` (cap-free) block-by-block, AEAD-encrypting each chunk under `K` (§4.4).
2. **Erasure-code.** The `erasure` handler (cap-free) turns each chunk's *k* data blocks into *m* parity blocks; the `chunker` computes all `n` block-ids and forms the chunk's descriptor, which the owner signs (§4.3).
3. **Place by negotiation.** For each block, the `store.coordinator` picks candidate cohort peers — ordered by reciprocity standing (§13) and current reachability — and sends `block.offer(block_id, size, signed descriptor)`. A peer with free quota and willingness replies `block.accept`; otherwise `block.decline` and the coordinator moves to the next candidate. There is no global placement function; placement is a short private negotiation within the cohort.
4. **Push.** On accept, the coordinator streams the block over the bulk plane (§3) together with its signed chunk descriptor, so the holder can verify it and later help heal the chunk.
5. **Build & store the manifest.** The `manifest` handler assembles the signed descriptors and encryption header, encrypts the manifest under `K`, and stores it the same erasure-coded way (§4.3). The manifest lists block-ids, not holders; which peer took which block is rediscovered live via have/want, so placement can shift under repair without the manifest going stale.
6. **Publish.** `manifest_id` is what the owner keeps and shares (with `K` sealed to each recipient, §4.4), wrapped in a signed 64 KB envelope.

The `n` blocks of a chunk are placed on **distinct peers** (the coordinator enforces no-two-blocks-of-a-chunk-same-holder), so losing one peer costs at most one block of any chunk — the core of the §10 invariant.

---

## 7. Reading a file (GET)

1. **Resolve the manifest.** Using the sealed `K` you were given, fetch the manifest's blocks from the cohort peers that hold them, verify by hash, and decrypt → the chunk descriptors.
2. **Locate blocks.** Send a have/want to the cohort for a chunk's block-ids. You need any *k* of *n* per chunk, so race requests to the *k* best-scoring reachable peers that answer; if some are offline, the same have/want surfaces any extra replicas repair has created.
3. **Fetch & verify.** Stream blocks over the bulk plane; each is checked against its `block_id` (self-verifying, §4.2).
4. **Decode & decrypt.** If all *k* data blocks arrived, concatenate them (systematic RS, no decode); otherwise RS-decode any *k* blocks to recover the chunk ciphertext. AEAD-decrypt, concatenate chunks.

Because any *k*-of-*n* suffices, a read succeeds even with up to *m* holders offline or unwilling — no peer is on the critical path.

---

## 8. Availability and offline tolerance

Peers are expected to disappear and come back. The protocol distinguishes a transient blip from real loss so it doesn't churn data on every disconnect — and it does so by direct observation within the cohort, not by a global refresh scheme.

**How liveness is observed.** Any block-holder (or the owner) periodically sends a have/want for a chunk's block-ids and notes who answers. There is no record to refresh and nothing to expire, so the picture is always current. Because have/want is only advertisement (§5.2), the picture is **backed by occasional verification-fetches**: a holder is counted as truly holding a block only if it has recently *served* that block (or a sampled one of its blocks) and the bytes hashed to their `block_id`. A peer that advertises blocks it cannot serve is detected this way and treated as not holding them — which also feeds reciprocity (§13).

**Three states per holder of a block:**
- **Live** — recently reachable *and* recently served a verification-fetch for the block (or a sampled sibling).
- **Suspected** — unreachable within a **grace window** `G` (default 24 h). *No repair.* This is precisely "a node may be offline for a period": a laptop closed overnight, a phone in a tunnel, a server rebooting all sit here and recover for free when they reappear.
- **Lost** — unreachable beyond `G`, or repeatedly failing to serve a block it advertises. Eligible to be counted as missing for repair.

**Redundancy measure.** For a chunk, `live_blocks` = number of distinct blocks with at least one Live holder. Data is safe while `live_blocks ≥ k`; the healthy target is `n = k + m`. Repair triggers on a **low-water mark** strictly above `k` (§9), never waiting until the chunk is one loss from death.

**Browser nodes specifically** are treated as low-uptime, often-Suspected holders: they may serve reads and act as extra cache while present, but the durable *m* leans on longer-lived cohort members. A deployment can tag node longevity so placement prefers steady peers for durability and lets browsers absorb read load.

---

## 9. Self-healing / repair

Repair is per-chunk, and it is performed by the chunk's own **block-holders**. Anyone holding a block also holds that chunk's signed descriptor (§4.3) — the sibling block-ids, `(k, m)`, and `chunk_id` — which is all you need to audit and rebuild it, and reconstruction runs on ciphertext, so a repairer never needs the file's key (only the author's public key, to check the descriptor). The sharing group *reads*; any block-holder *repairs*. No peer is special and no one is appointed; the work gets done by whoever notices first.

This is what makes repair redundant. The peers able to heal a chunk are exactly the peers storing it — about `n` of them — so repair survives as long as a single block-holder is online, and the repair-redundancy automatically scales with the durability `m` you chose. (The alternative, tying repair to whoever can read the manifest, would make a private file's owner the sole possible repairer — a single point of failure for healing even when the bytes themselves are amply redundant.)

**The repair loop (run by any block-holder on a jittered interval):**
1. Send a have/want to the cohort for the chunk's block-ids (§5), and sample a verification-fetch or two (§8) to confirm advertised blocks are actually retrievable → `live_blocks`.
2. If `live_blocks < low_water` (default `k + ⌈m/2⌉`), repair is needed.
3. **Avoid duplicate work** with a jittered timer: the peer that fires first announces it (`repair.claim`); others hold off and cancel when a freshly placed block shows up in have/want. Because the cohort is small and the claim is observable, this needs no election or coordinator.
4. The repairer fetches any *k* retrievable blocks, reconstructs the chunk's ciphertext, and **verifies `genesis_hash(reconstructed) == chunk_id`** from the signed descriptor before trusting the result — this catches a tampered `(k, m)`, a wrong fetched block, or any decode error keylessly, so a poisoned descriptor can never make repair mint or propagate garbage. It then re-encodes only the **missing** blocks (deterministic, so they keep their original block-ids) and places them on fresh cohort peers (§6 steps 3–4) with the signed descriptor, skipping current holders so redundancy spreads to new peers.
5. The new blocks are immediately discoverable via have/want; redundancy returns to `n` with no manifest change, since the manifest never named holders.

**Moving data on availability change** is the same loop run proactively: if a peer sees the cohort thinning (many Suspected/Lost holders, e.g. a correlated outage), it re-spreads blocks toward healthier peers before a chunk crosses low-water.

**The one real cost**: a chunk can only be healed while at least one of its block-holders is online within a repair interval. With about `n` holders that is a weak requirement, but it can still fail if a chunk's holders are *all* low-uptime and go dark together (e.g. an all-browser cohort overnight). Placing at least one durable peer among each chunk's holders removes the risk — which is also what §8 recommends for the durable `m`.

**Repair amplification is bounded** by erasure coding: regenerating one lost block costs *k* block-reads and one chunk reconstruction, and only the lost blocks are rebuilt. (When that *k*-read cost dominates, a Locally Repairable Code cuts it — §21.)

---

## 10. The redundancy invariant: no peer can make data unavailable

This requirement is met structurally, not by trust:

- **No block is unique.** A chunk survives on any *k* of *n* blocks, and the *n* blocks live on distinct peers (§6). One peer holds at most one block of a given chunk, so its disappearance — or its refusal to serve — costs at most one block. You need *more than m* peers to fail or defect simultaneously to lose a chunk.
- **No metadata is unique.** The manifest is stored the same erasure-coded way (§4.3); there is no single index server, and the holder map is not stored at all — it is recomputed live.
- **No single repairer is required.** Any of a chunk's ~`n` block-holders can heal it (§9), on ciphertext, without the read key; removing any one removes no capability. Repair-redundancy is therefore as high as the data-redundancy *n*, not gated on a small set of readers. And because each chunk's shape travels as an **author-signed descriptor** (§4.3), no holder can misdirect or suppress repair by tampering the header — an altered descriptor fails its signature check and is rejected.
- **Withholding is detected and routed around.** A holder that stops serving fails its verification-fetches (§8), loses reciprocity standing (§13), and gets skipped in future placement; its unreachability tips it to Lost and triggers repair. Active malice degrades to the same path as passive offline-ness.
- **Corruption is impossible to hide.** Content addressing (§4.2) means a tampered block fails its hash check and is discarded; the reader simply fetches another block.

The honest assumptions this rests on: *fewer than the redundancy budget of a chunk's holders fail or defect within a repair interval*, and *at least one of a chunk's block-holders is online within that interval*. Sizing `(k, m)`, the low-water mark, and the repair cadence against your cohort's real churn is the deployment's durability dial (§25).

---

## 11. Removal

In a store where other people hold your bytes, you cannot force a remote peer to delete on command, so removal is two mechanisms with different guarantees.

**Crypto-shredding — the guarantee.** Because every file has a random per-file key (§4.4), destroying that key makes all of its ciphertext blocks — and its encrypted manifest — permanent noise to everyone, immediately and irreversibly. The owner and sharing group drop the sealed key from their keystores; whatever ciphertext lingers on holders is unreadable forever. This is the only deletion the system can actually promise, and for confidentiality it is enough: a "deleted" file is one whose key no longer exists.

**Tombstones — best-effort space reclamation.** To get the bytes off disk, the owner publishes a **signed `block.tombstone`** for the chunk's block-ids, gossiped through the cohort. A holder that receives it verifies the signature, drops the blocks, and stops counting them. Online holders comply at once; offline holders comply when they reconnect and see the tombstone; and the tombstone also tells block-holders to **stop repairing** that chunk, so it is allowed to decay below low-water and be reclaimed instead of healed back to life. Anything a tombstone never reaches simply ages out through normal eviction (§14).

**Authority.** A tombstone is honored only when signed by the manifest's author (the §2 identity). For a shared file the simple rule is that only the owner's tombstone removes the data; a member who no longer wants it just drops its own copy and stops repairing — it cannot delete for everyone.

Tombstones are bounded too: a holder keeps one only until the referenced blocks are gone and a short grace period passes, so the tombstone set does not grow without limit.

---

## 12. Donating storage

"Donate whatever storage you have available" is the `store.local` bridge plus a host-configured quota.

**`store.local` (capability `store`)** is a host-native bridge with operations `put(block_id, bytes)`, `get(block_id) → bytes`, `has(block_id)`, `delete(block_id)`, `list(prefix)`, and `stat() → { quota, used, free }`. Like every bridge it runs the caller-capability check before touching disk, so only handlers that declared `store` at install time can reach it. A holder stores opaque `(block_id → ciphertext)` pairs plus the small signed descriptor (§4.3): it needs no file key and learns nothing about what it is holding beyond the chunk's shape.

**Backends differ by host, protocol does not:**
- **Long-running peer:** a directory on disk; quota is a config number; effectively always Live.
- **Browser node:** OPFS or IndexedDB; quota bounded by the browser's storage budget; eviction-aware (treat browser-evicted blocks as Lost and let repair handle them). The browser shell exposes a "donate N GB" control to set the quota.

**Quota honesty is enforced, not assumed.** A node advertises free space, but no peer trusts the number — it trusts the node's track record of *actually serving the data it accepted* (§8, §13). Lying about capacity gets you data you then fail to serve, which costs reciprocity standing. `store.local.stat()` is for the owner's own accounting and admission control (refuse `block.offer` when full), not a network-trusted figure.

---

## 13. Reciprocity: rewarding good citizens without a coin

The reward for being a good citizen is **durability for your own data and good service from your cohort**, and the thing that earns it is *reliably holding and serving data for others*. No token, no ledger, no global reputation object — just **direct, pairwise reciprocity**, which in a closed cohort is all you need and is inherently Sybil-proof: you score only peers you have actually interacted with, so identities a peer invents to inflate itself never enter your view.

### 13.1 The local score

Each node keeps, per peer, a small **decayed reciprocity balance** built only from things it has *witnessed directly*:
- **Service received** — blocks that peer has reliably held and served for you, confirmed by the verification-fetches that already back repair (§8): occasionally you fetch a random block you placed with a holder and check it hashes to its `block_id`. A pass raises the holder's score; a miss decays it. This reuses the ordinary fetch path — there is no separate challenge protocol and no proof object to store.
- **Reciprocity** — netted against how much you currently store *for* that peer, so the score reflects a running give-and-take.
- **Recency** — old observations decay, so a peer that stops serving fades, and the state never grows without bound.

`reputation.score(pubkey) → score` is a read-only query over these counters, used by placement (§6), by holders deciding whether to accept a `block.offer`, and by readers choosing whom to fetch from first. The whole computation is arithmetic over locally-witnessed events, so it lives in the pure, cap-free `reputation` handler (§17) — and a deployment that stores only among devices one person owns can replace it with a constant.

### 13.2 What it buys (the incentive loop)

Reciprocity is spendable as **priority**, which closes the loop without money:
- **Durability for your own data.** Peers you have reliably served accept your `block.offer`s readily and hold for you; a peer you have never reciprocated with is free to throttle you or ask you to contribute first.
- **A storage allowance proportional to contribution.** A soft, tit-for-tat budget: roughly, the cohort durably holds for you about as much as you have reliably held for others. Leeching is therefore self-limiting, and donating storage is directly valuable to the donor.
- **Preferential read bandwidth and faster repair participation.** Good citizens are chosen first to serve and to repair, and so get more chances to raise their score — the loop compounds.

Honest, available nodes climb; nodes that withhold, lie about capacity, or churn destructively fail verification-fetches, decay, and get routed around (§10). Being a good citizen is the *only* way to get good service for your own data.

**Judging peers you have not dealt with** — a friend-of-a-friend, or a node joining a new sub-cohort — is outside this local picture by design. If a deployment needs *portable, verifiable* reputation that carries across peers who have never stored for each other, it adds the optional signed-receipt and transitive-trust layer of §20. The base system does not need it, and leaving it out is what keeps reciprocity to a page of counters and keeps the §1 promise — Sybil resistance from the shape of the network, not from added machinery.

---

## 14. What to store, and what to evict

A node has finite donated space and will be offered far more than it can hold, so it needs a policy for what to accept and what to drop. This is not a new subsystem — it is the local face of the reciprocity loop (§13). The one structural idea is **two tiers of storage**:

- **Committed** — blocks a node accepted (`block.accept`) and now earns standing by reliably serving (§8, §13). These are not dropped casually: shedding one abruptly means failing its next verification-fetch and losing standing. A node sheds a commitment only by **graceful release** — re-placing the block on another peer, or letting repair pick it up — accepting that durability dips until redundancy is restored.
- **Opportunistic cache** — blocks picked up while serving reads, or extra replicas beyond `n`. Free to evict at any time, no commitment, no reciprocity cost.

**Admission (when a `block.offer` arrives).** Accept weighted by: reciprocity (prefer peers who store for you), social closeness, and how under-replicated the chunk is — a repair offer that lifts a chunk off its low-water mark outranks a routine first placement. Reserve a fraction of quota for commitments so cache cannot crowd out durability, and refuse offers outright when the committed tier is full.

**Eviction (under quota pressure).** Drop cache first, favoring blocks that are cold *and* well-replicated elsewhere, while protecting rare or globally under-replicated blocks (the ones repair would struggle to regenerate). Only if still pressed does a node gracefully release its lowest-value commitments — typically those for low-reciprocity peers. Tombstoned and long-unserved orphan blocks are first out the door, which is how dead data is reclaimed without an explicit delete.

Concretely, an eviction score like `coldness × redundancy_elsewhere × (1 / reciprocity_with_owner)`, with committed blocks weighted heavily against eviction, captures all of this from signals the node already tracks. The exact weighting is a tuning knob (§25); the property that matters is that a well-behaved node keeps what is scarce and what it owes, and sheds what is abundant and unasked-for.

---

## 15. Threat model and what leaks

Because the network is a closed social cohort, the dominant open-network threats shrink: you only peer with people you've added, so Sybil flooding and eclipse are not the everyday concern they are in an open network, and the installer policy stays restrictive (an open registry would be remote code execution) so untrusted WASM never lands.

**What is protected.** Content — encryption means holders see only ciphertext (§4.4). The wire — an authenticated, encrypted channel with each frame's signer pinned to the channel identity. The content↔holder mapping — there is no global index, and the holder map is never stored, only recomputed live within the cohort. Integrity — content addressing (§4.2) for bulk bytes, and an author signature on the chunk descriptor (§4.3) for the shape metadata that drives repair, so a holder cannot forge it to misdirect healing. Identity — signatures.

**What leaks, accepted by the closed-cohort assumption.** All of these are disclosures *to peers you have chosen to store with, about files you have already shared with them*:
- **Inventory size** — a peer you have/want with learns roughly how much you store and a shared file's block count.
- **Per-file holdings** — to a peer in a file's sharing group, which blocks you hold or want.
- **Chunk shape** — a block's descriptor (§4.3) tells whoever stores it the chunk's sibling block-ids and `(k, m)`, i.e. its size and shape — never its content. The PRF-tag hardening in §23 covers it if a deployment cares.
- **Interest** — asking a key-holder for a file reveals you wanted it (a non-key-holder learns nothing — the id is an opaque hash).
- **Social graph** — who you maintain channels with is visible at the transport level. This is the residual metadata of going social, and it is far smaller than what a global, queryable index would expose. (The optional gossip path of §20, if enabled, widens this — another reason it is off by default.)
- **Ex-member probing** — someone who once held a file's ids can probe for those specific blocks until repair rotates them away; for sensitive files, re-encrypt and rotate on a membership change (expensive, usually done only when it matters).

Optional hardening for cohorts that are less than fully trusted is documented separately in §23; none of it is needed for a friends-or-devices cohort, and adding it by default would make the system the complicated monster we are avoiding.

**Residual kernel-inherited risk.** The protocol does not bound a single handler's CPU or memory, so run the heavy `erasure` and `repair` handlers under a Worker watchdog.

---

## 16. New bridges (host-native, `SetHandler`-installed, one capability each)

| Bridge | Cap | Payload (request) | Host action |
| --- | --- | --- | --- |
| `store.local` | `store` | op-tagged: `put`/`get`/`has`/`delete`/`list`/`stat` (§12) | read/write the donated blob store (FS or OPFS/IndexedDB) |
| `net.send` | `net` | `[peer_id_len][peer_id][bytes...]` | addressed unicast to a cohort peer over its data channel (open/reuse) |
| `clock.now` | `clock` | (empty) | u64 unix ms — grace windows, repair jitter, score decay |
| `rand` | `rand` | `[n]` | n cryptographically-random bytes — content keys, nonces, key-sealing |

`net.send` is the one genuinely new transport primitive (it adds addressed unicast). Async by nature, so it returns a correlation id and the host later delivers the response back to the originating handler. `clock.now` and `rand` are conventional bridges a deployment likely already has.

---

## 17. New app handlers (WASM, installed via signed messages)

| Handler | Caps | Role |
| --- | --- | --- |
| `chunker` | — (pure) | AEAD-encrypt chunks (key supplied), slice into ≤ 48 KB blocks, compute block-ids, build chunk descriptors |
| `erasure` | — (pure) | Reed–Solomon encode/decode (on ciphertext) |
| `manifest` | — (pure) | build/parse manifests; seal/unseal content keys (randomness supplied) |
| `cohort` | `net`, `clock` | maintain the peer set and connections; run have/want, liveness, and the verification-fetch sampling that backs it (§8) |
| `store.coordinator` | `store`, `net`, `clock`, `rand` | orchestrate PUT/GET incl. placement negotiation and content-key/nonce generation; issue tombstones; windowed transfer; admission, eviction (§14) and reciprocity accounting (§13) |
| `repair` | `store`, `net`, `clock` | the repair loop: measure redundancy via have/want + verification-fetch, claim, reconstruct on ciphertext (§9) |
| `reputation` | — (pure) | decayed per-peer reciprocity counters from witnessed verification-fetches and served reads; `reputation.score` query (§13). Swap for the §20 receipts-and-transitive handler when portable reputation is needed |

Discovery and placement are deliberately light: a single small `cohort` handler keeps the peer set and runs have/want, and placement is just negotiation folded into `store.coordinator`. There is **no separate proof handler** — proving a holder still has data is an ordinary verification-fetch on the existing fetch path, scored locally by `reputation`. The four pure handlers (`chunker`, `erasure`, `manifest`, `reputation`) declare **no** capabilities, so the structural sandbox guarantees they can never reach disk or network even if buggy — the heavy crypto/coding code and the trust math are exactly where you want that guarantee. Mutating handlers (`store.coordinator`, `repair`) that act under a signer's authority consume a per-signer sequence number to reject replays.

---

## 18. Message catalog (control plane; every message ≤ 64 KB)

| Name | Direction | Payload sketch |
| --- | --- | --- |
| `store.put_req` / `store.put_done` | user ↔ coordinator | file blocks in / `manifest_id` out |
| `store.get_req` / `store.get_done` | user ↔ coordinator | `manifest_id` in / file blocks out |
| `block.offer` / `block.accept` / `block.decline` | coordinator ↔ peer | `block_id`, size, **signed chunk descriptor** (§4.3) / accept / reason |
| `block.fetch_req` / `block.data` / `block.ack` | reader ↔ holder | wanted block-ids / a block (bulk plane) / window ack |
| `disc.have` / `disc.want` | peer ↔ peer | block-ids held / block-ids wanted (the discovery layer, §5) |
| `repair.claim` | peer ↔ cohort | "I'm repairing this chunk" — suppresses duplicate repair (§9) |
| `block.tombstone` | owner → cohort | **signed** "delete these block-ids and stop repairing" (§11) |

Control messages that authorize a state change (the mutators in §17) carry a leading sequence number and are dropped on replay. Bulk `block.data`s carry no signature; they are validated by `genesis_hash(bytes) == block_id` (§3). The optional verifiable-reputation layer (§20) adds `proof.challenge` / `proof.receipt` and `rep.gossip`; the base protocol does not use them.

---

## 19. Bootstrap additions

On top of the kernel bootstrap, a storage-capable node additionally:

1. Installs the storage bridges it offers: `store.local` (always, to donate space), `net.send`, `clock.now`, `rand`.
2. Wires an installer policy that admits the storage app handlers — restrictive, *never* open, e.g. a content-hash allowlist of audited storage-handler bytecode plus a closed author set for who may publish upgrades.
3. Receives the storage app handlers as signed install messages (`chunker`, `erasure`, `manifest`, `cohort`, `store.coordinator`, `repair`, `reputation`) — each declaring exactly the caps in §17.
4. Joins its cohort: connects to known peers (by introduction or a rendezvous point), exchanges have/want, and starts serving.

A node that only wants to *donate* storage installs the holder-side path (`store.local`, `cohort`, the accept/serve half of `store.coordinator`) and never needs the writer's chunker/erasure/manifest. A read-only client needs the reverse. The onion composes per-role.

---

# Part II — Extensions

Everything below is **optional**. The system in Part I is a complete, durable, private store for a cohort of friends or your own devices. Add a layer here only when a specific assumption changes — the cohort grows beyond people who have stored for each other (§20), repair bandwidth dominates cost (§21), throughput on large files matters (§22), the cohort is less than fully trusted (§23), or you want cross-user dedup (§24).

## 20. Verifiable reputation: signed receipts and transitive trust

The base reciprocity score (§13) is *subjective* — your private opinion, not something you can show a third party. When a deployment needs **portable, verifiable** reputation — to judge a friend-of-a-friend you have never stored with, or to let a node carry standing into a new sub-cohort — it upgrades the local tally to signed receipts and weights them transitively. This is strictly additive: nothing in §13 changes, and the pure `reputation` handler is swapped for a richer (still cap-free) one.

### 20.1 Signed receipts (the earning event)

The earning event is the same verification-fetch that §8 and §13 already perform — request a random block, verify it hashes to `block_id` — but now the challenger emits a **signed receipt** on success:

```
proof.challenge:  { block_id, nonce }                        // challenger → holder (signed)
proof.receipt = signature-wrapped {
  holder_pubkey, block_id, nonce, timestamp, PASS,
}                                                            // signed by the challenger
```

Because a block is ≤ 48 KB and self-verifying, **the served block *is* the proof of retrievability** — no Merkle path or random-offset sector proof is needed. (Those exist for systems with gigabyte sectors, where you cannot afford to transfer the whole object to check it; at 48 KB they buy nothing.) The receipt is the kernel's signature wrapper doing what it is for: an authenticated, replay-resistant attestation, each carrying the challenge `nonce`. A holder accumulates receipts as a portable track record.

### 20.2 Transitive trust

A peer's reputation is then computed from the receipts *others signed about it*, weighted by **volume & longevity** (passing challenges for more data, over more time), **challenger diversity** (receipts from many *distinct* peers beat many from one), **recency under a hard age bound** `X` (receipts older than `X`, e.g. 90 days, are discarded rather than kept — this decays a peer that stops serving and bounds how much state anyone stores), and **retrieval success** (serving real `block.fetch_req`s, not just challenges).

The load-bearing rule: when receipts are gossiped (`rep.gossip`) they **must be weighted transitively, never summed flat**, or a clique manufactures its own diversity by signing each other glowing receipts. Concretely this is **EigenTrust-style transitive trust, personalized to the evaluator**. Each peer normalizes its locally-witnessed scores (§13) into a trust vector, then propagates trust over the gossiped receipt graph by damped power iteration — a peer's transitive score is the fixpoint of

```
trust(P) = (1 − d) · local_seed(P) + d · Σ_c trust(c) · rating_c(P)
```

— restarting from its **own** local view rather than any global pre-trusted set. Anchoring on the local seed is what makes it collusion-resistant and keeps it consistent with the subjective default: trust is computed *relative to you*, so a collective with no edge into your local trust set never gains weight, and there is no global reputation object to agree on or attack. A new honest node starts near zero on the gossip path until someone's local trust reaches it — it proves itself locally first — and because the local seed and every edge obey the recency bound, a peer that stops serving loses both its score *and* its power to vouch for others. The whole computation is arithmetic over collected signed receipts, so it stays in the pure `reputation` handler.

**Cost, and why it is optional.** This adds a stored receipt graph and a gossip path, and gossiping who-challenged-whom widens the social-graph disclosure of §15. None of it is needed for a cohort of friends or your own devices, where direct reciprocity (§13) already covers everyone you store with. Add it only when you must trust across people who have never stored for each other.

## 21. Locally Repairable Codes (LRC)

RS (§4.1) is MDS and dead simple — any *k* of *n* reconstruct, repair is a flat `live_blocks ≥ k` count (§8), and the handler is tiny. Its cost is **repair amplification**: healing one lost block reads *k* blocks and reconstructs the whole chunk (§9), and the common failure is exactly one lost block per chunk (§6 puts one block per peer). An **LRC** adds per-group *local* parities on top of *global* ones, so a single lost block rebuilds from just its local group — `r ≪ k` reads, a small linear combination, no full-chunk reconstruct (cheaper bandwidth, CPU, and memory, the last of which matters for browser holders, §3).

It preserves everything RS gives seedstore — fixed content-addressed blocks, deterministic re-encode so the signed descriptor (§4.3) still holds, keyless ciphertext repair — unlike a rateless fountain code (RaptorQ), which would break block content-addressing outright. The price is that LRCs are **not MDS**: durability becomes loss-pattern-dependent, so the clean §8/§10 "any *k* of *n*" accounting must become per-local-group health plus a global check, and §6 placement gains a "spread each local group across distinct peers" constraint.

The win scales with *k* — large for cold archives (`RS(20,20)` → painful 20-read repairs), marginal for small hot chunks — so if adopted it likely belongs as a per-chunk option (the `(k, m)` knob is already per-chunk, §4.1) rather than a blanket default. Revisit if repair bandwidth turns out to dominate operational cost. (Regenerating/MSR codes cut repair bandwidth further still but contact more helpers per repair — worse coordination under churn — so LRC is the pragmatic step.)

## 22. A dedicated bulk channel

The base bulk plane (§3) rides the existing data channel as unsigned, hash-verified frames — simplest, and entirely inside the kernel message model. For higher throughput on large files, a deployment can run a **dedicated bulk data channel** alongside the kernel-envelope channel on the same connection. The control plane negotiates a transfer (block-ids, order, window) over signed kernel messages; raw blocks then stream over the bulk channel. This is the most performant option for large files, at the cost of a second channel to manage. The integrity rule is unchanged: every block is validated by `genesis_hash(bytes) == block_id`.

## 23. Hardening a less-trusted cohort

Add only if a deployment's cohort is less than fully trusted; none of this is needed for a friends-or-devices cohort.

- **PRF locator tags.** Address blocks by `tag = PRF_{K_loc}(block_id)` (with `K_loc` a per-file locator key separate from the decryption key) instead of by the raw ciphertext hash. This decouples the locator from the content hash, gives holders and observers unlinkability, and lets you rotate locators on a membership change without re-encrypting. Cost: one extra per-file key and a second identifier in the manifest. **If you adopt this, the chunk descriptor's `chunk_id` and `block_ids` (§4.3) must be tagged the same way** — they are stable per-chunk identifiers held by every block-holder, so left in the clear they survive as cross-file linkage handles that defeat the unlinkability the tags otherwise buy. Tag them as `PRF_{K_loc}(·)` (the repairer still verifies reconstruction by recomputing the raw `chunk_id` locally and re-applying the PRF).
- **Size-hiding have/want.** Pad have-sets to a round number or send them as Bloom filters to blunt the inventory-size leak (§15) — cheap, and the right first step for a semi-trusted pool.
- **Size-Hiding PSI.** A malicious-secure, size-hiding private set intersection would hide set size and non-intersection elements even from an authorized-but-curious peer, at the cost of a multi-message protocol, real per-run latency, mandatory rate-limiting, and a substantial implementation burden. A possible future layer for genuinely semi-trusted community pools, **not** part of this design.

## 24. Convergent encryption for dedup

The base design uses a random per-file key, so two users storing the same file produce different ciphertext and no dedup. A deployment that wants **cross-user dedup** can opt into convergent encryption (key = hash(plaintext)), which makes identical plaintext converge to identical ciphertext and identical block-ids — at the cost of an equality-leak: a holder can tell that two users stored the same content. Off by default; choose it only where the dedup saving outweighs the leak.

---

## 25. Tuning knobs and open questions

- **`(k, m)`, chunk size, and block size `B`** — the durability/overhead dial. Size against measured cohort churn so the chance of losing more than *m* holders within one repair interval is acceptably small. `B` sets how many blocks a file becomes, and therefore manifest and have/want size.
- **Grace window `G` and liveness cadence** — set so ordinary offline patterns (overnight, commute, reboot) never trigger repair, but real departures do within a bounded time. Too short → churn storms; too long → slow healing. Includes how often, and how widely, to sample verification-fetches (§8).
- **Low-water mark & repair jitter** — trade healing speed against repair traffic and duplicate-repair avoidance.
- **Cohort uptime** — the load-bearing durability decision (§9): each chunk's holders should include at least one well-connected, long-lived peer so repair can always run.
- **Reciprocity decay & weighting** — the half-life of the local score and how strongly to net give-against-take (§13).
- **Committed/cache split & eviction weights** — how much quota a node reserves for durable commitments vs. opportunistic cache, and the weighting of the eviction score (§14).
- **Tombstone retention** — how long a holder keeps a tombstone after the referenced blocks are gone (§11).
- **Extensions, if enabled** — verifiable-reputation window `X`, EigenTrust damping `d`, and local-seed anchoring (§20); RS vs. LRC and where (§21); in-band vs. dedicated bulk channel (§22); hardening choices (§23); convergent vs. random-key encryption (§24). All are off or RS/in-band by default.

Everything above is expressible as bridges, pure-compute handlers, signed messages, and a restrictive policy callback — i.e. as ordinary seedkernel modules. The kernel never learns what a "file" is; it just keeps routing names to handlers, the bulk bytes never enter its 64 KB world, and the core stays five ideas deep: a social cohort, encryption, content addressing, erasure coding, and have/want — with reciprocity, not a coin, rewarding the good citizens.
