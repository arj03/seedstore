# Seed store: a peer-to-peer storage layer for seedkernel

## 1. Vision

Seedkernel already tells us where this layer belongs. §2.2 caps every envelope at 64 KB and says outright that anything bigger is handled by putting a **content hash** under the signature and fetching the actual bytes from an *external store*. **Seed store is that external store.** The kernel keeps doing one thing — route a name to a handler — and the bulk bytes never touch its dispatch path. Everything we add is the same three orthogonal pieces seedkernel is built from: a **name** to dispatch on, **bytes** that are a WASM handler, and an **author** who signed the install.

The job: let any node *donate whatever storage it has*, store files across a set of peers so that **no single peer can make a file unavailable**, tolerate peers being offline for stretches, **self-heal** by moving data when redundancy drops, **shard** large files so size is bounded only by the swarm, and **reward good citizens** with a verifiable reputation rather than a coin.

This design assumes a **closed, social network**: you store with and among peers you have a relationship with (friends, friends-of-friends, or an explicit storage group), not an open market of strangers. That assumption is what keeps the whole thing small — privacy and Sybil resistance come from the *shape* of the network, not from heavyweight cryptographic discovery. The whole system is four ideas: **a social cohort, client-side encryption, content addressing, and a have/want exchange.**

**Design principles (inherited from the kernel, applied to storage):**

- The storage layer adds **no new kernel concepts**. It is bridges + app handlers + message names, gated by the existing capability and signature machinery.
- **Integrity comes from content addressing, not from signatures.** A block is named by its hash; a block either hashes to its name or it is discarded. This is what lets bulk transfer skip the per-message verify that dominates kernel cost (§11).
- **Identity comes from the signature module.** A peer *is* its kernel pubkey (§6.5). Reputation and storage receipts key on that one identity.
- **Redundancy is erasure coding, not replication.** Any *k* of *n* fragments reconstruct a chunk, so up to *n − k* holders can vanish with no data loss, at a fraction of replication's overhead.
- **Placement is by relationship, not by global address.** Fragments live on peers in your cohort, chosen by negotiation and remembered in the (encrypted) manifest. There is no global index of who holds what — the absence of that index is a feature, not a gap (§5).
- **Confidentiality is structural.** The wire is encrypted (DTLS, §12); stored data is encrypted so holders only ever see ciphertext; and there is no public directory mapping content to holders. No extra discovery protocol is needed to get these properties.
- **Browser nodes and long-running peers are the same protocol** with different `store.local` backends and different default quotas — exactly as the chat demo already runs identically in a Node host and a browser shell (§12).

The reference composition stacks: storage app handlers → cohort + repair + proof handlers → storage bridges (`store.local`, `net.send`, `clock.now`, `rand`) → installer → signature → kernel.

---

## 1.1 Concepts at a glance

- **Block** — the unit that moves on the wire: a content-addressed slice of bytes, ≤ 48 KB so it fits an envelope with room for framing (§4). `block_id = genesis_hash(ciphertext_bytes)`.
- **Chunk** — a logical slice of a file (e.g. 4 MB) that is erasure-coded into *n* **fragments**, of which any *k* reconstruct it. Fragments are stored as blocks.
- **Manifest** — the small root object that lists a file's chunks, their RS parameters, fragment block-ids, the current **holders** of each fragment, and the wrapped content key. The only thing you need to retrieve a whole file, and the only place the holder map lives.
- **Cohort** — the bounded set of peers you have a storage relationship with. Discovery, placement, and repair all happen inside it. There is no global overlay.
- **Have/want** — the discovery primitive: peers tell each other which block-ids they hold or want. One round trip, no crypto protocol. Replaces a DHT lookup.
- **Repair delegate** — a peer the owner authorizes (by sharing the manifest + a repair capability) to audit redundancy and repair on its behalf. Ideally at least one delegate is long-running.
- **Receipt** — a *signed* attestation that a holder answered a storage challenge correctly (§12). A peer's reputation is the verifiable pile of receipts others signed about it.
- **`store.local`** — the I/O bridge (capability `store`) that reads/writes the node's donated blob store: filesystem on a server, OPFS/IndexedDB in a browser.

```
file ──chunk──► chunk[i] ──erasure-code──► fragment[i][0..n)
                                              │  each fragment = one content-addressed block of ciphertext
                                              ▼
                     placement: negotiate with cohort peers (frag.offer / accept)
                                              ▼
              push blocks ──► holders        record holders ──► manifest (shared in the group)
```

---

## 2. How it composes with the kernel

Nothing here changes the envelope, the dispatch rule, or `SetHandler`. Storage shows up as four kinds of seedkernel object:

**Identity.** Every operation that needs "who" reads `signature.signer` (§6.5). The author of a manifest, the signer of a storage receipt, the owner whose reputation moves — all are the top signer. There is no separate account system.

**Names.** All storage messages are envelopes with storage names. Bootstrap-style names follow the existing convention `hash("seedkernel.bootstrap.v1:" + canonical)`; app handlers install under author-scoped names per §5.1 of the kernel spec so two deployments' storage apps never collide.

**Capabilities.** Each storage bridge is bound to exactly one capability (§9 of the kernel spec), declared by the handlers that use it at install time and acknowledged through the reference policy's rule 3 (§7.4). A pure-compute handler (the chunker, the erasure coder, the manifest builder) declares **no** caps — it is computation, and the structural sandbox (§8.3) guarantees it can touch no I/O even if compromised.

**Transport.** The chat demo already carries kernel envelopes as binary WebRTC data-channel frames, with each frame's signer pinned to the channel's kernel pubkey (§12). Seed store reuses that transport and adds one capability-gated `net.send` for *addressed unicast* to a specific cohort peer (the chat mesh broadcasts; storage needs to talk to the one peer holding fragment *B*). Bulk blocks ride either the same channel as unsigned, hash-verified frames or a dedicated bulk data channel (§4).

**The 64 KB cap is the whole reason this layer exists** (§2.2), so §4 treats it first.

---

## 3. Data model: files → manifests → chunks → fragments

### 3.1 Chunking

A file is cut into fixed-size **chunks** (default 4 MB; a deployment knob). Fixed-size chunking is simplest; a deployment that wants cross-file dedup can swap in content-defined chunking (a rolling-hash cut) without touching anything else, because everything downstream addresses chunks by id, not by offset.

### 3.2 Erasure coding (the redundancy primitive)

Each chunk is encoded with **Reed–Solomon `RS(k, m)`** into `n = k + m` fragments, where any *k* fragments reconstruct the chunk. Defaults: `k = 10, m = 6` → `n = 16`, 1.6× storage overhead, survives the loss of any 6 holders. Compare naïve 3× replication, which survives only 2 losses at nearly double the cost. RS encode/decode is pure arithmetic over GF(2^8) and compiles to a small, cap-free WASM handler.

The choice of `(k, m)` is per-chunk and recorded in the manifest, so a deployment can dial durability per file (cold archives might use `RS(20, 20)`; hot ephemeral data `RS(4, 2)`).

### 3.3 Fragments are blocks

Each fragment is sliced into **blocks** of ≤ 48 KB (§4) and each block is content-addressed: `block_id = genesis_hash(block_bytes)`. A fragment that is one block long is the common case; large fragments are a short block list. Content addressing makes every block **self-verifying**: a receiver recomputes the hash and rejects anything that doesn't match, so a malicious holder cannot return corrupt bytes undetected, and no signature is needed on bulk data. Because the bytes are ciphertext (§3.5), the `block_id` is the hash of an encrypted blob — opaque and unguessable to anyone who has not handled that exact file.

### 3.4 The manifest

The manifest is the file's root object — small, and the only thing a reader needs to bootstrap a download. It is also where the holder map lives:

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
        {
          frag_index,
          block_ids: [...],              // the blocks that make up this fragment
          holders:   [pubkey, ...]       // cohort peers currently holding it
        }
      ]
    }, ...
  ]
  manifest_id = genesis_hash(manifest_bytes)
```

The manifest is stored exactly like file data — chunked, **erasure-coded, and spread across cohort peers** — and is shared with the file's sharing group, so it has no single point of failure and there is no "index server." A file is referenced by `manifest_id`; that one hash, under a signature, is what travels in a 64 KB kernel envelope (the §2.2 pattern, recursively). The `holders` lists make a read a direct fetch with no lookup; repair updates them and re-shares the manifest (§9).

### 3.5 Encryption (the load-bearing privacy mechanism)

§14 of the kernel spec is explicit: kernel envelopes are signed, not encrypted, and at-rest storage has *no* confidentiality unless a deployment adds an encryption module. In this design, **encryption is what makes the closed network safe** — it lets you store on cohort peers who can read nothing, and it makes block-ids opaque. Seed store encrypts **client-side before erasure coding**:

- Generate a random per-file content key; AEAD-encrypt each chunk (key + per-chunk nonce) before RS encoding. Holders store ciphertext fragments and learn nothing about content.
- The content key is wrapped to the file's sharing group and carried in the manifest; sharing a file means sharing/re-wrapping the key, not moving bytes.
- Random per-file keys mean two different files never produce colliding ciphertext, so a `block_id` is meaningful only to someone who has handled that exact file. Convergent encryption (key = hash(plaintext)) is an opt-in for deployments that want cross-user dedup and accept its equality-leak.

This is the "compose another wrapper" escape hatch §2.1/§14 describe, applied at the storage layer instead of the wire.

---

## 4. The bulk-data problem (64 KB) and the two planes

The single hardest constraint is that **no envelope may exceed 64 KB** (§2.2) and it is a fixed protocol constant, not a knob. So a 4 MB chunk cannot be one message. Seed store splits into two planes:

**Control plane — kernel envelopes.** Manifest root hashes, have/want exchanges, placement offers, fetch requests, challenges, receipts, repair coordination. These are small, identity-bearing, and signed where authorization matters. They flow through the normal `host.dispatch` pipeline and pay the ~83 µs verify (§11) — fine, because they are infrequent relative to bytes moved.

**Bulk plane — content-addressed blocks.** Fragment blocks ≤ 48 KB. These are **self-verifying by hash**, so they need no signature for integrity. Two transport options, chosen per deployment:

1. **In-band, unsigned, hash-verified frames** on the existing data channel. The receiver verifies `genesis_hash(bytes) == requested block_id` and drops on mismatch. This stays entirely inside the seedkernel message model and inherits DTLS confidentiality + the channel's pubkey pinning (§12), but avoids the verify-amplification §2.3 warns about because there is no signature to verify per block.
2. **A dedicated bulk data channel** alongside the kernel-envelope channel on the same `RTCPeerConnection`. The control plane negotiates a transfer (block-ids, order, window) over signed kernel messages; raw blocks then stream over the bulk channel. This is the most literal reading of §2.2's "external store" and the most performant for large files.

Either way the rule is the same: **the control plane carries hashes and authorization; the bulk plane carries hash-named bytes that authenticate themselves.** Transfers are flow-controlled with a simple windowed request/ack (`frag.fetch_req` lists wanted block-ids; holder streams `frag.block`s; receiver acks ranges) so a browser node doesn't blow its heap on a 4 MB fragment.

---

## 5. Discovery: a social cohort with have/want

We need to answer two questions — *which peers should hold a block?* and *who currently holds it?* — without a public, queryable index that would map content to holders. The closed-network assumption (§1) lets us answer both with almost no machinery.

### 5.1 The cohort

A node keeps connections to a **bounded set of peers it has a relationship with** — direct contacts plus, optionally, a hop or two out. There is no structured global keyspace, no XOR routing table, nothing to leak network-wide. New peers join the way Scuttlebutt peers do: by introduction, or via the existing relay-room rendezvous (§12 of the kernel spec). Cohort size is tens to low hundreds, which is what keeps every operation here cheap.

### 5.2 Have/want is the whole discovery layer

- *Who currently holds fragment F?* — you already know: the manifest records `holders` per fragment (§3.4). A read is a direct fetch, not a lookup.
- *Does this peer still hold these blocks? Are there extra replicas to use?* — a one-round **have/want** exchange: "I want these `block_id`s" / "I have these `block_id`s." No DHT walk, no cryptographic protocol, no rate-limit machinery.

Block-ids are hashes of random-key ciphertext (§3.5), so to a peer outside a file's sharing group they are opaque noise, and on the wire they are inside DTLS. The only parties who can interpret a have/want entry are those who already hold the file's key — i.e. people you deliberately shared with.

### 5.3 What this is, and is not

This is deliberately **not an open market**: strangers cannot find or serve your data, because there is no global index and nothing to query. That absence is exactly the privacy property the DHT could not provide. The cost is that storage is confined to your cohort — which is the trade we are choosing.

What leaks, and why it is acceptable here: a peer you exchange have/want with learns which block-ids you hold or want *of files you have already shared with it*, and roughly your inventory size. These are disclosures to people you have already chosen to store with, about files you have already shared with them. The full leak inventory and the optional hardening for less-trusted cohorts are in §13.

---

## 6. Writing a file (PUT)

1. **Chunk & encrypt.** The owner feeds the file to the `chunker` (cap-free) block-by-block (the 64 KB cap applies to messages between handlers too, §4.4 of the kernel spec). Each chunk is AEAD-encrypted (§3.5).
2. **Erasure-code.** The `erasure` handler (cap-free) turns each chunk into `n` fragments; the `chunker` slices fragments into ≤ 48 KB blocks and computes block-ids.
3. **Place by negotiation.** For each fragment, the `store.coordinator` picks candidate cohort peers — ordered by reputation (§12) and current reachability — and sends `frag.offer(block_id, size)`. A peer with free quota and willingness replies `frag.accept`; otherwise `frag.decline` and the coordinator moves to the next candidate. There is no global placement function; placement is a short private negotiation within the cohort.
4. **Push.** On accept, the coordinator streams the block over the bulk plane (§4).
5. **Record holders.** Each fragment's accepting peers are written into the manifest's `holders` list, and the manifest is shared with the file's sharing group (and stored the same erasure-coded way, §3.4) so the holder map is replicated, not centralized.
6. **Publish the manifest.** `manifest_id` is what the owner keeps/shares — wrapped in a signed 64 KB envelope (§2.2).

Distinct fragments of the same chunk are placed on **distinct peers** (the coordinator enforces no-two-fragments-same-holder per chunk), so losing one peer costs at most one fragment of any chunk — the core of the §10 invariant.

---

## 7. Reading a file (GET)

1. **Resolve the manifest.** You either hold it (you are in the sharing group) or fetch its blocks from the cohort peers the group replicated it to, then verify and decrypt the wrapped key.
2. **Locate fragments.** Read `holders` straight from the manifest. You need any *k* of *n* per chunk, so race requests to the *k* most-reputable reachable holders; if some are offline, a quick have/want with other cohort peers turns up any extra replicas repair has created.
3. **Fetch & verify.** Stream blocks over the bulk plane; each is checked against its `block_id` (self-verifying, §3.3).
4. **Decode & decrypt.** RS-decode each chunk from its *k* fragments, AEAD-decrypt, concatenate.

Because any *k*-of-*n* suffices, a read succeeds even with up to *m* holders offline or unwilling — no peer is on the critical path.

---

## 8. Availability and offline tolerance

Peers are expected to disappear and come back. The protocol distinguishes a transient blip from real loss so it doesn't churn data on every disconnect — but it does so by *direct observation within the cohort*, not by a global TTL/refresh scheme.

**How liveness is observed.** A repair delegate (§9) periodically reaches the holders named in a manifest — a lightweight have/want or heartbeat over the existing channel — and notes who answered.

**Three states per holder of a fragment:**
- **Live** — recently reachable and confirms it still holds the block.
- **Suspected** — unreachable within a **grace window** `G` (default 24 h). *No repair.* This is precisely "a node may be offline for a period": a laptop closed overnight, a phone in a tunnel, a server rebooting all sit here and recover for free when they reappear.
- **Lost** — unreachable beyond `G`. Eligible to be counted as missing for repair.

**Redundancy measure.** For a chunk, `live_fragments` = number of distinct fragments with at least one Live holder. Data is safe while `live_fragments ≥ k`; the healthy target is `n = k + m`. Repair triggers on a **low-water mark** strictly above `k` (§9), never waiting until the chunk is one loss from death.

**Browser nodes specifically** are treated as low-uptime, often-Suspected holders: they may serve reads and act as extra cache while present, but the durable *m* leans on longer-lived cohort members. A deployment can tag node longevity so placement prefers servers for durability and lets browsers absorb read load.

---

## 9. Self-healing / repair

Repair is **delegate-driven**. Without a DHT there are no ownerless XOR shepherds; instead the owner authorizes a small, explicit **repair group** by sharing the manifest plus a repair capability with a few trusted cohort peers — ideally including at least one always-on node.

**The repair loop (run by each delegate on a jittered interval):**
1. For each manifest it shepherds, reach the named holders (§8) → compute `live_fragments`.
2. If `live_fragments < low_water` (default `k + ⌈m/2⌉`), repair is needed.
3. **Pick one repairer to avoid duplicate work.** The delegate set is small and known, so the lowest-pubkey reachable delegate leads; the others set a short back-off and cancel when they see the manifest updated with fresh holders. No election protocol — a total order on a handful of known pubkeys is enough.
4. The repairer fetches any *k* live fragments, RS-decodes the chunk, re-encodes only the **missing** fragments, and places them on fresh cohort peers (§6 steps 3–5), excluding current holders so redundancy spreads to new peers.
5. It updates the manifest's `holders` and re-shares it; redundancy returns to `n`.

**Moving data on availability change** is the same machinery, run proactively: if a delegate sees a cohort region degrading (many Suspected/Lost holders, e.g. a correlated outage), it re-spreads fragments toward healthier peers before a chunk crosses low-water.

**Honest cost of dropping the DHT.** Repair now requires at least one delegate to be online within a repair interval. As long as the repair group has reasonable aggregate uptime (include one or two long-running peers), this is fine. A *purely* browser cohort with no always-on member genuinely loses durability here — that is the real price of the simpler, private model, and a deployment should ensure each sharing group has a durable delegate.

**Repair amplification is bounded** by erasure coding: regenerating one lost fragment costs *k* fragment-reads, not a full re-upload, and only the lost fragments are rebuilt.

---

## 10. The redundancy invariant: no peer can make data unavailable

This requirement is met structurally, not by trust:

- **No fragment is unique.** A chunk survives on any *k* of *n* fragments, and distinct fragments live on distinct peers (§6). One peer holds at most one fragment of a given chunk, so its disappearance — or its refusal to serve — costs at most one fragment. You need *more than m* peers to fail or defect simultaneously to lose a chunk.
- **No metadata is unique.** The manifest is stored the same erasure-coded way and shared across the file's group (§3.4); there is no single index server.
- **No single repairer is required.** The manifest and repair authority are shared across the repair group; any delegate can repair, and they overlap. Removing any one delegate removes no capability — provided the group retains aggregate uptime (the §9 honest cost).
- **Withholding is detected and routed around.** A holder that stops serving fails storage challenges (§12), loses reputation, gets skipped in future placement, and its unreachability tips it to Lost and triggers repair. Active malice degrades to the same path as passive offline-ness.
- **Corruption is impossible to hide.** Content addressing (§3.3) means a tampered block fails its hash check and is discarded; the reader simply fetches another fragment.

The honest assumptions this rests on: *fewer than the redundancy budget of a chunk's holders fail or defect within a repair interval*, and *at least one repair delegate is online within that interval*. Sizing `(k, m)`, the low-water mark, the repair cadence, and the delegate set against your cohort's real churn is the deployment's durability dial (§18).

---

## 11. Donating storage

"Donate whatever storage you have available" is the `store.local` bridge plus a host-configured quota.

**`store.local` (capability `store`)** is a host-native bridge (§9 of the kernel spec) with operations `put(block_id, bytes)`, `get(block_id) → bytes`, `has(block_id)`, `delete(block_id)`, `list(prefix)`, and `stat() → { quota, used, free }`. Like every bridge it runs the §8.2 caller-capability preamble before touching disk, so only handlers that declared `store` at install time can reach it. A holder stores opaque `(block_id → ciphertext)` pairs: it needs no file key and learns nothing about what it is holding.

**Backends differ by host, protocol does not:**
- **Long-running peer (Node host):** a directory on disk; quota is a config number; effectively always Live.
- **Browser node (browser shell):** OPFS or IndexedDB; quota bounded by the browser's storage budget; eviction-aware (treat browser-evicted blocks as Lost and let repair handle them). The browser shell exposes a "donate N GB" slider exactly as the chat shell exposes a Room field (§12).

**Quota honesty is enforced, not assumed.** A node advertises free space, but a delegate does not trust the number — it trusts the node's track record of *passing storage challenges for data it accepted* (§12). Lying about capacity gets you data you then fail to prove you hold, which costs reputation. `store.local.stat()` is for the owner's own accounting and admission control (refuse `frag.offer` when full), not a network-trusted figure.

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

Receipts are the kernel's signature wrapper (§6.3) doing exactly what it's for: an authenticated, replay-resistant attestation (each carries the challenge `nonce`; §4.4 `seq`/nonce discipline applies). A holder accumulates receipts as its **track record**.

### 12.2 What reputation is

A peer's reputation is computed from the receipts *others signed about it*, weighted by:
- **Volume & longevity** — passing challenges for more data, over more time.
- **Challenger diversity** — receipts from many *distinct* peers count more than many from one (collusion resistance).
- **Recency** — a decaying window so a peer that stops serving decays back down.
- **Retrieval success** — serving real `frag.fetch_req`s, not just challenges.

Two complementary views, and the closed network makes the simple one the default:
- **Subjective / local (default):** every peer scores peers it has directly interacted with. In a cohort you mostly *have* interacted with everyone you store with, so local scoring covers the common case and is inherently Sybil-proof — you only trust what you witnessed.
- **Gossiped / objective (optional):** peers exchange signed receipt summaries (`rep.gossip`) so you can evaluate a friend-of-a-friend you haven't met, discounting by how much you trust the attesters. EigenTrust-style transitive weighting is a drop-in; the inputs are all signed receipts.

`reputation.score(pubkey) → score` is a read-only `kernel.call` query, used by placement (§6), by holders deciding whether to accept a `frag.offer`, and by readers choosing whom to fetch from first.

### 12.3 What reputation buys (the incentive loop)

Reputation is spendable as **priority**, which closes the loop without money:
- **Durability for your own data.** High-reputation owners get their `frag.offer`s accepted readily and placed on the best holders; low/negative-reputation peers are throttled or asked to contribute first.
- **A storage allowance proportional to contribution.** A soft, tit-for-tat budget: roughly, the cohort will durably hold for you about as much as you have reliably held for others (Storj/BitTorrent-style reciprocity). This makes leeching self-limiting and makes donating storage directly valuable to the donor.
- **Preferential read bandwidth and faster repair participation.** Good citizens are chosen first to serve and to repair (and earn more receipts doing so — the loop compounds).

Honest, available, truthful-about-capacity nodes accumulate receipts and climb; nodes that withhold, lie, or churn destructively fail challenges, decay, and get routed around (§10). The "reward" is that being a good citizen is the *only* way to get good service for your own data.

---

## 13. Threat model and what leaks

Because the network is a closed social cohort, the dominant open-network threats shrink: you only peer with people you've added, so Sybil flooding and eclipse are not the everyday concern they are in an open DHT, and the installer policy stays restrictive (an open registry is remote code execution, §7.3) so untrusted WASM never lands.

**What is protected.** Content — encryption means holders see only ciphertext (§3.5). The wire — DTLS, with each frame's signer pinned to the channel pubkey (§12). The content↔holder mapping — there is no global index; the holder map lives only in the manifest, shared with the file's group. Integrity — content addressing (§3.3). Identity — signatures (§6.5).

**What leaks, accepted by the closed-cohort assumption.** All of these are disclosures *to peers you have chosen to store with, about files you have already shared with them*:
- **Inventory size** — a peer you have/want with learns roughly how much you store and a shared file's fragment count.
- **Per-file holdings** — to a peer in a file's sharing group, which fragments you hold or want.
- **Interest** — asking a key-holder for a file reveals you wanted it (a non-key-holder learns nothing — the id is an opaque hash).
- **Social graph** — who you maintain channels with is visible at the transport level. This is the residual metadata of going social, and it is far smaller than the open-DHT leak it replaces.
- **Ex-member probing** — someone who once held a file's ids can probe for those specific blocks until repair rotates them away; for sensitive files, re-encrypt/rotate on a membership change (expensive, usually accepted only when it matters).

**Optional hardening (documented, deliberately unbuilt).** Add only if a deployment's cohort is less than fully trusted; none of it is needed for a friends-or-devices cohort, and adding it by default would make the system the "complicated monster" we are avoiding:
- **PRF locator tags.** Address blocks by `tag = PRF_{K_loc}(fragment_id)` (with `K_loc` a per-file locator key separate from the decryption key) instead of by the raw ciphertext hash. This decouples the locator from the content hash, gives holders/observers unlinkability, and lets you rotate locators on a membership change without re-encrypting. Cost: one extra per-file key and a second identifier in the manifest.
- **Size-hiding have/want.** Pad have-sets to a round number or send them as Bloom filters to blunt the inventory-size leak — cheap, and the right first step for a semi-trusted pool.
- **Size-Hiding PSI.** A malicious-secure, size-hiding private set intersection (e.g. the SHI-PSI construction) would hide set size and non-intersection elements even from an authorized-but-curious peer, at the cost of a 5-message protocol, ~20–200 ms per run, mandatory rate-limiting, and a real implementation burden. It is a possible future layer for genuinely semi-trusted community pools, **not** part of this design.

**Residual kernel-inherited risks.** The protocol bounds verify-amplification and recursion but not a single handler's CPU/memory (§14 of the kernel spec), so run the heavy `erasure` and `repair` handlers under a Worker watchdog.

---

## 14. New bridges (host-native, `SetHandler`-installed, one capability each)

| Bridge | Cap | Payload (request) | Host action |
| --- | --- | --- | --- |
| `store.local` | `store` | op-tagged: `put`/`get`/`has`/`delete`/`list`/`stat` (§11) | read/write the donated blob store (FS or OPFS/IndexedDB) |
| `net.send` | `net` | `[peer_id_len][peer_id][bytes...]` | addressed unicast to a cohort peer over its data channel (open/reuse) |
| `clock.now` | `clock` | (empty) | u64 unix ms — grace windows, challenge timing, repair jitter |
| `rand` | `rand` | `[n]` | n cryptographically-random bytes — nonces, content keys, jitter |

`net.send` is the one genuinely new transport primitive (the chat demo broadcasts; storage needs unicast). Async by nature, so it follows the §9 async-bridge pattern: returns a correlation id, and the host later delivers the response via `kernel.call` *from the bridge's own name* so the originator can authenticate it. `clock.now` and `rand` are conventional bridges a deployment likely already has.

---

## 15. New app handlers (WASM, installed via signed messages)

| Handler | Caps | Role |
| --- | --- | --- |
| `chunker` | — (pure) | split files into chunks; slice fragments into ≤ 48 KB blocks; compute block-ids |
| `erasure` | — (pure) | Reed–Solomon encode/decode over GF(2^8) |
| `manifest` | — (pure) | build/parse manifests (incl. holder lists); wrap/unwrap content keys |
| `cohort` | `net`, `clock` | maintain the peer set and connections; run have/want exchanges and liveness checks |
| `store.coordinator` | `store`, `net`, `clock` | orchestrate PUT/GET, including placement negotiation; windowed transfer |
| `repair` | `store`, `net`, `clock` | delegate loop: measure redundancy, lead/back-off, reconstruct, re-share manifest (§9) |
| `proof` | `store`, `clock` | answer challenges (holder side) and issue them + sign receipts (challenger side) |
| `reputation` | — (pure) | accumulate signed receipts; compute local + optional gossiped scores; `reputation.score` query |

Dropping the DHT collapses what used to be a routing handler plus an XOR-placement handler into one small `cohort` handler (peer set + have/want) with placement folded into `store.coordinator`. The three pure handlers (`chunker`, `erasure`, `manifest`) declare **no** capabilities, so the structural sandbox (§8.3) guarantees they can never reach disk or network even if buggy — the heavy crypto/coding code is exactly where you want that guarantee. Mutating handlers (`store.coordinator`, `repair`, `proof`) that act under a signer's authority consume a `seq` per §4.4 of the kernel spec.

---

## 16. Message catalog (control plane; every message ≤ 64 KB)

| Name | Direction | Payload sketch |
| --- | --- | --- |
| `store.put_req` / `store.put_done` | user ↔ coordinator | file blocks in / `manifest_id` out |
| `store.get_req` / `store.get_done` | user ↔ coordinator | `manifest_id` in / file blocks out |
| `frag.offer` / `frag.accept` / `frag.decline` | coordinator ↔ holder | `block_id`, size / accept / reason |
| `frag.fetch_req` / `frag.block` / `frag.ack` | reader ↔ holder | wanted block-ids / a block (bulk plane) / window ack |
| `disc.have` / `disc.want` | peer ↔ peer | block-ids held / block-ids wanted (the discovery layer, §5) |
| `proof.challenge` / `proof.response` / `proof.receipt` | challenger ↔ holder | nonce+offset / sector+merkle / **signed** receipt |
| `repair.observe` / `repair.claim` | delegate ↔ delegate | redundancy report / "I'm repairing this manifest" |
| `rep.gossip` | peer ↔ peer | signed receipt summaries (optional, for friend-of-a-friend scoring) |

Control messages that authorize a state change (the mutators in §15) carry a leading `u32 seq` and are dropped on replay per §4.4 of the kernel spec. Bulk `frag.block`s carry no signature; they are validated by `genesis_hash(bytes) == block_id` (§4).

---

## 17. Bootstrap additions

On top of the kernel bootstrap (§10 of the kernel spec), a storage-capable node additionally:

1. `SetHandler` the storage bridges it offers: `store.local` (always, to donate space), `net.send`, `clock.now`, `rand`.
2. Wire an installer policy (§7.4) that admits the storage app handlers — restrictive, *never* open (§7.3), e.g. a content-hash allowlist of audited storage-handler bytecode plus a closed author set for who may publish upgrades.
3. Receive the storage app handlers as signed install messages (`chunker`, `erasure`, `manifest`, `cohort`, `store.coordinator`, `repair`, `proof`, `reputation`) — each declaring exactly the caps in §15, with cap-broadening acknowledged per rule 3.
4. Join its cohort: connect to known peers via introductions or the relay-room rendezvous (§12 of the kernel spec), exchange have/want, and start serving.

A node that only wants to *donate* storage installs the holder-side path (`store.local`, `cohort`, the accept/serve half of `store.coordinator`, the holder half of `proof`) and never needs the writer's chunker/erasure/manifest. A read-only client needs the reverse. The onion composes per-role.

---

## 18. Tuning knobs and open questions

- **`(k, m)` and chunk size** — the durability/overhead dial. Size against measured cohort churn so that `P(more than m holders lost within one repair interval)` is acceptably small.
- **Grace window `G` and liveness cadence** — set so ordinary offline patterns (overnight, commute, reboot) never trigger repair, but real departures do within a bounded time. Too short → churn storms; too long → slow healing.
- **Low-water mark & repair jitter** — trade healing speed against repair traffic and duplicate-repair avoidance.
- **Repair-delegate set** — who, how many, and the uptime requirement. This is the load-bearing durability decision once the DHT is gone (§9): each sharing group should have at least one durable delegate.
- **Reputation function** — the weighting of volume/diversity/recency, the decay rate, and whether to enable gossiped transitivity. This lives in the pure, swappable `reputation` handler.
- **Bulk transport choice** — in-band hash-verified frames (simplest, fully in-model) vs. a dedicated bulk channel (fastest). §4 supports either.
- **Convergent vs. random-key encryption** — dedup vs. equality-leak (§3.5).
- **Optional hardening** — PRF locator tags, padded/Bloom have-sets, or full PSI for less-trusted cohorts (§13). Off by default; add only when the cohort's trust assumption no longer holds.

Everything above is expressible as bridges, pure-compute handlers, signed messages, and a restrictive policy callback — i.e. as ordinary seedkernel modules. The kernel never learns what a "file" is; it just keeps routing names to handlers, the bulk bytes never enter its 64 KB world, and the design stays four ideas deep: a social cohort, encryption, content addressing, and have/want.
